/**
 * ransomware_scope_report writes the host pages on the clock, and a host named in a row of a timeline is held to 255 characters. The
 * page loop judged and wrote a row for every host with no clock: 5,000 hosts named with 20,000 characters each held the tool 951 s
 * against its 900 s timeout. At the clock (and the order's grace) the loop stops, and the hosts it did not write are counted and make
 * the answer partial.
 */
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { PACK, tool } from "./ransomware-pack-harness.ts";

const REPORT = join(PACK, "ransomware_scope_report", "run.py");

test("a host named in a timeline row with more than 255 characters is a row skipped, not a host", async () => {
  await withCwd(async (cwd) => {
    const rows = [
      { host: "alpha", time: "2026-10-02T08:00:00Z", kind: "logon" },
      { host: "h".repeat(256), time: "2026-10-02T08:00:00Z", kind: "logon" },
    ];
    await writeFile(join(cwd, "tl.jsonl"), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
    const out = await tool(REPORT, cwd, { timelines: [{ file: "tl.jsonl" }] });
    const a = JSON.parse(out.stdout);
    assert.equal(a.status, "partial");
    assert.equal(a.coverage_statement.hosts, 1, "only the host with a name of 255 characters or fewer is a host");
    assert.ok(a.partial_reasons.some((r: string) => /rows_skipped: 1/.test(r)), JSON.stringify(a.partial_reasons));
  });
});

test("the page loop reads the clock: at it the hosts not yet written are counted, and the answer says so", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "site"), { recursive: true });
    // A clock that moves half a second every time the tool looks at it, so that max_seconds and the order's grace pass within a few dozen looks.
    await writeFile(join(cwd, "site", "sitecustomize.py"), "import time\n_t = [0.0]\ndef monotonic():\n    _t[0] += 0.5\n    return _t[0]\ntime.monotonic = monotonic\n");
    const hosts = Array.from({ length: 400 }, (_, i) => `host-${String(i).padStart(4, "0")}`);
    await writeFile(join(cwd, "tl.jsonl"), JSON.stringify({ host: "alpha", time: "2026-10-02T08:00:00Z", kind: "logon" }) + "\n");
    const out = await tool(REPORT, cwd, { timelines: [{ file: "tl.jsonl" }], expected_hosts: hosts, max_seconds: 1 }, { PYTHONPATH: join(cwd, "site") });
    const a = JSON.parse(out.stdout);
    assert.equal(a.status, "partial", out.stdout.slice(0, 600));
    assert.ok(a.time_limit.hosts_not_written > 0, JSON.stringify(a.time_limit));
    assert.equal(a.time_limit.hosts_not_written + a.coverage_statement.hosts, 401, "every host is written or counted as not written");
    assert.ok(a.partial_reasons.some((r: string) => /while the host pages were written: \d+ hosts have no row/.test(r)), JSON.stringify(a.partial_reasons));
  });
});
