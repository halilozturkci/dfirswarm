/**
 * ransomware_scope_report: the host a timeline entry names applies to the events that carry none, and a census that could not be read
 * does not count as one. The tool fell back to the numeric host id for an event with no host, failed the string check and skipped every
 * event; and a census it could not open (a named pipe, a missing file) still counted its host among the hosts with a census, at 0 files
 * and 0 bytes.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { PACK, tool } from "./ransomware-pack-harness.ts";

const REPORT = join(PACK, "ransomware_scope_report", "run.py");

test("a timeline entry's host applies to its events that carry none; an event's own host still wins", async () => {
  await withCwd(async (cwd) => {
    const rows = [
      { time: "2026-10-02T08:00:00Z", kind: "logon" },
      { time: "2026-10-02T09:00:00Z", kind: "logon" },
      { host: "beta", time: "2026-10-02T10:00:00Z", kind: "logon" },
    ];
    await writeFile(join(cwd, "tl.jsonl"), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
    const a = JSON.parse((await tool(REPORT, cwd, { timelines: [{ host: "alpha", file: "tl.jsonl" }] })).stdout);
    assert.ok(!a.partial_reasons.some((r: string) => /rows_skipped/.test(r)), JSON.stringify(a.partial_reasons));
    const byHost = Object.fromEntries(a.hosts.map((h: { host: string; timeline?: { events: number } }) => [h.host, h.timeline?.events]));
    assert.deepEqual(byHost, { alpha: 2, beta: 1 });
  });
});

test("events with no host in an entry that names none are skipped and counted", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "tl.jsonl"), JSON.stringify({ time: "2026-10-02T08:00:00Z", kind: "logon" }) + "\n");
    const a = JSON.parse((await tool(REPORT, cwd, { timelines: [{ file: "tl.jsonl" }] })).stdout);
    assert.equal(a.status, "partial");
    assert.ok(a.partial_reasons.some((r: string) => /rows_skipped: 1/.test(r)), JSON.stringify(a.partial_reasons));
  });
});

test("a host whose census could not be read (missing file, named pipe) is unknown, not a host with a census", async () => {
  await withCwd(async (cwd) => {
    execFileSync("mkfifo", [join(cwd, "pipe.jsonl")]);
    const a = JSON.parse((await tool(REPORT, cwd, {
      censuses: [{ host: "alpha", file: "missing.jsonl" }, { host: "beta", file: "pipe.jsonl" }],
    })).stdout);
    assert.equal(a.status, "partial");
    assert.equal(a.coverage_statement.hosts, 2);
    assert.equal(a.coverage_statement.hosts_with_census, 0);
    assert.equal(a.coverage_statement.hosts_census_partial, 0);
    assert.equal(a.coverage_statement.hosts_unknown, 2);
    for (const h of a.hosts) {
      assert.equal(h.scope, "unknown");
      assert.match(h.scope_basis, /could not be read \(not_read\)/);
      assert.equal(h.censuses[0].receipt, "not_read");
      assert.equal(h.censuses[0].files, null);
    }
    assert.ok(a.partial_reasons.some((r: string) => /input_not_read/.test(r)), JSON.stringify(a.partial_reasons));
  });
});
