/**
 * ransomware-response: backup_destruction_correlate. The inputs are written from the documented output of the tools they come from
 * (the evtx_query result row, the vss_stores store list, the regkv key answer, the backup_audit_normalise event row, the
 * snapshot_chain_check chain row, the shell_history text row, the cloudtrail_parse record), never from a run of them.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, stat, symlink, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { PACK, exists, filesUnder, tool } from "./ransomware-pack-harness.ts";
import { AUDIT, tool as virtTool } from "./pack-virtualization-harness.ts";

const CORRELATE = join(PACK, "backup_destruction_correlate", "run.py");
const MANIFEST = join(PACK, "backup_destruction_correlate", "manifest.json");

type J = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Summary = { host: string; object: string; observations: Record<string, number>; flags: Array<{ flag: string }>; inventory_comparisons: number; verified_intact: number };

async function run(cwd: string, args: unknown, env: Record<string, string> = {}): Promise<{ a: J; stdout: string; stderr: string; code: number | null }> {
  const out = await tool(CORRELATE, cwd, args, env);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return { a: JSON.parse(out.stdout) as J, stdout: out.stdout, stderr: out.stderr, code: out.code };
}
async function put(cwd: string, name: string, data: unknown): Promise<string> {
  await mkdir(join(cwd, "work"), { recursive: true });
  await writeFile(join(cwd, "work", name), typeof data === "string" ? data : JSON.stringify(data));
  return `work/${name}`;
}
const flagsOf = (a: J, object: string, host?: string): string[] => ((a.summary as Summary[]).find((s) => s.object === object && (!host || s.host === host))?.flags ?? []).map((f) => f.flag);
const countsOf = (a: J, object: string): Record<string, number> => (a.summary as Summary[]).find((s) => s.object === object)!.observations;

// ---- documented shapes
const evtx = (events: J[], extra: J = {}): J => ({ parser: "evtx_query/4", status: "complete", events, count: events.length, returned: events.length, truncated: false, ...extra });
const create = (record: number, time: string, image: string, cmd: string, user = "admin1", pid = "0x1a4"): J => ({
  timestamp: time, event_id: 4688, channel: "Security", computer: "h", record_id: record, data: { NewProcessName: image, CommandLine: cmd, SubjectUserName: user, NewProcessId: pid } });
const exit = (record: number, time: string, image: string, pid = "0x1a4", status = "0x0"): J => ({
  timestamp: time, event_id: 4689, channel: "Security", record_id: record, data: { ProcessName: image, ProcessId: pid, Status: status } });
const script = (record: number, time: string, text: string): J => ({
  timestamp: time, event_id: 4104, channel: "Microsoft-Windows-PowerShell/Operational", record_id: record, data: { ScriptBlockText: text } });
const vss = (ids: string[], status = "complete"): J => ({ parser: "vss_stores/5", status, stores: ids.map((x, i) => ({ store: i + 1, identifier: x, creation_time: "2026-09-01 00:00:00" })) });
const VSSADMIN = "C:\\Windows\\System32\\vssadmin.exe";

test("a command is seen and two complete inventories show no change: the command is not called an effect", async () => {
  await withCwd(async (cwd) => {
    const e = await put(cwd, "e.json", evtx([create(10, "2026-10-01T10:00:00.1234567Z", VSSADMIN, "vssadmin delete shadows /all /quiet"), exit(11, "2026-10-01T10:00:02Z", VSSADMIN)]));
    const v1 = await put(cwd, "v1.json", vss(["a", "b"]));
    const v2 = await put(cwd, "v2.json", vss(["a", "b"]));
    const { a } = await run(cwd, { events: [{ host: "h1", file: e }], vss_inventories: [{ host: "h1", file: v1, collected_utc: "2026-10-01T09:00:00Z" }, { host: "h1", file: v2, collected_utc: "2026-10-01T11:00:00Z" }] });
    assert.deepEqual(countsOf(a, "shadow_copies"), { command_seen: 1, action_attempted: 1, reported_outcome: 1, inventory_change_observed: 0, recovery_loss_verified: 0 });
    assert.deepEqual(flagsOf(a, "shadow_copies").sort(), ["command_seen_without_inventory_change", "reported_exit_without_verified_loss"]);
    assert.equal(a.status, "complete", a.status_basis);
    const ob = (a.observations as J[]).find((o) => o.class === "action_attempted")!;
    assert.equal(ob.time_utc, "2026-10-01T10:00:00.123456Z");
    assert.equal(ob.actor_as_recorded, "admin1");
    assert.deepEqual(ob.source, { kind: "event", channel: "Security", event_id: 4688, record_id: 10, field: "NewProcessName" });
    assert.ok(ob.alternative_explanations.length >= 2);
    assert.equal(ob.time_uncertainty.uncertainty_seconds, null, "unknown, said as unknown");
    const outcome = (a.observations as J[]).find((o) => o.class === "reported_outcome")!;
    assert.equal(outcome.exit_status_class, "zero");
  });
});

test("the inventory shrinks with no command in the logs read: a change with nothing behind it", async () => {
  await withCwd(async (cwd) => {
    const v1 = await put(cwd, "v1.json", vss(["a", "b", "c"]));
    const v2 = await put(cwd, "v2.json", vss(["a"]));
    const e = await put(cwd, "e.json", evtx([create(1, "2026-10-01T08:00:00Z", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs")]));
    const { a } = await run(cwd, { events: [{ host: "h1", file: e }], vss_inventories: [{ host: "h1", file: v1, collected_utc: "2026-10-01T09:00:00Z" }, { host: "h1", file: v2, collected_utc: "2026-10-01T11:00:00Z" }] });
    assert.deepEqual(countsOf(a, "shadow_copies"), { command_seen: 0, action_attempted: 0, reported_outcome: 0, inventory_change_observed: 1, recovery_loss_verified: 0 });
    assert.deepEqual(flagsOf(a, "shadow_copies"), ["inventory_change_without_command"]);
    const ob = (a.observations as J[]).find((o) => o.class === "inventory_change_observed")!;
    assert.deepEqual([ob.removed_stores, ob.added_stores, ob.stores_before, ob.stores_after], [2, 0, 3, 1]);
    assert.equal(ob.interval_utc.from, "2026-10-01T09:00:00.000000Z");
    assert.equal(ob.time_utc, null, "a change has an interval, not a time");
  });
});

test("an inventory taken from an answer that did not say complete is not compared, and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const v1 = await put(cwd, "v1.json", vss(["a", "b"]));
    const v2 = await put(cwd, "v2.json", vss([], "partial"));
    const { a } = await run(cwd, { vss_inventories: [{ host: "h1", file: v1, collected_utc: "2026-10-01T09:00:00Z" }, { host: "h1", file: v2, collected_utc: "2026-10-01T11:00:00Z" }] });
    assert.equal(a.observation_counts.inventory_change_observed, 0, "a store missing from a partial listing is not a store removed");
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /inventory_not_complete: 1/);
  });
});

test("a reported success with no evidence of loss is a flag, and a verification apart from the logs is the only loss", async () => {
  await withCwd(async (cwd) => {
    const e = await put(cwd, "e.json", evtx([create(10, "2026-10-01T10:00:00Z", "C:\\Windows\\System32\\wbadmin.exe", "wbadmin delete catalog -quiet", "admin1", "0x20"), exit(11, "2026-10-01T10:00:01Z", "C:\\Windows\\System32\\wbadmin.exe", "0x20")]));
    const first = await run(cwd, { events: [{ host: "h1", file: e }] });
    assert.deepEqual(flagsOf(first.a, "backup_catalog").sort(), ["command_seen_nothing_to_compare", "reported_exit_without_verified_loss"]);
    assert.equal(countsOf(first.a, "backup_catalog").recovery_loss_verified, 0);
    const second = await run(cwd, { events: [{ host: "h1", file: e }], verifications: [{ host: "h1", object: "backup_catalog", result: "lost", verified_utc: "2026-10-01T12:00:00Z", method: "restore attempt", source: "ticket" }] });
    assert.equal(countsOf(second.a, "backup_catalog").recovery_loss_verified, 1);
    assert.deepEqual(flagsOf(second.a, "backup_catalog"), ["command_seen_nothing_to_compare"]);
    const intact = await run(cwd, { verifications: [{ host: "h1", object: "backup_catalog", result: "intact", verified_utc: "2026-10-01T12:00:00Z" }] });
    assert.equal(intact.a.observation_counts.recovery_loss_verified, 0);
    assert.equal(intact.a.summary[0].verified_intact, 1);
  });
});

test("the five classes are independent: each one arises from its own record and none is filled in from another", async () => {
  await withCwd(async (cwd) => {
    // text only (a script block): a command seen, no attempt, no outcome
    const textOnly = await put(cwd, "t.json", evtx([script(1, "2026-10-01T10:00:00Z", "Get-WmiObject Win32_ShadowCopy | % { $_.Delete() }")]));
    let r = await run(cwd, { events: [{ host: "h", file: textOnly }] });
    assert.deepEqual(r.a.observation_counts, { command_seen: 1, action_attempted: 0, reported_outcome: 0, inventory_change_observed: 0, recovery_loss_verified: 0 });
    // a process-creation record with no command line (the audit setting is off): nothing can be recognised
    const noCmd = await put(cwd, "n.json", evtx([{ timestamp: "2026-10-01T10:00:00Z", event_id: 4688, channel: "Security", record_id: 2, data: { NewProcessName: VSSADMIN, NewProcessId: "0x9" } }]));
    r = await run(cwd, { events: [{ host: "h", file: noCmd }] });
    assert.equal(Object.values(r.a.observation_counts as Record<string, number>).reduce((n, x) => n + x, 0), 0);
    // an exit record with no creation record: no outcome is made up
    const exitOnly = await put(cwd, "x.json", evtx([exit(3, "2026-10-01T10:00:00Z", VSSADMIN, "0x9")]));
    r = await run(cwd, { events: [{ host: "h", file: exitOnly }] });
    assert.equal(r.a.observation_counts.reported_outcome, 0);
    // a creation record of a harmless use of the same program: no destructive command
    const listing = await put(cwd, "l.json", evtx([create(4, "2026-10-01T10:00:00Z", VSSADMIN, "vssadmin list shadows")]));
    r = await run(cwd, { events: [{ host: "h", file: listing }] });
    assert.equal(r.a.observation_counts.command_seen, 0);
    // a verification alone, and an inventory change alone
    r = await run(cwd, { verifications: [{ host: "h", object: "snapshots", result: "partial", verified_utc: "2026-10-01T10:00:00Z", method: "m", source: "s" }] });
    assert.deepEqual(r.a.observation_counts, { command_seen: 0, action_attempted: 0, reported_outcome: 0, inventory_change_observed: 0, recovery_loss_verified: 1 });
    assert.deepEqual(flagsOf(r.a, "snapshots"), ["verified_loss_without_command"]);
    // a process started with a different program than the one the command names: a command seen, not an attempt
    const wrong = await put(cwd, "w.json", evtx([create(5, "2026-10-01T10:00:00Z", "C:\\Windows\\System32\\cmd.exe", "vssadmin delete shadows /all")]));
    r = await run(cwd, { events: [{ host: "h", file: wrong }] });
    assert.deepEqual([r.a.observation_counts.command_seen, r.a.observation_counts.action_attempted], [1, 0]);
  });
});

test("conflicting host clocks: the same records fall inside, or after, the interval of a change depending on the host's clock", async () => {
  await withCwd(async (cwd) => {
    const e = await put(cwd, "e.json", evtx([create(10, "2026-10-01T12:30:00Z", VSSADMIN, "vssadmin delete shadows /all")]));
    const v1 = await put(cwd, "v1.json", vss(["a", "b"]));
    const v2 = await put(cwd, "v2.json", vss(["a"]));
    const base = { events: [{ host: "h1", file: e }], vss_inventories: [{ host: "h1", file: v1, collected_utc: "2026-10-01T09:00:00Z" }, { host: "h1", file: v2, collected_utc: "2026-10-01T11:00:00Z" }] };
    const plain = await run(cwd, base);
    assert.ok(flagsOf(plain.a, "shadow_copies").includes("command_after_the_change_interval"), "recorded time 12:30 is after an interval that ends at 11:00");
    const fast = await run(cwd, { ...base, host_clocks: { h1: { offset_seconds: 7200, uncertainty_seconds: 60 } } });
    assert.ok(flagsOf(fast.a, "shadow_copies").includes("command_within_the_change_interval"), "a clock 2 h fast puts the command at 10:30, inside the interval");
    assert.ok(!flagsOf(fast.a, "shadow_copies").includes("command_after_the_change_interval"));
    assert.equal((fast.a.observations as J[]).find((o) => o.class === "command_seen")!.time_uncertainty.uncertainty_seconds, 60);
    assert.equal((fast.a.observations as J[]).find((o) => o.class === "command_seen")!.time_utc, "2026-10-01T12:30:00.000000Z", "the recorded time is not rewritten");
  });
});

test("service configuration: a Start value that changes between two complete reads is an inventory change", async () => {
  await withCwd(async (cwd) => {
    const k = (start: number) => ({ parser: "regkv/4", status: "complete", key: "ControlSet001\\Services\\VSS", values: { Start: start } });
    const a1 = await put(cwd, "k1.json", k(3));
    const a2 = await put(cwd, "k2.json", k(4));
    const { a } = await run(cwd, { service_keys: [{ host: "h1", file: a1, collected_utc: "2026-10-01T09:00:00Z" }, { host: "h1", file: a2, collected_utc: "2026-10-01T11:00:00Z" }] });
    const ob = (a.observations as J[]).find((o) => o.class === "inventory_change_observed")!;
    assert.deepEqual([ob.object, ob.start_before, ob.start_after, ob.disabled_after], ["service_configuration", 3, 4, true]);
    // regkv/5 answers are read the same way, alone and beside a regkv/4 answer of the same service.
    const k5 = (start: number) => ({ ...k(start), parser: "regkv/5" });
    const b1 = await put(cwd, "k5a.json", k5(2));
    const b2 = await put(cwd, "k5b.json", k5(4));
    for (const [first, second, before] of [[b1, b2, 2], [a1, b2, 3]] as const) {
      const next = await run(cwd, { service_keys: [{ host: "h1", file: first, collected_utc: "2026-10-01T09:00:00Z" }, { host: "h1", file: second, collected_utc: "2026-10-01T11:00:00Z" }] });
      const seen = (next.a.observations as J[]).find((o) => o.class === "inventory_change_observed")!;
      assert.deepEqual([seen.object, seen.start_before, seen.start_after, seen.disabled_after], ["service_configuration", before, 4, true]);
    }
  });
});

test("canaries in command lines, script text, actor names, job names and messages are on no channel, and no command text is printed at all", async () => {
  await withCwd(async (cwd) => {
    const secret = "CANARYSECRETVALUE9F8E7D6C5B4A";
    const user = "svc9F8E7D6C5B4A3210";
    const e = await put(cwd, "e.json", evtx([
      create(10, "2026-10-01T10:00:00Z", VSSADMIN, `vssadmin delete shadows /all /quiet -password ${secret}`, user),
      script(11, "2026-10-01T10:01:00Z", `$p='${secret}'; Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`),
    ]));
    const audit = await put(cwd, "a.json", { parser: "backup_audit_normalise/2", status: "complete", events: [
      { seq: 1, source_id: "S1", category: "snapshot_delete", result: "ok", actor: user, job: `job-${secret}`, message_chars: 40, object: `vm-${secret}`, time_utc: "2026-10-01T10:02:00Z" }] });
    const hist = await put(cwd, "h.jsonl", JSON.stringify({ id: "H000001", parser: "shell_history/14", user: "root", time: "2026-10-01T10:03:00Z", command: `zfs destroy tank/data@snap -k ${secret}` }) + "\n");
    const { a, stdout, stderr } = await run(cwd, { events: [{ host: "WIN-9F8E7D6C5B4A3210", file: e }], backup_audits: [{ host: "WIN-9F8E7D6C5B4A3210", file: audit }], shell_histories: [{ host: "lin1", file: hist }] });
    const files = await filesUnder(join(cwd, "work", "s1"));
    for (const text of [stdout, stderr, ...Object.values(files)]) {
      assert.ok(!text.includes(secret), "the secret is on a channel");
      assert.ok(!text.includes("9F8E7D6C5B4A3210"), "the identifier is on a channel");
      assert.ok(!/delete shadows|Remove-WmiObject|zfs destroy/i.test(text), "no command text is printed");
    }
    assert.ok((a.observations as J[]).some((o) => o.recogniser === "zfs_destroy_snapshot"));
    assert.equal(a.observation_counts.command_seen, 3);
  });
});

test("an unknown producer version is refused by name, for every kind of input", async () => {
  await withCwd(async (cwd) => {
    const cases: Array<[string, J, string]> = [
      ["events", { parser: "evtx_query/3", status: "complete", events: [] }, "evtx_query/3"],
      ["vss_inventories", { parser: "vss_stores/4", status: "complete", stores: [] }, "vss_stores/4"],
      ["service_keys", { parser: "regkv/3", status: "complete" }, "regkv/3"],
      ["backup_audits", { parser: "backup_audit_normalise/4", status: "complete", events: [] }, "backup_audit_normalise/4"],
      ["chain_checks", { parser: "snapshot_chain_check/9", status: "complete", chains: [] }, "snapshot_chain_check/9"],
      ["cloud_trails", { parser: "cloudtrail_parse/5", status: "complete", records: [] }, "cloudtrail_parse/5"],
    ];
    for (const [kind, doc, name] of cases) {
      const f = await put(cwd, `${kind}.json`, doc);
      const entry = kind === "vss_inventories" || kind === "service_keys" ? { host: "h", file: f, collected_utc: "2026-10-01T09:00:00Z" } : { host: "h", file: f };
      const out = await tool(CORRELATE, cwd, { [kind]: [entry] });
      assert.notEqual(out.code, 0, kind);
      const j = JSON.parse(out.stdout) as J;
      assert.equal(j.status, "failed", kind);
      assert.ok(String(j.error).includes(name), `${kind}: ${j.error}`);
    }
    const h = await put(cwd, "h.jsonl", JSON.stringify({ parser: "shell_history/13", command: "ls" }) + "\n");
    const out = await tool(CORRELATE, cwd, { shell_histories: [{ host: "h", file: h }] });
    assert.match(JSON.parse(out.stdout).error, /shell_history\/13/);
  });
});

// ---- part 2: virtualization, backup, Linux and cloud records
test("a backup job reported as succeeded while the chain check shows a missing base: the report and the loss are two observations", async () => {
  await withCwd(async (cwd) => {
    const audit = await put(cwd, "a.json", { parser: "backup_audit_normalise/2", status: "complete", events: [
      { seq: 1, source_id: "S1", category: "backup_end", result: "ok", time_utc: "2026-10-01T02:00:00Z", actor: "backup-svc" }] });
    const chain = await put(cwd, "c.json", { parser: "snapshot_chain_check/2", status: "complete", chains: [{ leaf: "d1", status: "broken", chain_length: 3 }, { leaf: "d2", status: "complete", chain_length: 2 }, { leaf: "d3", status: "cycle" }] });
    const { a } = await run(cwd, { backup_audits: [{ host: "pbs", file: audit }], chain_checks: [{ host: "pbs", file: chain }] });
    assert.deepEqual(countsOf(a, "backups"), { command_seen: 0, action_attempted: 0, reported_outcome: 1, inventory_change_observed: 0, recovery_loss_verified: 1 });
    assert.equal((a.observations as J[]).find((o) => o.class === "recovery_loss_verified")!.chain_status, "broken");
    assert.equal((a.summary as Summary[])[0]!.verified_intact, 1);
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /1 chains could not be followed/);
  });
});

test("a deleted snapshot with an intact chain is an action and a reported outcome, not a loss", async () => {
  await withCwd(async (cwd) => {
    const audit = await put(cwd, "a.json", { parser: "backup_audit_normalise/2", status: "complete", events: [
      { seq: 1, source_id: "S1", category: "snapshot_delete", result: "ok", time_utc: "2026-10-01T02:00:00Z", actor: "root@pam" }] });
    const chain = await put(cwd, "c.json", { parser: "snapshot_chain_check/2", status: "complete", chains: [{ leaf: "d1", status: "complete", chain_length: 3 }] });
    const { a } = await run(cwd, { backup_audits: [{ host: "pve", file: audit }], chain_checks: [{ host: "pve", file: chain }] });
    assert.deepEqual([countsOf(a, "snapshots").action_attempted, countsOf(a, "snapshots").reported_outcome, countsOf(a, "snapshots").recovery_loss_verified], [1, 1, 0]);
    assert.equal(a.observation_counts.recovery_loss_verified, 0);
    assert.deepEqual(flagsOf(a, "snapshots"), ["reported_exit_without_verified_loss"]);
  });
});

test("Linux and cloud records: a history command and a provider's API call, with clocks that disagree", async () => {
  await withCwd(async (cwd) => {
    const hist = await put(cwd, "h.jsonl", [
      { id: "H1", parser: "shell_history/14", user: "root", time: "2026-10-01T10:00:00Z", command: "restic -r /srv/r forget --keep-last 1 --prune" },
      { id: "H2", parser: "shell_history/14", user: "root", time: "2026-10-01T10:01:00Z", command: "ls -la" }].map((r) => JSON.stringify(r)).join("\n") + "\n");
    const cloud = await put(cwd, "c.json", { parser: "cloudtrail_parse/6", status: "complete", record_count: 3, records: [
      { event: "DeleteSnapshot", source: "ec2.amazonaws.com", time_utc: "2026-10-01T10:00:30Z", outcome: "no_error_recorded", user_name: "ops" },
      { event: "DeleteSnapshot", source: "elsewhere.example", time_utc: "2026-10-01T10:00:31Z", outcome: "no_error_recorded" },
      { event: "DeleteBackupVault", source: "backup.amazonaws.com", time_utc: "2026-10-01T10:00:32Z", outcome: "error_recorded", user_name: "ops" }] });
    const { a } = await run(cwd, { shell_histories: [{ host: "lin1", file: hist }], cloud_trails: [{ host: "acct1", file: cloud }], host_clocks: { lin1: { offset_seconds: 300, uncertainty_seconds: 5 } } });
    assert.equal((a.summary as Summary[]).find((s) => s.object === "backups" && s.host === "lin1")!.observations.command_seen, 1);
    const cloudRows = (a.observations as J[]).filter((o) => o.source.kind === "cloudtrail_parse");
    assert.deepEqual(cloudRows.map((o) => o.class).sort(), ["action_attempted", "action_attempted", "reported_outcome", "reported_outcome"]);
    assert.deepEqual(cloudRows.filter((o) => o.class === "reported_outcome").map((o) => o.outcome_recorded).sort(), ["error_or_failure", "no_error"]);
    assert.equal((a.observations as J[]).find((o) => o.recogniser === "restic_forget_or_prune")!.time_uncertainty.clock_offset_seconds, 300);
    assert.equal((a.observations as J[]).find((o) => o.source.kind === "cloudtrail_parse")!.time_uncertainty.clock_offset_seconds, null);
  });
});

// ---- the contract
test("a result file with a line that never ends, a huge sparse file with no newline, ends at max_seconds", async () => {
  await withCwd(async (cwd) => {
    const e = await put(cwd, "e.json", evtx([]));
    await mkdir(join(cwd, "work"), { recursive: true });
    const big = join(cwd, "work", "nonl.jsonl");
    await writeFile(big, "");
    try {
      await truncate(big, 300 * 1000 ** 3);
    } catch {
      return;
    }
    const began = Date.now();
    const { a } = await run(cwd, { events: [{ host: "h", file: e, result_file: "work/nonl.jsonl" }], max_seconds: 3 });
    assert.ok((Date.now() - began) / 1000 < 20);
    assert.equal(a.status, "partial");
    assert.equal(a.time_limit.reached, true);
  });
});

test("a named pipe, a directory, a link and a missing path on every input path end as a read failure, never a hang or a crash", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "dir"), { recursive: true });
    spawnSync("mkfifo", [join(cwd, "work", "pipe")]);
    const real = await put(cwd, "real.json", evtx([]));
    await symlink(join(cwd, real), join(cwd, "work", "link.json"));
    const paths = ["work/pipe", "work/dir", "work/link.json", "work/none", "work/bad\u0000name"];
    for (const p of paths) {
      for (const [kind, extra] of [["events", {}], ["events", { result_file: p }], ["vss_inventories", { collected_utc: "2026-10-01T09:00:00Z" }], ["service_keys", { collected_utc: "2026-10-01T09:00:00Z" }],
        ["backup_audits", {}], ["backup_audits", { rows_file: p }], ["chain_checks", {}], ["shell_histories", {}], ["cloud_trails", {}]] as Array<[string, J]>) {
        const file = "result_file" in extra || "rows_file" in extra ? real : p;
        const out = await tool(CORRELATE, cwd, { [kind]: [{ host: "h", file, ...extra }] });
        assert.doesNotMatch(out.stderr, /Traceback/, `${kind} ${p}`);
        const j = JSON.parse(out.stdout) as J;
        assert.ok(j.status === "partial" || j.status === "failed", `${kind} ${JSON.stringify(p)}: ${j.status}`);
      }
    }
  });
});

const SLOW = String.raw`
import json, os, runpy, sys, time
_real = json.loads
def slow(*a, **k):
    time.sleep(0.25)
    return _real(*a, **k)
json.loads = slow
script = sys.argv[1]
sys.argv = [script]
runpy.run_path(script, run_name="__main__")
`;

for (const [signal, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
  test(`${signal} while a result file is being read: one JSON answer, exit code ${code}, no temporary file left`, async () => {
    await withCwd(async (cwd) => {
      const e = await put(cwd, "e.json", evtx([]));
      await put(cwd, "r.jsonl", Array.from({ length: 40 }, (_, i) => JSON.stringify(create(i, "2026-10-01T10:00:00Z", VSSADMIN, "vssadmin delete shadows", "u", `0x${i + 1}`))).join("\n") + "\n");
      const child = spawn("python3", ["-c", SLOW, CORRELATE], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
      const out: Buffer[] = [];
      const err: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => out.push(c));
      child.stderr.on("data", (c: Buffer) => err.push(c));
      const closed = new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
      child.stdin.end(JSON.stringify({ events: [{ host: "h", file: e, result_file: "work/r.jsonl" }], limit: 1 }));
      const place = join(cwd, "work", "s1", "tool-output");
      const deadline = Date.now() + 20000;
      while (!((await exists(place)) && (await readdir(place)).length > 0) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
      await new Promise((r) => setTimeout(r, 300));
      child.kill(signal);
      if (signal === "SIGTERM") {
        child.kill("SIGHUP");
        child.kill("SIGINT");
      }
      const ended = await closed;
      if (signal === "SIGTERM") assert.ok([143, 129, 130].includes(ended ?? -1), `exit ${ended}: the first signal the process handled decides it (Python handles pending signals in number order)`);
      else assert.equal(ended, code, Buffer.concat(err).toString());
      const text = Buffer.concat(out).toString();
      assert.equal(text.trim().split("\n").length, 1, "one document, whatever signals followed");
      const doc = JSON.parse(text) as J;
      assert.equal(doc.status, "failed");
      assert.equal(doc.interrupted, true);
      assert.deepEqual(await readdir(place), []);
    });
  });
}

test("hostile parameters give a JSON refusal and never a traceback, 100,000-deep JSON included", async () => {
  await withCwd(async (cwd) => {
    const deep = (n: number): string => "[".repeat(n) + "]".repeat(n);
    const cases: Array<[string, string]> = [
      ["not json", "{"], ["deep nesting", `{"events": ${deep(100000)}}`], ["deep objects", `{"events": [${'{"a":'.repeat(100000)}1${"}".repeat(100000)}]}`],
      ["a huge integer", `{"limit": ${"9".repeat(5000)}, "events": []}`], ["wrong types", `{"events": "x"}`], ["numbers", `{"events": [1]}`],
      ["an array", `[]`], ["no input", `{}`], ["no collected_utc", `{"vss_inventories": [{"host": "h", "file": "x"}]}`],
      ["a bad time", `{"vss_inventories": [{"host": "h", "file": "x", "collected_utc": "yesterday"}]}`], ["unknown entry key", `{"events": [{"host": "h", "file": "x", "run": 1}]}`],
      ["a clock of NaN", `{"verifications": [], "host_clocks": {"h": {"offset_seconds": NaN}}, "events": []}`], ["a huge clock", `{"events": [], "host_clocks": {"h": {"offset_seconds": 1e300}}}`],
      ["a bad object", `{"verifications": [{"host": "h", "object": "everything", "result": "lost", "verified_utc": "2026-10-01T09:00:00Z"}]}`],
      ["a lone surrogate", `{"events": [{"host": "\\ud800", "file": "x"}]}`], ["only_objects of numbers", `{"events": [], "only_objects": [1]}`],
    ];
    for (const [label, input] of cases) {
      const child = spawnSync("python3", [CORRELATE], { cwd, input, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" }, timeout: 60000 });
      assert.doesNotMatch(child.stderr, /Traceback/, label);
      assert.ok(child.stdout, `${label}: no answer (status ${child.status}, signal ${child.signal}, error ${child.error?.message})`);
      const doc = JSON.parse(child.stdout) as J;
      if (label === "a lone surrogate") {
        assert.ok(["failed", "partial"].includes(doc.status), label);
        continue;
      }
      assert.equal(doc.status, "failed", `${label}: ${child.stdout.slice(0, 200)}`);
      assert.equal(child.status, 1, label);
    }
  });
});

test("time_limit.reached is true when the clock stopped the read, and an event row past the inline page asks for the result file", async () => {
  await withCwd(async (cwd) => {
    const rows = Array.from({ length: 5 }, (_, i) => create(i, "2026-10-01T10:00:00Z", VSSADMIN, "vssadmin delete shadows", "u", `0x${i + 1}`));
    const e = await put(cwd, "e.json", evtx(rows.slice(0, 2), { count: 5, truncated: true }));
    const { a } = await run(cwd, { events: [{ host: "h", file: e }] });
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /events_incomplete: 1/);
    const rf = await put(cwd, "r.jsonl", rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
    const whole = await run(cwd, { events: [{ host: "h", file: e, result_file: rf }] });
    assert.equal(whole.a.observation_counts.command_seen, 5);
    assert.match(whole.a.status_basis, /5 attempts have no process-exit record/);
  });
});

test("a rerun with other inputs or only_objects keeps the earlier observations file and names its own", async () => {
  await withCwd(async (cwd) => {
    const rows: J[] = [];
    for (let i = 0; i < 10; i++) rows.push(create(i, "2026-10-01T10:00:00Z", VSSADMIN, "vssadmin delete shadows", "u", `0x${i + 1}`));
    for (let i = 10; i < 14; i++) rows.push(create(i, "2026-10-01T10:00:00Z", "C:\\Windows\\System32\\wbadmin.exe", "wbadmin delete catalog", "u", `0x${i + 1}`));
    const e = await put(cwd, "e.json", evtx(rows));
    const first = await run(cwd, { events: [{ host: "h", file: e }], limit: 3 }, { JOB_ID: "j000001", OUT: join(cwd, "out") });
    const name = first.a.pages.observations.all_results as string;
    assert.ok(name, "the whole table is in a file");
    const file = join(cwd, "out", "tool-output", name.split("/").pop()!);
    const before = (await stat(file)).size;
    const second = await run(cwd, { events: [{ host: "h", file: e }], limit: 1, only_objects: ["backup_catalog"] }, { JOB_ID: "j000001", OUT: join(cwd, "out") });
    assert.notEqual(second.a.pages.observations.all_results, name);
    assert.equal((await stat(file)).size, before, "the earlier file is intact");
    assert.ok(second.a.observations_left_out_by_only_objects > 0);
  });
});

test("the manifest's claims hold and the shared blocks are the survey's", async () => {
  const manifest = JSON.parse(await readFile(MANIFEST, "utf8")) as { timeout_seconds: number; description: string; params: Record<string, { description: string }>; example: string };
  const source = await readFile(CORRELATE, "utf8");
  const max = /DEFAULT_SECONDS, MAX_SECONDS = (\d+), (\d+)/.exec(source)!;
  assert.ok(Number(max[2]) <= manifest.timeout_seconds - 60);
  assert.match(manifest.params.max_seconds!.description, new RegExp(`default ${max[1]}, at most ${max[2]}`));
  for (const p of ["evtx_query/4", "vss_stores/5", "regkv/4", "regkv/5", "backup_audit_normalise/2", "snapshot_chain_check/2", "shell_history/14", "cloudtrail_parse/6"]) {
    assert.ok(manifest.description.includes(p), p);
    assert.ok(source.includes(`"${p}"`), p);
  }
  for (const [name, re] of [["MAX_INPUTS", /20000/], ["MAX_HOSTS", /100000/], ["TRACK_CAP", /100000/], ["MAX_VERIFICATIONS", /20000/]] as const) assert.match(source, new RegExp(`${name} = ${re.source}`));
  assert.match(source, /MAX_DOC = 16 << 20/);
  assert.match(manifest.description, /500,000 event rows \(268,559,214 bytes/);
  assert.match(manifest.description, /so the tool declares no secret output/);
  assert.equal("secret_output" in (JSON.parse(await readFile(MANIFEST, "utf8")) as J), false);
  JSON.parse(manifest.example);
  for (const name of ["events", "vss_inventories", "service_keys", "backup_audits", "chain_checks", "shell_histories", "cloud_trails", "verifications", "host_clocks", "only_objects", "limit", "max_seconds"]) assert.ok(manifest.params[name], name);
  const code = source.replace(/"""[\s\S]*?"""/g, "").replace(/^\s*#.*$/gm, "");
  assert.doesNotMatch(code, /subprocess|os\.system|os\.exec|importlib|__import__|pickle|marshal|\beval\(|\bexec\(/);
  assert.doesNotMatch(code, /start_new_session|setsid|process_group/);
  assert.doesNotMatch(code, /"command"\s*:|"commandline"\s*:/i, "no row carries command text");
  const survey = await readFile(join(PACK, "encrypted_survey", "run.py"), "utf8");
  const block = (text: string, name: string): string => new RegExp(`^# BEGIN SHARED ${name}\\n[\\s\\S]*?^# END SHARED ${name}$`, "m").exec(text)![0];
  for (const name of ["PLACE", "PAGE", "STOP", "WITHHOLDING", "NAMES", "BACKSTOP"]) assert.equal(block(source, name), block(survey, name), name);
  assert.equal(((await stat(CORRELATE)).mode & 0o111) !== 0, true);
  // the leaves that name the tool list it and are no longer method only
  const pack = JSON.parse(await readFile(join(PACK, "..", "pack.json"), "utf8")) as { method_only: Array<{ path: string }>; tools: string[]; depends: string[] };
  for (const leaf of ["encryptor/destroyed-backups", "encryptor/windows-evidence", "encryptor/backup-infrastructure", "platforms/esxi-hypervisors"]) {
    assert.ok(!pack.method_only.some((m) => m.path === `skills/${leaf}.md`), leaf);
    assert.match(await readFile(join(PACK, "..", "skills", `${leaf}.md`), "utf8"), /^tools: \[backup_destruction_correlate\]$/m, leaf);
  }
  assert.ok(pack.tools.includes("backup_destruction_correlate"));
  assert.deepEqual(pack.depends.map((d) => d.split(/[<>=]/)[0]), ["computer-forensics-base"], "no dependency edge");
});

// ---- the fix round: the clock holds in every walk, every recogniser is linear, and the flags and statuses say what is true
const MODULE_LOADER = `
import importlib.util, json, sys, time
spec = importlib.util.spec_from_file_location("bdc", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
`;
function python(code: string, timeout: number): { out: J | null; stderr: string; status: number | null; signal: string | null } {
  const r = spawnSync("python3", ["-I", "-c", MODULE_LOADER + code, CORRELATE], { encoding: "utf8", timeout, maxBuffer: 64 << 20 });
  let out: J | null = null;
  try { out = JSON.parse(r.stdout) as J; } catch { /* a timeout leaves no JSON */ }
  return { out, stderr: r.stderr, status: r.status, signal: r.signal };
}
const WMI_DELETE = "Get-WmiObject Win32_ShadowCopy | % { $_.Delete() }";

test("20,000 attempts and 20,000 exit records of one process id are matched by bisection, under the clock", async () => {
  await withCwd(async (cwd) => {
    const n = 20000;
    const rows: string[] = [];
    // the exit records first (cheap to read), so that the reading ends well inside the clock and the matching is what is timed
    for (let i = 0; i < n; i++) rows.push(JSON.stringify(exit(2 * i + 1, "2020-01-01T00:00:00Z", VSSADMIN, "0x10")));
    for (let i = 0; i < n; i++) rows.push(JSON.stringify(create(2 * i, "2030-01-01T00:00:00Z", VSSADMIN, "vssadmin delete shadows /all", "u", "0x10")));
    const e = await put(cwd, "e.json", evtx([]));
    const f = await put(cwd, "e.jsonl", rows.join("\n") + "\n");
    const started = Date.now();
    const { a } = await run(cwd, { events: [{ host: "h", file: e, result_file: f }], max_seconds: 20 });
    const took = (Date.now() - started) / 1000;
    assert.ok(took < 20 + 5, `the run took ${took} s with max_seconds 20`);
    assert.equal(a.status, "partial");
    assert.ok(/attempts have no process-exit record|time limit/.test(a.status_basis), a.status_basis);
  });
});

test("the exit record found is the earliest at or after the start, and the matching walk stops at its clock and says so", () => {
  const r = python(`
ctx = m.Ctx(None, {})
class P:
    def add(self, row, evidence=None): return row
ctx.page = P()
hid = ctx.host("h")
for i in range(20000):
    ctx.add_exit(hid, 16, 2000000 - i, "0x%x" % i, {"i": i})        # arrives latest first
ctx.add_exit(hid, 17, None, "0x5", {"untimed": True})
ctx.add_exit(hid, 18, 100, "0x1", {"early": True})
first = ctx.first_exit(hid, 16, 1990000.5)
none_after = ctx.first_exit(hid, 18, 101)
untimed_for_17 = ctx.first_exit(hid, 17, 5)
before_all = ctx.first_exit(hid, 16, 0)
ctx.pending = [(hid, 16, 1990000.5, "shadow_copies", "r", "O1", "u", "2030-01-01T00:00:00.000000Z", "vssadmin.exe")] * 20000
m.set_deadline(100)
t = time.monotonic()
done = m.match_exits(ctx)
elapsed = time.monotonic() - t
m.set_deadline(-100)
stopped = m.match_exits(ctx)
print(json.dumps({"first": first[0], "none_after": none_after, "untimed": untimed_for_17[1], "before_all": before_all[0], "done": done, "elapsed": elapsed, "stopped": stopped}))
`, 120000);
  assert.ok(r.out, r.stderr);
  assert.equal(r.out.first, 1990001);
  assert.equal(r.out.none_after, null);
  assert.equal(r.out.untimed, "0x5");
  assert.equal(r.out.before_all, 1980001);
  assert.deepEqual(r.out.done, [0, 0]);
  assert.ok(r.out.elapsed < 5, `20,000 attempts matched in ${r.out.elapsed} s`);
  assert.deepEqual(r.out.stopped, [0, 20000], "past the clock no attempt is matched, and the number left is returned");
});

test("every recogniser, Windows and Linux, is linear on 64 KiB texts of hostile shapes", () => {
  const r = python(`
N = 65536
heads = ["vssadmin", "vssadmin.exe", "vssadmin delete", "wmic", "wmic shadowcopy", "diskshadow", "diskshadow.exe", "win32_shadowcopy", "remove-wmiobject",
         "remove-ciminstance", "wbadmin", "wbadmin delete", "bcdedit", "bcdedit.exe", "zfs", "zfs destroy", "lvremove", "btrfs", "btrfs subvolume", "restic",
         "borg", "rm", "rm -", "rm -r", "rm -rf", "shadowcopy", "delete", "backup", "snapshots", "recoveryenabled"]
def shapes(h):
    yield "repeat", (h + " ") * (N // (len(h) + 1))
    yield "repeat-tight", h * (N // len(h))
    for fill in ("r", " ", "a", "-", "\\t", "R", "@", "."):
        yield "head+fill " + repr(fill), (h + fill * N)[:N]
        yield "head+dash+fill+spaces " + repr(fill), (h + " -" + fill * (N // 2) + " " * N)[:N]
        yield "head+dash+fill+x " + repr(fill), (h + " -" + fill * (N // 2) + "x" * N)[:N]
        yield "repeat head+flags " + repr(fill), ((h + " -" + fill * 20 + "  ") * N)[:N]
        yield "repeat head+fill+backup " + repr(fill), ((h + " -r" + fill * 30 + " backup") * N)[:N]
patterns = [(r[0], r[3]) for r in m.RECOGNISERS] + [(r[0], r[2]) for r in m.LINUX_RECOGNISERS]
worst = (0.0, "", "")
count = 0
for h in heads:
    for shape, text in shapes(h):
        for rid, pat in patterns:
            t = time.perf_counter()
            pat.search(text)
            d = time.perf_counter() - t
            count += 1
            if d > worst[0]:
                worst = (d, rid, h + "/" + shape)
for rid, pat in patterns:
    for text in ("rm -" + "r" * 32000 + " " * 32000, "rm -" + "r" * 12000 + " " * 12000, "rm " + "-r " * 20000, "rm -r " + "a" * 65000):
        t = time.perf_counter()
        pat.search(text)
        d = time.perf_counter() - t
        count += 1
        if d > worst[0]:
            worst = (d, rid, "rm-shapes")
print(json.dumps({"worst_seconds": worst[0], "recogniser": worst[1], "shape": worst[2], "searches": count, "recognisers": len(patterns)}))
`, 280000);
  assert.ok(r.out, `a recogniser did not finish within 280 s: ${r.stderr} ${r.signal}`);
  assert.equal(r.out.recognisers, 13);
  assert.ok(r.out.worst_seconds < 1.5, `${r.out.recogniser} took ${r.out.worst_seconds} s on ${r.out.shape}`);
});

test("a 64 KiB shell-history command of the quadratic shape is read under the clock, and the commands beside it are still recognised", async () => {
  await withCwd(async (cwd) => {
    const hist = await put(cwd, "h.jsonl", [
      { id: "H1", parser: "shell_history/14", user: "root", time: "2026-10-01T10:00:00Z", command: "rm -" + "r".repeat(32000) + " ".repeat(32000) },
      { id: "H2", parser: "shell_history/14", user: "root", time: "2026-10-01T10:00:01Z", command: "rm -rf /srv/backups/old" },
      { id: "H3", parser: "shell_history/14", user: "root", time: "2026-10-01T10:00:02Z", command: "rm  -fr   /srv/snapshots" }].map((r) => JSON.stringify(r)).join("\n") + "\n");
    const started = Date.now();
    const { a } = await run(cwd, { shell_histories: [{ host: "lin1", file: hist }], max_seconds: 20 });
    assert.ok((Date.now() - started) / 1000 < 15);
    assert.equal(countsOf(a, "backups").command_seen, 2);
  });
});

test("a command after both inventories, or before both, is not called a command without a change", async () => {
  await withCwd(async (cwd) => {
    const v1 = await put(cwd, "v1.json", vss(["a", "b"]));
    const v2 = await put(cwd, "v2.json", vss(["a", "b"]));
    const inv = [{ host: "h1", file: v1, collected_utc: "2026-10-01T09:00:00Z" }, { host: "h1", file: v2, collected_utc: "2026-10-01T11:00:00Z" }];
    for (const [time, flag] of [["2026-10-01T12:00:00Z", "command_seen_after_the_last_inventory"], ["2026-10-01T08:00:00Z", "command_seen_before_the_first_inventory"], ["2026-10-01T10:00:00Z", "command_seen_without_inventory_change"]] as const) {
      const e = await put(cwd, "e.json", evtx([script(1, time, WMI_DELETE)]));
      const { a } = await run(cwd, { events: [{ host: "h1", file: e }], vss_inventories: inv });
      assert.deepEqual(flagsOf(a, "shadow_copies"), [flag], time);
    }
    // a host clock that runs ahead moves a command back into the interval
    const late = await put(cwd, "late.json", evtx([script(1, "2026-10-01T12:00:00Z", WMI_DELETE)]));
    const { a } = await run(cwd, { events: [{ host: "h1", file: late }], vss_inventories: inv, host_clocks: { h1: { offset_seconds: 7200, uncertainty_seconds: 0 } } });
    assert.deepEqual(flagsOf(a, "shadow_copies"), ["command_seen_without_inventory_change"]);
  });
});

test("an outcome-only backup job is not called an attempted action", async () => {
  await withCwd(async (cwd) => {
    const audit = await put(cwd, "a.json", { parser: "backup_audit_normalise/2", status: "complete", events: [{ seq: 1, source_id: "S1", category: "backup_job", result: "ok", time_utc: "2026-10-01T02:00:00Z" }] });
    const { a } = await run(cwd, { backup_audits: [{ host: "pbs", file: audit }] });
    const flag = (a.summary as Array<{ flags: Array<{ flag: string; meaning: string }> }>)[0]!.flags.find((f) => f.flag === "reported_exit_without_verified_loss")!;
    assert.doesNotMatch(flag.meaning, /attempted action/);
    assert.match(flag.meaning, /reported outcome is not a loss/);
  });
});

test("a shell history text file carries no status of its producer: that is said, and the producer's answer, when given, is checked", async () => {
  await withCwd(async (cwd) => {
    const hist = await put(cwd, "h.jsonl", JSON.stringify({ id: "H1", parser: "shell_history/14", user: "root", time: "2026-10-01T10:00:00Z", command: "ls" }) + "\n");
    const alone = await run(cwd, { shell_histories: [{ host: "lin1", file: hist }] });
    assert.equal(alone.a.status, "complete");
    assert.match(alone.a.status_basis, /shell_histories text files were given without their answer/);
    assert.deepEqual(alone.a.inputs_whose_producer_status_is_unknown, { shell_histories: 1 });
    const partial = await put(cwd, "ans-p.json", { parser: "shell_history/14", status: "partial" });
    const complete = await put(cwd, "ans-c.json", { parser: "shell_history/14", status: "complete" });
    const p = await run(cwd, { shell_histories: [{ host: "lin1", file: hist, answer: partial }] });
    assert.equal(p.a.status, "partial");
    assert.match(p.a.status_basis, /input_status_not_complete:shell_histories: 1/);
    const c = await run(cwd, { shell_histories: [{ host: "lin1", file: hist, answer: complete }] });
    assert.equal(c.a.status, "complete");
    assert.deepEqual(c.a.inputs_whose_producer_status_is_unknown, {});
    const wrong = await put(cwd, "ans-w.json", { parser: "shell_history/13", status: "complete" });
    const w = await tool(CORRELATE, cwd, { shell_histories: [{ host: "lin1", file: hist, answer: wrong }] });
    assert.match(JSON.parse(w.stdout).error, /shell_history\/13/);
  });
});

test("a chains table that is complete beside another table that was cut reads as complete", async () => {
  await withCwd(async (cwd) => {
    const chain = await put(cwd, "c.json", { parser: "snapshot_chain_check/2", status: "complete", truncated: true,
      pages: { chains: { matched: 1, returned: 1, truncated: false }, edges: { matched: 900, returned: 200, truncated: true } }, chains: [{ leaf: "d1", status: "complete", chain_length: 2 }] });
    const ok = await run(cwd, { chain_checks: [{ host: "pbs", file: chain }] });
    assert.equal(ok.a.status, "complete", ok.a.status_basis);
    const cut = await put(cwd, "c2.json", { parser: "snapshot_chain_check/2", status: "complete", truncated: true,
      pages: { chains: { matched: 500, returned: 200, truncated: true } }, chains: [{ leaf: "d1", status: "complete", chain_length: 2 }] });
    const bad = await run(cwd, { chain_checks: [{ host: "pbs", file: cut }] });
    assert.equal(bad.a.status, "partial");
    const audit = await put(cwd, "a.json", { parser: "backup_audit_normalise/2", status: "complete", truncated: true, pages: { events: { matched: 500, returned: 200, truncated: true } }, events: [] });
    assert.equal((await run(cwd, { backup_audits: [{ host: "pbs", file: audit }] })).a.status, "partial");
  });
});

test("an impossible calendar date is not a time: the row has none, and a verification or an inventory that carries one is refused", async () => {
  await withCwd(async (cwd) => {
    const e = await put(cwd, "e.json", evtx([script(1, "2026-02-30T10:00:00Z", WMI_DELETE)]));
    const { a } = await run(cwd, { events: [{ host: "h", file: e }] });
    assert.equal((a.observations as J[])[0]!.time_utc, null);
    const bad = await tool(CORRELATE, cwd, { verifications: [{ host: "h", object: "backup_catalog", result: "lost", verified_utc: "2026-02-30T10:00:00Z" }] });
    assert.match(JSON.parse(bad.stdout).error, /verification/);
    const vss1 = await put(cwd, "v.json", vss(["a"]));
    const worse = await tool(CORRELATE, cwd, { vss_inventories: [{ host: "h", file: vss1, collected_utc: "2026-02-30T10:00:00Z" }] });
    assert.match(JSON.parse(worse.stdout).error, /collected_utc/);
  });
});

test("the forms that fire as command_seen without being run, and the bounds of the fix round, are in the manifest", async () => {
  const manifest = JSON.parse(await readFile(MANIFEST, "utf8")) as { description: string; params: Record<string, { description: string }> };
  const text = manifest.description;
  for (const form of ["man lvremove", "cat lvremove.txt", "echo rm -rf /backups"]) assert.ok(text.includes(form), form);
  assert.match(text, /bounded only by the size of its inputs and the clock/);
  assert.match(text, /bisection/);
  assert.match(text, /20 seconds more/);
  assert.match(text, /command_seen_after_the_last_inventory/);
  assert.match(text, /2026-02-30/);
  assert.match(text, /no sealed text file/);
  assert.match(manifest.params.shell_histories!.description, /answer/);
  const source = await readFile(CORRELATE, "utf8");
  assert.match(source, /POST_GRACE = 20/);
});

// The one place this suite runs another tool: backup_audit_normalise is run at test time, so that what the correlate reads is what the tool really writes today
// (parser /3: provenance, preset and format fields beside the event rows), not a hand-written document.
test("a real backup_audit_normalise/3 answer (pve_task_index and pbs_task_log) is read: its category and result rows become observations", async () => {
  await withCwd(async (cwd) => {
    const hex = (n: number): string => n.toString(16).toUpperCase().padStart(8, "0");
    const upid = (start: number, type: string, id: string, end: number): string => `UPID:pve1:00000B73:0000D2F0:${hex(start)}:${type}:${id}:root@pam: ${hex(end)} OK`;
    const T = 1_790_000_000;
    await put(cwd, "index", [upid(T, "qmdelsnapshot", "100", T + 5), upid(T + 60, "prunejob", "", T + 90), upid(T + 120, "vzdump", "", T + 300)].join("\n") + "\n");
    await put(cwd, "pbs.log", ["2026-10-01T10:00:00Z: Starting prune on datastore 'store1'", "2026-10-01T10:00:01Z: remove vm/100/2026-09-01T00:00:00Z", "2026-10-01T10:00:02Z: TASK OK"].join("\n") + "\n");
    const idx = await virtTool(AUDIT, cwd, { path: "work/index", format: "pve_task_index" });
    const pbs = await virtTool(AUDIT, cwd, { path: "work/pbs.log", format: "pbs_task_log" });
    assert.equal(idx.code, 0, idx.stderr);
    assert.equal(pbs.code, 0, pbs.stderr);
    for (const out of [idx, pbs]) assert.equal(JSON.parse(out.stdout).parser, "backup_audit_normalise/3");
    const a1 = await put(cwd, "a1.json", idx.stdout);
    const a2 = await put(cwd, "a2.json", pbs.stdout);
    const { a, code } = await run(cwd, { backup_audits: [{ host: "pve1", file: a1 }, { host: "pbs1", file: a2 }] });
    assert.notEqual(a.status, "failed", JSON.stringify(a).slice(0, 400));
    assert.notEqual(code, 1);
    assert.doesNotMatch(JSON.stringify(a), /parser this tool does not read/);
    const obs = a.observations as J[];
    assert.ok(obs.some((o) => o.class === "action_attempted" && o.source?.kind === "backup_audit_normalise"), "an action from the real answer");
    assert.ok(obs.some((o) => o.class === "reported_outcome"), "an outcome from the real answer");
  });
});
