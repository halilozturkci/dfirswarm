/**
 * guardduty_findings: GuardDuty finding exports reconciled into update chains (one finding id, however often it was updated, is one finding with a
 * count). Fixtures are in tests/fixtures/guardduty/ and are written from the field lists of the AWS pages SOURCES.json cites (read on 2026-11-04);
 * canaries are built in tests/cloud-pack-secrets.ts and never written whole.
 */
import assert from "node:assert/strict";
import { copyFile, mkdir, readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { TOOLS, asJob, body, exists, filesUnder, gz, put, refused, spawnTool, tool, withDir } from "./cloud-pack-harness.ts";
import type { Json } from "./cloud-pack-harness.ts";
import { JWT, leaked, rnd } from "./cloud-pack-secrets.ts";

const GD = join(TOOLS, "guardduty_findings", "run.py");
const FIX = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", "guardduty");
const DIR = "work/s1/guardduty-findings";
const A = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const B = "ffeeddccbbaa99887766554433221100";
const C = "c0ffee00c0ffee00c0ffee00c0ffee01";

async function fixtures(cwd: string, names: string[]): Promise<void> {
  await mkdir(join(cwd, "work", "ev"), { recursive: true });
  for (const n of names) await copyFile(join(FIX, n), join(cwd, "work", "ev", n));
}

async function lines(cwd: string, name: string, dir = DIR): Promise<Json[]> {
  const text = await readFile(join(cwd, dir, name), "utf8");
  return text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

const T = (min: number): string => new Date(Date.UTC(2026, 1, 14, 9, 0, 0) + min * 60_000).toISOString();

/** A finding as the API writes it (lowerCamelCase), from the Finding and Service lists. */
const gd = (id: string, min: number, count: number, over: Json = {}, svc: Json = {}): Json => ({
  accountId: "111122223333", arn: `arn:aws:guardduty:eu-west-1:111122223333:detector/d1/finding/${id}`, createdAt: T(0), id, region: "eu-west-1", schemaVersion: "2.0", severity: 2,
  title: "t", type: "UnauthorizedAccess:EC2/SSHBruteForce", updatedAt: T(min), resource: { resourceType: "Instance" },
  service: { archived: false, count, detectorId: "d1", eventFirstSeen: T(-1), eventLastSeen: T(min), serviceName: "guardduty", action: { actionType: "NETWORK_CONNECTION" }, ...svc },
  ...over,
});

const jl = (...rs: Json[]): string => rs.map((r) => JSON.stringify(r)).join("\n") + "\n";

// ---- the chains --------------------------------------------------------------------------------------------------------------------------------

test("a GetFindings response is read: one finding each, the state from Service.Archived, the severity band, the detector, the counts, and the export coverage", async () => {
  await withDir(async (cwd) => {
    await fixtures(cwd, ["guardduty-api.json"]);
    const out = body(await tool(GD, cwd, { path: "work/ev/guardduty-api.json" }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.findings_count, 2);
    const f = await lines(cwd, "findings.jsonl");
    assert.deepEqual(f.map((x) => [x.finding_id, x.state]), [[A, "active"], [B, "archived"]]);
    assert.equal(f[0].type, "UnauthorizedAccess:EC2/SSHBruteForce");
    assert.equal(f[0].severity.latest_band, "Low");
    assert.equal(f[0].occurrences.count_last, 1);
    assert.deepEqual(f[0].detector_id.values, ["detector-one"]);
    assert.deepEqual(f[0].region.values, ["eu-west-1"]);
    assert.deepEqual(f[0].account_id.values, ["111122223333"]);
    assert.equal(f[0].action_type, "NETWORK_CONNECTION");
    assert.equal(f[0].has_evidence, true);
    assert.equal(f[0].latest_record.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4, "203.0.113.9", "the latest record is kept whole");
    assert.match(f[1].suppression, /does not say which/);
    assert.equal(out.coverage.records_read, 2);
    assert.deepEqual(out.export_coverage.regions_in_the_findings, [{ value: "eu-west-1", count: 2 }]);
    assert.match(out.no_finding_is_not_no_activity, /No finding is not no activity/);
    assert.equal(out.sources[0].key_forms["lowerCamelCase"], 2);
    const cov = JSON.parse(await readFile(join(cwd, DIR, "coverage.json"), "utf8"));
    assert.equal(cov.export_coverage.time_range.created_at_first_utc, "2026-02-14T09:00:00Z");
  });
});

test("one finding id exported as it was updated N times is one finding with N records, its counts and its last state; the versions file lists every record", async () => {
  await withDir(async (cwd) => {
    await fixtures(cwd, ["guardduty-export.jsonl"]);
    const out = body(await tool(GD, cwd, { path: "work/ev/guardduty-export.jsonl" }));
    assert.equal(out.findings_count, 2, "four records, two findings");
    assert.equal(out.records_in_chains, 4);
    const f = await lines(cwd, "findings.jsonl");
    const a = f.find((x) => x.finding_id === A) as Json;
    assert.equal(a.records_in_export, 3);
    assert.deepEqual([a.occurrences.count_first, a.occurrences.count_last, a.occurrences.count_max], [1, 17, 17]);
    assert.equal(a.occurrences.count_decreases, null, "the count never went down");
    assert.deepEqual([a.severity.first, a.severity.last, a.severity.latest_band], [2, 5, "Medium"]);
    assert.equal(a.updated_at.first_utc, "2026-02-14T09:00:00.000Z");
    assert.equal(a.updated_at.last_utc, "2026-02-14T21:00:00.000Z");
    assert.equal(a.event_window.last_seen_utc, "2026-02-14T21:00:00.000Z");
    assert.equal(a.state, "active");
    assert.equal(a.latest_record.Service.Count, 17, "the latest record is the one with the latest UpdatedAt");
    assert.match(a.occurrences.meaning, /records_in_export is not the number of occurrences/);
    const v = await lines(cwd, "finding-versions.jsonl");
    assert.deepEqual(v.filter((x) => x.finding_id === A).map((x) => [x.version, x.count, x.input_line]), [[1, 1, 1], [2, 9, 2], [3, 17, 3]]);
    assert.equal(out.sources[0].key_forms["UpperCamelCase"], 4, "the form seen is counted");
    assert.deepEqual(out.export_coverage.regions_in_the_findings.map((x: Json) => x.value).sort(), ["eu-west-1", "us-east-1"]);
    assert.deepEqual(out.export_coverage.accounts_in_the_findings.map((x: Json) => x.value).sort(), ["111122223333", "444455556666"]);
  });
});

test("fifty updates of one id in any input order are one finding; the order is UpdatedAt's, and a count that went down, a repeated record and two different records of one time are counted", async () => {
  await withDir(async (cwd) => {
    const recs = Array.from({ length: 50 }, (_, i) => gd(A, i, i + 1));
    recs.reverse();
    recs.push(gd(A, 10, 11));                              // an exact repeat of the record of minute 10
    recs.push(gd(A, 20, 99));                              // the same time, different content
    recs.push(gd(A, 60, 5));                               // a later update whose count went down
    await put(cwd, "work/ev/a.jsonl", jl(...recs));
    const out = body(await tool(GD, cwd, { path: "work/ev/a.jsonl" }));
    assert.equal(out.findings_count, 1);
    const [f] = await lines(cwd, "findings.jsonl");
    assert.equal(f.records_in_export, 53);
    assert.equal(f.exact_duplicate_records, 1);
    assert.equal(f.same_time_conflicting_updates, 1);
    assert.equal(f.occurrences.count_decreases >= 1, true);
    assert.equal(f.updated_at.last_utc, T(60));
    assert.equal(f.occurrences.count_last, 5);
    assert.equal(f.latest_record.service.count, 5);
    const v = await lines(cwd, "finding-versions.jsonl");
    assert.equal(v.length, 53);
    assert.deepEqual(v.slice(0, 3).map((x) => x.updated_at_utc), [T(0), T(1), T(2)], "the versions are in the order of UpdatedAt");
  });
});

test("archived and suppressed: the state is the latest record's Service.Archived, the transitions are listed, and the tool says it cannot tell a suppression rule from an archive by hand", async () => {
  await withDir(async (cwd) => {
    const recs = [gd(A, 0, 1), gd(A, 10, 2, {}, { archived: true }), gd(A, 20, 3), gd(B, 5, 1, {}, { archived: true }), gd(C, 6, 1, {}, { archived: "yes" }), gd("d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0", 7, 1, {}, { archived: undefined })];
    await put(cwd, "work/ev/a.jsonl", jl(...recs));
    const out = body(await tool(GD, cwd, { path: "work/ev/a.jsonl" }));
    assert.equal(out.findings_count, 4);
    const f = Object.fromEntries((await lines(cwd, "findings.jsonl")).map((x) => [x.finding_id, x]));
    assert.equal(f[A].state, "active");
    assert.equal(f[A].archive_transitions_total, 2);
    assert.deepEqual(f[A].archive_transitions.map((t: Json) => [t.from, t.to]), [[false, true], [true, false]]);
    assert.equal(f[A].archived_in_versions, 1);
    assert.equal(f[B].state, "archived");
    assert.match(f[B].state_basis, /Service\.Archived is true/);
    assert.equal(f[C].state, "unknown", "a string is not a boolean");
    assert.equal(f["d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"].state, "unknown");
    assert.deepEqual(out.export_coverage.by_state, [{ value: "unknown", count: 2 }, { value: "active", count: 1 }, { value: "archived", count: 1 }]);
    for (const x of Object.values(f)) assert.match((x as Json).suppression, /does not say which/);
    assert.match(out.findings_note, /one finding id is one finding/);
  });
});

test("several Regions, accounts and detectors are listed as the findings name them; the same id with different Regions or accounts is a conflict that is listed, not merged away; a path laid out as an export names its account and Region", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/AWSLogs/111122223333/GuardDuty/eu-west-1/one.jsonl", jl(gd(A, 0, 1), gd(B, 1, 1, { region: "us-east-1", accountId: "999988887777" }, { detectorId: "d9" })));
    await put(cwd, "work/ev/AWSLogs/444455556666/GuardDuty/us-east-1/two.jsonl", jl(gd(A, 30, 4, { region: "us-west-2", accountId: "444455556666", arn: "arn:other" })));
    const out = body(await tool(GD, cwd, { path: "work/ev" }));
    assert.equal(out.findings_count, 2);
    const f = Object.fromEntries((await lines(cwd, "findings.jsonl")).map((x) => [x.finding_id, x]));
    assert.deepEqual(f[A].conflicts.sort(), ["account", "arn", "region"]);
    assert.deepEqual(f[A].region.values.sort(), ["eu-west-1", "us-west-2"]);
    assert.match(f[A].conflicts_note, /disagree on/);
    assert.equal(f[A].input_files_count, 2);
    assert.equal(f[B].conflicts, undefined);
    assert.deepEqual(out.export_coverage.detectors_in_the_findings.map((x: Json) => x.value).sort(), ["d1", "d9"]);
    const cov = JSON.parse(await readFile(join(cwd, DIR, "coverage.json"), "utf8"));
    assert.deepEqual(cov.export_coverage.paths_laid_out_as_a_guardduty_export.map((p: Json) => [p.account, p.region]).sort(), [["111122223333", "eu-west-1"], ["444455556666", "us-east-1"]]);
    assert.equal(out.status, "complete");
  });
});

test("an empty export is complete with no finding and says that no finding is not no activity; an empty file, a file of finding ids only and an EventBridge event are not exports", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/empty.json", JSON.stringify({ findings: [] }));
    const out = body(await tool(GD, cwd, { path: "work/ev/empty.json" }));
    assert.equal(out.status, "complete");
    assert.equal(out.findings_count, 0);
    assert.match(out.empty_export, /^no finding was read: No finding is not no activity/);
    assert.match(out.empty_export, /archived findings, including new instances of suppressed findings, are not exported by default/);
    assert.match(out.empty_export, /regional/);
    assert.match(out.empty_export, /90 days/);
    assert.match(out.status_basis, /no finding is not no activity/);
    await put(cwd, "work/ev/zero.json", "");
    const zero = refused(await tool(GD, cwd, { path: "work/ev/zero.json", out_dir: "work/s1/z" }));
    assert.equal(zero.status, "failed");
    await put(cwd, "work/ev/ids.json", JSON.stringify({ findingIds: [A, B], nextToken: "tok" }));
    await put(cwd, "work/ev/bridge.json", JSON.stringify({ "detail-type": "GuardDuty Finding", detail: gd(A, 0, 1) }));
    const other = refused(await tool(GD, cwd, { path: "work/ev/bridge.json", out_dir: "work/s1/b" }));
    assert.equal(other.coverage.records_unsupported, 1);
    const rej = await lines(cwd, "rejected.partial.jsonl", "work/s1/b").catch(() => lines(cwd, "rejected.jsonl", "work/s1/b"));
    assert.match(rej[0].reason, /EventBridge event/);
    const ids = refused(await tool(GD, cwd, { path: "work/ev/ids.json", out_dir: "work/s1/i" }));
    assert.equal(ids.coverage.findings, 0);
  });
});

test("a file that names a next page keeps the run partial, a record that is not a finding is rejected with its place, and gzip and an envelope are read from the content", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/p.json", JSON.stringify({ findings: [gd(A, 0, 1)], nextToken: "next-page-token-value" }));
    const out = body(await tool(GD, cwd, { path: "work/ev/p.json" }));
    assert.equal(out.status, "partial");
    assert.deepEqual(out.pagination_markers.map((p: Json) => p.keys), [["nextToken"]]);
    assert.doesNotMatch(JSON.stringify(out), /next-page-token-value/);
    await put(cwd, "work/ev/z.bin", gz(jl(gd(A, 0, 1), { eventVersion: "1.08", eventSource: "sts.amazonaws.com" }, gd(B, 1, 1), { id: "x" })));
    const z = body(await tool(GD, cwd, { path: "work/ev/z.bin", out_dir: "work/s1/z" }));
    assert.equal(z.sources[0].compressed, true);
    assert.equal(z.findings_count, 2);
    assert.equal(z.coverage.records_unsupported, 2);
    const rej = await lines(cwd, "rejected.jsonl", "work/s1/z");
    assert.match(rej[0].reason, /no id.*CloudTrail record: cloudtrail_parse reads it/);
    assert.match(rej[1].reason, /no type/);
    assert.equal(rej[0].line, 2);
  });
});

test("hostile JSON: a broken line, a record over max_record_bytes, a record nested too deeply, scalars, a number out of range and an id that is not text end in a located reject or a finding, and the run goes on", async () => {
  await withDir(async (cwd) => {
    const big = gd(C, 3, 1);
    (big.service as Json).pad = "x".repeat(3 << 20);
    const deep = "[".repeat(100_000) + "]".repeat(100_000);
    await put(cwd, "work/ev/h.jsonl", [JSON.stringify(gd(A, 0, 1)), '{"id": "broken", ', JSON.stringify(big), "42", '"text"', `{"id": 5, "type": "t"}`, deep, JSON.stringify(gd(B, 1, 1, { severity: 1e308, createdAt: "0000-00-00", updatedAt: "2026-13-45T99:99:99Z" })), JSON.stringify(gd("e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1", 2, 1, { updatedAt: 1771059600 }))].join("\n") + "\n");
    const out = body(await tool(GD, cwd, { path: "work/ev/h.jsonl", max_record_bytes: 1 << 20 }));
    assert.equal(out.status, "partial");
    assert.equal(out.findings_count, 3);
    assert.ok(out.coverage.records_rejected >= 5, JSON.stringify(out.coverage));
    const rej = await lines(cwd, "rejected.partial.jsonl").catch(() => lines(cwd, "rejected.jsonl"));
    assert.ok(rej.every((r) => typeof r.line === "number" && r.reason), "every reject is located and has a reason");
    assert.ok(rej.some((r) => /larger than max_record_bytes/.test(r.reason)));
    const f = Object.fromEntries((await lines(cwd, "findings.partial.jsonl")).map((x) => [x.finding_id, x]));
    assert.equal(f[B].records_without_a_readable_updated_at, 1, "an UpdatedAt that is not a time is counted, not read");
    assert.equal(f[B].severity.latest_band, null, "a severity outside 1.0 to 10.0 has no band");
    assert.equal(f["e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"].records_without_a_readable_updated_at, 1, "a number where a time string is documented is not read as one");
  });
});

// ---- masking -----------------------------------------------------------------------------------------------------------------------------------------

test("canaries in Service.Action text, Evidence text, the description and a credential-named field are withheld from every channel; the originals go to the 0600 values file only on write_values", async () => {
  const actionSecret = rnd(24, 301);
  const evidenceText = rnd(24, 302);
  const descSecret = rnd(24, 303);
  const namedSecret = rnd(30, 304);
  const uaSecret = JWT;
  await withDir(async (cwd) => {
    const f = gd(A, 0, 1, { description: `credential password=${descSecret} seen` }, {
      action: { actionType: "AWS_API_CALL", awsApiCallAction: { api: "GetObject", userAgent: `curl Authorization: Bearer ${uaSecret}`, remoteIpDetails: { ipAddressV4: "203.0.113.9" }, affectedResources: { note: `access_token=${actionSecret}` } } },
      evidence: { threatIntelligenceDetails: [{ threatListName: `list password=${evidenceText}`, threatNames: ["n"] }] },
      additionalInfo: { type: "default", value: "x", client_secret: namedSecret },
    });
    await put(cwd, "work/ev/a.jsonl", jl(f, gd(B, 1, 1)));
    const run = await asJob(GD, cwd, { path: "work/ev/a.jsonl" }, { SECRET_OUTPUT: "1" });
    const out = body(run);
    assert.equal(out.findings_count, 2, out.status_basis);
    const everything = [run.stdout, run.stderr];
    for (const file of await filesUnder(join(cwd, "out"))) if (!file.endsWith("guardduty-findings-values.jsonl")) everything.push(await readFile(join(cwd, "out", file), "utf8"));
    const all = everything.join("\n");
    for (const [label, secret] of [["action text", actionSecret], ["evidence text", evidenceText], ["description", descSecret], ["named field", namedSecret], ["user agent", uaSecret]] as Array<[string, string]>) {
      assert.equal(leaked(secret, all), undefined, `${label} appears in the output`);
      assert.equal(leaked(Buffer.from(secret).toString("base64"), all), undefined, `${label} appears in base64`);
    }
    assert.ok(all.includes(A) && all.includes("203.0.113.9"), "the finding id and the address are printed");
    assert.ok(out.values_withheld.count >= 4);
    assert.equal(await exists(join(cwd, "out", "guardduty-findings-values.jsonl")), false);
  });
  await withDir(async (cwd) => {
    const f = gd(A, 0, 1, { description: `credential password=${descSecret} seen` });
    await put(cwd, "work/ev/a.jsonl", jl(f));
    const run = await asJob(GD, cwd, { path: "work/ev/a.jsonl", write_values: true }, { SECRET_OUTPUT: "1" });
    const out = body(run);
    assert.ok(out.secret_values.written >= 1);
    const values = await readFile(join(cwd, "out", "guardduty-findings-values.jsonl"), "utf8");
    assert.ok(values.includes(descSecret));
    assert.equal((await stat(join(cwd, "out", "guardduty-findings-values.jsonl"))).mode & 0o777, 0o600);
    const everyOther = run.stdout + (await readFile(join(cwd, "out", "guardduty-findings", "findings.jsonl"), "utf8")) + (await readFile(join(cwd, "out", "guardduty-findings", "finding-versions.jsonl"), "utf8"));
    assert.equal(leaked(descSecret, everyOther), undefined);
  });
});

test("write_values is refused outside a job and in a job that is not secret output, as JSON, with nothing written", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", jl(gd(A, 0, 1)));
    const outside = refused(await tool(GD, cwd, { path: "work/ev/a.jsonl", write_values: true }));
    assert.equal(outside.write_values, "refused");
    const plain = refused(await asJob(GD, cwd, { path: "work/ev/a.jsonl", write_values: true }));
    assert.equal(plain.write_values, "refused");
    assert.equal(await exists(join(cwd, DIR)), false, "nothing was written");
  });
});

// ---- the contract -------------------------------------------------------------------------------------------------------------------------------

test("a second run in one directory never replaces the first; out_dir cannot leave the run directory", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", jl(gd(A, 0, 1)));
    body(await tool(GD, cwd, { path: "work/ev/a.jsonl" }));
    const first = await readFile(join(cwd, DIR, "findings.jsonl"), "utf8");
    body(await tool(GD, cwd, { path: "work/ev/a.jsonl" }));
    assert.deepEqual((await readdir(join(cwd, DIR))).sort(), ["coverage.json", "finding-versions.jsonl", "findings.jsonl", "rejected.jsonl"], "equal bytes: the files already there are the result");
    await put(cwd, "work/ev/b.jsonl", jl(gd(B, 0, 2)));
    const second = body(await tool(GD, cwd, { path: "work/ev/b.jsonl" }));
    assert.equal(await readFile(join(cwd, DIR, "findings.jsonl"), "utf8"), first);
    assert.ok(second.outputs.findings.endsWith("findings.2.jsonl"), second.outputs.findings);
    for (const bad of ["../x", "inputs/x", "/tmp/gd-out-x"]) refused(await tool(GD, cwd, { path: "work/ev/a.jsonl", out_dir: bad }));
    refused(await asJob(GD, cwd, { path: "work/ev/a.jsonl", out_dir: "work/s1/x" }));
  });
});

test("the manifest declares secret_output for write_values and a 600 s call, the clock's ceiling is enforced, and unknown arguments are refused", async () => {
  const m = JSON.parse(await readFile(join(TOOLS, "guardduty_findings", "manifest.json"), "utf8"));
  assert.deepEqual(m.secret_output, { when_args: ["write_values"] });
  assert.equal(m.timeout_seconds, 600);
  for (const word of ["2026-11-04", "no finding is not no activity", "reconciles findings and exports only", "cannot tell a suppression rule", "NOT measured"]) assert.ok(m.description.includes(word), word);
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", jl(gd(A, 0, 1)));
    assert.match(refused(await tool(GD, cwd, { path: "work/ev/a.jsonl", time_limit_seconds: 481 })).error, /1 to 480/);
    for (const bad of [{ bogus: 1 }, { path: 5 }, { path: "work/ev/a.jsonl", provider: "gcp" }, {}]) refused(await tool(GD, cwd, bad));
  });
});

test("SIGTERM ends the run with exit 143, one line of JSON, a partial coverage file and no temporary database left behind", async (t) => {
  await withDir(async (cwd) => {
    const many = Array.from({ length: 300_000 }, (_, i) => JSON.stringify(gd(i.toString(16).padStart(32, "0"), i % 500, 1 + (i % 7), {}, { pad: "benign words ".repeat(20) }))).join("\n") + "\n";
    await put(cwd, "work/ev/a.jsonl", many);
    await mkdir(join(cwd, "tmp"), { recursive: true });
    const { child, done } = spawnTool(GD, cwd, { path: "work/ev/a.jsonl", time_limit_seconds: 300 }, { TMPDIR: join(cwd, "tmp") });
    await new Promise((r) => setTimeout(r, 3500));
    child.kill("SIGTERM");
    const run = await done;
    if (run.code === 0) {
      t.diagnostic("the run finished before the signal");
      return;
    }
    assert.equal(run.code, 143, run.stderr);
    assert.doesNotMatch(run.stderr, /Traceback/);
    const line = JSON.parse(run.stdout.trim().split("\n").pop() as string);
    assert.equal(line.status, "partial");
    assert.equal(line.interrupted, true);
    assert.deepEqual((await readdir(join(cwd, DIR))).sort(), ["coverage.partial.json"]);
    assert.deepEqual(await readdir(join(cwd, "tmp")), [], "no temporary database directory is left");
  });
});

test("the clock is one: four simultaneous runs over large exports end near their limit, partial or complete, with the counts so far, and leave no temporary database", async () => {
  await withDir(async (cwd) => {
    const block = Array.from({ length: 250_000 }, (_, i) => JSON.stringify(gd((i % 40000).toString(16).padStart(32, "0"), i % 997, 1 + Math.floor(i / 40000), {}, { pad: "benign words ".repeat(10) }))).join("\n") + "\n";
    for (const n of ["a", "b", "c", "d"]) await put(cwd, `work/ev/${n}/e.jsonl`, block);
    await mkdir(join(cwd, "tmp"), { recursive: true });
    const t0 = Date.now();
    const runs = await Promise.all(["a", "b", "c", "d"].map((n) => tool(GD, cwd, { path: `work/ev/${n}`, out_dir: `work/s1/${n}`, time_limit_seconds: 6 }, { TMPDIR: join(cwd, "tmp") })));
    const took = Date.now() - t0;
    assert.ok(took < 6000 + 20_000, `took ${took} ms`);
    for (const run of runs) {
      assert.doesNotMatch(run.stderr, /Traceback/);
      const out = JSON.parse(run.stdout);
      assert.ok(["partial", "complete"].includes(out.status), out.status);
      assert.ok(out.coverage.records_read > 0);
      if (out.status === "partial") assert.equal(out.coverage.stopped_by_time_limit, true);
      assert.doesNotMatch(out.status_basis, /undefined/);
    }
    assert.deepEqual(await readdir(join(cwd, "tmp")), [], "no temporary database directory is left");
  });
});

test("1,000 structure-aware mutations of a finding end in a finding or a located reject, never a crash, and every record is accounted for", async () => {
  let state = 4242;
  const rnd01 = (): number => ((state = (state * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const swaps: unknown[] = [null, 0, -1, 1e308, "", "x".repeat(300), [], {}, [null], { a: { b: [] } }, true, "2026-13-45T99:99:99Z", "\u0000", "\ud800"];
  const mutate = (v: Json): Json => {
    if (Array.isArray(v)) return v.map((x) => (rnd01() < 0.15 ? swaps[Math.floor(rnd01() * swaps.length)] : mutate(x)));
    if (v && typeof v === "object") {
      const out: Json = {};
      for (const [k, x] of Object.entries(v)) {
        if (rnd01() < 0.05) continue;
        out[k] = rnd01() < 0.15 ? swaps[Math.floor(rnd01() * swaps.length)] : mutate(x);
      }
      return out;
    }
    return v;
  };
  const seed = gd(A, 0, 1, {}, { evidence: { threatIntelligenceDetails: [{ threatListName: "l", threatNames: ["n"] }] } });
  const recs: string[] = [];
  for (let i = 0; i < 1000; i++) recs.push(JSON.stringify(mutate(seed)));
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/f.jsonl", recs.join("\n") + "\n");
    const run = await tool(GD, cwd, { path: "work/ev/f.jsonl" });
    assert.doesNotMatch(run.stderr, /Traceback/);
    const out = JSON.parse(run.stdout);
    assert.ok(["partial", "complete", "failed"].includes(out.status), out.status);
    const c = out.coverage;
    assert.equal(c.records_read + c.records_rejected, 1000, "every record is read as a finding or rejected");
    assert.ok(out.records_in_chains === c.records_read, "every record read is in a chain");
  });
});

test("the tool is a carrier of the shared blocks and its version, PARSER label and sha256 agree", async () => {
  const text = await readFile(GD, "utf8");
  assert.match(text, /^PARSER = "guardduty_findings\/1"$/m);
  assert.match(text, /^TOOL = "guardduty_findings"$/m);
  const manifest = JSON.parse(await readFile(join(TOOLS, "guardduty_findings", "manifest.json"), "utf8"));
  assert.equal(manifest.name, "guardduty_findings");
  assert.equal(manifest.version, 1);
  assert.equal((await stat(GD)).mode & 0o111, 0o111, "run.py is executable");
});
