/**
 * The cloud pack: signin_analyse, against Microsoft Graph's signIn resource (id, createdDateTime, userPrincipalName,
 * userId, appDisplayName, appId, ipAddress, clientAppUsed, correlationId, conditionalAccessStatus,
 * appliedConditionalAccessPolicies, authenticationRequirement, authenticationDetails, status{errorCode, failureReason,
 * additionalDetails}, deviceDetail, location{city, countryOrRegion, geoCoordinates}), the portal's CSV columns, and the
 * Google Reports API activity (id{time, uniqueQualifier, applicationName, customerId}, actor{email}, ipAddress,
 * events[{type, name, parameters[{name, value}]}]). Every fixture is built by the test from those layouts.
 */
import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { SIGNIN, asJob, body, everythingBut, exists, filesUnder, put, refused, rowsOf, tool, withDir } from "./cloud-pack-harness.ts";
import type { Json } from "./cloud-pack-harness.ts";

/** A Graph signIn. */
function signIn(i: number, time: string, code: number | null, over: Json = {}): Json {
  return {
    id: `signin-${i}`,
    createdDateTime: time,
    userPrincipalName: "alice@example.org",
    userId: "user-guid-1",
    appDisplayName: "Office 365 Exchange Online",
    appId: "00000002-0000-0ff1-ce00-000000000000",
    ipAddress: "198.51.100.1",
    clientAppUsed: "Browser",
    correlationId: `corr-${i}`,
    conditionalAccessStatus: "success",
    isInteractive: true,
    authenticationRequirement: "multiFactorAuthentication",
    appliedConditionalAccessPolicies: [{ id: "pol-1", displayName: "Require MFA for all users", enforcedGrantControls: ["Mfa"], enforcedSessionControls: [], result: "success" }],
    authenticationDetails: [{ authenticationStepDateTime: time, authenticationMethod: "Password", authenticationMethodDetail: "Password in the cloud", succeeded: code === 0 || code === null, authenticationStepResultDetail: "Correct password", authenticationStepRequirement: "Primary authentication" }],
    status: { errorCode: code, failureReason: code ? "Invalid username or password." : null, additionalDetails: null },
    deviceDetail: { deviceId: "", displayName: "", operatingSystem: "Windows 11", browser: "Edge 120.0.0", isCompliant: false, isManaged: false, trustType: "" },
    location: { city: "Istanbul", state: "Istanbul", countryOrRegion: "TR", geoCoordinates: {} },
    ...over,
  };
}

const graph = (...rows: Json[]): string => JSON.stringify({ "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns", value: rows });

async function run(cwd: string, name: string, text: string, args: Json = {}): Promise<Json> {
  await put(cwd, `work/ev/${name}`, text);
  return body(await tool(SIGNIN, cwd, { path: `work/ev/${name}`, ...args }));
}

const csvLine = (cells: string[]): string => cells.map((c) => (/[",\r\n]/.test(c) ? `"${c.replaceAll('"', '""')}"` : c)).join(",");
const PORTAL = ["Date (UTC)", "Request ID", "Correlation ID", "User", "Username", "Application", "IP address", "Location", "Status", "Sign-in error code", "Failure reason", "Client app", "Authentication requirement", "Conditional Access"];
const portalRow = (i: number, date: string, status: string, code: string, over: Record<string, string> = {}): string[] => {
  const v: Record<string, string> = { "Date (UTC)": date, "Request ID": `req-${i}`, "Correlation ID": `corr-${i}`, User: "Alice", Username: "alice@example.org", Application: "Office 365", "IP address": "198.51.100.1", Location: "Istanbul, TR", Status: status, "Sign-in error code": code, "Failure reason": "", "Client app": "Browser", "Authentication requirement": "Multifactor authentication", "Conditional Access": "Success", ...over };
  return PORTAL.map((k) => v[k]);
};
const portalCsv = (...rows: string[][]): string => [csvLine(PORTAL), ...rows.map(csvLine)].join("\r\n") + "\r\n";

// ---- outcome -----------------------------------------------------------------------------------------------------------------

test("a status that is neither a success nor a failure is an unknown outcome, not a failure", async () => {
  await withDir(async (cwd) => {
    const csv = portalCsv(portalRow(1, "2026-02-14T09:00:00Z", "Success", "0"), portalRow(2, "2026-02-14T09:01:00Z", "Pending", ""), portalRow(3, "2026-02-14T09:02:00Z", "Failure", "50126"));
    const out = await run(cwd, "s.csv", csv);
    assert.deepEqual(out.events.map((e: Json) => e.success), [true, null, false], "success is present and null for the unknown one");
    assert.deepEqual([out.successes, out.failures, out.unknown_outcome], [1, 1, 1]);
    const unknown = out.events[1];
    assert.equal(unknown.result_code, "Pending");
    assert.match(unknown.outcome_basis, /neither a success nor a failure value/);
  });
});

test("a result code is glossed by the tool and the provider's own words are kept as written, and 50158 is not called a conditional access failure", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, "s.json", graph(signIn(1, "2026-02-14T09:00:00Z", 50158, { status: { errorCode: 50158, failureReason: "External security challenge was not satisfied.", additionalDetails: "details as written" } })));
    const e = out.events[0];
    assert.equal(e.failure_reason, "External security challenge was not satisfied.");
    assert.equal(e.additional_details, "details as written");
    assert.equal(e.result, "external security challenge");
    assert.doesNotMatch(JSON.stringify(out), /conditional access failed/i);
    assert.equal(e.success, null, "50158 is a prompt of a flow, not the end of one");
    assert.equal(e.outcome_class, "interrupt");
  });
});

// ---- formats -------------------------------------------------------------------------------------------------------------------

test("a .jsonl file is read as JSON Lines, and the format is the content's, not the name's", async () => {
  await withDir(async (cwd) => {
    const jsonl = [signIn(1, "2026-02-14T09:00:00Z", 0), signIn(2, "2026-02-14T09:05:00Z", 50126)].map((r) => JSON.stringify(r)).join("\n") + "\n";
    const out = await run(cwd, "export.jsonl", jsonl);
    assert.equal(out.event_count, 2);
    assert.equal(out.coverage.records_rejected, 0);
    assert.equal(out.status, "complete");
    const fromName = await run(cwd, "really-csv.json", portalCsv(portalRow(1, "2026-02-14T09:00:00Z", "Success", "0")));
    assert.equal(fromName.event_count, 1);
    const census = await rowsOf(cwd, fromName, "file_census");
    assert.deepEqual([census[0].format, census[0].format_basis], ["csv", "the content"]);
  });
});

test("a malformed line, a value that is not a record and a truncated file are counted, located and listed; the rest is read", async () => {
  await withDir(async (cwd) => {
    const text = [JSON.stringify(signIn(1, "2026-02-14T09:00:00Z", 0)), "{broken", "42", JSON.stringify(signIn(2, "2026-02-14T09:05:00Z", 0))].join("\n");
    const out = await run(cwd, "x.jsonl", text);
    assert.equal(out.status, "partial");
    assert.equal(out.event_count, 2);
    assert.equal(out.coverage.records_rejected, 2);
    const rejected = await rowsOf(cwd, out, "rejected_records");
    assert.deepEqual(rejected.map((r: Json) => [r.record, r.line]), [[2, 2], [3, 3]]);
    assert.match(out.file_problems.join(" "), /record 2 at line 2/);
  });
});

test("a response that names a next page is partial, and the token is never printed", async () => {
  await withDir(async (cwd) => {
    const g = JSON.stringify({ value: [signIn(1, "2026-02-14T09:00:00Z", 0)], "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=SKIPTOKENVALUE0123456789abcdef" });
    const out = await run(cwd, "page.json", g);
    assert.equal(out.status, "partial");
    assert.deepEqual(out.pagination_markers.map((m: Json) => m.keys), [["@odata.nextLink"]]);
    assert.ok(!JSON.stringify(out).includes("SKIPTOKENVALUE0123456789abcdef"));
    const google = JSON.stringify({ kind: "admin#reports#activities", items: [], nextPageToken: "GOOGLEPAGETOKEN0123456789abcdef" });
    const g2 = await run(cwd, "g.json", google);
    assert.equal(g2.status, "partial");
    assert.ok(!JSON.stringify(g2).includes("GOOGLEPAGETOKEN0123456789abcdef"));
  });
});

test("a Google activity is expanded to one event per nested event, with the activity id and the event's position kept, and login_failure is a failure", async () => {
  await withDir(async (cwd) => {
    const activity = (qualifier: string, name: string, time: string): Json => ({
      kind: "admin#reports#activity",
      id: { time, uniqueQualifier: qualifier, applicationName: "login", customerId: "C0abcdef1" },
      actor: { email: "carol@example.org", profileId: "1234567890" },
      ipAddress: "203.0.113.50",
      events: [{ type: "login", name: "login_challenge", parameters: [{ name: "login_challenge_method", value: "totp" }] }, { type: "login", name, parameters: [{ name: "login_type", value: "google_password" }] }],
    });
    const items = [activity("q-1", "login_failure", "2026-02-14T09:00:00.000Z"), activity("q-2", "login_success", "2026-02-14T09:01:00.000Z")];
    const out = await run(cwd, "g.json", JSON.stringify({ kind: "admin#reports#activities", items }));
    assert.equal(out.event_count, 4);
    assert.deepEqual(out.events.map((e: Json) => [e.record, e.event_index, e.success]), [[1, 0, null], [1, 1, false], [2, 0, null], [2, 1, true]]);
    assert.deepEqual(out.events[1].activity_id, { time: "2026-02-14T09:00:00.000Z", uniqueQualifier: "q-1", applicationName: "login", customerId: "C0abcdef1" });
    assert.equal(out.events[1].user, "carol@example.org");
    assert.equal(out.events[1].client, "google_password");
    assert.equal(out.events[1].time_utc, "2026-02-14T09:00:00.000Z");
    assert.deepEqual(out.events[0].event_parameters, { login_challenge_method: "totp" });
  });
});

// ---- time ---------------------------------------------------------------------------------------------------------------------

test("a time with no zone is refused unless assume_utc says it is UTC; with it the answer records the assumption", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/z.json", graph(signIn(1, "2026-02-14T09:00:00", 0), signIn(2, "2026-02-14T09:05:00Z", 0)));
    const refusal = refused(await tool(SIGNIN, cwd, { path: "work/ev/z.json", out_file: "work/s1/events.jsonl" }));
    assert.equal(refusal.status, "failed");
    assert.match(refusal.error, /1 record\(s\) carry a time with no zone \(the first is record 1 at line 1: 2026-02-14T09:00:00\)/);
    assert.match(refusal.error, /assume_utc: true/);
    assert.equal(refusal.records_without_a_zone, 1);
    assert.equal(await exists(join(cwd, "work/s1/events.jsonl")), false, "a refusal writes nothing");
    const allowed = body(await tool(SIGNIN, cwd, { path: "work/ev/z.json", assume_utc: true }));
    assert.deepEqual(allowed.events.map((e: Json) => [e.time, e.time_utc, e.time_status]), [["2026-02-14T09:00:00", "2026-02-14T09:00:00Z", "assumed_utc"], ["2026-02-14T09:05:00Z", "2026-02-14T09:05:00Z", "zoned"]]);
    assert.match(allowed.assumptions.join(" "), /times with no zone were read as UTC because assume_utc was set: 1 event/);
  });
});

test("a column named Date (UTC) is read as UTC on its own say-so, and the basis says so; a day/month/year string needs a date order", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, "p.csv", portalCsv(portalRow(1, "2026-02-14 09:00:00", "Success", "0")));
    assert.equal(out.events[0].time_utc, "2026-02-14T09:00:00Z");
    assert.equal(out.events[0].time_basis, "the column is named Date (UTC)");
    assert.match(out.assumptions.join(" "), /column named Date \(UTC\)/);
    const slashed = portalCsv(portalRow(1, "03/04/2026 12:00:00", "Success", "0")).replace("Date (UTC)", "Timestamp");
    await put(cwd, "work/ev/s.csv", slashed);
    const refusal = refused(await tool(SIGNIN, cwd, { path: "work/ev/s.csv", assume_utc: true }));
    assert.match(refusal.error, /both 12 or less.*date_order/);
    const declared = body(await tool(SIGNIN, cwd, { path: "work/ev/s.csv", assume_utc: true, date_order: "dmy" }));
    assert.equal(declared.events[0].time_utc, "2026-04-03T12:00:00Z");
  });
});

// ---- the leads ---------------------------------------------------------------------------------------------------------------

test("three failures thirty days before a success are not a burst; three within minutes are, and the answer says which addresses and codes", async () => {
  await withDir(async (cwd) => {
    const farApart = graph(
      signIn(1, "2026-01-01T09:00:00Z", 50126), signIn(2, "2026-01-01T09:01:00Z", 50126), signIn(3, "2026-01-01T09:02:00Z", 50126),
      signIn(4, "2026-01-31T09:00:00Z", 0),
    );
    const none = await run(cwd, "far.json", farApart, { burst_window_seconds: 86400 });
    assert.deepEqual(none.failure_bursts_before_success, []);
    const dflt = await run(cwd, "far.json", farApart);
    assert.deepEqual(dflt.failure_bursts_before_success, [], "the default window is an hour");

    const close = graph(
      signIn(1, "2026-02-14T09:00:00Z", 50126, { ipAddress: "192.0.2.10" }), signIn(2, "2026-02-14T09:01:00Z", 50053, { ipAddress: "192.0.2.10" }), signIn(3, "2026-02-14T09:02:00Z", 50126, { ipAddress: "192.0.2.10" }),
      signIn(4, "2026-02-14T09:03:00Z", 0, { ipAddress: "203.0.113.5" }),
    );
    const burst = await run(cwd, "close.json", close);
    assert.equal(burst.failure_bursts_before_success.length, 1);
    const b = burst.failure_bursts_before_success[0];
    assert.deepEqual([b.failures_before, b.failure_result_codes, b.failure_addresses, b.success_address_among_failure_addresses], [3, { 50126: 2, 50053: 1 }, { "192.0.2.10": 3 }, false]);
    assert.equal(b.success.event_id, "signin-4");
    assert.deepEqual(b.failure_events.map((f: Json) => f.event_id), ["signin-1", "signin-2", "signin-3"]);
  });
});

test("failures are counted per account and application, and an unknown outcome ends a run", async () => {
  await withDir(async (cwd) => {
    const other = { appDisplayName: "Azure Portal" };
    const rows = graph(
      signIn(1, "2026-02-14T09:00:00Z", 50126), signIn(2, "2026-02-14T09:01:00Z", 50126, other), signIn(3, "2026-02-14T09:02:00Z", 50126), signIn(4, "2026-02-14T09:03:00Z", 50126, other),
      signIn(5, "2026-02-14T09:04:00Z", 0),
    );
    const out = await run(cwd, "apps.json", rows);
    assert.deepEqual(out.failure_bursts_before_success, [], "two failures in each application, then a success in one: no application has three");
    const interrupted = graph(signIn(1, "2026-02-14T09:00:00Z", 50126), signIn(2, "2026-02-14T09:01:00Z", 50126), { ...signIn(3, "2026-02-14T09:02:00Z", null), status: { errorCode: null, failureReason: "Interrupted" } }, signIn(4, "2026-02-14T09:03:00Z", 50126), signIn(5, "2026-02-14T09:04:00Z", 0));
    const after = await run(cwd, "interrupted.json", interrupted);
    assert.deepEqual(after.failure_bursts_before_success, []);
  });
});

test("every field a lead depends on is kept: ids, correlation id, authentication details, applied policies, device context, the raw record and where it came from", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, "s.json", graph(signIn(1, "2026-02-14T09:00:00Z", 0, { authenticationRequirement: "singleFactorAuthentication", tokenIssuerType: "AzureAD", uniqueTokenIdentifier: "abcDEF123_uniq" })));
    const e = out.events[0];
    assert.equal(e.event_id, "signin-1");
    assert.equal(e.correlation_id, "corr-1");
    assert.equal(e.user_id, "user-guid-1");
    assert.equal(e.authentication_details[0].authenticationMethod, "Password");
    assert.equal(e.conditional_access_policies[0].displayName, "Require MFA for all users");
    assert.deepEqual([e.token_issuer_type, e.unique_token_identifier], ["AzureAD", "abcDEF123_uniq"]);
    assert.equal(e.device_detail.operatingSystem, "Windows 11");
    assert.equal(e.raw_record.id, "signin-1");
    assert.deepEqual([e.record, e.line, e.event_index ?? null, e.parser], [1, 1, null, "signin_analyse/4"]);
    assert.equal(e.source_file.endsWith("s.json"), true);
    assert.equal(out.single_factor_successes.length, 1);
    assert.equal(out.single_factor_successes[0].event_id, "signin-1");
    assert.equal(out.single_factor_successes[0].correlation_id, "corr-1");
  });
});

test("an address seen once is said to be once in this export, and the heuristic is named for what it is", async () => {
  await withDir(async (cwd) => {
    const rows = [1, 2, 3].map((i) => signIn(i, `2026-02-14T09:0${i}:00Z`, 0, { ipAddress: `198.51.100.${i}` })).concat([signIn(4, "2026-02-14T09:04:00Z", 0, { ipAddress: "198.51.100.1" })]);
    const out = await run(cwd, "seen.json", graph(...rows));
    assert.deepEqual(out.addresses_seen_once.map((r: Json) => r.address), ["198.51.100.2", "198.51.100.3"]);
    assert.match(out.addresses_seen_once[0].why, /once among this account's events in this export.*may not hold/);
    assert.doesNotMatch(JSON.stringify(out), /unfamiliar|this account's history/);
  });
});

test("impossible travel carries the speed and the two events, and a record with no user is counted and kept out of the account analysis", async () => {
  await withDir(async (cwd) => {
    const geo = (lat: number, lon: number, country: string): Json => ({ location: { city: "x", countryOrRegion: country, geoCoordinates: { latitude: lat, longitude: lon } } });
    const rows = [signIn(1, "2026-02-14T09:00:00Z", 0, geo(41.0, 29.0, "TR")), signIn(2, "2026-02-14T09:20:00Z", 0, { ...geo(52.5, 13.4, "DE"), ipAddress: "192.0.2.9" }),
      signIn(3, "2026-02-14T09:10:00Z", 0, { userPrincipalName: null, userId: null, ...geo(0, 0, "XX") }), signIn(4, "2026-02-14T09:11:00Z", 0, { userPrincipalName: null, userId: null, ...geo(60, 60, "RU") })];
    const out = await run(cwd, "t.json", graph(...rows));
    assert.equal(out.impossible_travel.length, 1);
    const t = out.impossible_travel[0];
    assert.deepEqual([t.basis, t.coarse, t.from.event_id, t.to.event_id], ["coordinates", false, "signin-1", "signin-2"]);
    assert.ok(t.implied_speed_kmh > 900);
    assert.equal(out.coverage.events_without_user, 2);
    assert.equal(out.accounts, 1);
    const coarse = await run(cwd, "c.json", graph(signIn(1, "2026-02-14T09:00:00Z", 0), signIn(2, "2026-02-14T09:20:00Z", 0, { location: { city: "Berlin", countryOrRegion: "DE", geoCoordinates: {} } })));
    assert.deepEqual([coarse.impossible_travel[0].coarse, coarse.impossible_travel[0].basis], [true, "country change only"]);
  });
});

test("a large export is analysed from a database on disk and every event is kept", async () => {
  await withDir(async (cwd) => {
    const rows = Array.from({ length: 30000 }, (_, i) => signIn(i, new Date(Date.UTC(2026, 1, 14, 0, 0, i % 86000)).toISOString().replace(".000Z", "Z"), i % 7 === 0 ? 50126 : 0, { userPrincipalName: `user${i % 40}@example.org`, userId: `guid-${i % 40}`, ipAddress: `198.51.100.${i % 200}` }));
    const out = await run(cwd, "many.json", graph(...rows), { limit: 20 });
    assert.equal(out.event_count, 30000);
    assert.equal(out.accounts, 40);
    assert.equal(out.coverage.analysis_kept_in, "a temporary file");
    assert.equal((await rowsOf(cwd, out, "events")).length, 30000);
  });
});

// ---- secrets and where output goes --------------------------------------------------------------------------------------------

const JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const PASSWORD = "Hunter2-correct-horse";
const NEEDLES = [JWT, "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0", PASSWORD, "correct-horse"];

test("a credential-shaped value in a record is withheld from every row, the raw record and every file; the sealed values file holds it only in a job", async () => {
  await withDir(async (cwd) => {
    const row = signIn(1, "2026-02-14T09:00:00Z", 50126, { userAgent: `custom-agent token=${JWT}`, status: { errorCode: 50126, failureReason: `rejected password=${PASSWORD}`, additionalDetails: null }, clientSecret: PASSWORD });
    await put(cwd, `work/ev/${JWT}.json`, graph(row));
    const plain = await asJob(SIGNIN, cwd, { path: `work/ev/${JWT}.json`, limit: 1 }, {}, "out", "jplain");
    const parsed = body(plain);
    const all = await everythingBut(cwd, plain.stdout + plain.stderr, []);
    for (const needle of NEEDLES) assert.ok(!all.includes(needle), `the answer and its files hold ${needle.slice(0, 12)}...`);
    assert.ok(parsed.values_withheld.count >= 3, JSON.stringify(parsed.values_withheld.by_reason));
    assert.equal(parsed.events[0].user, "alice@example.org", "a user name is personal data and stays");
    assert.match(parsed.sensitive_output.personal_data, /user names, addresses/);

    const outside = refused(await tool(SIGNIN, cwd, { path: `work/ev/${JWT}.json`, write_values: true }));
    assert.match(outside.error, /write_values is refused outside a job/);
    const sealed = body(await asJob(SIGNIN, cwd, { path: `work/ev/${JWT}.json`, write_values: true }, {}, "out", "jsealed"));
    const file = join(cwd, "out", "signin-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const values = await readFile(file, "utf8");
    assert.ok(values.includes(PASSWORD) && values.includes(JWT));
    assert.ok(sealed.secret_values.written >= 3);
    const second = refused(await asJob(SIGNIN, cwd, { path: `work/ev/${JWT}.json`, write_values: true }, {}, "out", "jsealed"));
    assert.match(second.error, /the values file already exists/);
    assert.equal(await readFile(file, "utf8"), values);
  });
});

test("an out_file is never replaced by a smaller result, a job writes only under $OUT, and the whole is paged past limit", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/s.json", graph(signIn(1, "2026-02-14T09:00:00Z", 0), signIn(2, "2026-02-14T09:05:00Z", 50126)));
    body(await tool(SIGNIN, cwd, { path: "work/ev/s.json", out_file: "work/s1/events.jsonl" }));
    const kept = await readFile(join(cwd, "work/s1/events.jsonl"), "utf8");
    const second = body(await tool(SIGNIN, cwd, { path: "work/ev/s.json", out_file: "work/s1/events.jsonl", user: "nobody" }));
    assert.equal(await readFile(join(cwd, "work/s1/events.jsonl"), "utf8"), kept);
    assert.equal(second.complete_events, "work/s1/events.2.jsonl");
    const refusedOut = refused(await asJob(SIGNIN, cwd, { path: "work/ev/s.json", out_file: "work/events.jsonl" }));
    assert.match(refusedOut.error, /not under this job's output directory/);
    const paged = body(await asJob(SIGNIN, cwd, { path: "work/ev/s.json", limit: 1 }, {}, "out2"));
    assert.match(paged.pages.events.all_results, /^store\/jobs\/j\d+\/out\/tool-output\/signin_analyse-[0-9a-f]{16}\.jsonl$/);
    assert.equal((await rowsOf(cwd, paged, "events", "out2")).length, 2);
    assert.deepEqual(await filesUnder(join(cwd, "work", "ev")), ["s.json"]);
  });
});

test("a path that is a directory, a missing path and an unsupported file are JSON errors with counts", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/x.json", JSON.stringify({ not: "a sign-in export" }));
    const dir = refused(await tool(SIGNIN, cwd, { path: "work/ev" }));
    assert.match(dir.error, /regular file/);
    const missing = refused(await tool(SIGNIN, cwd, { path: "work/ev/none.json" }));
    assert.match(missing.error, /no such file/);
    const bad = refused(await tool(SIGNIN, cwd, { path: "work/ev/x.json" }));
    assert.equal(bad.status, "failed");
    assert.equal(bad.coverage.records_rejected, 1);
    assert.match(bad.file_problems.join(" "), /not a sign-in record: none of a user, a time, an address or a result/);
  });
});

test("a lone surrogate in a user name and a time outside the range of a 64-bit nanosecond count do not stop the run", async () => {
  await withDir(async (cwd) => {
    const text = graph(signIn(1, "2026-02-14T09:00:00Z", 0), signIn(2, "9999-12-31T23:59:59Z", 0)).replaceAll("alice@example.org", "al\\ud800ice@example.org");
    const out = await run(cwd, "s.json", text);
    assert.equal(out.event_count, 2);
    assert.deepEqual(out.events.map((e: Json) => e.time_status), ["zoned", "unparseable"]);
    assert.equal(out.accounts, 1);
    assert.match(JSON.stringify(out.events[0].user), /al.ud800ice@example.org/);
  });
});


// ---- review of #111 ---------------------------------------------------------------------------------------------------------------------------------

test("an Interrupted portal row keeps the code it carries and is null, not a failure: a multi-factor flow of three prompts and a success is no burst", async () => {
  await withDir(async (cwd) => {
    const csv = portalCsv(
      portalRow(1, "2026-02-14T09:00:00Z", "Interrupted", "50074"), portalRow(2, "2026-02-14T09:00:10Z", "Interrupted", "50074"),
      portalRow(3, "2026-02-14T09:00:20Z", "Interrupted", "50076"), portalRow(4, "2026-02-14T09:00:40Z", "Success", "0"),
    );
    const out = await run(cwd, "mfa.csv", csv);
    assert.deepEqual([out.successes, out.failures, out.interrupts, out.unknown_outcome], [1, 0, 3, 0]);
    assert.deepEqual(out.events.map((e: Json) => [e.success, e.outcome_class ?? null, e.result_code]), [[null, "interrupt", "50074"], [null, "interrupt", "50074"], [null, "interrupt", "50076"], [true, null, "0"]]);
    assert.match(out.events[0].outcome_basis, /Status says Interrupted/);
    assert.deepEqual(out.failure_bursts_before_success, []);
    assert.deepEqual(out.prompts_before_success, [], "three prompts are below the default of five");
    const fatigue = await run(cwd, "mfa.csv", csv, { prompt_min_count: 3 });
    assert.equal(fatigue.prompts_before_success.length, 1);
    assert.deepEqual([fatigue.prompts_before_success[0].prompts_before, fatigue.prompts_before_success[0].prompt_codes], [3, { 50074: 2, 50076: 1 }]);
    assert.match(fatigue.prompts_before_success[0].why, /not a conclusion/);
  });
});

test("in Graph JSON, which has no Interrupted status, the codes of a sign-in flow's prompts are interrupts and any other code is a failure", async () => {
  await withDir(async (cwd) => {
    const prompts = [50074, 50076, 50079, 50125, 50140, 50158];
    const rows = [...prompts.map((code, i) => signIn(i, `2026-02-14T09:00:0${i}Z`, code)), signIn(10, "2026-02-14T09:00:10Z", 50126), signIn(11, "2026-02-14T09:00:11Z", 0)];
    const out = await run(cwd, "g.json", graph(...rows));
    assert.deepEqual(out.events.map((e: Json) => e.success), [null, null, null, null, null, null, false, true]);
    assert.deepEqual([out.interrupts, out.failures, out.successes], [6, 1, 1]);
    assert.deepEqual(out.failure_bursts_before_success, [], "one real failure is not a burst, and the prompts are not failures");
    const three = await run(cwd, "g3.json", graph(signIn(1, "2026-02-14T09:00:00Z", 50074), signIn(2, "2026-02-14T09:00:01Z", 50074), signIn(3, "2026-02-14T09:00:02Z", 50074), signIn(4, "2026-02-14T09:00:03Z", 0)));
    assert.deepEqual(three.failure_bursts_before_success, []);
  });
});

test("an account is its object id, else its lower-cased user name, and never a display name: two people called Alice are two accounts, one person's case variants are one", async () => {
  await withDir(async (cwd) => {
    const two = portalCsv(
      portalRow(1, "2026-02-14T09:00:00Z", "Success", "0", { Username: "alice@example.org", Location: "Istanbul, Istanbul, TR" }),
      portalRow(2, "2026-02-14T09:10:00Z", "Success", "0", { Username: "alice@contoso.org", Location: "Berlin, Berlin, DE", "IP address": "203.0.113.9" }),
    );
    const apart = await run(cwd, "two.csv", two);
    assert.equal(apart.accounts, 2);
    assert.deepEqual(apart.impossible_travel, [], "two accounts that share a display name are not one account moving");
    assert.deepEqual(apart.events.map((e: Json) => [e.user, e.user_display_name]), [["alice@example.org", undefined], ["alice@contoso.org", undefined]].map(([u]) => [u, "Alice"]));
    const same = portalCsv(
      portalRow(1, "2026-02-14T09:00:00Z", "Success", "0", { Username: "Alice@Example.org" }),
      portalRow(2, "2026-02-14T09:10:00Z", "Success", "0", { Username: "alice@example.org" }),
    );
    assert.equal((await run(cwd, "same.csv", same)).accounts, 1);
    // With an object id the id is the key: one id under two user names (a rename) is one account.
    const renamed = graph(signIn(1, "2026-02-14T09:00:00Z", 0, { userPrincipalName: "old@example.org", userId: "id-9" }), signIn(2, "2026-02-14T09:10:00Z", 0, { userPrincipalName: "new@example.org", userId: "id-9" }));
    assert.equal((await run(cwd, "ren.json", renamed)).accounts, 1);
  });
});

test("the user filter reads the user name and the display name as printed; a user name is not hidden behind the display name", async () => {
  await withDir(async (cwd) => {
    const csv = portalCsv(
      portalRow(1, "2026-02-14T09:00:00Z", "Success", "0", { User: "Alice Example", Username: "alice@example.org" }),
      portalRow(2, "2026-02-14T09:01:00Z", "Success", "0", { User: "Bob Builder", Username: "bob@example.org" }),
    );
    const byName = await run(cwd, "f.csv", csv, { user: "^alice@" });
    assert.deepEqual(byName.events.map((e: Json) => e.user), ["alice@example.org"]);
    assert.equal(byName.coverage.events_filtered_out, 1);
    const byDisplay = await run(cwd, "f.csv", csv, { user: "^Bob B" });
    assert.deepEqual(byDisplay.events.map((e: Json) => e.user), ["bob@example.org"]);
  });
});

test("a portal Location is City, State, Country: a move between two cities of one country is no travel, and a change of country is coarse travel with both countries named", async () => {
  await withDir(async (cwd) => {
    const cities = portalCsv(
      portalRow(1, "2026-02-14T09:00:00Z", "Success", "0", { Location: "Istanbul, Istanbul, TR" }),
      portalRow(2, "2026-02-14T09:20:00Z", "Success", "0", { Location: "Ankara, Ankara, TR", "IP address": "198.51.100.2" }),
    );
    assert.deepEqual((await run(cwd, "c.csv", cities)).impossible_travel, []);
    const countries = portalCsv(
      portalRow(1, "2026-02-14T09:00:00Z", "Success", "0", { Location: "Istanbul, Istanbul, TR" }),
      portalRow(2, "2026-02-14T09:20:00Z", "Success", "0", { Location: "Berlin, Berlin, DE", "IP address": "203.0.113.9" }),
    );
    const out = await run(cwd, "k.csv", countries);
    assert.equal(out.impossible_travel.length, 1);
    const t = out.impossible_travel[0];
    assert.deepEqual([t.coarse, t.from.country, t.to.country, t.from.city, t.to.city], [true, "TR", "DE", "Istanbul", "Berlin"]);
    assert.equal(t.implied_speed_kmh, undefined);
  });
});

test("slash dates in a Date (UTC) column are as ambiguous as anywhere: refused without a date order, read with one, and proved by the file's own unambiguous row", async () => {
  await withDir(async (cwd) => {
    const ambiguous = portalCsv(portalRow(1, "03/04/2026 09:00:00", "Success", "0"));
    await put(cwd, "work/ev/p.csv", ambiguous);
    const refusal = refused(await tool(SIGNIN, cwd, { path: "work/ev/p.csv" }));
    assert.match(refusal.error, /day\/month\/year time whose two leading fields are both 12 or less.*Say which with date_order/);
    const declared = body(await tool(SIGNIN, cwd, { path: "work/ev/p.csv", date_order: "dmy" }));
    assert.deepEqual([declared.events[0].time_utc, declared.events[0].time_status], ["2026-04-03T09:00:00Z", "assumed_utc"]);
    assert.ok(declared.assumptions.some((a: string) => /Date \(UTC\)/.test(a)) && declared.assumptions.some((a: string) => /read as dmy \(declared\)/.test(a)));
    const proved = await run(cwd, "q.csv", portalCsv(portalRow(1, "03/04/2026 09:00:00", "Success", "0"), portalRow(2, "13/04/2026 09:00:00", "Success", "0")));
    assert.deepEqual(proved.events.map((e: Json) => e.time_utc), ["2026-04-03T09:00:00Z", "2026-04-13T09:00:00Z"]);
    assert.ok(proved.assumptions.some((a: string) => /detected from 1 unambiguous strings and none that contradict it/.test(a)));
  });
});

test("a format the caller names that the content contradicts is refused, and one it agrees with says so", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/p.csv", portalCsv(portalRow(1, "2026-02-14T09:00:00Z", "Success", "0")));
    await put(cwd, "work/ev/g.json", graph(signIn(1, "2026-02-14T09:00:00Z", 0)));
    assert.match(refused(await tool(SIGNIN, cwd, { path: "work/ev/p.csv", format: "json" })).error, /format json was asked for, and the content of .* reads as csv/);
    assert.match(refused(await tool(SIGNIN, cwd, { path: "work/ev/g.json", format: "csv" })).error, /format csv was asked for, and the content of .* reads as json/);
    const agreed = body(await tool(SIGNIN, cwd, { path: "work/ev/g.json", format: "json" }));
    const census = await rowsOf(cwd, agreed, "file_census");
    assert.equal(census[0].format_basis, "the format argument, and the content agrees");
  });
});

test("an id a lead cites is withheld when it is shaped like a credential, and the lead still says where the event is", async () => {
  await withDir(async (cwd) => {
    const rows = [1, 2, 3].map((i) => signIn(i, `2026-02-14T09:0${i}:00Z`, 50126, { id: `${JWT}.${i}`, correlationId: `password=Hunter2-${i}` }));
    rows.push(signIn(4, "2026-02-14T09:04:00Z", 0, { id: `${JWT}.4` }));
    const out = await run(cwd, "g.json", graph(...rows));
    assert.equal(out.failure_bursts_before_success.length, 1);
    const text = JSON.stringify([out.failure_bursts_before_success, out.pages.burst_members]);
    assert.ok(!text.includes(JWT.slice(20, 60)), "a burst's references hold no raw id");
    assert.ok(!text.includes("Hunter2-"));
    const members = await rowsOf(cwd, out, "burst_members");
    assert.deepEqual(members.map((m: Json) => [m.role, m.record]).slice(0, 2), [["failure", 1], ["failure", 2]]);
    assert.ok(members.every((m: Json) => !/withheld[^\]]*\] a value assigned/.test(JSON.stringify(m))), "a marker is not scrubbed a second time");
  });
});

test("every failure of a burst is listed: ten inline with their total, all of them in burst_members", async () => {
  await withDir(async (cwd) => {
    const rows = Array.from({ length: 25 }, (_, i) => signIn(i, `2026-02-14T09:${String(10 + Math.floor(i / 6)).padStart(2, "0")}:${String((i % 6) * 9).padStart(2, "0")}Z`, 50126));
    rows.push(signIn(99, "2026-02-14T09:20:00Z", 0));
    const out = await run(cwd, "g.json", graph(...rows));
    const burst = out.failure_bursts_before_success[0];
    assert.deepEqual([burst.failures_before, burst.failure_events.length, burst.failure_events_total], [25, 10, 25]);
    assert.match(burst.failure_events_listed_in, /pages\.burst_members \(burst 1\)/);
    const members = await rowsOf(cwd, out, "burst_members");
    assert.deepEqual([members.length, members.filter((m: Json) => m.role === "failure").length, members.filter((m: Json) => m.role === "success").length], [26, 25, 1]);
  });
});

test("two successes at one recorded second in two far places are listed with no speed, and a pair a second apart has one", async () => {
  await withDir(async (cwd) => {
    const geo = (lat: number, lon: number): Json => ({ location: { city: "x", countryOrRegion: "XX", geoCoordinates: { latitude: lat, longitude: lon } } });
    const same = await run(cwd, "s.json", graph(signIn(1, "2026-02-14T09:00:00Z", 0, geo(41.0, 29.0)), signIn(2, "2026-02-14T09:00:00Z", 0, { ...geo(52.5, 13.4), ipAddress: "192.0.2.9" })));
    assert.equal(same.impossible_travel.length, 1);
    const t = same.impossible_travel[0];
    assert.deepEqual([t.seconds_apart, t.implied_speed_kmh, t.coarse], [0, null, false]);
    assert.match(t.why, /same recorded second/);
    const apart = await run(cwd, "a.json", graph(signIn(1, "2026-02-14T09:00:00Z", 0, geo(41.0, 29.0)), signIn(2, "2026-02-14T09:00:01Z", 0, { ...geo(52.5, 13.4), ipAddress: "192.0.2.9" })));
    assert.ok(apart.impossible_travel[0].implied_speed_kmh > 900);
  });
});

test("a Google activity of another application is rejected, named, and the read is partial; Login success and Login failure are alike in a flat CSV", async () => {
  await withDir(async (cwd) => {
    const activity = (id: string, app: string, name: string): Json => ({ id: { time: "2026-02-14T09:00:00Z", uniqueQualifier: id, applicationName: app, customerId: "C1" }, actor: { email: "a@example.org" }, ipAddress: "198.51.100.1", events: [{ type: app, name }] });
    const out = await run(cwd, "g.json", JSON.stringify({ kind: "admin#reports#activities", items: [activity("1", "drive", "view"), activity("2", "login", "login_success")] }));
    assert.deepEqual([out.status, out.event_count, out.coverage.records_rejected], ["partial", 1, 1]);
    assert.match(out.file_problems.join(" "), /a Workspace activity of the application drive, not a login activity/);
    const cells = (name: string, at: string): string[] => [at, "a@example.org", "198.51.100.1", name];
    const flat = [csvLine(["Date", "User", "IP address", "Event name"]), ...[0, 1, 2].map((i) => csvLine(cells("Login failure", `2026-02-14T09:0${i}:00Z`))), csvLine(cells("Login success", "2026-02-14T09:03:00Z"))].join("\r\n") + "\r\n";
    const csv = await run(cwd, "f.csv", flat);
    assert.deepEqual([csv.successes, csv.failures, csv.failure_bursts_before_success.length], [1, 3, 1]);
  });
});

test("an event with no time that could be decoded is counted, kept, left out of the bursts and the travel, and the read is partial", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, "g.json", graph(signIn(1, "2026-02-14T09:00:00Z", 0), signIn(2, "not a time", 0), signIn(3, "2026-02-14T09:02:00Z", 0)), { assume_utc: true });
    assert.equal(out.event_count, 3);
    assert.equal(out.coverage.events_without_a_decoded_time, 1);
    assert.equal(out.status, "partial");
    assert.match(out.file_problems.join(" "), /1 event\(s\) have a time that could not be decoded/);
  });
});

test("a service principal has its own account name, an archive is named and not read, and the file is read from its content when its name lies", async () => {
  await withDir(async (cwd) => {
    const rows = [1, 2, 3].map((i) => ({ id: `sp-${i}`, createdDateTime: `2026-02-14T09:0${i}:00Z`, userPrincipalName: null, userId: null, servicePrincipalName: "build-agent", servicePrincipalId: "sp-guid-1", appDisplayName: "Build", ipAddress: "198.51.100.1", status: { errorCode: 7000215 } }));
    rows.push({ id: "sp-4", createdDateTime: "2026-02-14T09:04:00Z", userPrincipalName: null, userId: null, servicePrincipalName: "build-agent", servicePrincipalId: "sp-guid-1", appDisplayName: "Build", ipAddress: "198.51.100.1", status: { errorCode: 0 } });
    const out = await run(cwd, "sp.json", JSON.stringify({ value: rows }));
    assert.equal(out.coverage.events_without_user, 0);
    assert.equal(out.accounts, 1);
    assert.equal(out.failure_bursts_before_success.length, 1);
    assert.match(out.failure_bursts_before_success[0].user, /service principal build-agent/);
    await put(cwd, "work/ev/logs.zip", Buffer.concat([Buffer.from("PK\x03\x04", "latin1"), Buffer.alloc(60, 0)]));
    const zip = refused(await tool(SIGNIN, cwd, { path: "work/ev/logs.zip" }));
    assert.equal(zip.status, "failed");
    assert.match(JSON.stringify(zip), /ZIP|zip/);
  });
});


test("the nil object id is no id: two people whose records carry it are two accounts", async () => {
  await withDir(async (cwd) => {
    const nil = "00000000-0000-0000-0000-000000000000";
    const out = await run(cwd, "g.json", graph(signIn(1, "2026-02-14T09:00:00Z", 0, { userId: nil, userPrincipalName: "a@example.org" }), signIn(2, "2026-02-14T09:01:00Z", 0, { userId: nil, userPrincipalName: "b@example.org" })));
    assert.equal(out.accounts, 2);
  });
});
