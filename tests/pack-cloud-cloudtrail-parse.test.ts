/**
 * The cloud pack: cloudtrail_parse, against CloudTrail's documented record layout (userIdentity with its sessionContext,
 * requestParameters, responseElements, additionalEventData, the lookup-events envelope, digest files).
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 *
 * Secrets: the tool withholds a value that is named or shaped like a credential in every channel and writes the originals
 * only to a sealed values file in a job (the secret-safe pattern of recovery_key_scan, docs/packs.md).
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { ALICE, TRAIL, assumedResponse, asJob, body, ct, everythingBut, exists, filesUnder, gz, lines, put, refused, rowsOf, session, tool, trail, withDir } from "./cloud-pack-harness.ts";
import type { Ev, Json } from "./cloud-pack-harness.ts";

const ROLE = "arn:aws:iam::111122223333:role/Admin";
const SESSION_ARN = "arn:aws:sts::111122223333:assumed-role/Admin/alice-session";
const MALLORY = { ...ALICE, arn: "arn:aws:iam::999988887777:user/mallory", userName: "mallory", accessKeyId: "AKIAEXAMPLEMALLORY" };

const failedAssume = (over: Ev = {}): Ev =>
  ct({ eventID: "fail-1", eventTime: "2026-02-14T09:03:00Z", userIdentity: MALLORY, requestParameters: { roleArn: ROLE, roleSessionName: "alice-session" }, responseElements: null, errorCode: "AccessDenied", errorMessage: "not authorized to perform: sts:AssumeRole", ...over });
const goodAssume = (over: Ev = {}): Ev =>
  ct({ eventID: "good-1", eventTime: "2026-02-14T09:00:00Z", userIdentity: ALICE, requestParameters: { roleArn: ROLE, roleSessionName: "alice-session" }, responseElements: assumedResponse("ASIAEXAMPLESESSION", SESSION_ARN), ...over });
const action = (over: Ev = {}): Ev =>
  ct({ eventID: "act-1", eventTime: "2026-02-14T09:05:00Z", eventSource: "iam.amazonaws.com", eventName: "CreateAccessKey", userIdentity: session(SESSION_ARN, "ASIAEXAMPLESESSION", "2026-02-14T09:00:01Z"), requestParameters: { userName: "bob" }, ...over });

async function run(cwd: string, files: Record<string, string | Buffer>, args: Json = {}): Promise<Json> {
  for (const [name, text] of Object.entries(files)) await put(cwd, `work/ev/${name}`, text);
  return body(await tool(TRAIL, cwd, { path: "work/ev", ...args }));
}

const origin = (out: Json, id: string): Json => out.records.find((r: Json) => r.event_id === id)?.session_origin;

// ---- role attribution ------------------------------------------------------------------------------------------------

test("a session is linked to the successful AssumeRole that returned it, and a failed call for the same role and session name is never chosen", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "a.json": trail(failedAssume(), goodAssume(), action()) });
    const link = origin(out, "act-1");
    assert.equal(link.label, "candidate", "a link is a candidate, never attribution");
    assert.equal(link.source_event_id, "good-1");
    assert.equal(link.basis, "access_key_id_returned_by_the_call");
    assert.equal(link.caller.user_name, "alice");
    assert.equal(link.session_arn_agrees, true);
    assert.ok(!JSON.stringify(link).includes("fail-1"), "the failed call is not named as a source");
    assert.equal(out.session_links.assume_calls_indexed, 1);
    assert.equal(out.session_links.assume_calls_with_an_error_not_indexed, 1);
    // The old fields claimed an attribution; they are gone.
    assert.equal(out.records.some((r: Json) => "role_assumed_by" in r || "assume_role_event_id" in r), false);
  });
});

test("a session whose only AssumeRole failed has no source in the records, and the answer says so", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "a.json": trail(failedAssume(), action()) });
    assert.equal(origin(out, "act-1").label, "not_found");
    assert.match(origin(out, "act-1").reason, /no successful AssumeRole-family call/);
  });
});

test("two successful calls that could have issued a session are named and none is chosen, until the session's creationDate separates them", async () => {
  await withDir(async (cwd) => {
    const second = goodAssume({ eventID: "good-2", eventTime: "2026-02-14T09:30:00Z", responseElements: assumedResponse("ASIAEXAMPLESECOND", SESSION_ARN) });
    // The use carries the session ARN and no access key id.
    const noKey = (created?: string): Ev => {
      const id = session(SESSION_ARN, undefined, created ?? "");
      if (!created) delete (id.sessionContext as Json).attributes;
      return action({ eventTime: "2026-02-14T10:00:00Z", userIdentity: id });
    };
    const ambiguous = await run(cwd, { "a.json": trail(goodAssume(), second, noKey()) });
    const link = origin(ambiguous, "act-1");
    assert.equal(link.label, "unresolved");
    assert.deepEqual(link.candidates.map((c: Json) => c.source_event_id).sort(), ["good-1", "good-2"]);
    assert.equal(link.candidate_count, 2);
    assert.equal("source_event_id" in link, false, "none is chosen");
    // creationDate 09:30:02 is within five seconds of the second call only.
    const narrowed = await run(cwd, { "a.json": trail(goodAssume(), second, noKey("2026-02-14T09:30:02Z")) });
    const one = origin(narrowed, "act-1");
    assert.equal(one.label, "candidate");
    assert.equal(one.source_event_id, "good-2");
    assert.equal(one.basis, "session_arn_returned_by_the_call_and_session_creationDate");
    // A creationDate that matches none of them is not_found (the calls outside the window are listed), never the nearest.
    const none = await run(cwd, { "a.json": trail(goodAssume(), second, noKey("2026-02-14T09:15:00Z")) });
    assert.equal(origin(none, "act-1").label, "not_found");
    assert.match(origin(none, "act-1").reason, /none was logged within 5 seconds/);
    assert.deepEqual(origin(none, "act-1").calls_outside_the_window.sort(), ["good-1", "good-2"]);
  });
});

test("an AssumeRole logged after the use cannot have issued the session", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "a.json": trail(action(), goodAssume({ eventTime: "2026-02-14T10:00:00Z" })) });
    assert.equal(origin(out, "act-1").label, "not_found");
  });
});

test("in another partition, and with a role path, the session ARN is derived in the role's own partition and never as arn:aws", async () => {
  await withDir(async (cwd) => {
    const gov = "arn:aws-us-gov:sts::111122223333:assumed-role/Admin/s1";
    const caller = { type: "IAMUser", principalId: "AIDAGOV", arn: "arn:aws-us-gov:iam::999988887777:user/carol", accountId: "999988887777", userName: "carol" };
    const assume = ct({ eventID: "gov-assume", userIdentity: caller, requestParameters: { roleArn: "arn:aws-us-gov:iam::111122223333:role/ops/team/Admin", roleSessionName: "s1" }, responseElements: null });
    const use = ct({ eventID: "gov-use", eventTime: "2026-02-14T09:05:00Z", eventSource: "s3.amazonaws.com", eventName: "ListBuckets", userIdentity: session(gov, undefined, "2026-02-14T09:00:00Z", "arn:aws-us-gov:iam::111122223333:role/ops/team/Admin") });
    const out = await run(cwd, { "a.json": trail(assume, use) });
    const link = origin(out, "gov-use");
    assert.equal(link.label, "candidate");
    assert.equal(link.basis, "session_arn_derived_from_the_request_and_session_creationDate");
    assert.equal(link.source_event_id, "gov-assume");
    assert.ok(!JSON.stringify(out).includes("arn:aws:"), "no arn:aws: reconstruction in the commercial partition's form");
  });
});

// ---- coverage: nothing is skipped quietly ------------------------------------------------------------------------------

test("a JSON Lines file with one broken line is partial: the line is rejected, located and listed, and the other lines are read", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "x.jsonl": lines(JSON.stringify(ct({ eventID: "l-1" })), "{this is not json", JSON.stringify(ct({ eventID: "l-3" }))) });
    assert.equal(out.status, "partial");
    assert.equal(out.coverage.records_read, 2);
    assert.equal(out.coverage.records_rejected, 1);
    assert.equal(out.unreadable_files, 0, "the file was read; one line of it was not");
    const rejected = await rowsOf(cwd, out, "rejected_records");
    assert.equal(rejected.length, 1);
    assert.equal(rejected[0].line, 2);
    assert.equal(rejected[0].record, 2);
    assert.match(rejected[0].reason, /malformed JSON/);
    assert.match(out.file_problems.join("\n"), /x\.jsonl.*record 2 at line 2/);
  });
});

test("a record that is not an event, a file that is not CloudTrail, an empty file and a digest file are each counted and named", async () => {
  await withDir(async (cwd) => {
    const digest = { awsAccountId: "111122223333", digestStartTime: "2026-02-14T08:00:00Z", digestEndTime: "2026-02-14T09:00:00Z", digestPublicKeyFingerprint: "abcdef", logFiles: [] };
    const out = await run(cwd, {
      "good.json": trail(ct({ eventID: "g-1" }), { hello: "world" }),
      "other.json": JSON.stringify({ unrelated: true, list: [1, 2, 3] }),
      "empty.json": "",
      "d_Digest.json": JSON.stringify(digest),
    });
    assert.equal(out.status, "partial");
    assert.equal(out.coverage.files_found, 4);
    assert.equal(out.coverage.files_read, 0, "no file is complete: each has something left over");
    assert.deepEqual([out.coverage.files_partial, out.coverage.files_unsupported, out.coverage.files_empty, out.coverage.files_digest], [1, 1, 1, 1]);
    assert.equal(out.coverage.records_read, 1);
    assert.deepEqual(out.digest_files.map((f: string) => f.split("/").pop()), ["d_Digest.json"]);
    assert.equal(out.integrity.digest_chain_validated, false);
    assert.match(out.integrity.note, /No integrity validation/);
    const census = await rowsOf(cwd, out, "file_census");
    assert.deepEqual(census.map((c: Json) => c.status).sort(), ["digest", "empty", "partial", "unsupported"]);
  });
});

test("a digest file next to complete logs is named and not validated, and does not make the read partial", async () => {
  await withDir(async (cwd) => {
    const digest = { awsAccountId: "111122223333", digestStartTime: "2026-02-14T08:00:00Z", digestEndTime: "2026-02-14T09:00:00Z", digestPublicKeyFingerprint: "abcdef", logFiles: [] };
    const out = await run(cwd, { "a.json": trail(ct({ eventID: "g-1" })), "z_Digest.json": JSON.stringify(digest) });
    assert.equal(out.status, "complete");
    assert.deepEqual(out.digest_files.map((f: string) => f.split("/").pop()), ["z_Digest.json"]);
    assert.deepEqual([out.integrity.digest_chain_validated, out.integrity.performed, out.integrity.digest_files_seen], [false, false, 1]);
  });
});

test("a file of nothing but unsupported content is an error answer with the counts, not an empty result", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/not.json", JSON.stringify({ x: 1 }));
    const out = refused(await tool(TRAIL, cwd, { path: "work/ev/not.json" }));
    assert.equal(out.status, "failed");
    assert.equal(out.coverage.files_unsupported, 1);
    assert.match(out.error, /no CloudTrail event could be read/);
  });
});

test("a gzip that ends early is a named partial file with what it held before the break", async () => {
  await withDir(async (cwd) => {
    const many = lines(...Array.from({ length: 30000 }, (_, i) => JSON.stringify(ct({ eventID: `bulk-${i}`, requestParameters: { n: i, padding: `${i}`.repeat(8) } }))));
    const whole = gz(many);
    await put(cwd, "work/ev/cut.json.gz", whole.subarray(0, Math.floor(whole.length * 0.6)));
    const out = await run(cwd, {});
    assert.equal(out.status, "partial");
    assert.equal(out.coverage.files_partial, 1);
    assert.ok(out.coverage.records_read > 0 && out.coverage.records_read < 30000, `kept what was read: ${out.coverage.records_read}`);
    assert.match(out.file_problems.join("\n"), /cut\.json\.gz.*compressed stream/);
  });
});

test("expansion past max_expanded_bytes stops the file, says so, and keeps what was read", async () => {
  await withDir(async (cwd) => {
    const many = lines(...Array.from({ length: 4000 }, (_, i) => JSON.stringify(ct({ eventID: `cap-${i}` }))));
    await put(cwd, "work/ev/big.json.gz", gz(many));
    const out = await run(cwd, {}, { max_expanded_bytes: 100000 });
    assert.equal(out.status, "partial");
    assert.match(out.file_problems.join("\n"), /max_expanded_bytes \(100000\)/);
    assert.ok(out.coverage.records_read > 0 && out.coverage.records_read < 4000);
    assert.ok(out.coverage.bytes_read <= 100000);
  });
});

test("an envelope that names a next page is partial, its token is never printed, and a lookup-events entry is read through its CloudTrailEvent text", async () => {
  await withDir(async (cwd) => {
    const inner = ct({ eventID: "lookup-1", eventName: "DescribeInstances", eventSource: "ec2.amazonaws.com", userIdentity: ALICE });
    const page = { Events: [{ EventId: "lookup-1", EventName: "DescribeInstances", Username: "alice", CloudTrailEvent: JSON.stringify(inner) }, { EventId: "x" }], NextToken: "NEXTTOKENVALUE0123456789abcdef" };
    const out = await run(cwd, { "page.json": JSON.stringify(page) });
    assert.equal(out.status, "partial");
    assert.deepEqual(out.pagination_markers.map((m: Json) => m.keys), [["NextToken"]]);
    assert.equal(out.records[0].event_id, "lookup-1");
    assert.equal(out.coverage.records_rejected, 1, "the entry with no CloudTrailEvent text is rejected, not read as an event");
    assert.ok(!JSON.stringify(out).includes("NEXTTOKENVALUE0123456789abcdef"));
  });
});

test("a Records file read as a stream gives every record its file, record number and line, and a time kept raw beside its decoding", async () => {
  await withDir(async (cwd) => {
    const body_ = "{\n  \"Records\": [\n" + [1, 2, 3].map((i) => "    " + JSON.stringify(ct({ eventID: `s-${i}`, eventTime: i === 3 ? "2026-02-14T09:00:00.1234567Z" : "2026-02-14T09:00:0" + i + "Z" }))).join(",\n") + "\n  ]\n}\n";
    const out = await run(cwd, { "pretty.json": body_ });
    assert.deepEqual(out.records.map((r: Json) => [r.event_id, r.record, r.line]), [["s-1", 1, 3], ["s-2", 2, 4], ["s-3", 3, 5]]);
    assert.equal(out.records[2].time, "2026-02-14T09:00:00.1234567Z");
    assert.equal(out.records[2].time_utc, "2026-02-14T09:00:00.1234567Z", "the fractions are kept");
    assert.equal(out.records[0].parser, "cloudtrail_parse/4");
    assert.equal(out.first_event, "2026-02-14T09:00:00.1234567Z");
    assert.equal(out.last_event, "2026-02-14T09:00:02Z");
  });
});

// ---- what the records carry ---------------------------------------------------------------------------------------------

test("the access key id, source identity, response, additional event data (MFAUsed), shared event id and recipient account are kept", async () => {
  await withDir(async (cwd) => {
    const identity = session("arn:aws:sts::111122223333:assumed-role/Admin/web", "ASIAEXAMPLEWEB", "2026-02-14T09:00:00Z");
    (identity.sessionContext as Json).sourceIdentity = "alice@example.org";
    const login = ct({ eventID: "login-1", eventSource: "signin.amazonaws.com", eventName: "ConsoleLogin", userIdentity: identity, sharedEventID: "shared-1", responseElements: { ConsoleLogin: "Success" }, additionalEventData: { MFAUsed: "No", LoginTo: "https://console.aws.amazon.com/console/home" } });
    const out = await run(cwd, { "a.json": trail(login) });
    const r = out.records[0];
    assert.equal(r.access_key_id, "ASIAEXAMPLEWEB");
    assert.equal(r.source_identity, "alice@example.org");
    assert.equal(r.mfa_used, "No");
    assert.equal(r.additional.MFAUsed, "No");
    assert.equal(r.response.ConsoleLogin, "Success");
    assert.equal(r.console_login, "Success");
    assert.equal(r.shared_event_id, "shared-1");
    assert.equal(r.recipient_account, "111122223333");
    assert.equal(r.user_identity.sessionContext.attributes.creationDate, "2026-02-14T09:00:00Z");
  });
});

test("an error code is classified by its name: only authorisation denials are refusals, throttling and validation are not, and a failed console login is an error too", async () => {
  await withDir(async (cwd) => {
    const as = (name: string, code: string, arn: string): Ev => ct({ eventID: `err-${code}`, eventName: name, userIdentity: { ...ALICE, arn }, errorCode: code, errorMessage: "x" });
    const out = await run(cwd, {
      "a.json": trail(
        as("ListUsers", "AccessDenied", "arn:aws:iam::1:user/denied"),
        as("DescribeInstances", "ThrottlingException", "arn:aws:iam::1:user/busy"),
        as("PutParameter", "ValidationException", "arn:aws:iam::1:user/typo"),
        as("GetObject", "InternalFailure", "arn:aws:iam::1:user/unlucky"),
        ct({ eventID: "login-fail", eventSource: "signin.amazonaws.com", eventName: "ConsoleLogin", userIdentity: { ...ALICE, arn: "arn:aws:iam::1:user/denied" }, responseElements: { ConsoleLogin: "Failure" }, errorMessage: "Failed authentication" }),
      ),
    });
    assert.deepEqual(out.error_classes, { authorisation_denied: 1, throttling: 1, validation: 1, service: 1, authentication: 1 });
    assert.deepEqual(out.refusals_by_identity.map((r: Json) => [r.identity, r.total]), [["arn:aws:iam::1:user/denied", 1]]);
    const busy = out.errors_by_identity.find((e: Json) => e.identity === "arn:aws:iam::1:user/busy");
    assert.deepEqual(busy.classes, { throttling: 1 });
    assert.equal(out.records.find((r: Json) => r.event_id === "login-fail").outcome, "failure_recorded_in_the_response");
    const only = await run(cwd, {}, { errors_only: true });
    assert.equal(only.record_count, 5);
  });
});

test("what the tool flags says what the API name is, and does not say what happened", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "a.json": trail(ct({ eventID: "stop", eventName: "StopLogging", eventSource: "cloudtrail.amazonaws.com", userIdentity: ALICE, requestParameters: { name: "main-trail" } })) });
    const note = out.records[0].notable;
    assert.match(note, /StopLogging call/);
    assert.doesNotMatch(note + out.note, /first hour|the gap that follows is the finding|equivalent of clearing|shape of permission enumeration|data events are not/i);
  });
});

// ---- secrets ------------------------------------------------------------------------------------------------------------

const SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const SESSION_TOKEN = "IQoJb3JpZ2luX2VjEXAMPLE" + "Zz9Yx8Wv7".repeat(20);
const JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const PASSWORD = "Hunter2-correct-horse";
const NEEDLES = [SECRET_KEY, "wJalrXUtnFEMI", SESSION_TOKEN, "Zz9Yx8Wv7Zz9Yx8Wv7", JWT, "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0", PASSWORD, "correct-horse"];

const SECRET_FILES = (): Record<string, string> => ({
  [`${JWT}.json`]: trail(
    ct({ eventID: "s-1", eventName: "CreateAccessKey", eventSource: "iam.amazonaws.com", userIdentity: ALICE, userAgent: `custom-client token=${JWT}`, requestParameters: { userName: "bob" }, responseElements: { accessKey: { accessKeyId: "AKIANEWKEYEXAMPLE", secretAccessKey: SECRET_KEY, status: "Active" } } }),
    ct({ eventID: "s-2", userIdentity: ALICE, requestParameters: { roleArn: ROLE, roleSessionName: "s", environment: { variables: { DB_PASSWORD: PASSWORD, MODE: "prod" } } }, responseElements: assumedResponse("ASIAEXAMPLESESSION", SESSION_ARN, SESSION_TOKEN) }),
    ct({ eventID: "s-3", userIdentity: ALICE, errorCode: "ValidationException", errorMessage: `bad value password=${PASSWORD}`, requestParameters: { description: `see Authorization: Bearer ${JWT}` } }),
  ),
});

test("a value named or shaped like a credential is in no row, no path, no error message and no file the answer names, and the identifiers beside it stay", async () => {
  await withDir(async (cwd) => {
    for (const [name, text] of Object.entries(SECRET_FILES())) await put(cwd, `work/ev/${name}`, text);
    const run1 = await asJob(TRAIL, cwd, { path: "work/ev", limit: 1 });
    const answer = run1.stdout;
    const parsed = body(run1);
    const all = await everythingBut(cwd, answer + run1.stderr, []);
    for (const needle of NEEDLES) assert.ok(!all.includes(needle), `the answer and its files hold ${needle.slice(0, 12)}...`);
    assert.ok(all.includes("AKIANEWKEYEXAMPLE"), "an access key id is an identifier and stays");
    assert.ok(all.includes("ASIAEXAMPLESESSION"));
    assert.ok(parsed.values_withheld.count >= 5, JSON.stringify(parsed.values_withheld.by_reason));
    assert.ok(parsed.values_withheld.by_reason["credential-named field"] >= 3);
    assert.equal(parsed.secret_values.requested, false);
    assert.match(parsed.sensitive_output.advice, /secret_output: true/);
    // The file the answer names holds the whole result, withheld the same way.
    const rows = await rowsOf(cwd, parsed, "records");
    assert.equal(rows.length, 3);
    assert.match(JSON.stringify(rows[0].response), /withheld: credential-named field, 40 characters/);
    // A path component shaped like a token is withheld from every printed path.
    assert.match(parsed.records[0].source_file, /\[withheld: a JSON Web Token/);
  });
});

test("an error message and a refused out_file never echo a name shaped like a credential", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.json", trail(ct({ eventID: "x-1" })));
    const missing = refused(await tool(TRAIL, cwd, { path: `work/ev/${JWT}-missing` }));
    assert.ok(!JSON.stringify(missing).includes(JWT));
    const bad = refused(await tool(TRAIL, cwd, { path: "work/ev", out_file: `inputs/${JWT}.jsonl` }));
    assert.ok(!JSON.stringify(bad).includes(JWT));
    assert.match(bad.error, /cannot be under inputs\//);
  });
});

test("write_values puts the originals in a mode 0600 file under $OUT, only in a job; outside a job it is refused and nothing is written; a second run in the same job is refused, not a crash", async () => {
  await withDir(async (cwd) => {
    for (const [name, text] of Object.entries(SECRET_FILES())) await put(cwd, `work/ev/${name}`, text);
    const outside = refused(await tool(TRAIL, cwd, { path: "work/ev", write_values: true }));
    assert.match(outside.error, /write_values is refused outside a job/);
    assert.equal(outside.written, false);
    assert.deepEqual(await filesUnder(join(cwd, "work", "ev")).then((f) => f.filter((n) => !n.endsWith(".json"))), []);

    const first = body(await asJob(TRAIL, cwd, { path: "work/ev", write_values: true }, {}, "out", "jsame"));
    assert.equal(first.secret_values.requested, true);
    assert.ok(first.secret_values.written >= 5);
    assert.equal(first.secret_values.contains_secret_values, true);
    const file = join(cwd, "out", "cloudtrail-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const values = await readFile(file, "utf8");
    for (const needle of [SECRET_KEY, SESSION_TOKEN, PASSWORD, JWT]) assert.ok(values.includes(needle), `the sealed file holds ${needle.slice(0, 10)}...`);
    for (const row of values.trimEnd().split("\n")) assert.ok(JSON.parse(row).finding_id.startsWith("W"));
    // The rest of what the job left is clean.
    const rest = await everythingBut(cwd, JSON.stringify(first), ["out/cloudtrail-values.jsonl"]);
    for (const needle of NEEDLES) assert.ok(!rest.includes(needle), `the job's other files hold ${needle.slice(0, 10)}...`);

    const second = refused(await asJob(TRAIL, cwd, { path: "work/ev", write_values: true }, {}, "out", "jsame"));
    assert.match(second.error, /the values file already exists/);
    assert.equal(await readFile(file, "utf8"), values, "the earlier file is untouched");
  });
});

test("with nothing withheld the values file stays an empty mode 0600 file and the answer says written: 0", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/plain.json", trail(ct({ eventID: "p-1", userIdentity: ALICE, requestParameters: { roleArn: ROLE, roleSessionName: "s" } })));
    const out = body(await asJob(TRAIL, cwd, { path: "work/ev", write_values: true }));
    assert.equal(out.secret_values.written, 0);
    assert.equal(out.secret_values.contains_secret_values, false);
    const file = join(cwd, "out", "cloudtrail-values.jsonl");
    assert.equal((await stat(file)).size, 0);
    assert.equal((await stat(file)).mode & 0o777, 0o600);
  });
});

// ---- where output goes ----------------------------------------------------------------------------------------------------

test("an out_file is never replaced by a smaller result: the earlier file is kept and this one is named beside it", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.json", trail(failedAssume(), goodAssume(), action()));
    const first = body(await tool(TRAIL, cwd, { path: "work/ev/a.json", out_file: "work/s1/records.jsonl" }));
    const kept = await readFile(join(cwd, "work/s1/records.jsonl"), "utf8");
    assert.equal(kept.trimEnd().split("\n").length, 3);
    assert.equal(first.complete_records, "work/s1/records.jsonl");
    const second = body(await tool(TRAIL, cwd, { path: "work/ev/a.json", out_file: "work/s1/records.jsonl", events: ["CreateAccessKey"] }));
    assert.equal(await readFile(join(cwd, "work/s1/records.jsonl"), "utf8"), kept, "the larger earlier result is untouched");
    assert.equal(second.complete_records, "work/s1/records.2.jsonl");
    assert.match(second.pages.records.all_results_note, /was kept/);
    // The same answer again is the file that is already there.
    const again = body(await tool(TRAIL, cwd, { path: "work/ev/a.json", out_file: "work/s1/records.jsonl" }));
    assert.equal(again.complete_records, "work/s1/records.jsonl");
    assert.ok(!(await exists(join(cwd, "work/s1/records.3.jsonl"))));
  });
});

test("in a job the whole result is under $OUT; an out_file elsewhere in the run directory is a JSON error, and the run directory is not written", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.json", trail(failedAssume(), goodAssume(), action()));
    const refusedOut = refused(await asJob(TRAIL, cwd, { path: "work/ev/a.json", out_file: "work/cloudtrail.jsonl" }));
    assert.match(refusedOut.error, /not under this job's output directory/);
    assert.equal(await exists(join(cwd, "work", "cloudtrail.jsonl")), false);
    const named = body(await asJob(TRAIL, cwd, { path: "work/ev/a.json", out_file: "out/records.jsonl" }));
    assert.match(named.complete_records, /^store\/jobs\/j\d+\/out\/records\.jsonl$/);
    assert.ok(await exists(join(cwd, "out", "records.jsonl")));
    const paged = body(await asJob(TRAIL, cwd, { path: "work/ev/a.json", limit: 1 }, {}, "out2"));
    assert.match(paged.pages.records.all_results, /^store\/jobs\/j\d+\/out\/tool-output\/cloudtrail_parse-[0-9a-f]{16}\.jsonl$/);
    assert.equal(paged.truncated, true);
    const wholeRows = await rowsOf(cwd, paged, "records", "out2");
    assert.equal(wholeRows.length, 3);
    assert.deepEqual((await filesUnder(join(cwd, "work", "ev"))), ["a.json"], "nothing was written under work/ by a job");
  });
});

test("a result larger than limit is paged losslessly in an agent's own tool-output directory, with a random file name", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "a.json": trail(...Array.from({ length: 7 }, (_, i) => ct({ eventID: `p-${i}`, userIdentity: ALICE }))) }, { limit: 3 });
    assert.equal(out.records.length, 3);
    assert.equal(out.record_count, 7);
    assert.equal(out.inline_limited, true);
    assert.match(out.pages.records.all_results, /^work\/s1\/tool-output\/cloudtrail_parse-[0-9a-f]{16}\.jsonl$/);
    assert.equal((await rowsOf(cwd, out, "records")).length, 7);
  });
});

test("a name that is not UTF-8 and a lone surrogate in a record are written as escapes, never a traceback", async () => {
  await withDir(async (cwd) => {
    // a lone surrogate arrives through a JSON escape (a backslash and u d800) in a parameter's name and in its value
    const text = '{"Records":[{"eventName":"X","eventSource":"s3.amazonaws.com","eventTime":"2026-02-14T09:00:00Z","eventID":"u-1","requestParameters":{"bad\\ud800key":"v\\udc00"}}]}';
    await put(cwd, "work/ev/surrogate.json", text);
    const out = await run(cwd, {});
    assert.equal(out.coverage.records_read, 1);
    // a file name with a byte that is not UTF-8 (the platform may refuse to create one: then only the first case runs)
    const name = Buffer.concat([Buffer.from(join(cwd, "work", "ev") + "/"), Buffer.from([0x62, 0xff, 0x2e, 0x6a, 0x73, 0x6f, 0x6e])]);
    const made = await writeFile(name, trail(ct({ eventID: "u-2" }))).then(() => true, () => false);
    if (made) {
      const again = body(await tool(TRAIL, cwd, { path: "work/ev", limit: 1 }));
      assert.equal(again.coverage.records_read, 2);
      assert.ok(await rowsOf(cwd, again, "records"), "the whole is readable");
    }
  });
});

test("a path that cannot be written is a JSON error, not a traceback", async (t) => {
  if (process.getuid?.() === 0) return t.skip("running as root: a read-only directory does not stop a write");
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.json", trail(ct({ eventID: "r-1" })));
    await mkdir(join(cwd, "work", "locked"), { recursive: true });
    await chmod(join(cwd, "work", "locked"), 0o500);
    try {
      const out = await tool(TRAIL, cwd, { path: "work/ev/a.json", out_file: "work/locked/records.jsonl" });
      assert.notEqual(out.code, 0);
      assert.doesNotMatch(out.stderr, /Traceback/);
      assert.match(JSON.parse(out.stdout).error, /could not be written|cannot be created/);
    } finally {
      await chmod(join(cwd, "work", "locked"), 0o700);
    }
  });
});

test("a large Records file is read as a stream and every record is kept", async () => {
  await withDir(async (cwd) => {
    const records = Array.from({ length: 40000 }, (_, i) => ct({ eventID: `m-${i}`, eventName: i % 2 ? "ListUsers" : "GetCallerIdentity", userIdentity: { ...ALICE, arn: `arn:aws:iam::999988887777:user/u${i % 50}` } }));
    await put(cwd, "work/ev/many.json", trail(...records));
    const out = body(await tool(TRAIL, cwd, { path: "work/ev/many.json", limit: 10 }));
    assert.equal(out.status, "complete");
    assert.equal(out.record_count, 40000);
    assert.equal(out.pages.by_identity.matched, 50, "every identity is counted; the table is paged past limit, not cut");
    assert.equal((await rowsOf(cwd, out, "by_identity")).length, 50);
    assert.equal((await rowsOf(cwd, out, "records")).length, 40000);
  });
});

test("a Records file that is empty of records is complete, and says so only about the supplied file", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "none.json": JSON.stringify({ Records: [] }) });
    assert.equal(out.status, "complete");
    assert.match(out.status_basis, /says nothing about whether the export holds everything/);
    assert.equal(out.record_count, 0);
  });
});

test("files are read in a stable order: the files of a directory by name, then its subdirectories by name", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "b.json": trail(ct({ eventID: "b" })), "a.json": trail(ct({ eventID: "a" })), "z/inner.json": trail(ct({ eventID: "z" })), "m/inner.json": trail(ct({ eventID: "m" })) });
    assert.deepEqual(out.records.map((r: Json) => r.event_id), ["a", "b", "m", "z"]);
  });
});

test("a lone surrogate in an identifier, a time far outside the range of a 64-bit nanosecond count and a record that is malformed in the middle of an array are each handled, not fatal", async () => {
  await withDir(async (cwd) => {
    // eventID and session name carry a lone surrogate (a JSON escape); the use is linked through a database that cannot store one
    const assume = JSON.stringify(goodAssume({ eventID: "SURROGATE-PLACEHOLDER" })).replace("SURROGATE-PLACEHOLDER", "id-\\ud800-x");
    const text = `{"Records":[${assume},${JSON.stringify(action())},${JSON.stringify(ct({ eventID: "far", eventTime: "9999-12-31T23:59:59Z" }))}]}`;
    const out = await run(cwd, { "a.json": text });
    assert.equal(out.coverage.records_read, 3);
    assert.equal(out.records.find((r: Json) => r.event_id === "far").time_status, "unparseable");
    assert.equal(out.records.find((r: Json) => r.event_id === "far").time_utc, undefined === null ? 0 : null, "an undecodable time is a null, present");
    assert.equal(origin(out, "act-1").label, "candidate");
    assert.equal(origin(out, "act-1").source_event_id, "id-\\ud800-x", "kept as its escape");
  });
  await withDir(async (cwd) => {
    const out = await run(cwd, { "b.json": `{"Records":[${JSON.stringify(ct({ eventID: "ok-1" }))}, {"eventName": "X" "eventSource": "y"}, ${JSON.stringify(ct({ eventID: "ok-3" }))}]}` });
    assert.equal(out.status, "partial");
    assert.deepEqual(out.records.map((r: Json) => r.event_id), ["ok-1"]);
    const rejected = await rowsOf(cwd, out, "rejected_records");
    assert.match(rejected[0].reason, /malformed JSON/, "a record that is malformed is not reported as too large");
    assert.match(out.file_problems.join(" "), /the rest was not read/);
  });
});

test("lists in the answer are bounded and counted: thirty digest files are thirty, twenty-five of them named", async () => {
  await withDir(async (cwd) => {
    const digest = { awsAccountId: "1", digestStartTime: "a", digestEndTime: "b", digestPublicKeyFingerprint: "f", logFiles: [] };
    const files: Record<string, string> = { "good.json": trail(ct({ eventID: "g" })) };
    for (let i = 0; i < 30; i++) files[`d${String(i).padStart(2, "0")}_Digest.json`] = JSON.stringify(digest);
    const out = await run(cwd, files);
    assert.equal(out.digest_file_count, 30);
    assert.equal(out.digest_files.length, 25);
    assert.equal(out.pages.file_census.matched, 31, "every file is in the census");
  });
});

test("a link left where the values file would go is refused by name, and nothing is written through it", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/plain.json", trail(ct({ eventID: "p-1", userIdentity: ALICE })));
    await mkdir(join(cwd, "out"), { recursive: true });
    await put(cwd, "elsewhere.txt", "untouched");
    await symlink(join(cwd, "elsewhere.txt"), join(cwd, "out", "cloudtrail-values.jsonl"));
    const out = refused(await asJob(TRAIL, cwd, { path: "work/ev", write_values: true }));
    assert.match(out.error, /the values file already exists/);
    assert.equal(await readFile(join(cwd, "elsewhere.txt"), "utf8"), "untouched");
    // a link that points nowhere is refused the same way (O_EXCL does not follow it)
    await rm(join(cwd, "out", "cloudtrail-values.jsonl"));
    await symlink(join(cwd, "nowhere"), join(cwd, "out", "cloudtrail-values.jsonl"));
    const dangling = refused(await asJob(TRAIL, cwd, { path: "work/ev", write_values: true }));
    assert.match(dangling.error, /the values file already exists/);
    assert.equal(await exists(join(cwd, "nowhere")), false);
  });
});

test("the time limit ends the read, keeps what was read, and names the files that were not reached", async () => {
  await withDir(async (cwd) => {
    const records = Array.from({ length: 150000 }, (_, i) => ct({ eventID: `t-${i}`, userIdentity: { ...ALICE, arn: `arn:aws:iam::999988887777:user/u${i % 30}` }, requestParameters: { n: i } }));
    await put(cwd, "work/ev/a-big.json", JSON.stringify({ Records: records }));
    await put(cwd, "work/ev/b-small.json", trail(ct({ eventID: "b-1" })));
    const out = body(await tool(TRAIL, cwd, { path: "work/ev", time_limit_seconds: 1, limit: 5 }));
    assert.equal(out.status, "partial");
    assert.equal(out.coverage.stopped_by_time_limit, true);
    assert.ok(out.coverage.records_read > 0 && out.coverage.records_read < 150000, `kept what was read: ${out.coverage.records_read}`);
    assert.equal(out.coverage.files_not_attempted, 1);
    assert.deepEqual(out.files_not_attempted_named.map((f: string) => f.split("/").pop()), ["b-small.json"]);
    assert.equal(out.session_links.index_complete, false, "the session index stopped at its share of the time and says so");
    const census = await rowsOf(cwd, out, "file_census");
    assert.equal(census[0].status, "partial");
    assert.match(census[0].problems.join(" "), /the time limit ended the read/);
  });
});

test("link_sessions: false skips the session index and says so", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "a.json": trail(goodAssume(), action()) }, { link_sessions: false });
    assert.equal(origin(out, "act-1"), undefined);
    assert.deepEqual(out.session_links, { performed: false, why: "link_sessions was false" });
  });
});

test("bytes that are not UTF-8 are replaced and counted, and the read is partial, not complete", async () => {
  await withDir(async (cwd) => {
    const text = Buffer.concat([Buffer.from('{"Records":[{"eventName":"X","eventSource":"s3.amazonaws.com","eventTime":"2026-02-14T09:00:00Z","eventID":"b-1","userAgent":"ag'), Buffer.from([0xff, 0xfe, 0xfd]), Buffer.from('ent"}]}')]);
    await put(cwd, "work/ev/bad.json", text);
    const out = await run(cwd, {});
    assert.equal(out.status, "partial");
    assert.equal(out.coverage.replacement_characters, 3);
    assert.equal(out.records[0].event_id, "b-1");
  });
});


// ---- review of #111: one call is one call, a key that disagrees disproves, and the cap is on what is listed ---------------------------------

test("one call delivered twice is one call: the same eventID in two exports, and a cross-account call logged in two accounts, are not an ambiguity", async () => {
  await withDir(async (cwd) => {
    // The same file exported twice: one eventID, two copies.
    const twice = await run(cwd, { "a.json": trail(goodAssume(), action()), "b.json": trail(goodAssume()) });
    const link = origin(twice, "act-1");
    assert.equal(link.label, "candidate", JSON.stringify(link));
    assert.equal(link.source_event_id, "good-1");
    assert.equal(link.copies_total, 1);
    assert.equal(twice.session_links.assume_calls_indexed, 2, "both copies are in the index");
  });
  await withDir(async (cwd) => {
    // A call that crosses accounts is logged in both, with two eventIDs and one sharedEventID.
    const home = goodAssume({ eventID: "x-home", sharedEventID: "shared-1", recipientAccountId: "999988887777" });
    const target = goodAssume({ eventID: "x-target", sharedEventID: "shared-1", recipientAccountId: "111122223333" });
    const out = await run(cwd, { "a.json": trail(home, target, action()) });
    const link = origin(out, "act-1");
    assert.equal(link.label, "candidate", JSON.stringify(link));
    assert.equal(link.copies_total, 1);
    assert.deepEqual([link.source_event_id, link.copies[0].event_id].sort(), ["x-home", "x-target"]);
  });
  await withDir(async (cwd) => {
    // Two different calls that share nothing are still two.
    const out = await run(cwd, { "a.json": trail(goodAssume(), goodAssume({ eventID: "good-2", eventTime: "2026-02-14T09:00:03Z", responseElements: assumedResponse("ASIAEXAMPLESECOND", SESSION_ARN) }), action({ userIdentity: session(SESSION_ARN, undefined, "") })) });
    assert.equal(origin(out, "act-1").label, "unresolved");
  });
});

test("a call that returned a different access key id did not issue the session, even when the session ARN is the same", async () => {
  await withDir(async (cwd) => {
    const other = goodAssume({ responseElements: assumedResponse("ASIAEXAMPLEOTHER00", SESSION_ARN) });
    const out = await run(cwd, { "a.json": trail(other, action()) });
    const link = origin(out, "act-1");
    assert.equal(link.label, "not_found", JSON.stringify(link));
    assert.match(link.reason, /returned a different access key id/);
    assert.ok(!JSON.stringify(link).includes("good-1") || /different access key id/.test(link.reason));
    // The same call, with the key the session carries, is the source.
    const same = await run(cwd, { "a.json": trail(goodAssume(), action()) });
    assert.equal(origin(same, "act-1").label, "candidate");
  });
});

test("sixty calls for one session ARN are sixty calls: creationDate picks the one at its time, whatever its position, and no creationDate lists them with their count", async () => {
  await withDir(async (cwd) => {
    const at = (i: number): string => new Date(Date.UTC(2026, 1, 14, 9, 0, 0) + i * 60_000).toISOString().replace(".000Z", "Z");
    const calls = Array.from({ length: 60 }, (_, i) => goodAssume({ eventID: `m-${i}`, eventTime: at(i), responseElements: assumedResponse(`ASIAEXAMPLEKEY${String(i).padStart(4, "0")}`, SESSION_ARN) }));
    const noKey = (created: string): Ev => {
      const id = session(SESSION_ARN, undefined, created);
      if (!created) delete (id.sessionContext as Json).attributes;
      return action({ eventTime: "2026-02-14T10:30:00Z", userIdentity: id });
    };
    // Call 55 is the 56th: past the 51 rows an unfiltered LIMIT would have kept.
    const narrowed = await run(cwd, { "a.json": trail(...calls, noKey(new Date(Date.UTC(2026, 1, 14, 9, 55, 2)).toISOString().replace(".000Z", "Z"))) });
    const link = origin(narrowed, "act-1");
    assert.equal(link.label, "candidate", JSON.stringify(link).slice(0, 300));
    assert.equal(link.source_event_id, "m-55");
    const blind = await run(cwd, { "a.json": trail(...calls, noKey("")) });
    const wide = origin(blind, "act-1");
    assert.equal(wide.label, "unresolved");
    assert.equal(wide.candidate_count, 60);
    assert.match(wide.reason, /60 distinct successful calls match; none was chosen \(the first 50 are listed\)/);
    assert.equal(wide.candidates.length, 50);
    assert.equal("source_event_id" in wide, false);
  });
});

// ---- review of #111: reading --------------------------------------------------------------------------------------------------------------

test("a gzip that ends early keeps every record before the break, whatever its size: a small file loses nothing it had delivered", async () => {
  await withDir(async (cwd) => {
    const records = Array.from({ length: 2500 }, (_, i) => ct({ eventID: `z-${i}`, eventSource: "s3.amazonaws.com", eventName: "GetObject", requestParameters: { key: `k-${i}-${"x".repeat(20)}` } }));
    const whole = gz(JSON.stringify({ Records: records }));
    assert.ok(whole.length < 1 << 20);
    for (const share of [0.3, 0.6, 0.9]) {
      await put(cwd, "work/ev/cut.json.gz", whole.subarray(0, Math.floor(whole.length * share)));
      const out = body(await tool(TRAIL, cwd, { path: "work/ev/cut.json.gz", link_sessions: false }));
      assert.equal(out.status, "partial");
      assert.ok(out.coverage.records_read > share * 1000, `${share}: ${out.coverage.records_read} records kept`);
      assert.match(out.file_problems.join(" "), /ends early/);
    }
    // An intact file of the same size is complete, and a gzip that expands past one read is read whole.
    await put(cwd, "work/ev/whole.json.gz", whole);
    const intact = body(await tool(TRAIL, cwd, { path: "work/ev/whole.json.gz", link_sessions: false }));
    assert.deepEqual([intact.status, intact.record_count], ["complete", 2500]);
  });
});

test("a compressible gzip is read whole: more than one read of output, a trailer, then a second member", async () => {
  await withDir(async (cwd) => {
    const first = gzipSync(Buffer.from(JSON.stringify(ct({ eventID: "m-1" })) + "\n" + "\n".repeat(3 << 20)));
    const second = gzipSync(Buffer.from(JSON.stringify(ct({ eventID: "m-2" })) + "\n"));
    await put(cwd, "work/ev/multi.jsonl.gz", Buffer.concat([first, second]));
    const out = body(await tool(TRAIL, cwd, { path: "work/ev/multi.jsonl.gz", link_sessions: false }));
    assert.deepEqual([out.status, out.record_count], ["complete", 2], JSON.stringify(out.file_problems));
  });
});

test("a hundred mebibytes of blank lines in a small gzip cost seconds, not minutes, and the limits still hold", async () => {
  await withDir(async (cwd) => {
    const zeros = Buffer.alloc(1 << 20, 10);
    const parts = [Buffer.from(JSON.stringify(ct({ eventID: "f-1" })) + "\n"), ...Array.from({ length: 100 }, () => zeros)];
    await put(cwd, "work/ev/flood.json.gz", gzipSync(Buffer.concat(parts)));
    const started = Date.now();
    const out = body(await tool(TRAIL, cwd, { path: "work/ev/flood.json.gz", time_limit_seconds: 2, link_sessions: false }));
    assert.ok(Date.now() - started < 20_000, `the flood took ${Date.now() - started} ms`);
    assert.equal(out.record_count, 1);
    assert.ok(out.coverage.stopped_by_time_limit === true || out.status === "complete");
  });
});

test("a pretty-printed export whose records follow another member is streamed, not read as one document", async () => {
  await withDir(async (cwd) => {
    const records = Array.from({ length: 5 }, (_, i) => ct({ eventID: `d-${i}`, eventSource: "s3.amazonaws.com", eventName: "GetObject" }));
    await put(cwd, "work/ev/doc.json", JSON.stringify({ meta: { pages: [1, 2, 3] }, Records: records }, null, 2));
    const out = body(await tool(TRAIL, cwd, { path: "work/ev/doc.json", link_sessions: false }));
    const census = await rowsOf(cwd, out, "file_census");
    assert.deepEqual([out.status, out.record_count, census[0].mode], ["complete", 5, "envelope"]);
    // An array of envelopes (jq -s) is read envelope by envelope.
    await put(cwd, "work/ev/slurped.json", JSON.stringify([{ Records: records.slice(0, 2) }, { Records: records.slice(2) }]));
    const slurped = body(await tool(TRAIL, cwd, { path: "work/ev/slurped.json", link_sessions: false }));
    assert.deepEqual([slurped.status, slurped.record_count], ["complete", 5], JSON.stringify(slurped.file_problems));
  });
});

test("the list of rejected records is bounded: a hundred thousand are listed, the rest are counted, and a file that is nothing but junk stops early", async () => {
  await withDir(async (cwd) => {
    const junk = "x\n".repeat(100_500);
    await put(cwd, "work/ev/a.jsonl", JSON.stringify(ct({ eventID: "ok-1" })) + "\n" + junk);
    const out = body(await tool(TRAIL, cwd, { path: "work/ev/a.jsonl", link_sessions: false }));
    assert.equal(out.status, "partial");
    assert.equal(out.coverage.records_rejected, 100_500);
    assert.equal(out.coverage.rejected_records_not_listed, 500);
    assert.equal(out.pages.rejected_records.matched, 100_000);
    await put(cwd, "work/ev/b.jsonl", "x\n".repeat(5000));
    const nothing = refused(await tool(TRAIL, cwd, { path: "work/ev/b.jsonl", link_sessions: false }));
    assert.match(nothing.file_problems.join(" "), /the first 1000 records were all rejected/);
    assert.ok(nothing.coverage.records_rejected <= 1001);
  });
});

test("an archive is named and not read: as the path it is unsupported, in a directory the read is partial and the archive is in skipped", async () => {
  await withDir(async (cwd) => {
    const zip = Buffer.concat([Buffer.from("PK\x03\x04", "latin1"), Buffer.alloc(60, 0)]);
    await put(cwd, "work/ev/logs.zip", zip);
    const alone = refused(await tool(TRAIL, cwd, { path: "work/ev/logs.zip" }));
    assert.equal(alone.status, "failed");
    assert.match(JSON.stringify(alone), /ZIP|zip/);
    await put(cwd, "work/ev/a.json", trail(ct({ eventID: "a-1" })));
    const dir = body(await tool(TRAIL, cwd, { path: "work/ev", link_sessions: false }));
    assert.equal(dir.status, "partial", "a file that was not read is not a complete read");
    assert.ok(dir.skipped.some((s: Json) => /archive/.test(s.reason) && s.path.endsWith("logs.zip")), JSON.stringify(dir.skipped));
    assert.equal(dir.record_count, 1);
  });
});

// ---- review of #111: what a record carries, what an output is called ----------------------------------------------------------------

test("eventVersion, requestID, addendum, tlsDetails and any other top-level key are kept, and a version this tool has not seen makes the read partial", async () => {
  await withDir(async (cwd) => {
    const record = ct({ eventID: "v-1", eventVersion: "1.09", eventSource: "s3.amazonaws.com", eventName: "GetObject", addendum: { reason: "DELIVERY_DELAY", updatedFields: "eventName" }, tlsDetails: { tlsVersion: "TLSv1.3", cipherSuite: "TLS_AES_128_GCM_SHA256" }, vpcEndpointId: "vpce-0abc", futureField: { a: 1 } });
    const out = await run(cwd, { "a.json": trail(record) });
    const r = out.records[0];
    assert.deepEqual([r.event_version, r.request_id], ["1.09", "11111111-2222-3333-4444-555555555555"]);
    assert.equal(r.other_fields.addendum.reason, "DELIVERY_DELAY");
    assert.equal(r.other_fields.tlsDetails.tlsVersion, "TLSv1.3");
    assert.deepEqual(r.other_fields.futureField, { a: 1 });
    assert.deepEqual(out.coverage.event_versions, { "1.09": 1 });
    assert.equal(out.status, "complete");
    const future = await run(cwd, { "a.json": trail(ct({ eventID: "v-2", eventVersion: "2.0" })) });
    assert.equal(future.coverage.events_with_an_unknown_version, 1);
    assert.equal(future.status, "partial");
  });
});

test("a read that ended early publishes out_file as <name>.partial and never under the requested name; a whole read does", async () => {
  await withDir(async (cwd) => {
    const records = Array.from({ length: 2000 }, (_, i) => ct({ eventID: `p-${i}`, eventSource: "s3.amazonaws.com", eventName: "GetObject", requestParameters: { key: `k-${i}-${"y".repeat(30)}` } }));
    const whole = gz(JSON.stringify({ Records: records }));
    await put(cwd, "work/ev/cut.json.gz", whole.subarray(0, Math.floor(whole.length * 0.7)));
    const cut = body(await tool(TRAIL, cwd, { path: "work/ev/cut.json.gz", link_sessions: false, out_file: "work/s1/all.jsonl", limit: 5 }));
    assert.equal(cut.status, "partial");
    assert.match(cut.records_file_status, /^partial/);
    assert.match(cut.partial_records, /all\.partial\.jsonl$/);
    assert.equal(await exists(join(cwd, "work/s1/all.jsonl")), false);
    assert.equal(await exists(join(cwd, "work/s1/all.partial.jsonl")), true);
    await put(cwd, "work/ev/whole.json.gz", whole);
    const full = body(await tool(TRAIL, cwd, { path: "work/ev/whole.json.gz", link_sessions: false, out_file: "work/s1/full.jsonl", limit: 5 }));
    assert.equal(full.status, "complete");
    assert.match(full.complete_records, /full\.jsonl$/);
    assert.equal(await exists(join(cwd, "work/s1/full.partial.jsonl")), false);
  });
});

test("error codes of other services are classified by what they say: SNS and Cognito denials, EC2 server errors, and a failed console login", async () => {
  await withDir(async (cwd) => {
    const as = (id: string, source: string, name: string, code: string): Ev => ct({ eventID: id, eventSource: source, eventName: name, userIdentity: { ...ALICE, arn: `arn:aws:iam::1:user/${id}` }, errorCode: code, errorMessage: "x" });
    const out = await run(cwd, {
      "a.json": trail(
        as("sns", "sns.amazonaws.com", "Publish", "AuthorizationError"),
        as("cognito-login", "cognito-idp.amazonaws.com", "InitiateAuth", "NotAuthorizedException"),
        as("ssm-denied", "ssm.amazonaws.com", "GetParameter", "NotAuthorizedException"),
        as("ec2-server", "ec2.amazonaws.com", "RunInstances", "Server.InternalError"),
        as("ec2-unavailable", "ec2.amazonaws.com", "RunInstances", "Server.Unavailable"),
        as("ec2-denied", "ec2.amazonaws.com", "RunInstances", "Client.UnauthorizedOperation"),
        as("expired", "s3.amazonaws.com", "GetObject", "ExpiredToken"),
        ct({ eventID: "console", eventSource: "signin.amazonaws.com", eventName: "ConsoleLogin", userIdentity: { ...ALICE, arn: "arn:aws:iam::1:user/console" }, responseElements: { ConsoleLogin: "Failure" }, errorMessage: "Failed authentication" }),
      ),
    });
    const klass = (id: string): string => out.records.find((r: Json) => r.event_id === id).error_class;
    assert.deepEqual(["sns", "cognito-login", "ssm-denied", "ec2-server", "ec2-unavailable", "ec2-denied", "expired", "console"].map(klass),
      ["authorisation_denied", "authentication", "authorisation_denied", "service", "service", "authorisation_denied", "authentication", "authentication"]);
    assert.deepEqual(out.refusals_by_identity.map((r: Json) => r.identity).sort(), ["arn:aws:iam::1:user/ec2-denied", "arn:aws:iam::1:user/sns", "arn:aws:iam::1:user/ssm-denied"]);
  });
});

test("an event that happens to carry a digest file's keys is still an event", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "a.json": trail(ct({ eventID: "dg-1", eventSource: "s3.amazonaws.com", eventName: "PutObject", digestPublicKeyFingerprint: "abcd", logFiles: [], digestStartTime: "2026-02-14T09:00:00Z" })) });
    assert.deepEqual([out.record_count, out.digest_file_count], [1, 0]);
  });
});

test("the note says the number of calls, not that it names every candidate", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "a.json": trail(goodAssume(), action()) });
    assert.doesNotMatch(out.note, /names every candidate/);
    assert.match(out.note, /lists the matching calls up to a cap, with their count/);
  });
});


// ---- delta review of #111 -------------------------------------------------------------------------------------------------------------

test("copies of one call that disagree on the caller or the returned key are not merged in silence: the session is unresolved and says why, whatever the order of the files", async () => {
  await withDir(async (cwd) => {
    const mine = goodAssume({ eventID: "d-1", sharedEventID: "shared-d" });
    const theirs = goodAssume({ eventID: "d-2", sharedEventID: "shared-d", userIdentity: MALLORY });
    for (const files of [{ "a.json": trail(mine, theirs, action()) }, { "a.json": trail(theirs, mine, action()) }]) {
      const out = await run(cwd, files);
      const link = origin(out, "act-1");
      assert.equal(link.label, "unresolved", JSON.stringify(link).slice(0, 300));
      assert.match(link.reason, /disagree on the caller or the returned access key id/);
      assert.equal(link.candidates[0].copies.some((c: Json) => c.differs_from_the_first), true);
      assert.equal("caller" in link, false, "no caller is chosen");
    }
  });
});

test("linking twenty thousand uses to five thousand calls of one session ARN takes seconds: the lookups are by index and counted once", async () => {
  await withDir(async (cwd) => {
    const records: Ev[] = [];
    for (let i = 0; i < 5000; i++) records.push(goodAssume({ eventID: `c-${i}`, eventTime: `2026-02-14T09:${String(Math.floor(i / 60) % 60).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z`, responseElements: assumedResponse(`ASIAEXAMPLEKEY${String(i).padStart(4, "0")}`, SESSION_ARN) }));
    for (let j = 0; j < 20000; j++) {
      records.push(action({ eventID: `u-${j}`, eventTime: `2026-02-14T11:${String(Math.floor(j / 60) % 60).padStart(2, "0")}:${String(j % 60).padStart(2, "0")}Z`, userIdentity: session(SESSION_ARN, `ASIAOTHER${String(j).padStart(8, "0")}`, `2026-02-14T08:${String(Math.floor(j / 60) % 60).padStart(2, "0")}:${String(j % 60).padStart(2, "0")}Z`) }));
    }
    await put(cwd, "work/ev/many.json", trail(...records));
    const started = Date.now();
    const out = body(await tool(TRAIL, cwd, { path: "work/ev/many.json", limit: 5 }));
    assert.ok(Date.now() - started < 45_000, `the linking took ${Date.now() - started} ms`);
    assert.equal(out.record_count, 25000);
    assert.equal(out.session_links.assume_calls_indexed, 5000);
  });
});

test("a session from GetSessionToken has no AssumeRole call and the answer says that is not a gap; a not_found that names a different key says it once", async () => {
  await withDir(async (cwd) => {
    const derived = goodAssume({ responseElements: assumedResponse("ASIAEXAMPLEOTHER00", SESSION_ARN) });
    const out = await run(cwd, { "a.json": trail(derived, action()) });
    const reason: string = origin(out, "act-1").reason;
    assert.equal(reason.split("returned a different access key id").length - 1, 1, reason);
    assert.match(out.note, /GetSessionToken or GetFederationToken/);
  });
});
