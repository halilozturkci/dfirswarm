/**
 * The cloud pack's three tools share one block of code (tests/pack-cloud-shared.test.ts holds the copies equal), and a reviewer
 * who fed them hostile and foreign input found the same faults in all three. This suite holds each fix, tool by tool: a filter
 * pattern is stopped whatever its shape, the time limit holds inside a record, a foreign format is not "complete", a number JSON
 * cannot hold does not end the run, one malformed record does not either, a name is not printed where the answer says it is
 * withheld, and a file skipped for its name is not a complete read. Every fixture is built here from the formats' own layouts.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { SIGNIN, TRAIL, UAL, asJob, body, ct, everythingBut, put, refused, spawnTool, tool, trail, withDir } from "./cloud-pack-harness.ts";
import type { Json } from "./cloud-pack-harness.ts";
import { JWT } from "./cloud-pack-secrets.ts";

const SCRIPTS = { cloudtrail_parse: TRAIL, signin_analyse: SIGNIN, ual_parse: UAL } as const;

/** A Graph signIn, with the fields a sign-in has. */
const signIn = (i: number, over: Json = {}): Json => ({
  id: `signin-${i}`, createdDateTime: `2026-02-14T09:${String(i % 60).padStart(2, "0")}:00Z`, userPrincipalName: "alice@example.org", userId: "user-guid-1",
  appDisplayName: "Office 365 Exchange Online", ipAddress: "198.51.100.1", clientAppUsed: "Browser", correlationId: `corr-${i}`,
  authenticationRequirement: "multiFactorAuthentication", status: { errorCode: 0 }, location: { city: "Istanbul", countryOrRegion: "TR", geoCoordinates: {} }, ...over,
});
const graph = (...rows: Json[]): string => JSON.stringify({ value: rows });

/** A native audit event. */
const audit = (over: Json = {}): Json => ({
  CreationTime: "2026-02-14T09:00:00Z", Id: "rec-1", Operation: "Send", RecordType: 50, ResultStatus: "Succeeded", Workload: "Exchange", UserId: "alice@example.org",
  ClientIPAddress: "203.0.113.7", ...over,
});

/** JSON text with `marker` strings replaced by the raw text `raw` (JSON.stringify cannot write 1e999 or a 5000-digit integer). */
const withRaw = (value: unknown, marker: string, raw: string): string => (typeof value === "string" ? value : JSON.stringify(value)).replace(`"${marker}"`, raw);

async function lines(path: string): Promise<Json[]> {
  const text = await readFile(path, "utf8");
  return text.trimEnd().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

// ---- C-R1-01: a pattern is stopped whatever its shape ---------------------------------------------------------------------

test("a filter pattern with bounded repeats inside bounded repeats is stopped at a quarter of a second, named, in all three tools", async () => {
  const shapes: Array<[string, number]> = [["(a?){30}a{30}", 30], ["(\\w{1,20}){1,10}@", 200], ["(.{0,40}){0,40}@", 200], ["(.*){5}x", 300]];
  const subjects: Array<[string, string, string, (n: number) => string]> = [
    [TRAIL, "identity", "t.json", (n) => trail(ct({ userIdentity: { type: "IAMUser", arn: "a".repeat(n) } }))],
    [SIGNIN, "user", "s.json", (n) => graph(signIn(1, { userPrincipalName: "a".repeat(n) }))],
    [UAL, "user", "u.json", (n) => JSON.stringify([audit({ UserId: "a".repeat(n) })])],
  ];
  await withDir(async (cwd) => {
    for (const [script, key, file, make] of subjects) {
      for (const [pattern, n] of shapes) {
        await put(cwd, `work/ev/${file}`, make(n));
        const started = Date.now();
        const { done } = spawnTool(script, cwd, { path: `work/ev/${file}`, [key]: pattern, ...(script === TRAIL ? { link_sessions: false } : {}), time_limit_seconds: 5 }, {}, 20_000);
        const out = await done;
        assert.ok(!out.stderr.includes("[harness] killed"), `${script.split("/").slice(-2)[0]} ${pattern}: the call hung`);
        const answer = refused(out);
        assert.equal(answer.status, "failed");
        assert.match(answer.error, /took longer than 0\.25 seconds/, `${pattern}`);
        assert.ok(Date.now() - started < 15_000, `${pattern} returned in ${Date.now() - started} ms`);
      }
    }
  });
});

test("a pattern with bounded repeats that finishes at once still filters", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/t.json", trail(ct({ eventID: "a", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::111122223333:user/alice" } }), ct({ eventID: "b", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::111122223333:user/bob" } })));
    const out = body(await tool(TRAIL, cwd, { path: "work/ev/t.json", identity: "^arn:aws:iam::\\d{12}:user/[a-z]{1,10}$", link_sessions: false }));
    assert.equal(out.record_count, 2);
    const one = body(await tool(TRAIL, cwd, { path: "work/ev/t.json", identity: "user/(al){1,3}ice$", link_sessions: false }));
    assert.equal(one.record_count, 1);
  });
});

// ---- C-R1-02: the time limit holds inside a record ------------------------------------------------------------------------

const HOSTILE = "sas:x ".repeat(10833); // 65,000 characters, every six of them a credential-shaped stretch

test("one record of many long strings is cut by a time limit of one second, counted and listed, and the answer is JSON", async () => {
  await withDir(async (cwd) => {
    const request: Json = {};
    for (let i = 0; i < 150; i++) request[`k${i}`] = HOSTILE;
    await put(cwd, "work/ev/t.json", trail(ct({ requestParameters: request })));
    const started = Date.now();
    const { done } = spawnTool(TRAIL, cwd, { path: "work/ev/t.json", time_limit_seconds: 1, link_sessions: false }, {}, 60_000);
    const out = await done;
    assert.ok(!out.stderr.includes("[harness] killed"), "the call hung");
    const answer = JSON.parse(out.stdout);
    assert.ok(Date.now() - started < 15_000, `returned in ${Date.now() - started} ms for a limit of 1 s`);
    assert.equal(answer.status, "partial");
    assert.equal(answer.coverage.stopped_by_time_limit, true);
    assert.equal(answer.coverage.records_rejected, 1);
    assert.match(JSON.stringify(answer.rejected_records), /time limit ended the read inside this record/);
  });
});

test("a CSV row of many long cells is cut by a time limit of one second, in signin_analyse and ual_parse", async () => {
  const cell = HOSTILE.slice(0, 40000);
  const row = (n: number): string => Array.from({ length: n }, () => cell).join(",");
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/s.csv", `User principal name,Date (UTC),IP address,Status,${Array.from({ length: 300 }, (_, i) => `c${i}`).join(",")}\na@example.org,2026-02-14T09:00:00Z,198.51.100.1,Success,${row(300)}\n`);
    await put(cwd, "work/ev/u.csv", `Operation,UserId,CreationTime,Workload,${Array.from({ length: 300 }, (_, i) => `c${i}`).join(",")}\nSend,a@example.org,2026-02-14T09:00:00Z,Exchange,${row(300)}\n`);
    for (const [script, file] of [[SIGNIN, "s.csv"], [UAL, "u.csv"]]) {
      const started = Date.now();
      const { done } = spawnTool(script, cwd, { path: `work/ev/${file}`, time_limit_seconds: 1 }, {}, 60_000);
      const out = await done;
      assert.ok(!out.stderr.includes("[harness] killed"), `${file}: the call hung`);
      const answer = JSON.parse(out.stdout);
      assert.ok(Date.now() - started < 15_000, `${file} returned in ${Date.now() - started} ms for a limit of 1 s`);
      assert.notEqual(answer.status, "complete", file);      // the one row was cut by the limit, and the answer says so
      assert.equal(answer.coverage.stopped_by_time_limit, true, file);
      assert.match(JSON.stringify(answer.rejected_records), /time limit ended the read inside this record/, file);
    }
  });
});

test("a CSV line longer than max_record_bytes stops the file, named, as a JSON record longer than it is rejected", async () => {
  await withDir(async (cwd) => {
    const big = "x".repeat(17 << 20);
    await put(cwd, "work/ev/s.csv", `User principal name,Date (UTC),IP address,Status,note\na@example.org,2026-02-14T09:00:00Z,198.51.100.1,Success,ok\na@example.org,2026-02-14T09:01:00Z,198.51.100.1,Success,${big}\n`);
    await put(cwd, "work/ev/u.csv", `Operation,UserId,CreationTime,Workload,note\nSend,a@example.org,2026-02-14T09:00:00Z,Exchange,ok\nSend,a@example.org,2026-02-14T09:01:00Z,Exchange,${big}\n`);
    for (const [script, file] of [[SIGNIN, "s.csv"], [UAL, "u.csv"]]) {
      const answer = body(await tool(script, cwd, { path: `work/ev/${file}` }));
      assert.equal(answer.status, "partial", file);
      assert.match(JSON.stringify(answer.file_problems), /longer than 16777216/, file);
    }
  });
});

test("the time limit has a ceiling the manifest's timeout can hold: 480 seconds", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/t.json", trail(ct({})));
    await put(cwd, "work/ev/s.json", graph(signIn(1)));
    await put(cwd, "work/ev/u.json", JSON.stringify([audit()]));
    for (const [script, file] of [[TRAIL, "t.json"], [SIGNIN, "s.json"], [UAL, "u.json"]]) {
      const over = refused(await tool(script, cwd, { path: `work/ev/${file}`, time_limit_seconds: 500 }));
      assert.match(over.error, /from 1 to 480/, file);
      assert.equal((await tool(script, cwd, { path: `work/ev/${file}`, time_limit_seconds: 480 })).code, 0, file);
    }
    for (const name of Object.keys(SCRIPTS)) {
      const manifest = JSON.parse(await readFile(join(SCRIPTS[name as keyof typeof SCRIPTS], "..", "manifest.json"), "utf8"));
      assert.match(manifest.params.time_limit_seconds.description, /default 420, at most 480/, name);
      assert.ok(manifest.timeout_seconds >= 600, name);
    }
  });
});

// ---- C-R1-03: a foreign format is not a complete read ---------------------------------------------------------------------

test("a GCP audit entry, a bare time-and-message log and an Azure activity record are not sign-ins or audit records, and the answer counts them", async () => {
  await withDir(async (cwd) => {
    const gcp = { logName: "projects/p/logs/cloudaudit.googleapis.com%2Factivity", timestamp: "2026-02-14T09:00:00Z", severity: "NOTICE",
      protoPayload: { "@type": "type.googleapis.com/google.cloud.audit.AuditLog", methodName: "SetIamPolicy", authenticationInfo: { principalEmail: "alice@example.org" } } };
    for (const [name, text, count] of [["gcp.json", JSON.stringify([gcp, { ...gcp, timestamp: "2026-02-14T09:05:00Z" }]), 2], ["msg.json", JSON.stringify([{ time: "2026-02-14T09:00:00Z", msg: "hello" }, { time: "2026-02-14T09:01:00Z", msg: "again" }]), 2]] as const) {
      await put(cwd, `work/ev/${name}`, text);
      const out = refused(await tool(SIGNIN, cwd, { path: `work/ev/${name}` }));
      assert.equal(out.status, "failed", name);
      assert.notEqual(out.status, "complete");
      assert.equal(out.coverage.records_not_sign_ins, count, name);
      assert.equal(out.coverage.events, 0, name);
    }
    // a GCP log entry has an `operation` too, and it is an object: it is not a native audit event
    await put(cwd, "work/ev/gcp-ual.json", JSON.stringify([{ ...gcp, operation: { id: "op-1", producer: "compute.googleapis.com", first: true } }]));
    const ual = refused(await tool(UAL, cwd, { path: "work/ev/gcp-ual.json" }));
    assert.equal(ual.status, "failed");
    assert.equal(ual.coverage.rows_not_audit_records, 1);
    // a file of sign-ins with a foreign record among them is partial, with the one counted
    await put(cwd, "work/ev/mixed.json", graph(signIn(1), signIn(2), { time: "2026-02-14T09:00:00Z", msg: "hello" } as Json));
    const mixed = body(await tool(SIGNIN, cwd, { path: "work/ev/mixed.json" }));
    assert.equal(mixed.status, "partial");
    assert.equal(mixed.coverage.records_not_sign_ins, 1);
    assert.equal(mixed.coverage.events, 2);
  });
});

test("an Azure activity record, an Event Grid event and a bare name are not CloudTrail events, and the answer counts them", async () => {
  await withDir(async (cwd) => {
    const azure = { eventName: { value: "EndRequest", localizedValue: "End request" }, eventTimestamp: "2026-02-14T09:00:00Z", eventDataId: "d-1", caller: "alice@example.org",
      operationName: { value: "Microsoft.Compute/virtualMachines/write" }, eventTime: "2026-02-14T09:00:00Z", eventID: "x-1" };
    const grid = { id: "g-1", eventType: "Microsoft.Storage.BlobCreated", eventTime: "2026-02-14T09:00:00Z", eventID: "g-1", subject: "/blobServices/default/containers/c", data: {} };
    const bare = { eventName: "Login", eventTime: "2026-02-14T09:00:00Z", eventID: "b-1" };
    await put(cwd, "work/ev/foreign.json", JSON.stringify([azure, grid, bare]));
    const out = refused(await tool(TRAIL, cwd, { path: "work/ev/foreign.json", link_sessions: false }));
    assert.equal(out.status, "failed");
    assert.equal(out.coverage.records_not_cloudtrail_events, 3);
    assert.equal(out.coverage.records_read, 0);
    await put(cwd, "work/ev/mixed.json", JSON.stringify({ Records: [ct({ eventID: "ok-1" }), azure, ct({ eventID: "ok-2" })] }));
    const mixed = body(await tool(TRAIL, cwd, { path: "work/ev/mixed.json", link_sessions: false }));
    assert.equal(mixed.status, "partial");
    assert.equal(mixed.coverage.records_not_cloudtrail_events, 1);
    assert.equal(mixed.record_count, 2);
    assert.match(JSON.stringify(mixed.rejected_records), /not a CloudTrail event/);
  });
});

// ---- C-R1-04, C-R1-05: numbers JSON cannot hold -----------------------------------------------------------------------------

test("1e999, -1e999 and a 5000-digit integer anywhere in a record do not end the run, and every file the answer names is JSON", async () => {
  const digits = "9".repeat(5000);
  await withDir(async (cwd) => {
    const cases: Array<[string, string, string, Json, string]> = [
      [TRAIL, "t.json", "out.jsonl", {}, withRaw(trail(ct({ requestParameters: { n: "__RAW__", m: "__RAW2__" } })), "__RAW__", "1e999").replace('"__RAW2__"', "-1e999")],
      [TRAIL, "t5.json", "out5.jsonl", {}, withRaw(trail(ct({ requestParameters: { n: "__RAW__" } })), "__RAW__", digits)],
      [SIGNIN, "s.json", "sout.jsonl", {}, withRaw(graph(signIn(1, { extra: "__RAW__" })), "__RAW__", "1e999")],
      [SIGNIN, "s5.json", "sout5.jsonl", {}, withRaw(graph(signIn(1, { extra: "__RAW__" })), "__RAW__", digits)],
      [UAL, "u.json", "uout.jsonl", {}, withRaw(JSON.stringify([audit({ Extra: "__RAW__" })]), "__RAW__", "1e999")],
      [UAL, "u5.json", "uout5.jsonl", {}, withRaw(JSON.stringify([audit({ Extra: "__RAW__" })]), "__RAW__", digits)],
    ];
    for (const [script, file, outFile, extra, text] of cases) {
      await put(cwd, `work/ev/${file}`, text);
      const answer = body(await tool(script, cwd, { path: `work/ev/${file}`, out_file: `work/s1/${outFile}`, limit: 1, ...extra, ...(script === TRAIL ? { link_sessions: false } : {}) }));
      assert.equal(answer.status, "complete", file);
      const rows = await lines(join(cwd, "work", "s1", outFile));
      assert.equal(rows.length, 1, file);
      assert.doesNotMatch(await readFile(join(cwd, "work", "s1", outFile), "utf8"), /Infinity|NaN/, file);
      assert.match(JSON.stringify(rows[0]), file.includes("5") ? /9{5000}/ : /1e999/, "the number is kept, as the text it was written as");
    }
  });
});

test("an out_file written after a first page is still JSON when the number comes in a later record", async () => {
  await withDir(async (cwd) => {
    const text = JSON.stringify({ Records: [ct({ eventID: "a" }), ct({ eventID: "b", requestParameters: { n: "__RAW__" } })] }).replace('"__RAW__"', "1e999");
    await put(cwd, "work/ev/t.json", text);
    const answer = body(await tool(TRAIL, cwd, { path: "work/ev/t.json", out_file: "work/s1/all.jsonl", limit: 1, link_sessions: false }));
    assert.equal(answer.status, "complete");
    assert.equal((await lines(join(cwd, "work", "s1", "all.jsonl"))).length, 2);
  });
});

// ---- C-R1-06: one malformed record does not end the run ---------------------------------------------------------------------

test("a record whose identity, parameters or coordinates have the wrong type is read, and the records around it are too", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/t.json", trail(ct({ eventID: "g1" }), ct({ eventID: "x1", userIdentity: { type: "IAMUser", arn: ["x"] } }), ct({ eventID: "x2", userIdentity: { type: "IAMUser", userName: { a: 1 }, accessKeyId: ["k"] } }),
      ct({ eventID: "x3", userIdentity: { type: "AssumedRole", arn: { a: 1 }, accessKeyId: { b: 2 }, sessionContext: "no" } }), ct({ eventID: "g2" })));
    const t = body(await tool(TRAIL, cwd, { path: "work/ev/t.json" }));
    assert.equal(t.record_count, 5);
    assert.equal(t.status, "complete");

    const google = (n: number, events: Json[]): Json => ({ id: { time: `2026-02-14T09:0${n}:00Z`, applicationName: "login" }, actor: { email: "alice@example.org" }, ipAddress: "198.51.100.1", events });
    await put(cwd, "work/ev/g.json", JSON.stringify({ items: [google(1, [{ name: "login_success", parameters: 5 }]), google(2, [{ name: "login_success", parameters: [{ name: ["x"], value: "1" }] }]), google(3, [{ name: "login_success", parameters: [{ name: "login_type", value: "google_password" }] }])] }));
    const g = body(await tool(SIGNIN, cwd, { path: "work/ev/g.json" }));
    assert.equal(g.event_count, 3);
    assert.equal(g.status, "complete");
    await put(cwd, "work/ev/s.json", graph(signIn(1, { location: { city: "A", countryOrRegion: "TR", geoCoordinates: { latitude: "inf", longitude: "inf" } } }), signIn(2, { location: { city: "B", countryOrRegion: "TR", geoCoordinates: { latitude: "nan", longitude: 5 } } }),
      signIn(3, { location: { city: "C", countryOrRegion: "TR", geoCoordinates: { latitude: 99, longitude: 5 } } })));
    const s = body(await tool(SIGNIN, cwd, { path: "work/ev/s.json" }));
    assert.equal(s.event_count, 3);
    assert.equal(s.impossible_travel.length, 0, "a place that is not on Earth is no place to measure from");

    await put(cwd, "work/ev/u.json", JSON.stringify([audit({ Id: "a", RecordType: "²" }), audit({ Id: "b", RecordType: "①" }), audit({ Id: "c", RecordType: "9".repeat(5000) }), audit({ Id: "d" })]));
    await put(cwd, "work/ev/u2.json", withRaw([audit({ Id: "e", ResultCount: "__RAW__" })], "__RAW__", "1e999"));
    const u = body(await tool(UAL, cwd, { path: "work/ev/u.json", record_type: "50" }));
    assert.equal(u.rows_read, 4);
    assert.equal(u.record_count, 1);
    const u2 = body(await tool(UAL, cwd, { path: "work/ev/u2.json" }));
    assert.equal(u2.rows_read, 1);
  });
});

/** A tool run through a shim: `patch` is Python that runs with the tool's module as `m` before `m.main()`. */
function shimmed(script: string, cwd: string, args: Json, patch: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const shim = [
    "import importlib.util, json, sys",
    "spec = importlib.util.spec_from_file_location('tool', sys.argv[1])",
    "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    patch,
    "m.main()",
  ].join("\n");
  return new Promise((resolve) => {
    const child = spawn("python3", ["-c", shim, script], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    const timer = setTimeout(() => child.kill("SIGKILL"), 60_000);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") });
    });
    child.stdin.end(JSON.stringify(args));
  });
}

/** Makes the page refuse any row that holds BOOM-MARKER, so the catch for a failure nobody foresaw is the one exercised. */
const BOOM = [
  "orig = m.LosslessPage.add",
  "def add(self, row):",
  "    if 'BOOM-MARKER' in json.dumps(row, default=str): raise RuntimeError('boom')",
  "    return orig(self, row)",
  "m.LosslessPage.add = add",
].join("\n");
const boom = (script: string, cwd: string, args: Json): ReturnType<typeof shimmed> => shimmed(script, cwd, args, BOOM);

test("a record that fails for a reason nobody foresaw is counted, located and listed, and the run goes on (all three tools)", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/t.json", trail(ct({ eventID: "g1" }), ct({ eventID: "bad", requestParameters: { v: "BOOM-MARKER" } }), ct({ eventID: "g2" })));
    await put(cwd, "work/ev/s.json", graph(signIn(1), signIn(2, { appDisplayName: "BOOM-MARKER" }), signIn(3)));
    await put(cwd, "work/ev/u.json", JSON.stringify([audit({ Id: "g1" }), audit({ Id: "bad", ObjectId: "BOOM-MARKER" }), audit({ Id: "g2" })]));
    for (const [script, file, key, good] of [[TRAIL, "t.json", "record_count", 2], [SIGNIN, "s.json", "event_count", 2], [UAL, "u.json", "record_count", 2]] as const) {
      const out = await boom(script, cwd, { path: `work/ev/${file}`, ...(script === TRAIL ? { link_sessions: false } : {}) });
      assert.equal(out.code, 0, out.stderr + out.stdout);
      const answer = JSON.parse(out.stdout);
      assert.equal(answer[key], good, file);
      assert.equal(answer.status, "partial", file);
      assert.match(JSON.stringify(answer.rejected_records), /could not be processed \(RuntimeError: boom\)/, file);
      const rejected = script === UAL ? answer.coverage.rows_rejected : answer.coverage.records_rejected;
      assert.equal(rejected, 1, file);
    }
  });
});

test("the walk of a directory reads the time limit: the directories it did not list are named, and the read is partial", async () => {
  await withDir(async (cwd) => {
    for (const d of ["a", "b", "c"]) {
      await put(cwd, `work/ev/${d}/t.json`, trail(ct({ eventID: d })));
      await put(cwd, `work/uev/${d}/u.json`, JSON.stringify([audit({ Id: d })]));
    }
    // the clock reads "in time" for its first two looks and "out of time" for every one after
    const late = ["calls = [0]", "def oot():", "    calls[0] += 1", "    return calls[0] > 2", "m.out_of_time = oot"].join("\n");
    for (const [script, dir] of [[TRAIL, "work/ev"], [UAL, "work/uev"]] as const) {
      const out = await shimmed(script, cwd, { path: dir, ...(script === TRAIL ? { link_sessions: false } : {}) }, late);
      assert.doesNotMatch(out.stderr, /Traceback/);
      const answer = JSON.parse(out.stdout);
      assert.match(JSON.stringify(answer.skipped), /time limit ended the listing of directories/, script);
      assert.notEqual(answer.status, "complete", script);
    }
  });
});

// ---- C-R1-07: a record nested very deeply -------------------------------------------------------------------------------------

test("a list nested 800, 900 and 990 deep is read, and a record nested 20000 deep is rejected alone with the records after it read", async () => {
  const deep = (n: number): string => "[".repeat(n) + "]".repeat(n);
  await withDir(async (cwd) => {
    for (const n of [800, 900, 990]) {
      await put(cwd, `work/ev/d${n}.json`, `{"Records":[${JSON.stringify(ct({ eventID: "a" })).slice(0, -1)},"requestParameters":{"deep":${deep(n)}}}]}`);
      const out = await tool(TRAIL, cwd, { path: `work/ev/d${n}.json`, link_sessions: false });
      assert.equal(out.code, 0, `${n}: ${out.stderr}${out.stdout.slice(0, 300)}`);
      assert.equal(JSON.parse(out.stdout).record_count, 1, `${n}`);
    }
    const hostile = `${JSON.stringify(ct({ eventID: "x" })).slice(0, -1)},"requestParameters":{"deep":${deep(20000)}}}`;
    await put(cwd, "work/ev/t.json", `{"Records":[${JSON.stringify(ct({ eventID: "a" }))},${hostile},${JSON.stringify(ct({ eventID: "c" }))}]}`);
    const t = body(await tool(TRAIL, cwd, { path: "work/ev/t.json", link_sessions: false }));
    // Python before 3.13 cannot decode a record this deep (it is rejected alone); a newer one can (it is read, its depth withheld)
    assert.ok(t.record_count >= 2 && t.records.some((r: Json) => r.event_id === "c"), "the record after the deep one is read");
    if (t.record_count === 2) {
      assert.equal(t.status, "partial");
      assert.match(JSON.stringify(t.rejected_records), /nested too deeply/);
    }
    await put(cwd, "work/ev/s.json", `{"value":[${JSON.stringify(signIn(1))},{"id":"deep","userPrincipalName":"a@example.org","x":${deep(20000)}},${JSON.stringify(signIn(3))}]}`);
    const s = body(await tool(SIGNIN, cwd, { path: "work/ev/s.json" }));
    assert.ok(s.event_count >= 2 && s.events.some((e: Json) => e.event_id === "signin-3"));
    await put(cwd, "work/ev/u.json", `[${JSON.stringify(audit({ Id: "a" }))},{"Operation":"Send","UserId":"a@example.org","x":${deep(20000)}},${JSON.stringify(audit({ Id: "c" }))}]`);
    const u = body(await tool(UAL, cwd, { path: "work/ev/u.json" }));
    assert.ok(u.rows_read >= 2 && u.records.some((r: Json) => r.record_id === "c"));
  });
});

// ---- C-R1-08: a file skipped for its name is not a complete read --------------------------------------------------------------

test("a directory with a file the tool skipped for its name is partial, and says so", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.json", trail(ct({ eventID: "a" })));
    await put(cwd, "work/ev/b.log", trail(ct({ eventID: "b" })));
    await put(cwd, "work/ev/CloudTrail_x", trail(ct({ eventID: "c" })));
    const t = body(await tool(TRAIL, cwd, { path: "work/ev", link_sessions: false }));
    assert.equal(t.status, "partial");
    assert.equal(t.skipped_by_name_count, 2);
    assert.equal(t.record_count, 1);
    assert.match(t.status_basis, /skipped/);
    await put(cwd, "work/uev/a.json", JSON.stringify([audit({ Id: "a" })]));
    await put(cwd, "work/uev/b.txt", "Operation,UserId\nSend,a@example.org\n");
    const u = body(await tool(UAL, cwd, { path: "work/uev" }));
    assert.equal(u.status, "partial");
    assert.match(u.status_basis, /skipped/);
    await put(cwd, "work/clean/a.json", trail(ct({ eventID: "a" })));
    assert.equal(body(await tool(TRAIL, cwd, { path: "work/clean", link_sessions: false })).status, "complete");
  });
});

// ---- C-R1-09, C-R1-10, C-R1-11: nothing is printed where the answer says it is withheld ----------------------------------------

const NAMEVALUE = { Name: "password", Value: "Hunter2CanaryPw" };

test("a Name/Value pair where a string was expected is not printed as the text of a dictionary", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/t.json", trail(ct({ eventVersion: NAMEVALUE, userIdentity: { type: "IAMUser", arn: NAMEVALUE }, sourceIPAddress: NAMEVALUE })));
    await put(cwd, "work/ev/u.json", JSON.stringify([audit({ Operation: NAMEVALUE, UserId: NAMEVALUE, ClientIPAddress: NAMEVALUE, RecordType: NAMEVALUE })]));
    await put(cwd, "work/ev/s.json", graph(signIn(1, { userPrincipalName: NAMEVALUE, ipAddress: NAMEVALUE, appDisplayName: NAMEVALUE, status: { errorCode: NAMEVALUE } }),
      { id: { time: "2026-02-14T09:00:00Z", applicationName: NAMEVALUE }, actor: { email: "a@example.org" }, ipAddress: "198.51.100.1", events: [{ name: "login_success" }] } as Json));
    for (const [script, file, args] of [[TRAIL, "t.json", { link_sessions: false }], [UAL, "u.json", {}], [SIGNIN, "s.json", {}]] as const) {
      const run = await tool(script, cwd, { path: `work/ev/${file}`, ...args });
      assert.doesNotMatch(run.stdout, /Hunter2CanaryPw/, file);
      assert.doesNotMatch(run.stderr, /Hunter2CanaryPw/, file);
      assert.equal(JSON.parse(run.stdout).status === undefined, false, file);
    }
  });
});

test("a Name/Value pair written as JSON text inside a string is withheld by its name, in all three tools, and a pair that is not a credential stays", async () => {
  const text = JSON.stringify([{ Name: "Password", Value: "Hunter2CanaryPw" }, { Name: "Subject", Value: "hello world" }, { Name: "NextToken", Value: "page-two-marker" }]);
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/t.json", trail(ct({ requestParameters: { parameters: text } })));
    await put(cwd, "work/ev/u.json", JSON.stringify([audit({ ExtraColumn: text })]));
    await put(cwd, "work/ev/s.json", graph(signIn(1, { extra: text })));
    for (const [script, file, args] of [[TRAIL, "t.json", { link_sessions: false }], [UAL, "u.json", {}], [SIGNIN, "s.json", {}]] as const) {
      const run = await tool(script, cwd, { path: `work/ev/${file}`, ...args });
      assert.doesNotMatch(run.stdout, /Hunter2CanaryPw/, file);
      assert.match(run.stdout, /hello world/, `${file}: a pair that is not a credential stays`);
      assert.match(run.stdout, /page-two-marker/, `${file}: a next-page token is a position, not a secret`);
    }
  });
});

test("a key shaped like a credential is withheld from the pointers an answer lists, and the values file keeps the real pointer", async () => {
  await withDir(async (cwd) => {
    const key = "https://svc:Pa55CanaryW0rd@host.example/x";
    const awsShaped = "Zq9Xw7Vb6Nm5Lk4Jh3Gf/Dd1Sa0Pp9Oo8Ii7Uu6Y";
    assert.equal(awsShaped.length, 40);
    await put(cwd, "work/ev/t.json", trail(ct({ requestParameters: { [key]: { password: "zzzzzzzz" }, [awsShaped]: { secret: "yyyyyyyy" } } })));
    const run = await asJob(TRAIL, cwd, { path: "work/ev/t.json", link_sessions: false, write_values: true });
    const answer = body(run);
    assert.ok(answer.values_withheld.count >= 2);
    const everything = await everythingBut(cwd, run.stdout, ["out/cloudtrail-values.jsonl"]);
    assert.doesNotMatch(everything, /Pa55CanaryW0rd/);
    assert.ok(!everything.includes(awsShaped), "the 40-character key name");
    const vault = await readFile(join(cwd, "out", "cloudtrail-values.jsonl"), "utf8");
    assert.match(vault, /Pa55CanaryW0rd/, "the values file holds the real pointer");
    assert.match(vault, /zzzzzzzz/);
  });
});

test("an account known only by an id shaped like a credential is printed withheld, never lower-cased and whole", async () => {
  await withDir(async (cwd) => {
    const rows = [1, 2, 3].map((i) => signIn(i, { userPrincipalName: null, userDisplayName: null, userId: JWT, authenticationRequirement: "singleFactorAuthentication" }));
    await put(cwd, "work/ev/s.json", graph(...rows));
    const run = await tool(SIGNIN, cwd, { path: "work/ev/s.json" });
    const answer = body(run);
    const everything = await everythingBut(cwd, run.stdout, []);
    assert.ok(!everything.toLowerCase().includes(JWT.toLowerCase().slice(0, 30)), "the id, in any case");
    assert.equal(answer.single_factor_successes.length, 3);
    assert.match(answer.single_factor_successes[0].user, /^id:\[withheld: a json web token/);
    assert.equal(answer.accounts, 1);
    // two accounts whose ids differ are two accounts, even when both are withheld to the same text
    const other = JWT.slice(0, -4) + "AAAA";
    await put(cwd, "work/ev/s2.json", graph(signIn(1, { userPrincipalName: null, userId: JWT }), signIn(2, { userPrincipalName: null, userId: other })));
    assert.equal(body(await tool(SIGNIN, cwd, { path: "work/ev/s2.json" })).accounts, 2);
  });
});

test("a number under a credential's name is withheld too: 0 and 1 are not 'nothing'", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/t.json", trail(ct({ requestParameters: { pin: 0, otp: 1, password: 0, token: false, mfaCode: 123456 } })));
    const run = await tool(TRAIL, cwd, { path: "work/ev/t.json", link_sessions: false });
    const answer = body(run);
    const request = answer.records[0].request;
    assert.equal(request.pin, "[withheld: credential-named field, a number]");
    assert.equal(request.otp, "[withheld: credential-named field, a number]");
    assert.equal(request.password, "[withheld: credential-named field, a number]");
    assert.equal(request.mfaCode, "[withheld: credential-named field, a number]");
    assert.equal(request.token, false, "a boolean is not a secret");
  });
});

// ---- the manifests say what the tools now do ----------------------------------------------------------------------------------------

test("the manifests say every pattern test is timed, and that a skipped or foreign file is not complete", async () => {
  for (const name of Object.keys(SCRIPTS)) {
    const manifest = JSON.parse(await readFile(join(SCRIPTS[name as keyof typeof SCRIPTS], "..", "manifest.json"), "utf8"));
    const text = JSON.stringify(manifest);
    assert.match(text, /every test of any pattern is timed/, name);
    assert.match(text, /a quarter of a second/, name);
    if (name !== "signin_analyse") assert.match(manifest.description, /skipped for its name/, name);
    assert.match(manifest.description, name === "cloudtrail_parse" ? /records_not_cloudtrail_events/ : name === "signin_analyse" ? /records_not_sign_ins/ : /rows_not_audit_records/, name);
  }
});
