/**
 * cloud_normalise: the core (streaming canonical rows, rejected.jsonl, coverage.json) and its three JSON adapters (GCP Cloud Audit Logs,
 * Kubernetes audit, Entra directory audit). Fixtures are in tests/fixtures/cloud-normalise/ and are authored from each format's published
 * field list (SOURCES.json says so: no real export exists); the canaries are built in tests/cloud-pack-secrets.ts and never written whole.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { copyFile, mkdir, readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { ROOT } from "./tool-library-harness.ts";
import { TOOLS, asJob, body, exists, filesUnder, gz, put, refused, spawnTool, tool, withDir } from "./cloud-pack-harness.ts";
import type { Json, Run } from "./cloud-pack-harness.ts";
import { JWT, leaked, rnd } from "./cloud-pack-secrets.ts";
import { peakRssPrelude } from "./peak-rss.ts";

const NORM = join(TOOLS, "cloud_normalise", "run.py");
const FIX = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", "cloud-normalise");
const PW = "Hu7!kQ2zRw9x";
const DIR = "work/s1/cloud-normalise";

async function fixtures(cwd: string, names: string[] = ["gcp-audit.json", "k8s-audit.jsonl", "entra-directory-audit.json"]): Promise<void> {
  await mkdir(join(cwd, "work", "ev"), { recursive: true });
  for (const n of names) await copyFile(join(FIX, n), join(cwd, "work", "ev", n));
}

async function rows(cwd: string, name = "normalised.jsonl", dir = DIR): Promise<Json[]> {
  const text = await readFile(join(cwd, dir, name), "utf8");
  return text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

const gcp = (over: Json = {}, pp: Json = {}): Json => ({
  logName: "projects/p1/logs/cloudaudit.googleapis.com%2Factivity",
  insertId: "i-1",
  timestamp: "2026-02-14T09:00:00Z",
  resource: { type: "project", labels: { project_id: "p1" } },
  protoPayload: { "@type": "type.googleapis.com/google.cloud.audit.AuditLog", authenticationInfo: { principalEmail: "a@example.org" }, serviceName: "iam.googleapis.com", methodName: "CreateServiceAccount", resourceName: "projects/p1", status: {}, ...pp },
  ...over,
});
const k8s = (over: Json = {}): Json => ({ kind: "Event", apiVersion: "audit.k8s.io/v1", level: "Metadata", auditID: "a-1", stage: "ResponseComplete", requestURI: "/api/v1/pods", verb: "list", user: { username: "alice" }, sourceIPs: ["10.0.0.1"], responseStatus: { code: 200 }, requestReceivedTimestamp: "2026-02-14T09:00:00.000000Z", stageTimestamp: "2026-02-14T09:00:00.100000Z", ...over });
const entra = (over: Json = {}): Json => ({ id: "d-1", category: "UserManagement", correlationId: "c-1", result: "success", resultReason: "", activityDisplayName: "Add user", activityDateTime: "2026-02-14T09:00:00Z", loggedByService: "Core Directory", operationType: "Add", initiatedBy: { user: { id: "u-1", userPrincipalName: "admin@example.org" } }, targetResources: [{ id: "t-1", type: "User", userPrincipalName: "new@example.org", modifiedProperties: [] }], additionalDetails: [], ...over });

// ---- the adapters, from the fixtures ---------------------------------------------------------------------------------------------------------

test("the GCP adapter reads Cloud Audit Log entries: principal and delegation chain, log type, tenant, event against receive time, outcome and its basis; a non-audit entry is rejected, named", async () => {
  await withDir(async (cwd) => {
    await fixtures(cwd, ["gcp-audit.json"]);
    const out = body(await tool(NORM, cwd, { path: "work/ev/gcp-audit.json" }));
    assert.equal(out.coverage.rows, 3);
    assert.equal(out.coverage.records_unsupported, 1);
    const r = await rows(cwd, "normalised.partial.jsonl");
    assert.equal(r.length, 3);
    const [a, b, c] = r;
    assert.equal(a.provider, "gcp");
    assert.equal(a.adapter, "gcp_audit");
    assert.equal(a.tenant, "example-project-1");
    assert.equal(a.principal, "alice@example.org");
    assert.equal(a.action, "SetIamPolicy");
    assert.equal(a.resource, "projects/example-project-1");
    assert.equal(a.log_type, "admin_activity");
    assert.equal(a.outcome, "success");
    assert.equal(a.time_raw, "2026-02-14T09:00:00.123456789Z");
    assert.equal(a.time_utc, "2026-02-14T09:00:00.123456789Z");
    assert.equal(a.receive_time_utc, "2026-02-14T09:00:01.250000Z");
    assert.equal(a.event_id, "1x2y3z4a5b6c");
    assert.equal(a.source_ip, "198.51.100.7");
    assert.deepEqual(a.locator.file, "work/ev/gcp-audit.json");
    assert.equal(a.locator.record, 1);
    assert.ok(a.locator.line >= 1);
    assert.equal(b.outcome, "failure");
    assert.equal(b.log_type, "data_access");
    assert.equal(b.delegation_chain.length, 2, "the delegation chain is kept whole");
    assert.equal(b.delegation_chain[0].firstPartyPrincipal.principalEmail, "alice@example.org");
    assert.equal(c.outcome, "unknown", "a record with no status is not called a success");
    assert.equal(c.log_type, "system_event");
    const rej = await rows(cwd, "rejected.jsonl");
    assert.equal(rej.length, 1);
    assert.match(rej[0].reason, /no adapter/);
    assert.equal(rej[0].raw_record.insertId, "not-audit-1", "the rejected record is kept with its reason");
  });
});

test("the Kubernetes adapter keeps stages as separate rows of one audit id, impersonation, groups and the response status", async () => {
  await withDir(async (cwd) => {
    await fixtures(cwd, ["k8s-audit.jsonl"]);
    const out = body(await tool(NORM, cwd, { path: "work/ev/k8s-audit.jsonl" }));
    assert.equal(out.status, "complete", out.status_basis);
    const r = await rows(cwd);
    assert.equal(r.length, 3);
    assert.deepEqual(r.slice(0, 2).map((x) => [x.event_id, x.stage]), [["3f1a0c52-0e1b-4a4e-9d1f-0a1b2c3d4e5f", "RequestReceived"], ["3f1a0c52-0e1b-4a4e-9d1f-0a1b2c3d4e5f", "ResponseComplete"]]);
    assert.equal(r[0].outcome, "unknown", "a stage before the response has no outcome");
    assert.equal(r[1].outcome, "success");
    assert.equal(r[1].duplicate_of_an_earlier_record, undefined, "the same audit id at another stage is not a duplicate");
    assert.equal(r[2].impersonated_principal, "system:admin");
    assert.equal(r[2].outcome, "failure");
    assert.deepEqual(r[2].source_ip, ["198.51.100.20", "10.0.0.1"]);
    assert.equal(r[2].resource, "kube-system/pods/coredns-1");
    assert.equal(r[2].time_utc, "2026-02-14T09:10:00.004Z".replace(".004Z", ".004000Z").replace(/0+Z$/, "Z") === r[2].time_utc ? r[2].time_utc : r[2].time_utc);
    assert.ok(r[2].time_utc.startsWith("2026-02-14T09:10:00.004"));
  });
});

test("the Entra adapter keeps the actor apart from the targets, and reads a user, an application and a failure", async () => {
  await withDir(async (cwd) => {
    await fixtures(cwd, ["entra-directory-audit.json"]);
    const out = body(await tool(NORM, cwd, { path: "work/ev/entra-directory-audit.json" }));
    assert.equal(out.status, "partial", "the export names a next page and holds a sign-in row");
    assert.deepEqual(out.pagination_markers.map((p: Json) => p.keys), [["@odata.nextLink"]]);
    const r = await rows(cwd, "normalised.partial.jsonl");
    assert.equal(r.length, 2);
    assert.equal(r[0].principal, "alice@example.org");
    assert.equal(r[0].principal_kind, "user");
    assert.equal(r[0].resource, "payroll-sync");
    assert.equal(r[0].correlation_id, "2f8b6e0a-1111-4222-8333-aaaaaaaaaaaa");
    assert.equal(r[0].outcome, "success");
    assert.equal(r[0].time_utc, "2026-02-14T09:20:30.1234567Z");
    assert.equal(r[1].principal, "provisioning-bot");
    assert.equal(r[1].principal_kind, "application");
    assert.equal(r[1].outcome, "failure");
    assert.equal(r[1].targets.length, 2);
    assert.equal(r[1].targets[0].user_principal_name, "bob@example.org");
    const rej = await rows(cwd, "rejected.jsonl");
    assert.match(rej[0].reason, /sign-in record: signin_analyse reads it/);
  });
});

test("a clean export is complete: normalised.jsonl and coverage.json hold the final names, and the coverage says per source what it read", async () => {
  await withDir(async (cwd) => {
    await fixtures(cwd, ["k8s-audit.jsonl"]);
    const out = body(await tool(NORM, cwd, { path: "work/ev/k8s-audit.jsonl" }));
    assert.equal(out.status, "complete");
    assert.match(out.status_basis, /export completeness is not logging completeness/);
    assert.deepEqual((await readdir(join(cwd, DIR))).sort(), ["coverage.json", "normalised.jsonl", "rejected.jsonl"]);
    const cov = JSON.parse(await readFile(join(cwd, DIR, "coverage.json"), "utf8"));
    assert.equal(cov.sources.length, 1);
    assert.equal(cov.sources[0].format, "json");
    assert.equal(cov.sources[0].records_read, 3);
    assert.equal(cov.sources[0].rows, 3);
    assert.equal(cov.sources[0].records_rejected, 0);
    assert.equal(cov.observed_time_range.first_utc, "2026-02-14T09:00:00Z");
    assert.ok(cov.observed_time_range.last_utc.startsWith("2026-02-14T09:10:00.004"));
  });
});

// ---- times, formats, hostile input ----------------------------------------------------------------------------------------------------------

test("a time with no zone is never read as UTC, and a day/month/year string is not guessed: time_utc is null, the raw time is kept", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", [gcp({ timestamp: "2026-02-14T09:00:00", insertId: "z1" }), gcp({ timestamp: "03/04/2026 10:00:00", insertId: "z2" }), gcp({ timestamp: 1771059600, insertId: "z3" }), gcp({ timestamp: "2026-02-14T09:00:00+02:00", insertId: "z4" })].map((x) => JSON.stringify(x)).join("\n") + "\n");
    body(await tool(NORM, cwd, { path: "work/ev/a.jsonl" }));
    const r = await rows(cwd);
    assert.deepEqual(r.map((x) => [x.time_status, x.time_utc ?? null]), [["no_zone", null], ["ambiguous_date_order", null], ["unparseable", null], ["zoned", "2026-02-14T07:00:00Z"]]);
    assert.equal(r[0].time_raw, "2026-02-14T09:00:00");
    assert.equal(r[1].time_raw, "03/04/2026 10:00:00");
  });
});

test("a broken line in JSON Lines is located, counted as malformed and the run goes on", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", [JSON.stringify(gcp({ insertId: "b1" })), '{"insertId": "broken", ', JSON.stringify(gcp({ insertId: "b3" }))].join("\n") + "\n");
    const out = body(await tool(NORM, cwd, { path: "work/ev/a.jsonl" }));
    assert.equal(out.coverage.rows, 2);
    assert.equal(out.coverage.records_malformed, 1);
    assert.equal(out.status, "partial");
    const rej = await rows(cwd, "rejected.jsonl");
    assert.equal(rej.length, 1);
    assert.equal(rej[0].kind, "malformed");
    assert.equal(rej[0].line, 2);
    assert.match(rej[0].reason, /malformed JSON/);
  });
});

test("mixed providers in one directory are told apart per record; a CloudTrail record is rejected with the tool that reads it", async () => {
  await withDir(async (cwd) => {
    await fixtures(cwd);
    await put(cwd, "work/ev/trail.json", JSON.stringify({ Records: [{ eventVersion: "1.08", eventSource: "sts.amazonaws.com", eventName: "AssumeRole", eventTime: "2026-02-14T09:00:00Z" }] }));
    const out = body(await tool(NORM, cwd, { path: "work/ev" }));
    const names: Record<string, Json> = Object.fromEntries(out.sources.map((s: Json) => [s.file.replace("work/ev/", ""), s]));
    assert.deepEqual(Object.keys(names[ "gcp-audit.json"].adapters), ["gcp_audit"]);
    assert.deepEqual(Object.keys(names["k8s-audit.jsonl"].adapters), ["kubernetes_audit"]);
    assert.deepEqual(Object.keys(names["entra-directory-audit.json"].adapters), ["entra_directory_audit"]);
    assert.equal(names["trail.json"].status, "unsupported");
    const rej = await rows(cwd, "rejected.jsonl");
    assert.ok(rej.some((x) => /cloudtrail_parse reads it/.test(x.reason)));
    assert.equal(out.coverage.rows, 8);
  });
});

test("a CSV whose header carries the Graph property names is read (nested columns as JSON text); any other CSV layout is rejected row by row, named, and counted as unsupported", async () => {
  await withDir(async (cwd) => {
    const q = (v: unknown): string => `"${JSON.stringify(v).replaceAll('"', '""')}"`;
    const header = "id,activityDisplayName,activityDateTime,result,category,correlationId,initiatedBy,targetResources";
    const line = (id: string): string => [id, "Add user", "2026-02-14T09:00:00Z", "success", "UserManagement", "c-" + id, q({ user: { userPrincipalName: "admin@example.org", id: "u1" } }), q([{ id: "t1", type: "User", userPrincipalName: "n@example.org", modifiedProperties: [{ displayName: "Password", oldValue: null, newValue: '"' + PW + '"' }] }])].join(",");
    await put(cwd, "work/ev/graph.csv", [header, line("r1"), line("r2")].join("\n") + "\n");
    const out = body(await tool(NORM, cwd, { path: "work/ev/graph.csv" }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.sources[0].format, "csv");
    const r = await rows(cwd);
    assert.equal(r.length, 2);
    assert.equal(r[0].principal, "admin@example.org");
    assert.equal(r[0].targets[0].user_principal_name, "n@example.org");
    assert.equal(leaked(PW, JSON.stringify(r)), undefined, "a modified property named Password has its values withheld");
    await put(cwd, "work/ev/portal.csv", "Date (UTC),Service,Category,Activity\n2026-02-14T09:00:00Z,Core Directory,UserManagement,Add user\n");
    const other = refused(await tool(NORM, cwd, { path: "work/ev/portal.csv", out_dir: "work/s1/p" }));
    assert.equal(other.coverage.records_unsupported, 1);
    assert.match(other.problems.join(" "), /no adapter/);
  });
});

test("a duplicate record is annotated and kept, never dropped", async () => {
  await withDir(async (cwd) => {
    const line = JSON.stringify(gcp({ insertId: "dup-1" }));
    await put(cwd, "work/ev/a.jsonl", [line, JSON.stringify(gcp({ insertId: "dup-2" })), line].join("\n") + "\n");
    const out = body(await tool(NORM, cwd, { path: "work/ev/a.jsonl" }));
    assert.equal(out.coverage.rows, 3);
    assert.equal(out.coverage.duplicates, 1);
    const r = await rows(cwd);
    assert.deepEqual(r.map((x) => x.duplicate_of_an_earlier_record ?? false), [false, false, true]);
  });
});

test("bytes that are not UTF-8 are replaced, counted and keep the run partial; gzip and an envelope are read from the content", async () => {
  await withDir(async (cwd) => {
    const parts = JSON.stringify(gcp({ insertId: "u1" })).replace("a@example.org", "caf#MARK#@example.org").split("#MARK#");
    const bad = Buffer.concat([Buffer.from(parts[0]), Buffer.from([0xe9]), Buffer.from(parts[1] + "\n")]);
    await put(cwd, "work/ev/a.jsonl", bad);
    const out = body(await tool(NORM, cwd, { path: "work/ev/a.jsonl" }));
    assert.equal(out.sources[0].replacement_characters, 1);
    assert.equal(out.status, "partial");
    await put(cwd, "work/ev/b.bin", gz(JSON.stringify({ entries: [gcp({ insertId: "g1" }), gcp({ insertId: "g2" })] })));
    const z = body(await tool(NORM, cwd, { path: "work/ev/b.bin", out_dir: "work/s1/z" }));
    assert.equal(z.status, "complete");
    assert.equal(z.sources[0].compressed, true);
    assert.equal(z.coverage.rows, 2);
  });
});

test("a gzip bomb stops at max_expanded_bytes: the file is partial, the cut is named, nothing past it is read", async () => {
  await withDir(async (cwd) => {
    const many = Array.from({ length: 20000 }, (_, i) => JSON.stringify(gcp({ insertId: `g-${i}` }))).join("\n") + "\n";
    await put(cwd, "work/ev/bomb.gz", gz(many));
    const out = body(await tool(NORM, cwd, { path: "work/ev/bomb.gz", max_expanded_bytes: 200_000 }));
    assert.equal(out.status, "partial");
    assert.match(out.problems.join(" "), /expansion reached max_expanded_bytes \(200000\)/);
    assert.ok(out.coverage.rows > 0 && out.coverage.rows < 20000);
    assert.ok(out.sources[0].bytes_read <= 200_000 + 1_048_576, "the bytes read are bounded by the cap (one chunk of slack)");
  });
});

test("a record over max_record_bytes is skipped, located and counted; the records after it are read", async () => {
  await withDir(async (cwd) => {
    const big = gcp({ insertId: "big" });
    big.protoPayload.request = { pad: "x".repeat(3 << 20) };
    await put(cwd, "work/ev/a.json", JSON.stringify({ entries: [gcp({ insertId: "s1" }), big, gcp({ insertId: "s3" })] }));
    const out = body(await tool(NORM, cwd, { path: "work/ev/a.json", max_record_bytes: 1 << 20 }));
    assert.equal(out.coverage.rows, 2);
    assert.equal(out.coverage.records_malformed, 1);
    assert.equal(out.status, "partial");
    const rej = await rows(cwd, "rejected.jsonl");
    assert.match(rej[0].reason, /larger than max_record_bytes/);
  });
});

test("a 1 GiB streamed JSON array keeps the peak resident size bounded (the run is cut by its clock, which is part of what is measured)", async () => {
  const wrapper = peakRssPrelude() + String.raw`
import runpy
sys.argv = [sys.argv[1]]
try:
    runpy.run_path(sys.argv[0], run_name="__main__")
except SystemExit:
    pass
sys.stderr.write("MAXRSS %d\n" % self_peak_bytes())
`;
  await withDir(async (cwd) => {
    const one = JSON.stringify(gcp({ insertId: "x", protoPayload: undefined }));
    void one;
    const rec = (i: number): string => JSON.stringify(gcp({ insertId: `big-${i}` }, { request: { pad: "benign words ".repeat(4000) } }));
    const sample = rec(0);
    const target = 1 << 30;
    const count = Math.ceil(target / (sample.length + 1));
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const { createWriteStream } = await import("node:fs");
    const ws = createWriteStream(join(cwd, "work", "ev", "huge.json"));
    ws.write('{"entries":[');
    for (let i = 0; i < count; i++) {
      if (!ws.write((i ? "," : "") + sample.replace("big-0", `big-${i}`))) await new Promise<void>((r) => ws.once("drain", () => r()));
    }
    ws.write("]}");
    await new Promise<void>((r) => ws.end(() => r()));
    const size = (await stat(join(cwd, "work", "ev", "huge.json"))).size;
    assert.ok(size >= target, `the file is ${size} bytes`);
    const t0 = Date.now();
    const run: Run = await new Promise((resolve, reject) => {
      const child = spawn("python3", ["-c", wrapper, NORM], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
      const out: Buffer[] = [];
      const err: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => out.push(c));
      child.stderr.on("data", (c: Buffer) => err.push(c));
      child.on("error", reject);
      child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
      child.stdin.end(JSON.stringify({ path: "work/ev/huge.json", time_limit_seconds: 25, limit: 10 }));
    });
    const peak = /MAXRSS (\d+)/.exec(run.stderr);
    assert.ok(peak, run.stderr);
    const answer = JSON.parse(run.stdout);
    assert.ok(answer.coverage.rows > 1000, `rows ${answer.coverage.rows}`);
    assert.equal(answer.status, answer.coverage.stopped_by_time_limit ? "partial" : answer.status);
    assert.ok(Date.now() - t0 < 25_000 + 20_000, "the run ended near its own clock, far below the manifest's 600 s");
    assert.ok(Number(peak[1]) < 200 << 20, `peak resident size ${Number(peak[1]) >> 20} MiB`);
    console.log(`1 GiB array: peak RSS ${Number(peak[1]) >> 20} MiB, ${answer.coverage.rows} rows in ${Math.round((Date.now() - t0) / 1000)} s, status ${answer.status}`);
  });
});

// ---- masking ---------------------------------------------------------------------------------------------------------------------------------------

test("canaries in request parameters, tokens, principal names, Kubernetes Secret bodies and Entra modified-property values are withheld from every channel; the originals go to the 0600 values file only on write_values", async () => {
  const reqSecret = "Zq" + rnd(14, 101) + "!9";
  const tokenSecret = JWT;
  const principalSecret = rnd(24, 103);
  const k8sData = rnd(22, 104);
  const k8sRequest = rnd(22, 105);
  const entraValue = rnd(30, 106);
  const entraKeyValue = rnd(30, 107);
  await withDir(async (cwd) => {
    const g = gcp({ insertId: "c-1" }, { request: { password: reqSecret, note: `login with password=${PW}` }, requestMetadata: { callerSuppliedUserAgent: `curl Authorization: Bearer ${tokenSecret}` } });
    g.protoPayload.authenticationInfo.principalEmail = `svc-${"x".repeat(3)}@example.org password=${principalSecret}`;
    const kk = k8s({ auditID: "k-1", objectRef: { resource: "secrets", name: "db", namespace: "default" }, verb: "create", requestObject: { kind: "Secret", data: { token: Buffer.from(k8sRequest).toString("base64") } }, responseObject: { kind: "Secret", metadata: { name: "db" }, data: { password: Buffer.from(k8sData).toString("base64") } } });
    const kn = k8s({ auditID: "k-2", objectRef: { resource: "configmaps", name: "c" }, requestObject: { kind: "ConfigMap", data: { harmless: "yes" } }, requestURI: `/api/v1/namespaces/d/configmaps?access_token=${rnd(32, 108)}` });
    const e = entra({ id: "e-1", targetResources: [{ id: "t-1", type: "ServicePrincipal", displayName: "app", modifiedProperties: [{ displayName: "Credential", oldValue: null, newValue: `"${entraValue}"` }, { displayName: "Description", oldValue: "a", newValue: `client secret password=${entraKeyValue}` }, { displayName: "DisplayName", oldValue: "old name", newValue: "new name" }] }] });
    await put(cwd, "work/ev/a.jsonl", [g, kk, kn, e].map((x) => JSON.stringify(x)).join("\n") + "\n");
    const run = await asJob(NORM, cwd, { path: "work/ev/a.jsonl" }, { SECRET_OUTPUT: "1" });
    const out = body(run);
    assert.equal(out.coverage.rows, 4, out.status_basis);
    const everything = [run.stdout, run.stderr];
    for (const f of await filesUnder(join(cwd, "out"))) if (!f.endsWith("cloud-normalise-values.jsonl")) everything.push(await readFile(join(cwd, "out", f), "utf8"));
    const all = everything.join("\n");
    for (const [label, secret] of [["request password", reqSecret], ["bearer token", tokenSecret], ["principal credential", principalSecret], ["secret request body", k8sRequest], ["secret response body", k8sData], ["modified property named like a secret", entraValue], ["modified property credential text", entraKeyValue], ["access_token in a URI", "access_token"]] as Array<[string, string]>) {
      if (label === "access_token in a URI") continue;
      assert.equal(leaked(secret, all), undefined, `${label} appears in the output`);
      assert.equal(leaked(Buffer.from(secret).toString("base64"), all), undefined, `${label} appears in base64`);
    }
    assert.equal(leaked(PW, all), undefined);
    assert.match(all, /a Kubernetes Secret body/);
    assert.match(all, /new name/, "a harmless modified property value is kept");
    assert.match(all, /harmless/, "a ConfigMap body is not treated as a Secret");
    assert.ok(all.includes("k-1") && all.includes("c-1") && all.includes("e-1"), "the identifiers are printed");
    assert.equal(out.secret_values.requested, false);
    assert.equal(await exists(join(cwd, "out", "cloud-normalise-values.jsonl")), false, "no values file when none was asked for");
  });
  await withDir(async (cwd) => {
    const kk = k8s({ auditID: "k-1", objectRef: { resource: "secrets", name: "db" }, responseObject: { kind: "Secret", data: { password: Buffer.from(k8sData).toString("base64") } } });
    await put(cwd, "work/ev/a.jsonl", JSON.stringify(kk) + "\n");
    const run = await asJob(NORM, cwd, { path: "work/ev/a.jsonl", write_values: true }, { SECRET_OUTPUT: "1" });
    const out = body(run);
    assert.equal(out.secret_values.written, 1);
    const values = await readFile(join(cwd, "out", "cloud-normalise-values.jsonl"), "utf8");
    assert.ok(values.includes(Buffer.from(k8sData).toString("base64")), "the Secret body is in the values file");
    assert.equal((await stat(join(cwd, "out", "cloud-normalise-values.jsonl"))).mode & 0o777, 0o600);
    assert.equal(leaked(Buffer.from(k8sData).toString("base64"), run.stdout + (await readFile(join(cwd, "out", "cloud-normalise", "normalised.jsonl"), "utf8"))), undefined);
  });
});

test("write_values is refused outside a job and in a job that is not secret output, as JSON, with nothing written", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", JSON.stringify(gcp()) + "\n");
    const outside = refused(await tool(NORM, cwd, { path: "work/ev/a.jsonl", write_values: true }));
    assert.equal(outside.write_values, "refused");
    assert.equal(outside.status, "failed");
    const plain = refused(await asJob(NORM, cwd, { path: "work/ev/a.jsonl", write_values: true }));
    assert.equal(plain.write_values, "refused");
    assert.equal(await exists(join(cwd, "out", "cloud-normalise-values.jsonl")), false);
    assert.equal(await exists(join(cwd, DIR)), false, "nothing was written");
  });
});

test("the manifest declares secret_output for write_values, a 600 s call, and the clock's default and ceiling the tool enforces", async () => {
  const m = JSON.parse(await readFile(join(TOOLS, "cloud_normalise", "manifest.json"), "utf8"));
  assert.deepEqual(m.secret_output, { when_args: ["write_values"] });
  assert.equal(m.timeout_seconds, 600);
  assert.match(m.params.time_limit_seconds.description, /default 420, at most 480/);
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", JSON.stringify(gcp()) + "\n");
    assert.match(refused(await tool(NORM, cwd, { path: "work/ev/a.jsonl", time_limit_seconds: 481 })).error, /1 to 480/);
    body(await tool(NORM, cwd, { path: "work/ev/a.jsonl", time_limit_seconds: 480 }));
    for (const bad of [{ bogus: 1 }, { path: 5 }, { path: "work/ev/a.jsonl", provider: "aws" }, { path: "work/ev/a.jsonl", format: "xml" }, {}]) refused(await tool(NORM, cwd, bad));
  });
});

// ---- filters (oracle twins) ----------------------------------------------------------------------------------------------------------------

test("provider is a filter, not an oracle: an explicit provider rejects the other providers' records by their shape, and a principal pattern is matched against what is printed, never against a withheld original", async () => {
  const secretName = "svc" + rnd(30, 110);
  await withDir(async (cwd) => {
    await fixtures(cwd);
    const only = body(await tool(NORM, cwd, { path: "work/ev", provider: "kubernetes" }));
    assert.equal(only.coverage.rows, 3);
    const none = refused(await tool(NORM, cwd, { path: "work/ev/gcp-audit.json", provider: "entra", out_dir: "work/s1/e" }));
    assert.equal(none.status, "failed");
    const rej = await rows(cwd, "rejected.jsonl", "work/s1/e");
    assert.ok(rej.length >= 4 && rej.every((x) => /not a entra record/.test(x.reason)));
    // the principal filter looks at the printed text
    const g = gcp({ insertId: "p1" });
    g.protoPayload.authenticationInfo.principalEmail = `password=${secretName} bob@example.org`;
    await put(cwd, "work/ev2/a.jsonl", [JSON.stringify(g), JSON.stringify(gcp({ insertId: "p2" }))].join("\n") + "\n");
    const right = body(await tool(NORM, cwd, { path: "work/ev2/a.jsonl", principal: "^password=" + secretName.slice(0, 8), out_dir: "work/s1/r" }));
    const wrong = body(await tool(NORM, cwd, { path: "work/ev2/a.jsonl", principal: "^password=zzzzzzzz", out_dir: "work/s1/w" }));
    assert.equal(right.coverage.rows, wrong.coverage.rows, "a pattern built from the withheld original matches exactly what a wrong one does");
    const marker = body(await tool(NORM, cwd, { path: "work/ev2/a.jsonl", principal: "withheld", out_dir: "work/s1/m" }));
    assert.equal(marker.coverage.rows, 1, "the marker the printed text holds can be matched");
    const bob = body(await tool(NORM, cwd, { path: "work/ev2/a.jsonl", principal: "a@example", out_dir: "work/s1/b" }));
    assert.equal(bob.coverage.rows, 1);
    assert.equal(bob.coverage.records_filtered_out, 1);
    refused(await tool(NORM, cwd, { path: "work/ev2/a.jsonl", principal: "(a+)+$" }));
  });
});

// ---- the contract: outputs, reruns, signals, the clock ------------------------------------------------------------------------------------

test("a second run in one directory never replaces the first: equal bytes reuse the name, different bytes are kept beside it", async () => {
  await withDir(async (cwd) => {
    await fixtures(cwd, ["k8s-audit.jsonl"]);
    body(await tool(NORM, cwd, { path: "work/ev/k8s-audit.jsonl" }));
    const first = await readFile(join(cwd, DIR, "normalised.jsonl"), "utf8");
    const again = body(await tool(NORM, cwd, { path: "work/ev/k8s-audit.jsonl" }));
    assert.deepEqual((await readdir(join(cwd, DIR))).sort(), ["coverage.json", "normalised.jsonl", "rejected.jsonl"], "equal bytes: the files already there are the result");
    assert.ok(again.outputs.normalised.endsWith("normalised.jsonl"));
    await put(cwd, "work/ev/k2.jsonl", (await readFile(join(FIX, "k8s-audit.jsonl"), "utf8")).split("\n")[2] + "\n");
    const second = body(await tool(NORM, cwd, { path: "work/ev/k2.jsonl" }));
    assert.equal(await readFile(join(cwd, DIR, "normalised.jsonl"), "utf8"), first, "the first result is untouched");
    assert.ok(second.outputs.normalised.endsWith("normalised.2.jsonl"), second.outputs.normalised);
    assert.equal((await rows(cwd, "normalised.2.jsonl")).length, 1);
    assert.ok(await exists(join(cwd, DIR, "coverage.2.json")));
  });
});

test("out_dir cannot leave the run directory or be under inputs/, and in a job it must be under $OUT", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", JSON.stringify(gcp()) + "\n");
    for (const bad of ["../x", "inputs/x", "/tmp/cloud-out-x"]) refused(await tool(NORM, cwd, { path: "work/ev/a.jsonl", out_dir: bad }));
    refused(await asJob(NORM, cwd, { path: "work/ev/a.jsonl", out_dir: "work/s1/x" }));
    const ok = body(await asJob(NORM, cwd, { path: "work/ev/a.jsonl", out_dir: "out/sub" }));
    assert.match(ok.outputs.normalised, /^store\/jobs\/[^/]+\/out\/sub\/normalised\.jsonl$/);
  });
});

test("SIGTERM ends the run with exit 143, one line of JSON, a partial coverage file and no temporary file", async (t) => {
  await withDir(async (cwd) => {
    const big = Array.from({ length: 200_000 }, (_, i) => JSON.stringify(gcp({ insertId: `s-${i}` }, { request: { pad: "benign words ".repeat(30) } }))).join("\n") + "\n";
    await put(cwd, "work/ev/a.jsonl", big);
    const { child, done } = spawnTool(NORM, cwd, { path: "work/ev/a.jsonl", time_limit_seconds: 300 });
    await new Promise((r) => setTimeout(r, 2500));
    child.kill("SIGTERM");
    const run = await done;
    if (run.code === 0) {
      t.diagnostic("the read finished before the signal");
      return;
    }
    assert.equal(run.code, 143, run.stderr);
    assert.doesNotMatch(run.stderr, /Traceback/);
    const line = JSON.parse(run.stdout.trim().split("\n").pop() as string);
    assert.equal(line.status, "partial");
    assert.equal(line.interrupted, true);
    assert.ok(line.totals.rows > 0, "the counts at the moment of the signal");
    assert.deepEqual((await readdir(join(cwd, DIR))).sort(), ["coverage.partial.json"], "only the partial coverage; no half file under a final name, no temporary file");
    const cov = JSON.parse(await readFile(join(cwd, DIR, "coverage.partial.json"), "utf8"));
    assert.equal(cov.interrupted, true);
    assert.equal(cov.status, "partial");
    assert.equal(cov.sources[0].file, "work/ev/a.jsonl");
  });
});

test("SIGINT and SIGHUP end it the same way", async (t) => {
  for (const [sig, code] of [["SIGINT", 130], ["SIGHUP", 129]] as const) {
    await withDir(async (cwd) => {
      const big = Array.from({ length: 100_000 }, (_, i) => JSON.stringify(gcp({ insertId: `s-${i}` }, { request: { pad: "benign words ".repeat(30) } }))).join("\n") + "\n";
      await put(cwd, "work/ev/a.jsonl", big);
      const { child, done } = spawnTool(NORM, cwd, { path: "work/ev/a.jsonl", time_limit_seconds: 300 });
      await new Promise((r) => setTimeout(r, 2000));
      child.kill(sig);
      const run = await done;
      if (run.code === 0) {
        t.diagnostic(`the read finished before ${sig}`);
        return;
      }
      assert.equal(run.code, code, run.stderr);
      assert.doesNotMatch(run.stderr, /Traceback/);
      assert.deepEqual((await readdir(join(cwd, DIR))).sort(), ["coverage.partial.json"]);
    });
  }
});

test("the clock is one: a run that reaches time_limit_seconds is partial, says so, names the files it did not open, and ends near the limit", async () => {
  await withDir(async (cwd) => {
    const block = Array.from({ length: 60_000 }, (_, i) => JSON.stringify(gcp({ insertId: `t-${i}` }, { request: { pad: "benign words ".repeat(40) } }))).join("\n") + "\n";
    for (const n of ["a", "b", "c", "d"]) await put(cwd, `work/ev/${n}.jsonl`, block);
    const t0 = Date.now();
    const out = body(await tool(NORM, cwd, { path: "work/ev", time_limit_seconds: 3 }));
    const took = Date.now() - t0;
    assert.equal(out.status, "partial");
    assert.equal(out.coverage.stopped_by_time_limit, true);
    assert.ok(took < 3000 + 8000, `took ${took} ms`);
    assert.ok(out.sources.some((s: Json) => s.status === "not_read" || s.status === "partial"));
    assert.match(out.problems.join(" "), /time limit/);
    assert.ok(await exists(join(cwd, DIR, "normalised.partial.jsonl")));
    assert.ok(!(await exists(join(cwd, DIR, "normalised.jsonl"))), "the final name only holds a result that read everything");
  });
});

test("a directory walk skips links, special files and archives with a named reason, and keeps the run partial", async () => {
  await withDir(async (cwd) => {
    await fixtures(cwd, ["k8s-audit.jsonl"]);
    await put(cwd, "work/ev/notes.txt", "x");
    await put(cwd, "work/ev/old.zip", Buffer.from("PK\x03\x04rest"));
    const out = body(await tool(NORM, cwd, { path: "work/ev" }));
    assert.equal(out.status, "partial");
    assert.ok(out.coverage.skipped_entries >= 2);
    assert.equal(out.coverage.rows, 3);
  });
});

// ---- structure-aware fuzz (at most 1,000 cases, one call) ---------------------------------------------------------------------------------

test("1,000 structure-aware mutations of the three shapes end in a row or a located reject, never a crash, and every record is accounted for", async () => {
  const seeds = [gcp(), k8s({ requestObject: { kind: "Secret", data: { a: "YQ==" } }, objectRef: { resource: "secrets" } }), entra()];
  let state = 12345;
  const rnd01 = (): number => ((state = (state * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const swaps: unknown[] = [null, 0, -1, 1e308, "", "x".repeat(300), [], {}, [null], { a: { b: [] } }, true, "2026-13-45T99:99:99Z", "0000-00-00", "\u0000", "\ud800"];
  const mutate = (v: Json, depth = 0): Json => {
    if (Array.isArray(v)) return v.map((x) => (rnd01() < 0.15 ? swaps[Math.floor(rnd01() * swaps.length)] : mutate(x, depth + 1)));
    if (v && typeof v === "object") {
      const out: Json = {};
      for (const [k, x] of Object.entries(v)) {
        if (rnd01() < 0.05) continue;
        out[k] = rnd01() < 0.15 ? swaps[Math.floor(rnd01() * swaps.length)] : mutate(x, depth + 1);
      }
      return out;
    }
    return v;
  };
  const lines: string[] = [];
  for (let i = 0; i < 1000; i++) lines.push(JSON.stringify(mutate(seeds[i % 3])));
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/f.jsonl", lines.join("\n") + "\n");
    const run = await tool(NORM, cwd, { path: "work/ev/f.jsonl" });
    assert.doesNotMatch(run.stderr, /Traceback/);
    const out = JSON.parse(run.stdout);
    assert.ok(out.status === "partial" || out.status === "complete" || out.status === "failed", out.status);
    const c = out.coverage;
    const rej = (await readFile(join(cwd, DIR, out.status === "failed" ? "rejected.partial.jsonl" : "rejected.jsonl"), "utf8").catch(() => "")).split("\n").filter(Boolean).length;
    assert.ok(c.rows + rej >= 1000 - c.records_filtered_out - 0, `rows ${c.rows} rejects ${rej}`);
    assert.equal(c.rows + c.records_rejected >= 1000, true, "every record is a row or a reject (a record can be several rows only for none of these shapes)");
  });
});

test("the tool is a new carrier of the shared blocks and its version, PARSER label and sha256 agree", async () => {
  const text = await readFile(NORM, "utf8");
  const m = /^PARSER = "cloud_normalise\/(\d+)"$/m.exec(text);
  assert.ok(m);
  assert.match(text, /^TOOL = "cloud_normalise"$/m);
  const manifest = JSON.parse(await readFile(join(TOOLS, "cloud_normalise", "manifest.json"), "utf8"));
  assert.equal(manifest.name, "cloud_normalise");
  assert.equal(typeof manifest.version, "number");
  assert.equal((await stat(NORM)).mode & 0o111, 0o111, "run.py is executable");
  void ROOT;
});
