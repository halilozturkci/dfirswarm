/**
 * The cloud-export-inventory recipe (packs/cloud-forensics/recipes/cloud-export-inventory): it inventories a set of supplied exports and states
 * export completeness apart from logging completeness. Fixtures are built here from the formats' own layouts (Cloud Logging, audit.k8s.io/v1,
 * Graph directoryAudit) and are never a tool's output.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { ROOT } from "./tool-library-harness.ts";
import { leaked, rnd } from "./cloud-pack-secrets.ts";

type Json = any; // eslint-disable-line @typescript-eslint/no-explicit-any
const RECIPE = join(ROOT, "packs", "cloud-forensics", "recipes", "cloud-export-inventory");
const RUN = process.env.CLOUD_RECIPE_DIR ? join(process.env.CLOUD_RECIPE_DIR, "run.py") : join(RECIPE, "run.py");
const FIX = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", "cloud-normalise");

type Out = { code: number | null; stdout: string; stderr: string };

function exec(verb: "detect" | "run", paths: string[], cwd: string, extra: string[] = [], env: Record<string, string> = {}): { child: ReturnType<typeof spawn>; done: Promise<Out> } {
  const argv = [RUN, verb, "--target", JSON.stringify({ paths, name: "set" }), ...extra];
  const child = spawn("python3", argv, { cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout?.on("data", (c: Buffer) => out.push(c));
  child.stderr?.on("data", (c: Buffer) => err.push(c));
  const timer = setTimeout(() => child.kill("SIGKILL"), 120_000);
  const done = new Promise<Out>((resolve) => child.on("close", (code) => {
    clearTimeout(timer);
    resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") });
  }));
  return { child, done };
}

async function inventory(cwd: string, paths: string[], out = "out", env: Record<string, string> = {}): Promise<{ run: Out; cov: Json; findings: string[][]; files: string[][] }> {
  const run = await exec("run", paths, cwd, ["--out", join(cwd, out)], env).done;
  assert.doesNotMatch(run.stderr, /Traceback/);
  const cov = JSON.parse(await readFile(join(cwd, out, "coverage.json"), "utf8"));
  const tsv = async (n: string): Promise<string[][]> => (await readFile(join(cwd, out, n), "utf8")).trimEnd().split("\n").slice(1).map((l) => l.split("\t"));
  return { run, cov, findings: await tsv("findings.tsv"), files: await tsv("files.tsv") };
}

async function withDir(fn: (cwd: string) => Promise<void>): Promise<void> {
  const cwd = await mkdtemp(join(tmpdir(), "cloud-inventory-"));
  try {
    await mkdir(join(cwd, "ev"), { recursive: true });
    await fn(cwd);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}

const gcp = (id: string, time = "2026-02-14T09:00:00Z", extra: Json = {}): string => JSON.stringify({ logName: "projects/p1/logs/cloudaudit.googleapis.com%2Factivity", insertId: id, timestamp: time, resource: { type: "project", labels: { project_id: "p1" } }, protoPayload: { "@type": "type.googleapis.com/google.cloud.audit.AuditLog", methodName: "m", serviceName: "s", authenticationInfo: { principalEmail: "a@example.org" }, ...extra } });
const has = (rows: string[][], kind: string): string[][] => rows.filter((r) => r[0] === kind);

test("a directory of mixed formats: every file has its own status, format, provider, tenant, counts and range; the recipe is an inventory, with the receipt's four files", async () => {
  await withDir(async (cwd) => {
    for (const n of ["gcp-audit.json", "k8s-audit.jsonl", "entra-directory-audit.json"]) await copyFile(join(FIX, n), join(cwd, "ev", n));
    await writeFile(join(cwd, "ev", "trail.json"), JSON.stringify({ Records: [{ eventVersion: "1.08", eventSource: "sts.amazonaws.com", eventName: "AssumeRole", eventTime: "2026-02-14T08:00:00Z", eventID: "e1", recipientAccountId: "111122223333" }] }));
    await writeFile(join(cwd, "ev", "login.csv"), "id,createdDateTime,userPrincipalName,appDisplayName\ns1,2026-02-14T07:00:00Z,a@example.org,Portal\n");
    await writeFile(join(cwd, "ev", "notes.txt"), "not an export");
    const { run, cov, files } = await inventory(cwd, [join(cwd, "ev")]);
    assert.equal(run.code, 0, run.stderr);
    assert.deepEqual((await readdir(join(cwd, "out"))).sort(), ["coverage.json", "files.tsv", "findings.tsv", "index.tsv"]);
    const by = Object.fromEntries(files.map((r) => [r[0].split("/").pop() as string, r]));
    assert.equal(by["gcp-audit.json"][1], "complete");
    assert.equal(by["gcp-audit.json"][5], "example-project-1");
    assert.equal(by["gcp-audit.json"][6], "4");
    assert.equal(by["gcp-audit.json"][7], "3", "three records a reader of this pack takes");
    assert.equal(by["gcp-audit.json"][9], "1", "one that none takes");
    assert.equal(by["gcp-audit.json"][10], "2026-02-14T09:00:00.123456789Z");
    assert.equal(by["k8s-audit.jsonl"][2], "jsonl");
    assert.match(by["trail.json"][4], /cloudtrail/);
    assert.equal(by["trail.json"][5], "111122223333");
    assert.equal(by["login.csv"][2], "csv");
    assert.equal(by["login.csv"][4], "entra_signin");
    assert.equal(cov.set.records, 4 + 3 + 3 + 1 + 1);
    assert.equal(cov.status, "partial", "a notes.txt of a name the recipe does not read is named, not silently skipped");
    assert.ok(cov.skipped.total >= 1);
    assert.equal(cov.logging_completeness.state, "not_assessed");
    assert.match(cov.status_basis, /entr(y|ies) of the target were not taken|not complete/);
    assert.ok(cov.steps.every((s: Json) => s.status === "ok" || s.status === "partial"), JSON.stringify(cov.steps));
    assert.equal(cov.finished, true);
    assert.equal(cov.secret_bearing["files.tsv"] !== undefined && cov.secret_bearing["findings.tsv"] !== undefined, true);
  });
});

test("export completeness is stated apart from logging completeness: a clean set is 'no reason to doubt found', never complete logging", async () => {
  await withDir(async (cwd) => {
    await writeFile(join(cwd, "ev", "a.jsonl"), [gcp("i1"), gcp("i2", "2026-02-14T10:00:00Z")].join("\n") + "\n");
    const { run, cov } = await inventory(cwd, [join(cwd, "ev")]);
    assert.equal(run.code, 0);
    assert.equal(cov.status, "complete");
    assert.equal(cov.export_completeness.state, "no_reason_to_doubt_found");
    assert.match(cov.export_completeness.basis, /does not show that the export is whole/);
    assert.equal(cov.logging_completeness.state, "not_assessed");
    assert.match(cov.logging_completeness.basis, /retention, licence, audit configuration and delivery delay/);
    assert.match(cov.status_basis, /nothing about the provider's logging/);
    const asked = JSON.parse(run.stdout);
    assert.equal(asked.export_completeness, "no_reason_to_doubt_found");
  });
});

test("a truncated gzip is partial with the break named, and the other files are unaffected", async () => {
  await withDir(async (cwd) => {
    const good = gzipSync(Buffer.from([gcp("g1"), gcp("g2")].join("\n") + "\n"));
    const whole = gzipSync(Buffer.from(Array.from({ length: 2000 }, (_, i) => gcp(`t-${i}`)).join("\n") + "\n"));
    await writeFile(join(cwd, "ev", "ok.jsonl.gz"), good);
    await writeFile(join(cwd, "ev", "cut.jsonl.gz"), whole.subarray(0, Math.floor(whole.length / 2)));
    const { cov, files } = await inventory(cwd, [join(cwd, "ev")]);
    const by = Object.fromEntries(files.map((r) => [r[0].split("/").pop() as string, r]));
    assert.equal(by["ok.jsonl.gz"][1], "complete");
    assert.equal(by["ok.jsonl.gz"][3], "True");
    assert.equal(by["cut.jsonl.gz"][1], "partial");
    assert.ok(Number(by["cut.jsonl.gz"][6]) > 0 && Number(by["cut.jsonl.gz"][6]) < 2000, "the records before the break are counted");
    assert.equal(cov.status, "partial");
    assert.ok(cov.inputs.some((i: Json) => i.status === "partial" && /cut/.test(i.path)));
  });
});

test("an empty export is named as empty, and 'an empty export is not an empty log'", async () => {
  await withDir(async (cwd) => {
    await writeFile(join(cwd, "ev", "zero.json"), "");
    await writeFile(join(cwd, "ev", "none.json"), '{"entries": []}');
    const { cov, findings, files } = await inventory(cwd, [join(cwd, "ev")]);
    assert.deepEqual(files.map((r) => r[1]).sort(), ["empty", "empty"]);
    assert.equal(has(findings, "empty_export").length, 2);
    assert.match(has(findings, "empty_export")[0][2], /not an empty log/);
    assert.equal(cov.status, "partial");
    assert.equal(cov.export_completeness.state, "doubts_found");
  });
});

test("a count equal to a result cap is a reason to doubt, not a finding; a count one under it is not", async () => {
  await withDir(async (cwd) => {
    await writeFile(join(cwd, "ev", "capped.jsonl"), Array.from({ length: 5000 }, (_, i) => gcp(`c-${i}`, "2026-02-14T09:00:00Z")).join("\n") + "\n");
    await writeFile(join(cwd, "ev", "under.jsonl"), Array.from({ length: 4999 }, (_, i) => gcp(`u-${i}`, "2026-02-14T09:00:00Z")).join("\n") + "\n");
    const { findings, cov } = await inventory(cwd, [join(cwd, "ev")]);
    const caps = has(findings, "result_cap_suspect");
    assert.equal(caps.length, 1);
    assert.match(caps[0][1], /capped\.jsonl$/);
    assert.match(caps[0][2], /holds exactly 5000 records/);
    assert.match(caps[0][2], /may have been cut \(a reason to doubt, not a finding\)/);
    assert.equal(cov.export_completeness.state, "doubts_found");
    await writeFile(join(cwd, "ev", "acquisition.json"), JSON.stringify({ result_size: 4999 }));
    const again = await inventory(cwd, [join(cwd, "ev")], "out2");
    assert.equal(has(again.findings, "result_cap_suspect").length, 2, "the result_size the caller recorded is a cap too");
  });
});

test("next-page markers are found in an envelope and named, and a set named page-K-of-N with a page missing says which", async () => {
  await withDir(async (cwd) => {
    const page = (n: number, token: boolean): string => JSON.stringify({ entries: [JSON.parse(gcp(`p${n}`))], ...(token ? { nextPageToken: "tok" + n } : {}) });
    await writeFile(join(cwd, "ev", "export-page-1-of-3.json"), page(1, true));
    await writeFile(join(cwd, "ev", "export-page-3-of-3.json"), page(3, false));
    await writeFile(join(cwd, "ev", "odata.json"), JSON.stringify({ value: [JSON.parse(gcp("o1"))], "@odata.nextLink": "https://graph.example/next" }));
    const { findings, files } = await inventory(cwd, [join(cwd, "ev")]);
    assert.equal(has(findings, "next_page_marker").length, 2);
    assert.ok(has(findings, "next_page_marker").some((r) => /nextPageToken/.test(r[2])));
    assert.ok(has(findings, "next_page_marker").some((r) => /@odata\.nextLink/.test(r[2])));
    const missing = has(findings, "page_missing");
    assert.equal(missing.length, 1);
    assert.match(missing[0][2], /page\(s\) 2 of 3 are not in the set/);
    assert.equal(files.length, 3);
    void rnd;
  });
});

test("the interval requested against the interval returned: inside, outside, not reached, and no interval or one with no zone", async () => {
  await withDir(async (cwd) => {
    await writeFile(join(cwd, "ev", "a.jsonl"), [gcp("i1", "2026-02-14T09:00:00Z"), gcp("i2", "2026-02-14T11:00:00Z")].join("\n") + "\n");
    const ask = async (interval: Json | undefined, out: string): Promise<Json> => {
      await writeFile(join(cwd, "ev", "acquisition.json"), JSON.stringify({ exported_by: "ops", query: "q", permission: "p", ...(interval ? { interval_requested: interval } : {}) }));
      return (await inventory(cwd, [join(cwd, "ev")], out)).cov;
    };
    const inside = await ask({ start: "2026-02-14T08:30:00Z", end: "2026-02-14T11:30:00Z" }, "o1");
    assert.equal(inside.set.interval_requested_against_returned.state, "returned_inside_requested");
    assert.equal(inside.set.interval_requested_against_returned.first_record_after_requested_start_seconds, 1800);
    assert.match(inside.set.interval_requested_against_returned.meaning, /does not show that every event in it was exported/);
    const outside = await ask({ start: "2026-02-14T09:30:00Z", end: "2026-02-14T10:30:00Z" }, "o2");
    assert.equal(outside.set.interval_requested_against_returned.state, "returned_outside_requested");
    const far = await ask({ start: "2026-02-10T00:00:00Z", end: "2026-02-20T00:00:00Z" }, "o3");
    assert.equal(far.set.interval_requested_against_returned.state, "returned_inside_requested");
    assert.equal(far.export_completeness.state, "doubts_found", "the records reach neither end of a ten-day request");
    const nozone = await ask({ start: "2026-02-14T00:00:00", end: "2026-02-15T00:00:00" }, "o4");
    assert.equal(nozone.set.interval_requested_against_returned.state, "cannot_compare");
    const none = await ask(undefined, "o5");
    assert.match(none.set.interval_requested_against_returned.state, /no interval was requested/);
    assert.equal(none.acquisition.recorded.exported_by, "ops");
    await rm(join(cwd, "ev", "acquisition.json"));
    const absent = (await inventory(cwd, [join(cwd, "ev")], "o6")).cov;
    assert.equal(absent.acquisition.state, "not supplied");
  });
});

test("duplicates within a file and across files are counted and kept, and a gap of a day or more between ranges is named", async () => {
  await withDir(async (cwd) => {
    await writeFile(join(cwd, "ev", "a.jsonl"), [gcp("d1", "2026-02-10T09:00:00Z"), gcp("d1", "2026-02-10T09:00:00Z"), gcp("d2", "2026-02-10T10:00:00Z")].join("\n") + "\n");
    await writeFile(join(cwd, "ev", "b.jsonl"), gcp("d2", "2026-02-10T10:00:00Z") + "\n");
    await writeFile(join(cwd, "ev", "c.jsonl"), gcp("d3", "2026-02-14T10:00:00Z") + "\n");
    const { cov, findings, files } = await inventory(cwd, [join(cwd, "ev")]);
    assert.equal(cov.set.duplicates_in_files, 1);
    assert.equal(cov.set.duplicates_across_files, 1);
    assert.equal(cov.set.records, 5, "a duplicate is counted as a record: nothing is removed");
    assert.equal(files.length, 3);
    assert.equal(has(findings, "duplicates").length, 2);
    const gap = has(findings, "gap_between_files");
    assert.equal(gap.length, 1);
    assert.match(gap[0][2], /no file covers the time between/);
  });
});

test("no record value is printed: canaries in a request, a principal and a token appear in no output, only identifiers do", async () => {
  const secret = "Zq" + rnd(20, 301) + "!7";
  const principal = "u" + rnd(26, 302);
  await withDir(async (cwd) => {
    await writeFile(join(cwd, "ev", "a.jsonl"), gcp("canary-1", "2026-02-14T09:00:00Z", { request: { password: secret, note: `Authorization: Bearer ${secret}` }, authenticationInfo: { principalEmail: principal + "@example.org" } }) + "\n");
    const { run } = await inventory(cwd, [join(cwd, "ev")]);
    const all = [run.stdout, run.stderr];
    for (const f of await readdir(join(cwd, "out"))) all.push(await readFile(join(cwd, "out", f), "utf8"));
    const text = all.join("\n");
    assert.equal(leaked(secret, text), undefined);
    assert.equal(leaked(principal, text), undefined);
    assert.doesNotMatch(text, /canary-1/, "a record id is not printed either");
    assert.match(text, /\bp1\b/, "the project identifier is");
  });
});

test("the receipt exists from the first moment and a second run never overwrites the first", async () => {
  await withDir(async (cwd) => {
    await writeFile(join(cwd, "ev", "a.jsonl"), gcp("r1") + "\n");
    const first = await inventory(cwd, [join(cwd, "ev")]);
    const before = await readFile(join(cwd, "out", "coverage.json"), "utf8");
    const again = await exec("run", [join(cwd, "ev")], cwd, ["--out", join(cwd, "out")]).done;
    assert.notEqual(again.code, 0);
    assert.match(JSON.parse(again.stdout).error, /never overwritten/);
    assert.equal(await readFile(join(cwd, "out", "coverage.json"), "utf8"), before);
    assert.equal(first.cov.finished, true);
  });
});

test("SIGTERM leaves the partial receipt (finished false, the file being read partial), one line of JSON, exit 143 and no temporary file", async (t) => {
  await withDir(async (cwd) => {
    const big = Array.from({ length: 150_000 }, (_, i) => gcp(`s-${i}`, "2026-02-14T09:00:00Z", { request: { pad: "benign words ".repeat(30) } })).join("\n") + "\n";
    await writeFile(join(cwd, "ev", "a.jsonl"), big);
    const { child, done } = exec("run", [join(cwd, "ev")], cwd, ["--out", join(cwd, "out")]);
    await new Promise((r) => setTimeout(r, 1500));
    child.kill("SIGTERM");
    const run = await done;
    if (run.code === 0) {
      t.diagnostic("the inventory finished before the signal");
      return;
    }
    assert.equal(run.code, 143, run.stderr);
    assert.doesNotMatch(run.stderr, /Traceback/);
    const line = JSON.parse(run.stdout.trim().split("\n").pop() as string);
    assert.equal(line.status, "partial");
    assert.equal(line.interrupted_by_signal, 15);
    const cov = JSON.parse(await readFile(join(cwd, "out", "coverage.json"), "utf8"));
    assert.equal(cov.finished, false);
    assert.equal(cov.status, "partial");
    assert.ok(cov.errors.some((e: string) => /signal 15/.test(e)));
    assert.ok(cov.inputs.every((i: Json) => i.status !== "reading"));
    assert.equal((await readdir(join(cwd, "out"))).filter((n) => n.endsWith(".tmp")).length, 0);
  });
});

test("one deadline covers the reads: files after it are not_attempted, and the status is partial", async () => {
  await withDir(async (cwd) => {
    const block = Array.from({ length: 40_000 }, (_, i) => gcp(`t-${i}`, "2026-02-14T09:00:00Z", { request: { pad: "benign words ".repeat(20) } })).join("\n") + "\n";
    for (const n of ["a", "b", "c", "d", "e", "f"]) await writeFile(join(cwd, "ev", `${n}.jsonl`), block);
    const t0 = Date.now();
    const { cov, files } = await inventory(cwd, [join(cwd, "ev")], "out", { CLOUD_EXPORT_INVENTORY_SECONDS: "2" });
    assert.ok(Date.now() - t0 < 2000 + 8000, `took ${Date.now() - t0} ms`);
    assert.equal(cov.status, "partial");
    assert.ok(files.some((r) => r[1] === "not_attempted" || r[1] === "partial"));
    assert.ok(cov.steps.some((s: Json) => s.status === "partial"));
  });
});

test("detect has three answers: 0 for a cloud log export, 1 for a file that is not one, 2 for a target it cannot read", async () => {
  await withDir(async (cwd) => {
    await writeFile(join(cwd, "ev", "a.jsonl"), gcp("x1") + "\n");
    await writeFile(join(cwd, "ev", "plain.json"), '{"hello": "world"}');
    await writeFile(join(cwd, "ev", "text.txt"), "protoPayload is only a word here");
    const yes = await exec("detect", [join(cwd, "ev", "a.jsonl")], cwd).done;
    assert.equal(yes.code, 0);
    assert.equal(JSON.parse(yes.stdout).applies, true);
    const dir = await exec("detect", [join(cwd, "ev")], cwd).done;
    assert.equal(dir.code, 0, "a directory holding one is an export set");
    for (const f of ["plain.json", "text.txt"]) {
      const no = await exec("detect", [join(cwd, "ev", f)], cwd, ["--probe-out", join(cwd, "probe")]).done;
      assert.equal(no.code, 1, f);
      assert.equal(JSON.parse(no.stdout).applies, false);
    }
    const gone = await exec("detect", [join(cwd, "ev", "missing.json")], cwd).done;
    assert.equal(gone.code, 2);
    assert.equal(JSON.parse(gone.stdout).applies, "unknown");
  });
});

test("the copied reader text is the cloud tools' shared text, byte for byte; the manifest declares no secret_output; the seal has registered the recipe with its digest", async () => {
  const tool = await readFile(join(ROOT, "packs", "cloud-forensics", "tools", "signin_analyse", "run.py"), "utf8");
  const recipe = await readFile(RUN, "utf8");
  const slice = (text: string, from: string, to: string): string => text.slice(text.indexOf(from), text.indexOf(to));
  const readerTool = slice(tool, "# ---- reading files: a bounded stream", "# ---- END SHARED BLOCK").trimEnd();
  assert.ok(readerTool.length > 30_000);
  assert.ok(recipe.includes(readerTool), "the reading and CSV text of the shared block is in the recipe unchanged");
  const stampsTool = slice(tool, "# ---- timestamps", "class Tally").trimEnd();
  assert.ok(recipe.includes(stampsTool), "the timestamp text up to ns_to_utc is in the recipe unchanged");
  const json = JSON.parse(await readFile(join(RECIPE, "recipe.json"), "utf8"));
  assert.equal(json.secret_output, undefined);
  assert.equal(json.id, "cloud-export-inventory");
  assert.deepEqual(json.auto, []);
  assert.equal(json.sha256, createHash("sha256").update(await readFile(join(RECIPE, "run.py"))).digest("hex"));
  const pack = JSON.parse(await readFile(join(ROOT, "packs", "cloud-forensics", "pack.json"), "utf8"));
  assert.ok(JSON.stringify(pack.recipes ?? []).includes("cloud-export-inventory"));
});
