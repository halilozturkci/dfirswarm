/**
 * ransomware-response: ransomware_scope_report. Hosts with partial inputs, a host listed twice, conflicting censuses, inputs of another tool
 * version, no extrapolation and no estate-wide percentage, the SQLite index under the output directory, stop signals, identifier-shaped host
 * names, and the real producers' outputs read back. The 10-million-row census is in tests/pack-ransomware-scope-report-deep.test.ts.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { PACK, SURVEY, exists, filesUnder, tool } from "./ransomware-pack-harness.ts";

const REPORT = join(PACK, "ransomware_scope_report", "run.py");
const EXTENT = join(PACK, "encryption_extent", "run.py");
const VALIDATE = join(PACK, "recovery_validate", "run.py");
const MANIFEST = join(PACK, "ransomware_scope_report", "manifest.json");

type Host = {
  host_id: string; host: string; scope: string; scope_basis: string;
  denominators?: { files: number; bytes: number; candidate_file_fraction: number | null };
  censuses?: Array<{ files: number; bytes: number; by_status: Record<string, { files: number; bytes: number }>; receipt: string }>;
  encryption_extent?: { files: number; bytes_named: number; bytes_inspected: number; bytes_not_inspected: number; high_entropy_runs: number };
  assessed_against_unassessed?: { census_bytes: number; assessed_bytes: number; unassessed_bytes: number; assessed_exceeds_census: boolean };
  recovery_checks?: { by_verdict: Record<string, { files: number }>; validated_files: number };
  candidate_against_validated: { candidate_files: number | null; validated_files: number };
  timeline?: { kinds: number; events: number; first: string; last: string };
  collection_coverage?: Array<{ status: string | null; status_basis: string | null }>;
};
type Answer = {
  status: string; status_basis: string; partial_reasons: string[]; hosts: Host[]; error?: string; interrupted?: boolean;
  coverage_statement: Record<string, unknown> & { hosts: number; hosts_unknown: number; hosts_conflict: number; census_files: number; census_bytes: number; extrapolated: boolean; estate_wide_percentage: null };
  index: { file: string }; pages: { hosts: { matched: number; all_results?: string }; timeline: { matched: number } }; timeline: Array<Record<string, unknown>>;
};

async function run(cwd: string, args: unknown, env: Record<string, string> = {}): Promise<{ answer: Answer; stdout: string; stderr: string; code: number | null }> {
  const out = await tool(REPORT, cwd, args, env);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return { answer: JSON.parse(out.stdout) as Answer, stdout: out.stdout, stderr: out.stderr, code: out.code };
}

const receipt = (parser: string, status = "complete"): string => JSON.stringify({ record: "receipt", rows: 0, parser, status }) + "\n";
async function census(cwd: string, name: string, rows: Array<[string, number]>, parser = "encrypted_survey/3", withReceipt = true, status = "complete"): Promise<string> {
  const body = rows.map(([st, bytes], i) => JSON.stringify({ record: "file", file: `x/${i}`, bytes, status: st })).join("\n") + "\n";
  await writeFile(join(cwd, name), body + (withReceipt ? receipt(parser, status) : ""));
  return name;
}
const byId = (a: Answer, id: string): Host => a.hosts.find((h) => h.host_id === id)!;

test("three hosts with partial inputs: scope with denominators, unknown for the host without a census, and no extrapolation or estate-wide percentage", async () => {
  await withCwd(async (cwd) => {
    const a = await census(cwd, "a.jsonl", [["candidate", 1000], ["candidate", 2000], ["noncandidate", 7000], ["unmeasured", 100]]);
    const b = await census(cwd, "b.jsonl", [["noncandidate", 500], ["noncandidate", 500]], "encrypted_survey/3", false);
    await writeFile(join(cwd, "ext-a.jsonl"), [
      { record: "file", file_id: 1, bytes: 1000, status: "inspected", windows: 1, bytes_inspected: 1000, high_entropy_runs: 1 },
      { record: "file", file_id: 2, bytes: 2000, status: "partial", windows: 1, bytes_inspected: 500, high_entropy_runs: 0 },
      { record: "receipt", rows: 2, parser: "encryption_extent/1", status: "partial" },
    ].map((r) => JSON.stringify(r)).join("\n") + "\n");
    await writeFile(join(cwd, "rec-a.jsonl"), [
      { record: "file", file_id: 1, bytes: 1000, verdict: "matches_known_original", status: "checked" },
      { record: "file", file_id: 2, bytes: 2000, verdict: "structurally_valid", status: "checked" },
      { record: "receipt", rows: 2, parser: "recovery_validate/1", status: "complete" },
    ].map((r) => JSON.stringify(r)).join("\n") + "\n");
    await writeFile(join(cwd, "tl.jsonl"), [
      { host: "alpha", time: "2026-10-02T08:00:00Z", kind: "logon" }, { host: "alpha", time: "2026-10-01T07:00:00.5Z", kind: "logon" },
      { host: "gamma", time: "2026-10-03T00:00:00Z", kind: "service" }, { host: "alpha", time: "not a time", kind: "logon" },
    ].map((r) => JSON.stringify(r)).join("\n") + "\n");
    await writeFile(join(cwd, "cov.json"), JSON.stringify({ status: "partial", status_basis: "the volume shadow copies were not collected" }));
    const { answer } = await run(cwd, {
      censuses: [{ host: "alpha", file: a }, { host: "beta", file: b }], extents: [{ host: "alpha", file: "ext-a.jsonl" }],
      recovery_checks: [{ host: "alpha", file: "rec-a.jsonl" }], timelines: [{ file: "tl.jsonl" }], coverage: [{ host: "beta", file: "cov.json" }],
      expected_hosts: ["delta"],
    });
    assert.equal(answer.status, "partial");
    const alpha = answer.hosts.find((h) => h.host === "alpha")!;
    const beta = answer.hosts.find((h) => h.host === "beta")!;
    const gamma = answer.hosts.find((h) => h.host === "gamma")!;
    const delta = answer.hosts.find((h) => h.host === "delta")!;
    assert.equal(alpha.scope, "complete");
    assert.deepEqual([alpha.denominators!.files, alpha.denominators!.bytes, alpha.denominators!.candidate_file_fraction], [4, 10100, 0.5]);
    assert.deepEqual(alpha.assessed_against_unassessed, { ...alpha.assessed_against_unassessed!, census_bytes: 10100, assessed_bytes: 1500, unassessed_bytes: 8600, assessed_exceeds_census: false });
    assert.deepEqual([alpha.encryption_extent!.bytes_named, alpha.encryption_extent!.bytes_inspected, alpha.encryption_extent!.bytes_not_inspected, alpha.encryption_extent!.high_entropy_runs], [3000, 1500, 1500, 1]);
    assert.deepEqual([alpha.candidate_against_validated.candidate_files, alpha.candidate_against_validated.validated_files], [2, 1], "structurally valid is not validated");
    assert.deepEqual([alpha.timeline!.events, alpha.timeline!.first, alpha.timeline!.last], [2, "2026-10-01T07:00:00.500000Z", "2026-10-02T08:00:00.000000Z"]);
    assert.equal(beta.scope, "partial", "a census without a receipt is itself partial");
    assert.match(beta.scope_basis, /no receipt/);
    assert.equal(beta.collection_coverage![0]!.status, "partial");
    for (const h of [gamma, delta]) {
      assert.equal(h.scope, "unknown");
      assert.equal(h.denominators, undefined, "no denominator is made up for a host without a census");
      assert.equal(h.assessed_against_unassessed, undefined);
    }
    assert.equal(gamma.timeline!.events, 1);
    const s = answer.coverage_statement;
    assert.equal(s.hosts, 4);
    assert.equal(s.hosts_unknown, 2);
    assert.equal(s.hosts_with_census, 2);
    assert.equal(s.census_files, 6, "the totals add the hosts that have a census, and nothing is added for the others");
    assert.equal(s.extrapolated, false);
    assert.equal(s.estate_wide_percentage, null);
    assert.doesNotMatch(JSON.stringify(answer), /percent(age)?_encrypted|estate_percent/);
    assert.ok((answer.partial_reasons ?? []).some((r) => /unknown/.test(r)));
    assert.ok(answer.partial_reasons.some((r) => /rows_skipped: 1|no_receipt:censuses: 1/.test(r)));
  });
});

test("a host listed twice, or with two censuses, is a conflict: both are shown apart and neither is added to the totals", async () => {
  await withCwd(async (cwd) => {
    const one = await census(cwd, "one.jsonl", [["candidate", 100], ["noncandidate", 100]]);
    const two = await census(cwd, "two.jsonl", [["noncandidate", 100]]);
    const solo = await census(cwd, "solo.jsonl", [["noncandidate", 10]]);
    const { answer } = await run(cwd, { censuses: [{ host: "twice", file: one }, { host: "twice", file: two }, { host: "solo", file: solo }] });
    const twice = answer.hosts.find((h) => h.host === "twice")!;
    assert.equal(twice.scope, "conflict");
    assert.equal(twice.censuses!.length, 2);
    assert.deepEqual(twice.censuses!.map((c) => c.files).sort(), [1, 2]);
    assert.equal(twice.denominators, undefined);
    assert.equal(answer.coverage_statement.hosts_conflict, 1);
    assert.equal(answer.coverage_statement.census_files, 1, "only the host with exactly one census is in the sums");
    assert.equal(answer.status, "partial");
  });
});

test("an input of another tool version is refused by name, and a receipt that says partial makes the host's census partial", async () => {
  await withCwd(async (cwd) => {
    const old = await census(cwd, "old.jsonl", [["candidate", 1]], "encrypted_survey/2");
    const refused = await tool(REPORT, cwd, { censuses: [{ host: "h", file: old }] });
    assert.notEqual(refused.code, 0);
    const doc = JSON.parse(refused.stdout) as { status: string; error: string };
    assert.equal(doc.status, "failed");
    assert.match(doc.error, /encrypted_survey\/2/);
    await writeFile(join(cwd, "e.jsonl"), receipt("encryption_extent/9"));
    const refusedExtent = JSON.parse((await tool(REPORT, cwd, { extents: [{ host: "h", file: "e.jsonl" }] })).stdout) as { error: string };
    assert.match(refusedExtent.error, /encryption_extent\/9/);
    const part = await census(cwd, "part.jsonl", [["candidate", 1]], "encrypted_survey/3", true, "partial");
    const { answer } = await run(cwd, { censuses: [{ host: "h", file: part }] });
    assert.equal(answer.hosts[0]!.scope, "partial");
    assert.equal(answer.status, "partial");
    // a producer that is not a census at all
    await writeFile(join(cwd, "none.jsonl"), "not json\n");
    const odd = await run(cwd, { censuses: [{ host: "h", file: "none.jsonl" }] });
    assert.equal(odd.answer.status, "partial");
  });
});

test("a complete answer needs exactly one complete census per host, and says so", async () => {
  await withCwd(async (cwd) => {
    const a = await census(cwd, "a.jsonl", [["noncandidate", 10], ["candidate", 20]]);
    const { answer } = await run(cwd, { censuses: [{ host: "a", file: a }] });
    assert.equal(answer.status, "complete", answer.status_basis);
    assert.equal(answer.coverage_statement.hosts_with_complete_census, 1);
    assert.equal(answer.hosts[0]!.scope, "complete");
  });
});

test("the real producers' outputs are read back: a census of encrypted_survey, the profiles of encryption_extent and recovery_validate", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "a.docx.locked"), randomBytes(9000));
    await writeFile(join(cwd, "work", "ev", "b.txt"), Buffer.from("plain text ".repeat(900)));
    const survey = JSON.parse((await tool(SURVEY, cwd, { root: "work/ev" })).stdout) as { census: { file: string } };
    const extent = JSON.parse((await tool(EXTENT, cwd, { policy: "full", census: survey.census.file })).stdout) as { profile: { file: string } };
    const valid = JSON.parse((await tool(VALIDATE, cwd, { items: ["work/ev/b.txt"] })).stdout) as { profile: { file: string } };
    const { answer } = await run(cwd, {
      censuses: [{ host: "pc1", file: survey.census.file }], extents: [{ host: "pc1", file: extent.profile.file }], recovery_checks: [{ host: "pc1", file: valid.profile.file }],
    });
    assert.equal(answer.status, "complete", answer.status_basis);
    const h = answer.hosts[0]!;
    assert.deepEqual([h.denominators!.files, h.candidate_against_validated.candidate_files], [2, 1]);
    assert.equal(h.encryption_extent!.files, 1);
    assert.equal(h.encryption_extent!.bytes_inspected, 9000);
    assert.equal(h.recovery_checks!.by_verdict.structurally_valid!.files, 1);
    assert.equal(h.candidate_against_validated.validated_files, 0);
  });
});

test("the index is a SQLite file under the output directory, holds sums and no row of an input, and a rerun keeps the earlier one", async () => {
  await withCwd(async (cwd) => {
    const a = await census(cwd, "a.jsonl", Array.from({ length: 500 }, (_, i): [string, number] => [i % 5 ? "noncandidate" : "candidate", i]));
    const first = await run(cwd, { censuses: [{ host: "a", file: a }] });
    assert.match(first.answer.index.file, /^work\/s1\/tool-output\/ransomware_scope_report-index-[0-9a-f]{16}\.sqlite$/);
    const file = join(cwd, first.answer.index.file);
    const dump = spawnSync("python3", ["-c", "import sqlite3,sys\nd=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)\nprint(d.execute('select count(*) from agg').fetchone()[0], d.execute(\"select a,b from agg where kind='census' and key='candidate'\").fetchone())", file], { encoding: "utf8" });
    assert.equal(dump.stdout.trim(), "2 (100, 24750)", dump.stderr);
    const text = (await readFile(file)).toString("latin1");
    assert.ok(!text.includes("x/123"), "no row of the input is in the index");
    const same = await run(cwd, { censuses: [{ host: "a", file: a }] });
    assert.equal(same.answer.index.file, first.answer.index.file, "the same bytes are named again");
    const more = await census(cwd, "more.jsonl", Array.from({ length: 501 }, (_, i): [string, number] => [i % 5 ? "noncandidate" : "candidate", i]));
    const second = await run(cwd, { censuses: [{ host: "a", file: more }] });
    assert.match(second.answer.index.file, /-2\.sqlite$/, "other bytes take the next free name and the earlier index stays");
    assert.equal(await exists(file), true);
    // nothing was written outside the output directory
    const scaffolding = new Set(["inputs/AF-Case2.E01", "inputs/Webserver.E01", "bin/icat", "icat-args.txt", "a.jsonl", "more.jsonl"]);
    const all = Object.keys(await filesUnder(cwd)).filter((n) => !n.startsWith("work/s1/tool-output/") && !scaffolding.has(n));
    assert.deepEqual(all, []);
    assert.deepEqual((await readdir(join(cwd, "work", "s1", "tool-output"))).filter((n) => n.startsWith(".")), []);
  });
});

test("host names that are identifier-shaped are withheld on every channel, keep apart by host_id, and come in an order that does not follow the name", async () => {
  await withCwd(async (cwd) => {
    const names = ["WIN-9F8E7D6C5B4A3210", "WIN-1A2B3C4D5E6F7081", "plainhost"];
    const files = [];
    for (const [i, n] of names.entries()) files.push({ host: n, file: await census(cwd, `c${i}.jsonl`, [["candidate", 5 + i]]) });
    const { answer, stdout, stderr } = await run(cwd, { censuses: files });
    const all = [stdout, stderr, ...Object.values(await filesUnder(join(cwd, "work", "s1")))];
    for (const text of all) for (const id of ["9F8E7D6C5B4A3210", "1A2B3C4D5E6F7081"]) assert.ok(!text.includes(id), `${id} is on no channel`);
    assert.equal(new Set(answer.hosts.map((h) => h.host_id)).size, 3);
    assert.equal(answer.hosts.filter((h) => h.host.includes("withheld")).length, 2);
    assert.ok(answer.hosts.some((h) => h.host === "plainhost"));
  });
});

const SLOW_SIGNAL = String.raw`
import os, runpy, sys, time
_real = os.fdopen
def slow(*a, **k):
    time.sleep(float(os.environ["SLOW_OPEN"]))
    return _real(*a, **k)
os.fdopen = slow
script = sys.argv[1]
sys.argv = [script]
runpy.run_path(script, run_name="__main__")
`;

for (const [signal, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
  test(`${signal} while an input is being read: one JSON answer, exit code ${code}, the index and the pages removed`, async () => {
    await withCwd(async (cwd) => {
      const a = await census(cwd, "a.jsonl", Array.from({ length: 100 }, (): [string, number] => ["candidate", 1]));
      const child = spawn("python3", ["-c", SLOW_SIGNAL, REPORT], { cwd, env: { ...process.env, AGENT_ID: "s1", SLOW_OPEN: "8" } });
      const out: Buffer[] = [];
      const err: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => out.push(c));
      child.stderr.on("data", (c: Buffer) => err.push(c));
      const closed = new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
      child.stdin.end(JSON.stringify({ censuses: [{ host: "a", file: a }] }));
      const place = join(cwd, "work", "s1", "tool-output");
      const deadline = Date.now() + 20000;
      while (!((await exists(place)) && (await readdir(place)).length > 0) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
      await new Promise((r) => setTimeout(r, 300));
      child.kill(signal);
      assert.equal(await closed, code, Buffer.concat(err).toString());
      const doc = JSON.parse(Buffer.concat(out).toString()) as Answer;
      assert.equal(doc.status, "failed");
      assert.equal(doc.interrupted, true);
      assert.deepEqual(await readdir(place), []);
    });
  });
}

test("hostile parameters give a JSON refusal and never a traceback", async () => {
  await withCwd(async (cwd) => {
    const deep = (n: number): string => "[".repeat(n) + "]".repeat(n);
    const cases: Array<[string, string]> = [
      ["not json", "{"], ["deep nesting", `{"censuses": ${deep(100000)}}`], ["a huge integer", `{"censuses": [], "limit": ${"9".repeat(5000)}}`],
      ["wrong types", `{"censuses": "x"}`], ["an entry without host", `{"censuses": [{"file": "x"}]}`], ["an array", `[]`], ["no input", `{}`],
      ["an unknown entry key", `{"censuses": [{"host": "h", "file": "x", "run": 1}]}`], ["a host that is a number", `{"censuses": [{"host": 5, "file": "x"}]}`],
      ["expected_hosts of numbers", `{"expected_hosts": [1]}`],
    ];
    for (const [label, input] of cases) {
      const child = spawnSync("python3", [REPORT], { cwd, input, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" }, timeout: 60000 });
      assert.doesNotMatch(child.stderr, /Traceback/, label);
      const doc = JSON.parse(child.stdout) as { status: string };
      assert.equal(doc.status, "failed", `${label}: ${child.stdout}`);
      assert.equal(child.status, 1, label);
    }
    // a named pipe and a missing file are read failures of one input, not a hang or a crash
    spawnSync("mkfifo", [join(cwd, "p.fifo")]);
    const { answer } = await run(cwd, { censuses: [{ host: "h", file: "p.fifo" }, { host: "g", file: "missing.jsonl" }, { host: "k", file: "bad\u0000" }] });
    assert.equal(answer.status, "partial");
    assert.ok(answer.partial_reasons.some((r) => /input_not_read:not_a_regular_file: 1/.test(r)));
    assert.ok(answer.partial_reasons.some((r) => /input_not_read:read_failed: 1/.test(r)));
    assert.ok(answer.partial_reasons.some((r) => /input_not_read:path_invalid: 1/.test(r)));
  });
});

test("the manifest's claims hold: the clock, the accepted parsers, the 100,000-host bound, no percentage, nothing imported from another tool, shared blocks the survey's", async () => {
  const manifest = JSON.parse(await readFile(MANIFEST, "utf8")) as { timeout_seconds: number; description: string; params: Record<string, { description: string }>; example: string };
  const source = await readFile(REPORT, "utf8");
  const max = /DEFAULT_SECONDS, MAX_SECONDS = (\d+), (\d+)/.exec(source)!;
  assert.ok(Number(max[2]) <= manifest.timeout_seconds - 60);
  assert.match(manifest.params.max_seconds!.description, new RegExp(`default ${max[1]}, at most ${max[2]}`));
  for (const p of ["encrypted_survey/3", "encryption_extent/1", "recovery_validate/1"]) {
    assert.ok(manifest.description.includes("`" + p + "`") || manifest.description.includes(p), p);
    assert.ok(source.includes(`"${p}"`), p);
  }
  assert.match(source, /MAX_HOSTS = 100000/);
  assert.match(manifest.description, /At most 100,000 hosts/);
  assert.match(manifest.description, /estate_wide_percentage: null/);
  assert.match(manifest.description, /10,000,000 rows \(261 bytes each, 2\.6 GB\) was read in 76 s at 24 MB resident/);
  JSON.parse(manifest.example);
  const code = source.replace(/"""[\s\S]*?"""/g, "").replace(/^\s*#.*$/gm, "");
  assert.doesNotMatch(code, /subprocess|os\.system|os\.exec|importlib|__import__|pickle|marshal|\beval\(|\bexec\(/);
  assert.doesNotMatch(code, /start_new_session|setsid|process_group/);
  const survey = await readFile(join(PACK, "encrypted_survey", "run.py"), "utf8");
  const block = (text: string, name: string): string => new RegExp(`^# BEGIN SHARED ${name}\\n[\\s\\S]*?^# END SHARED ${name}$`, "m").exec(text)![0];
  for (const name of ["PLACE", "PAGE", "STOP", "WITHHOLDING", "NAMES", "BACKSTOP"]) assert.equal(block(source, name), block(survey, name), name);
  assert.equal(((await stat(REPORT)).mode & 0o111) !== 0, true);
  // the leaves that name the tool list it and are no longer method only
  const pack = JSON.parse(await readFile(join(PACK, "..", "pack.json"), "utf8")) as { method_only: Array<{ path: string }>; tools: string[] };
  for (const leaf of ["scope/phase-timeline", "reporting/conclusions-and-controls"]) {
    assert.ok(!pack.method_only.some((m) => m.path === `skills/${leaf}.md`), leaf);
    assert.match(await readFile(join(PACK, "..", "skills", `${leaf}.md`), "utf8"), /^tools: \[ransomware_scope_report\]$/m);
  }
  assert.ok(pack.tools.includes("ransomware_scope_report"));
});
