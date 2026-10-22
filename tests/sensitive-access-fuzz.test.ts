/**
 * The access record's reader must never crash on a chain file it was handed
 * damaged, hand-made or hostile (docs/adr/0018): a missing file is empty, a
 * file that cannot be read and a line that is not the shape is a problem line,
 * and what the other files hold is still read. A thousand seeded cases damage
 * the journal, the trace, the ledger, the audit and the job manifests, singly
 * and together; the rules and the hub's line are fed random rows.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { after, test } from "node:test";
import { sensitiveIndex } from "../scripts/output-hygiene.ts";
import { LOWER_BOUND_SENTENCE, accessRecord, classifyTraceRow, parseSensitiveAccessArgs, provenance, renderAccess, verifyAccess, type AccessRecord } from "../scripts/sensitive-access.ts";
import { fixtureFiles, tempBase, writeFiles } from "./sensitive-access-fixture.ts";

const CASES = 1000;
const SCRIPT = join(import.meta.dirname, "..", "scripts", "sensitive-access.ts");
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

/** mulberry32: a seeded generator, so a failing case is the same case again. */
function prng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number) => Math.floor(next() * n);
  const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)];
  return { next, int, pick };
}
type Rng = ReturnType<typeof prng>;

const STRINGS = ["", "j000001", "j000034", "../../etc/passwd", "store/jobs/j000001/out/values.jsonl", "store/jobs/*", "a".repeat(300), "\u0000‮\ud800", "declared", "secret_output", "derived", "named_in_text", "seat_read", "path", "maybe", "system", "E-1", "job:j000001/x", "tool-output/a/b", "__proto__", "constructor", "0".repeat(64), "x\ny"];
function randomJson(r: Rng, depth = 0): unknown {
  switch (r.int(depth > 2 ? 7 : 9)) {
    case 0: return null;
    case 1: return r.next() < 0.5;
    case 2: return r.pick([0, -1, 1.5, 9007199254740993, 1e308, -0]);
    case 3: case 4: case 5: return r.pick(STRINGS);
    case 6: return r.pick(STRINGS).repeat(r.int(40));
    case 7: return Array.from({ length: r.int(4) }, () => randomJson(r, depth + 1));
    default: return Object.fromEntries(Array.from({ length: r.int(5) }, () => [r.pick(["type", "job", "at", "seq", "scope", "sensitive", "because", "from", "how", "object", "auto_declared", "could_read_sensitive", "tool", "agent", "args", "result", "refs", "by", "command", "argv", "detail", "files", "path", "sha256", "requester", "spec", "__proto__"]), randomJson(r, depth + 1)]));
  }
}
/** Replace a value somewhere inside a parsed line with a random JSON value. */
function scramble(r: Rng, v: unknown, depth = 0): unknown {
  if (typeof v === "object" && v !== null && depth < 4 && r.next() < 0.7) {
    const copy: unknown = Array.isArray(v) ? [...v] : { ...v };
    const keys = Object.keys(copy as object);
    if (!keys.length) return randomJson(r);
    const k = r.pick(keys);
    (copy as Record<string, unknown>)[k] = scramble(r, (copy as Record<string, unknown>)[k], depth + 1);
    return copy;
  }
  return randomJson(r);
}
const JUNK = ["", "null", "[]", "5", '"s"', "{", '{"a":', "true", "\u0000\u0001", '{"tool":"sensitive_access","agent":"system"}', "}{", "[[[[[[[[[[", '{"type":"job_committed","job":"j000001","sensitive":"yes"}', "﻿{}"];

/** Damage a JSON-lines text; `bad` is the 1-based line of a line that is not JSON, when one was put in. */
function damage(r: Rng, text: string): { text: string; bad: number | null } {
  let lines = text.split("\n");
  for (let n = r.int(3); n >= 0; n -= 1) {
    const k = r.int(lines.length);
    switch (r.int(7)) {
      case 0: lines = lines.slice(0, k); break;
      case 1: lines[k] = (lines[k] ?? "").slice(0, r.int((lines[k] ?? "").length + 1)); break;
      case 2: lines[k] = r.pick(JUNK); break;
      case 3: lines.splice(k, 0, lines[k] ?? ""); break;
      case 4: lines.splice(k, 1); break;
      default:
        try {
          lines[k] = JSON.stringify(scramble(r, JSON.parse(lines[k] ?? "")));
        } catch {
          lines[k] = JSON.stringify(randomJson(r));
        }
    }
  }
  let bad: number | null = null;
  if (r.next() < 0.4) {
    const k = r.int(lines.length + 1);
    lines.splice(k, 0, `{"torn": ${r.pick(["", "[", "\"x", "tru"])}`);
    bad = k + 1;
  }
  return { text: lines.join("\n"), bad };
}

const EVENT_VIAS = new Set(["declared_input", "auto_declared", "api_page", "path", "text", "cited", "operator_view"]);
const EVIDENCE = new Set(["harness_verified_link", "harness_observed_read", "agent_claim"]);
function wellFormed(rec: AccessRecord) {
  assert.ok(Array.isArray(rec.events) && Array.isArray(rec.jobs) && Array.isArray(rec.reach) && Array.isArray(rec.requests) && Array.isArray(rec.problems));
  assert.ok(rec.problems_total >= rec.problems.length && rec.problems.length <= 200);
  for (const e of rec.events) {
    assert.ok(EVENT_VIAS.has(e.via) && EVIDENCE.has(e.evidence) && ["certain", "path", "text", "maybe"].includes(e.certainty), JSON.stringify(e));
    assert.equal(typeof e.ref, "string");
    assert.ok(e.job === null || typeof e.job === "string");
  }
  for (const p of rec.problems) assert.ok(typeof p.file === "string" && typeof p.why === "string");
  assert.equal(rec.lower_bound, LOWER_BOUND_SENTENCE);
}

test(`${CASES} damaged runs: the reader never throws, reads what is whole and names what is not`, async () => {
  const root = await tempBase("access-fuzz-");
  dirs.push(root);
  const r = prng(20261021);
  const targets = ["run1/store/journal.jsonl", "run1/traces/events.jsonl", "run1/ledger/entries.jsonl", "operator-audit.jsonl", "run1/store/jobs/j000001/manifest.json", "run1/store/jobs/j000034/manifest.json", "run1/team.json"] as const;
  let withProblem = 0;
  for (let i = 0; i < CASES; i += 1) {
    const where = `case ${i}`;
    const base = join(root, `c${i}`);
    const files = fixtureFiles();
    const touched = new Set<string>();
    const knownBad: Array<{ file: string; line: number }> = [];
    const fileLevel: Array<{ rel: string; how: string }> = [];
    for (let n = 1 + r.int(3); n > 0; n -= 1) {
      const rel = r.pick(targets);
      touched.add(rel);
      const roll = r.int(12);
      if (roll === 0) { fileLevel.push({ rel, how: "missing" }); continue; }
      if (roll === 1) { fileLevel.push({ rel, how: "dir" }); continue; }
      if (roll === 2) { fileLevel.push({ rel, how: "link" }); continue; }
      const name = rel.replace(/^run1\//, "");
      for (let k = knownBad.length - 1; k >= 0; k -= 1) if (knownBad[k].file === name) knownBad.splice(k, 1);
      if (roll === 3) { files[rel] = Buffer.from(Array.from({ length: r.int(600) }, () => r.int(256))).toString("latin1"); continue; }
      if (roll === 4) { files[rel] = "{".repeat(100_000); continue; }
      const d = damage(r, files[rel]);
      files[rel] = d.text;
      if (d.bad !== null && rel.endsWith(".jsonl")) knownBad.push({ file: name, line: d.bad });
    }
    const S = await writeFiles(base, Object.fromEntries(Object.entries(files).filter(([rel]) => !fileLevel.some((f) => f.rel === rel))));
    for (const f of new Map(fileLevel.map((f) => [f.rel, f])).values()) {
      const path = join(base, f.rel);
      await mkdir(join(path, ".."), { recursive: true });
      if (f.how === "dir") await mkdir(path, { recursive: true });
      if (f.how === "link") await symlink(join(base, "nowhere"), path).catch(() => undefined);
    }
    let rec: AccessRecord;
    try {
      rec = await accessRecord(S, { derive: true, runsDir: base });
      wellFormed(rec);
      const text = renderAccess(rec, provenance(rec));
      assert.ok(text.endsWith(`${LOWER_BOUND_SENTENCE}\n`), where);
      JSON.stringify(rec);
      await verifyAccess(S);
    } catch (err) {
      throw new Error(`${where}: ${(err as Error).stack}\ntouched: ${[...touched].join(", ")}; file-level: ${JSON.stringify(fileLevel)}`);
    }
    if (rec.problems_total) withProblem += 1;
    // A line that was put in and is not JSON is named, by file and line, when its file was read at all.
    for (const b of knownBad) {
      if (fileLevel.some((f) => f.rel === `run1/${b.file}` || f.rel === b.file)) continue;
      assert.ok(rec.problems.some((p) => p.file === b.file && p.line === b.line) || rec.problems_total > rec.problems.length, `${where}: line ${b.line} of ${b.file} is not named: ${JSON.stringify(rec.problems.slice(0, 5))}`);
    }
    // The files that were not damaged are still read: a partial record, not none.
    const journalWhole = !["run1/store/journal.jsonl", "run1/store/jobs/j000001/manifest.json", "run1/store/jobs/j000034/manifest.json"].some((f) => touched.has(f));
    if (journalWhole) {
      assert.equal(rec.events.filter((e) => e.evidence === "harness_verified_link").length, 3, where);
      if (!touched.has("run1/ledger/entries.jsonl")) assert.equal(rec.events.filter((e) => e.evidence === "agent_claim").length, 2, where);
    }
    if (!touched.has("run1/traces/events.jsonl")) assert.ok(rec.events.some((e) => e.source === "trace" && e.recorded), where);
    // The run is named by team.json: a damaged one names another run, and the audit lines are then not this run's.
    if (!touched.has("operator-audit.jsonl") && !touched.has("run1/team.json")) assert.equal(rec.events.filter((e) => e.via === "operator_view").length, 1, where);
  }
  assert.ok(withProblem > CASES / 4, "the damage is real: a good share of the cases name a problem");
});

test("the command line survives a damaged run too: exit 0, the sentence last, a problem line for what could not be read", async () => {
  const root = await tempBase("access-fuzz-cli-");
  dirs.push(root);
  const r = prng(7);
  for (let i = 0; i < 12; i += 1) {
    const files = fixtureFiles();
    for (const rel of ["run1/store/journal.jsonl", "run1/traces/events.jsonl", "run1/ledger/entries.jsonl"]) files[rel] = damage(r, files[rel]).text;
    const S = await writeFiles(join(root, `c${i}`), files);
    for (const args of [[], ["--json", "--derive"], ["--verify"]]) {
      const out = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", SCRIPT, S, "--runs-dir", join(root, `c${i}`), ...args], { encoding: "utf8" });
      assert.equal(out.status, 0, `case ${i} ${args.join(" ")}: ${out.stderr}`);
      if (args.includes("--json")) JSON.parse(out.stdout);
      else assert.ok(out.stdout.includes(LOWER_BOUND_SENTENCE));
    }
  }
});

test("the rules and the hub's line take any row: random tools and arguments never throw, and nothing outside the index is named", async () => {
  const base = await tempBase("access-fuzz-rules-");
  dirs.push(base);
  const S = await writeFiles(base, fixtureFiles());
  const index = await sensitiveIndex(S);
  const r = prng(99);
  const tools = ["read", "grep", "find", "ls", "bash", "powershell", "edit", "write", "job_run", "", "sensitive_access", "constructor", "__proto__"];
  const bits = ["store/jobs/", "j000001", "j000034", "/out/", "values.jsonl", " ", "*", "{", "store", "/", "find ", "grep -r ", "tool-output/a/b.out", "catalog/gen/g1/", "0123456789abcdef".repeat(4), "\n", "\"", "'", "$(", "; ", "j000010", "../", "."];
  const junk = (): string => Array.from({ length: r.int(30) }, () => r.pick(bits)).join("");
  const copies = new Map([["tool-output/a/b.out", "j000001"]]);
  for (let i = 0; i < CASES; i += 1) {
    const args = r.next() < 0.3 ? randomJson(r) : { command: junk(), path: junk(), file: junk(), cmd: r.next() < 0.5 ? junk() : randomJson(r) };
    const row = { tool: r.pick(tools as unknown[]), args };
    const out = classifyTraceRow(row, index, { sandbox: S, copies });
    for (const c of out) {
      assert.ok(c.job === null || index.jobs.has(c.job), `a job outside the index: ${c.job}`);
      assert.ok(["path", "text", "api_page"].includes(c.via) && Array.isArray(c.paths));
      for (const id of c.candidates ?? []) assert.ok(index.jobs.has(id));
    }
    const parsed = parseSensitiveAccessArgs(randomJson(r));
    assert.equal(typeof parsed.ok, "boolean");
  }
  // Patterns that make a regular expression slow, in a long row.
  const long = ["store/jobs/{a,".repeat(5_000), "{".repeat(100_000), "store/jobs/[".repeat(20_000), "store/jobs/".repeat(30_000), `store/jobs/${"a".repeat(200_000)}`, `grep ${" ".repeat(200_000)}x`, "j".repeat(300_000), `${"a".repeat(100_000)}store`, "tool-output/".repeat(30_000), "0123456789abcdef".repeat(20_000)];
  for (const text of long) {
    const t0 = Date.now();
    classifyTraceRow({ tool: "bash", args: { command: text } }, index, { sandbox: S, copies });
    classifyTraceRow({ tool: "read", args: { path: text } }, index, { sandbox: S, copies });
    classifyTraceRow({ tool: "grep", args: { path: text } }, index, { sandbox: S, copies });
    assert.ok(Date.now() - t0 < 5000, `a row of ${text.length} characters took ${Date.now() - t0} ms`);
  }
});

test("a thousand-line trace of hub lines is read whole, and a very long line is one line", async () => {
  const base = await tempBase("access-fuzz-big-");
  dirs.push(base);
  const files = fixtureFiles();
  const rows: string[] = [];
  for (let i = 0; i < 3000; i += 1) rows.push(JSON.stringify({ ts: "2026-10-21T14:10:00.000Z", agent: "agent-2", tool: "bash", args: { command: `echo ${i} ${"x".repeat(i % 7 === 0 ? 20000 : 10)}` }, result: { ok: true }, sid: "s", seq: i }));
  files["run1/traces/events.jsonl"] = `${rows.join("\n")}\n`;
  const S = await writeFiles(base, files);
  await writeFile(join(base, "touch"), "");
  const rec = await accessRecord(S, { derive: true, runsDir: base });
  assert.deepEqual(rec.problems, []);
  assert.equal(rec.events.filter((e) => e.source === "trace").length, 0, "none of the 3000 rows reaches a sensitive output");
});
