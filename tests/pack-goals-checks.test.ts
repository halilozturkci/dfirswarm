/**
 * The goal templates of every pack: what completion is judged by.
 *
 * A goal's `## Checks` are shell lines the harness runs under `set -euo pipefail`. The owner removed the
 * numeric minimum of `event` entries from them (completion is judged by the answer dispositions that
 * scripts/check-answers.ts reads), so this suite holds three things for every packs/*\/goals/*.md:
 *
 *  - no check counts ledger events against a minimum, reads the ledger, or compares a number;
 *  - the other checks are still there (the report exists, one heading per question, the answer check over
 *    exactly the questions the goal asks, the inputs check, the skill index read);
 *  - each check that reads work/report.md is run the way the harness runs it, on reports of about 300 KB per
 *    answer, and neither fails on a closed pipe nor reads outside the answer it names.
 *
 * It reads the files on disk, so a goal template added by a later pack is held to the same rules.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

type Goal = { id: string; text: string; checks: string[]; questions: number };

function goals(): Goal[] {
  const out: Goal[] = [];
  for (const pack of readdirSync(join(ROOT, "packs")).sort()) {
    let files: string[] = [];
    try { files = readdirSync(join(ROOT, "packs", pack, "goals")).filter((f) => f.endsWith(".md")).sort(); } catch { continue; }
    for (const f of files) {
      const text = readFileSync(join(ROOT, "packs", pack, "goals", f), "utf8");
      const checks = [...text.slice(text.indexOf("## Checks")).matchAll(/^- `(.+)`$/gm)].map((m) => m[1]);
      const asked = /answers questions 1 to (\d+) under the headings/.exec(text.replace(/\s+/g, " "));
      assert.ok(asked, `${pack}/${f}: the definition of done says how many questions it answers`);
      out.push({ id: `${pack}/${f}`, text, checks, questions: Number(asked[1]) });
    }
  }
  return out;
}

const GOALS = goals();

test("there are goal templates to hold, and none counts ledger events against a minimum", () => {
  assert.ok(GOALS.length >= 14, `found ${GOALS.length} goal templates`);
  for (const g of GOALS) {
    assert.ok(g.checks.length >= 5, `${g.id}: has its checks`);
    for (const c of g.checks) {
      assert.doesNotMatch(c, /"kind":"event"|kind\\?":\\?"event/, `${g.id}: a check counts event entries: ${c}`);
      assert.doesNotMatch(c, /grep -c\b[^`]*-ge\s+\d+|-ge\s+\d+/, `${g.id}: a check holds a numeric minimum: ${c}`);
      assert.doesNotMatch(c, /ledger\/|entries\.jsonl/, `${g.id}: a check reads the ledger: ${c}`);
      assert.doesNotMatch(c, /\s-(?:ge|gt|le|lt|eq|ne)\s|>=|<=|\bNR\s*[<>=]/, `${g.id}: a check compares a number: ${c}`);
    }
    assert.doesNotMatch(g.text, /at least \w+ (dated )?events?\b/i, `${g.id}: the prose asks for an event count`);
  }
});

test("the other checks stay: the report, one heading per question, the answers over exactly those questions, the inputs, the skill index", () => {
  for (const g of GOALS) {
    const nums = Array.from({ length: g.questions }, (_, i) => i + 1);
    assert.ok(g.checks.includes("test -f work/report.md"), `${g.id}: the report must exist`);
    assert.ok(g.checks.includes(`for n in ${nums.join(" ")}; do grep -q "^## $n\\." work/report.md || exit 1; done`), `${g.id}: one heading per question 1..${g.questions}`);
    const answers = g.checks.filter((c) => c.includes("scripts/check-answers.ts"));
    assert.equal(answers.length, 1, `${g.id}: one answers check`);
    assert.ok(answers[0].endsWith(`--sections ${nums.join(",")},summary,narrative`), `${g.id}: the answers check names the ${g.questions} questions, the summary and the narrative: ${answers[0]}`);
    assert.equal(g.checks.filter((c) => c.includes('"tool":"inputs_check"') && c.endsWith(`grep -q '"content_ok":true'`)).length, 1, `${g.id}: the inputs check`);
    assert.ok(g.checks.includes(`grep -q '"tool":"skill"' traces/events.jsonl`), `${g.id}: the skill index was read`);
  }
});

/**
 * What a pipe in a check is: a `|` that is neither inside a single-quoted string (a regex or a program text)
 * nor half of `||`. A pipe inside a double-quoted string is still a pipe: `"$(a | b)"` runs one.
 */
function pipes(check: string): boolean {
  const bare = check.replace(/'[^']*'/g, "''").replace(/\|\|/g, "");
  return bare.includes("|");
}

const PHRASES = [
  "Times are UTC.", "Retention and revocation: sessions were revoked.", "A structure at offset 0x00001000.", "The snap length (snaplen) is 262144.",
  "The sample was not executed: static analysis only.", "digest " + "ab12".repeat(16), "No unallocated space was delivered by this logical acquisition.",
  "A full file system extraction, logical, backup, physical or app export.", "Exfiltration conclusion: partial",
  "Recovery position: restorable and tested - one object",
].join("\n");
const FILLER = "A line of the answer that is only filler and names none of the things a check looks for.\n".repeat(3400); // about 300 KB

function section(n: number, body: string): string { return `## ${n}. Answer ${n}\n${body}\n`; }

function runChecks(dir: string, checks: string[], report: string): Map<string, number> {
  mkdirSync(join(dir, "work"), { recursive: true });
  writeFileSync(join(dir, "work", "report.md"), report);
  const res = new Map<string, number>();
  for (const c of checks) {
    const r = spawnSync("bash", ["-c", `set -euo pipefail; ${c}`], { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
    res.set(c, r.status ?? -1);
  }
  return res;
}

test("every check that reads the report passes a 300 KB-per-answer report under set -euo pipefail, whichever answer is long", () => {
  const dir = mkdtempSync(join(tmpdir(), "goal-checks-"));
  try {
    for (const g of GOALS) {
      const reportChecks = g.checks.filter((c) => c.includes("work/report.md") && !c.includes("check-answers.ts"));
      assert.ok(reportChecks.length >= 2, `${g.id}: report checks found`);
      for (const c of reportChecks) assert.ok(!pipes(c), `${g.id}: a pipe in a check that reads the report (grep -q ends early, the writer gets SIGPIPE, pipefail fails the check): ${c}`);
      // The phrases are at the start of every answer and 300 KB of filler follows each of them.
      const all = Array.from({ length: g.questions }, (_, i) => section(i + 1, `${PHRASES}\n${FILLER}`)).join("");
      for (let i = 0; i < 2; i++) for (const [c, status] of runChecks(dir, reportChecks, all)) assert.equal(status, 0, `${g.id}: ${c} (try ${i})`);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a check that names an answer reads that answer only: the same words in the other answers do not satisfy it, and in its own they do", () => {
  const dir = mkdtempSync(join(tmpdir(), "goal-checks-"));
  try {
    let bound = 0;
    for (const g of GOALS) {
      const awks = g.checks.filter((c) => c.startsWith("awk ") && c.includes("work/report.md") && /\^## (\d+)\\\./.test(c));
      for (const c of awks) {
        bound++;
        const k = Number(/\^## (\d+)\\\./.exec(c)![1]);
        const build = (inK: boolean): string => Array.from({ length: g.questions }, (_, i) => section(i + 1, (i + 1 === k) === inK ? `${PHRASES}\n${FILLER}` : FILLER)).join("");
        assert.equal(runChecks(dir, [c], build(false)).get(c), 1, `${g.id}: ${c} is satisfied by words in other answers than ${k}`);
        assert.equal(runChecks(dir, [c], build(true)).get(c), 0, `${g.id}: ${c} is not satisfied by the words in answer ${k}`);
      }
    }
    assert.ok(bound >= 4, `the answer-bound checks were found (${bound})`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a report that says none of what the checks look for fails the ones that look, and a missing heading fails the heading check", () => {
  const dir = mkdtempSync(join(tmpdir(), "goal-checks-"));
  try {
    for (const g of GOALS) {
      const bare = Array.from({ length: g.questions }, (_, i) => section(i + 1, FILLER)).join("");
      const res = runChecks(dir, g.checks.filter((c) => c.includes("work/report.md") && !c.includes("check-answers.ts")), bare);
      for (const [c, status] of res) {
        const looks = !c.startsWith("test -f") && !c.startsWith("for n in") && !c.startsWith("! grep");
        assert.equal(status, looks ? 1 : 0, `${g.id}: ${c} on a report with no phrase`);
      }
      const headings = g.checks.find((c) => c.startsWith("for n in"))!;
      const missing = Array.from({ length: g.questions }, (_, i) => section(i + 1, "x")).slice(1).join("");
      assert.equal(runChecks(dir, [headings], missing).get(headings), 1, `${g.id}: a report without heading 1 passes the heading check`);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the inputs check reads the last inputs_check record of a long trace under pipefail", () => {
  const dir = mkdtempSync(join(tmpdir(), "goal-checks-"));
  try {
    mkdirSync(join(dir, "traces"), { recursive: true });
    const line = (ok: boolean): string => `{"tool":"inputs_check","content_ok":${ok}}\n`;
    const other = '{"tool":"read","path":"inputs/a"}\n'.repeat(12000);
    for (const g of GOALS) {
      const c = g.checks.find((x) => x.includes('"tool":"inputs_check"'))!;
      const run = (trace: string): number => {
        writeFileSync(join(dir, "traces", "events.jsonl"), trace);
        return spawnSync("bash", ["-c", `set -euo pipefail; ${c}`], { cwd: dir, stdio: "ignore" }).status ?? -1;
      };
      assert.equal(run(line(false) + other + line(true) + other), 0, `${g.id}: the last record says the inputs are intact`);
      assert.equal(run(line(true) + other + line(false) + other), 1, `${g.id}: the last record says they are not`);
      assert.equal(run(other), 1, `${g.id}: no record at all`);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
