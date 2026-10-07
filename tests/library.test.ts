/**
 * The investigation library, held to its own contract (library/README.md):
 * the metadata block the picker reads, the sections the swarm's contract
 * needs, checks the finish line can run, and none of the mistakes the
 * eighteen published runs taught (a bare `find inputs` under a bind, a
 * harness event named as a tool, a check that leaks an answer, `## Seats`).
 * The first half exercises the module on a scratch library; the second
 * lints every entry that ships.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { countChecks } from "../scripts/ui/goals.ts";
import {
  LIBRARY_CATEGORIES,
  LIBRARY_EVIDENCE,
  LIBRARY_OS,
  libraryDir,
  listLibrary,
  parseFrontMatter,
  readLibraryEntry,
} from "../scripts/ui/library.ts";

const REPO = dirname(dirname(fileURLToPath(import.meta.url)));
const run = promisify(execFile);

const ENTRY = `---
title: Scratch case
summary: A case for the test
evidence: disk-image, logs
os: windows
tags: one, two
inputs: whatever
seats: 3
cap_usd: 12.5
wall_clock: 45
unknown_key: kept but ignored
---
## Goal

Something.

## Definition of done

A thing exists.

## Checks

- \`test -f work/report.md\`
- \`test -f work/timeline.md\`
`;

test("the metadata block is parsed and stripped; a file without one is all body", () => {
  const { meta, body } = parseFrontMatter(ENTRY);
  assert.equal(meta.title, "Scratch case");
  assert.equal(meta.evidence, "disk-image, logs");
  assert.equal(meta.unknown_key, "kept but ignored");
  assert.ok(body.startsWith("## Goal\n"), `body starts at the goal: ${JSON.stringify(body.slice(0, 20))}`);
  assert.deepEqual(parseFrontMatter("## Goal\n\nno block\n"), { meta: {}, body: "## Goal\n\nno block\n" });
  const open = "---\ntitle: never closed\n## Goal\n";
  assert.deepEqual(parseFrontMatter(open), { meta: {}, body: open }, "a block that never closes is not a block");
});

test("the library lists entries by category, reads one with its metadata, and refuses what is not an entry", async () => {
  const root = await mkdtemp(join(tmpdir(), "library-"));
  try {
    const lib = libraryDir(root);
    await mkdir(join(lib, "windows"), { recursive: true });
    await mkdir(join(lib, "logs"), { recursive: true });
    await mkdir(join(lib, "not-a-category"), { recursive: true });
    await writeFile(join(lib, "README.md"), "# not an entry\n");
    await writeFile(join(lib, "windows", "scratch-case.md"), ENTRY);
    await writeFile(join(lib, "logs", "plain.md"), "## Goal\n\nPlain.\n\n## Definition of done\n\nx\n");
    await writeFile(join(lib, "windows", "Bad Name.md"), ENTRY);
    await writeFile(join(lib, "not-a-category", "orphan.md"), ENTRY);
    await writeFile(join(root, "outside.md"), ENTRY);
    await symlink(join(root, "outside.md"), join(lib, "windows", "linked.md"));

    const entries = await listLibrary(root);
    assert.deepEqual(
      entries.map((e) => e.id),
      ["windows/scratch-case", "logs/plain"],
      "category order is the library's, a README, a bad name, an unknown category and a symlink are not entries",
    );
    const scratch = entries[0];
    assert.equal(scratch.title, "Scratch case");
    assert.deepEqual(scratch.evidence, ["disk-image", "logs"]);
    assert.deepEqual(scratch.tags, ["one", "two"]);
    assert.equal(scratch.seats, 3);
    assert.equal(scratch.cap_usd, 12.5);
    assert.equal(scratch.wall_clock, 45);
    assert.equal(scratch.checks, 2);
    assert.equal(scratch.has_definition_of_done, true);
    assert.equal(entries[1].title, "Plain.", "no block: the title is the first line under the goal");
    assert.equal(entries[1].os, "any");

    const doc = await readLibraryEntry(root, "windows/scratch-case");
    assert.ok(doc.text.startsWith("## Goal"), "the text the editor gets starts after the block");
    assert.ok(!doc.text.includes("cap_usd"), "the block is gone from the text");

    await assert.rejects(readLibraryEntry(root, "windows/nope"), /404|no library entry/);
    await assert.rejects(readLibraryEntry(root, "windows/linked"), /not a library entry|points outside|symlink/);
    await assert.rejects(readLibraryEntry(root, "../outside"), /library id/);
    await assert.rejects(readLibraryEntry(root, "windows/../outside"), /library id/);
    await assert.rejects(readLibraryEntry(root, "not-a-category/orphan"), /library id/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// --- the entries that ship ------------------------------------------------

const RESERVED_EVENTS = [
  "inputs_check",
  "inputs_guard",
  "inputs_violation",
  "claim_violation",
  "agent_start",
  "agent_stop",
  "finish_line",
  "idle_nudge",
  "sentinel_nudge",
];

function section(body: string, heading: RegExp): string | null {
  const lines = body.split("\n");
  const at = lines.findIndex((l) => heading.test(l.trim()));
  if (at === -1) return null;
  const out: string[] = [];
  for (let i = at + 1; i < lines.length; i++) {
    if (/^#{1,6}\s/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out.join("\n");
}

function checksOf(body: string): string[] {
  const out: string[] = [];
  const sec = section(body, /^##\s+Checks\s*$/);
  if (sec === null) return out;
  for (const line of sec.split("\n")) {
    if (!/^\s*[-*]\s/.test(line)) continue;
    for (const m of line.matchAll(/`+([^`]+)`+/g)) out.push(m[1].trim());
  }
  return out;
}

test("every entry that ships keeps the library's contract", async () => {
  const entries = await listLibrary(REPO);
  // LIBRARY_MIN lets an author lint a library that is still being written.
  const min = Number(process.env.LIBRARY_MIN ?? 30);
  assert.ok(entries.length >= min, `the library ships at least ${min} investigations, found ${entries.length}`);
  const titles = new Set<string>();
  const problems: string[] = [];
  const bad = (id: string, what: string) => problems.push(`${id}: ${what}`);

  for (const entry of entries) {
    const file = join(libraryDir(REPO), entry.category, `${entry.slug}.md`);
    const raw = await readFile(file, "utf8");
    const { meta, body } = parseFrontMatter(raw);
    const id = entry.id;

    // The block the picker reads.
    if (!meta.title) bad(id, "no title in the metadata block");
    if (!meta.summary) bad(id, "no summary in the metadata block");
    if (titles.has(entry.title)) bad(id, `title is not unique: ${entry.title}`);
    titles.add(entry.title);
    if (!entry.evidence.length) bad(id, "no evidence kinds");
    for (const kind of entry.evidence) {
      if (!(LIBRARY_EVIDENCE as readonly string[]).includes(kind)) bad(id, `unknown evidence kind ${kind}`);
    }
    if (!(LIBRARY_OS as readonly string[]).includes(entry.os)) bad(id, `unknown os ${entry.os}`);
    if (!entry.tags.length) bad(id, "no tags");
    if (!entry.inputs) bad(id, "no inputs line: what does the operator put under inputs/?");
    // swarm.sh reads this instead of guessing sets from the goal's words.
    if (!/^(dfir|crypto|linux)(,(dfir|crypto|linux))*$/.test(String(meta.toolbox ?? "").replace(/\s/g, ""))) bad(id, "no toolbox line naming the sets from dfir, crypto, linux");
    if (meta.category && meta.category !== entry.category) bad(id, `category ${meta.category} is not the directory ${entry.category}`);
    if (entry.seats !== undefined && (entry.seats < 1 || entry.seats > 12)) bad(id, `seats ${entry.seats} is not a team`);
    if (raw.length > 32_000) bad(id, `${raw.length} characters: over the console's 32,000`);
    if (raw.length < 4_000) bad(id, `${raw.length} characters: too thin to be specific`);

    // The sections the contract needs, in order.
    const order = ["## Goal", "### Questions the report has to answer", "### Ground rules", "## How to divide the work", "## Definition of done", "## Checks"];
    let last = -1;
    for (const h of order) {
      const at = body.split("\n").findIndex((l) => l.trim() === h);
      if (at === -1) bad(id, `missing section ${h}`);
      else if (at < last) bad(id, `section ${h} is out of order`);
      last = Math.max(last, at);
    }
    if (/^##\s+Seats\s*$/m.test(body)) bad(id, "has a ## Seats section; the harness assigns nobody anything");

    // The questions and the heading loop agree.
    const questions = section(body, /^###\s+Questions the report has to answer\s*$/) ?? "";
    const numbers = [...questions.matchAll(/^(\d+)\.\s/gm)].map((m) => Number(m[1]));
    if (numbers.length < 5) bad(id, `${numbers.length} questions; an investigation asks at least five`);
    for (let i = 0; i < numbers.length; i++) if (numbers[i] !== i + 1) bad(id, `questions are not numbered 1..N (${numbers.join(",")})`);
    const loop = /for n in ((?:\d+ ?)+); do grep -q "\^## \$n\\\." work\/report\.md/.exec(body);
    if (!loop) bad(id, "no heading loop check over work/report.md");
    else {
      const listed = loop[1].trim().split(/\s+/).map(Number);
      if (listed.length !== numbers.length) bad(id, `the heading loop counts ${listed.length} questions, the list has ${numbers.length}`);
    }

    // The ground rules and the division the runs converged on.
    // Entries wrap at 76 columns, so a phrase may break across lines.
    const flat = (s: string | null) => (s ?? "").replace(/\s+/g, " ");
    const rules = flat(section(body, /^###\s+Ground rules\s*$/));
    for (const must of ["read-only", "work/extracted/<your id>/", "`record`", "kind=ioc", "labelled as one", "Never make a network request", "make_tool", "English", "never a credential", "never running"]) {
      if (!rules.includes(must)) bad(id, `ground rules do not say: ${must}`);
    }
    // The packs' index is in every agent's prompt and the worker prompt says how to use it. A goal that tells the
    // agents to call skill() with no id has each of them read the index again: ~30 tokens of pointer when the
    // prompt carries it whole, the whole of it (up to ~3.4k tokens for twelve packs) when the prompt shows routers only.
    if (/call it once with no id|`skill` is in your tool list|skill\(\) with no/.test(flat(body))) {
      bad(id, "tells the agents to call skill() for the index: the index is already in their prompt, and the worker prompt carries the protocol");
    }
    // Volatility's windows.* plugins need an ISF; under the default netguard
    // they fail unless the kickoff allowed the symbol server by name.
    if (/Volatility/.test(body) && !body.includes("isf-server.techanarchy.net")) {
      bad(id, "lists Volatility but does not name the symbol server (--allow-host isf-server.techanarchy.net)");
    }
    const divide = flat(section(body, /^##\s+How to divide the work\s*$/));
    // The report author and the critic (ledger version 4): answers from the ledger, the critic's acts on them.
    for (const must of ["name(name, doing)", "sign-off", "ledger/ledger.md", "cannot be the one who certifies", "**Report author and critic.**", "`record(kind=answer)`", "`summary` and `narrative`", "`attest`", "`dispute`", "The critic writes no answer; the author attests nothing of their own. The sign-off is these acts, not a post."]) {
      if (!divide.includes(must)) bad(id, `division of work does not say: ${must}`);
    }
    const dod = flat(section(body, /^##\s+Definition of done\s*$/));
    for (const must of ["work/report.md", "one `answer` entry per question", "one each for `summary` and `narrative`", "named by a limitation", "has recorded `attest` or `dispute` on each answer", "work/timeline.md", "inputs/` is unchanged"]) {
      if (!dod.includes(must)) bad(id, `definition of done does not mention ${must}`);
    }
    if (/SIGN-OFF/.test(dod)) bad(id, "the definition of done still asks for a SIGN-OFF post; the sign-off is the critic's acts on the answers");

    // The checks: parseable, runnable, and none of the known traps.
    const checks = checksOf(body);
    if (checks.length < 6) bad(id, `${checks.length} checks; the standard set alone is seven`);
    if (countChecks(body) !== checks.length) bad(id, "the console would count the checks differently from this test");
    const text = checks.join("\n");
    for (const must of ["test -f work/report.md", "test -f work/timeline.md", "ledger/entries.jsonl", `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections`, `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`]) {
      if (!text.includes(must)) bad(id, `standard check missing: ${must}`);
    }
    // The answers check names every question the goal numbers, and the summary and the narrative;
    // a brief's questions are counted from the brief.
    const answersCheck = checks.find((c) => c.includes("scripts/check-answers.ts")) ?? "";
    const want = [...numbers.map(String), "summary", "narrative"].join(",");
    if (!answersCheck.endsWith(`--sections ${want}`) && !answersCheck.endsWith("--sections-in inputs/CASE.md --sections summary,narrative")) {
      bad(id, `the answers check does not name questions 1..${numbers.length}, summary and narrative: ${answersCheck}`);
    }
    if (answersCheck.includes("--report")) bad(id, "the answers check reads the report; it reads the ledger's answers");
    if (/find +inputs\b/.test(text) && !/find -[HL] inputs/.test(text)) bad(id, "a check walks inputs/ with a bare find");

    // The timeline counts dated rows, with no header arithmetic, and the
    // ledger it is built from holds at least three quarters of them.
    const rows = /at least (\d+) dated rows \(the ISO 8601 UTC time in the first column, after any `#` index\)/.exec(dod);
    if (!rows) bad(id, "the definition of done does not fix the timeline's dated rows and their time column");
    else {
      const x = Number(rows[1]);
      const dated = `test "$(grep -cE '^\\| *([0-9]+ *\\| *)?[0-9]{4}-[0-9]{2}-[0-9]{2}' work/timeline.md)" -ge ${x}`;
      if (!text.includes(dated)) bad(id, `the timeline check does not count ${x} dated rows`);
      const ledger = /grep -c '"kind":"event"' ledger\/entries\.jsonl\)" -ge (\d+)/.exec(text);
      const floor = /ledger holds the dated events the narrative/.test(dod) ? 1 : Math.ceil(0.75 * x);
      if (!ledger || Number(ledger[1]) < floor) bad(id, `the ledger event floor is below ${floor} for ${x} timeline rows`);
    }
    if (/grep -c '\^\| ' work\/timeline\.md/.test(text)) bad(id, "counts every table line in work/timeline.md, not dated rows");
    if (/head -\d+ work\/timeline\.md/.test(text)) bad(id, "looks for the timeline's header in the file's first lines, not its header row");
    // "Every answer cites evidence", held per numbered section (library/README.md).
    if (!checks.some((c) => c.startsWith("awk 'BEGIN{") && c.includes("4*b>n") && c.endsWith("work/report.md"))) {
      bad(id, "no per-section citation check over work/report.md");
    }
    // A bare word in prose is not a citation: "offset" needs its number, a hypothesis its label.
    const cite = checks.find((c) => c.includes("4*b>n")) ?? "";
    if (/\|hypothesis[|/]/.test(cite) || !cite.includes("offset|record ?id|event ?id)[ #:=]*[0-9]")) bad(id, "the citation check counts a bare word as a citation");
    // A count of files passes on an empty rule or a stray extract; check what the file holds.
    if (/find work\/rules -name '\*\.yar\*' 2>\/dev\/null \| wc -l/.test(text)) bad(id, "counts YARA files instead of checking a rule is declared");
    if (text.includes("work/rules") && !checks.some((c) => c.startsWith("command -v yara >/dev/null || exit 0;"))) bad(id, "checks work/rules without the guarded compile check");
    if (/find work\/extracted -type f/.test(text)) bad(id, "counts extracted files instead of reading work/extracted/**/SHA256SUMS");
    if (text.includes("SHA256SUMS") && !/sha256sum -c.*shasum -a 256 -c/.test(text)) bad(id, "counts SHA256SUMS lines without verifying them");
    if (/find work\/rules -name /.test(text)) bad(id, "finds YARA files with -name, which misses .YAR");
    // Under pipefail, grep -q ending a pipe can fail a check that matched (SIGPIPE upstream).
    if (checks.some((c) => /\| *grep -q \.$/.test(c))) bad(id, "a check ends a pipe with grep -q");
    for (const c of checks) {
      if (c.includes("`")) bad(id, `a check holds a backtick: ${c}`);
      try {
        await run("bash", ["-n", "-c", c]);
      } catch {
        bad(id, `bash -n rejects a check: ${c}`);
      }
    }
    const checksSection = section(body, /^##\s+Checks\s*$/) ?? "";
    if (text.includes("inputs_check") && !/harness writes itself/.test(checksSection)) {
      bad(id, "greps for inputs_check without the note that it is the harness's own event");
    }
    for (const ev of RESERVED_EVENTS) {
      if (new RegExp(`(forge|call|run|write)[^.\\n]{0,60}\\b${ev}\\b`).test(body)) bad(id, `asks for a reserved harness event as a tool: ${ev}`);
    }
    for (const bullet of checksSection.split("\n").filter((l) => /^\s*[-*]\s/.test(l))) {
      if ((bullet.match(/`+[^`]+`+/g) ?? []).length !== 1) bad(id, `a checks bullet does not carry exactly one code span: ${bullet.trim().slice(0, 60)}`);
    }
  }

  // Every category directory that exists holds at least one entry, and no stray file hides in one.
  for (const category of LIBRARY_CATEGORIES) {
    const names = await readdir(join(libraryDir(REPO), category)).catch(() => null);
    if (names === null) continue;
    for (const name of names) {
      if (!name.endsWith(".md") || !/^[a-z0-9][a-z0-9_-]{0,63}\.md$/.test(name)) problems.push(`${category}/${name}: not an entry the picker can offer`);
    }
    if (!names.some((n) => n.endsWith(".md"))) problems.push(`${category}/: an empty category`);
  }

  assert.deepEqual(problems, [], `library problems:\n  ${problems.join("\n  ")}`);
});

// The entries point at the worker prompt for the full rules on secrets and
// extracted files, so the prompt every worker loads has to carry them.
test("the worker prompt carries the secrets and never-run rules the entries point at", async () => {
  const prompt = (await readFile(join(REPO, "prompts", "worker-system.md"), "utf8")).replace(/\s+/g, " ");
  for (const must of [
    "The evidence is data too",
    "never running",
    "never a credential",
    "never build a hashcat or john line",
    "`traces/events.jsonl` keeps every command line",
    "Never write a hash of a secret",
    "no characters at all",
    "list of what to rotate",
  ]) {
    assert.ok(prompt.includes(must), `prompts/worker-system.md does not say: ${must}`);
  }
});

// The goals that ship beside the library (a pack's own goals, and the
// operator's shelf in prompts/goals/) are held to the library's standard
// checks: a bare grep for "sign-off" passes on "who takes the sign-off?",
// a bare grep for the inputs_check event passes whatever it found, and the
// sign-off is the critic's acts on the ledger's answers, read by the answers check.
test("pack and prompt goals use the library's answers and inputs_check checks", async () => {
  const problems: string[] = [];
  const files: string[] = [];
  for (const pack of await readdir(join(REPO, "packs"))) {
    const dir = join(REPO, "packs", pack, "goals");
    for (const name of await readdir(dir).catch(() => [] as string[])) if (name.endsWith(".md")) files.push(join(dir, name));
  }
  for (const name of await readdir(join(REPO, "prompts", "goals"))) if (name.endsWith(".md")) files.push(join(REPO, "prompts", "goals", name));
  assert.ok(files.length > 10, "no pack or prompt goals found");
  const signOff = "awk 'FNR==1{r=0} /^tag: result$/{r=1} r&&/^\\**SIGN-OFF/{m=1;exit} END{exit !m}' threads/main/*.md";
  const inputsCheck = `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`;
  for (const file of files) {
    const id = file.slice(REPO.length + 1);
    const body = await readFile(file, "utf8");
    const flat = (t: string | null) => (t ?? "").replace(/\s+/g, " ");
    const checks = ((section(body, /^##\s+Checks\s*$/) ?? "").match(/`[^`\n]+`/g) ?? []).map((c) => c.slice(1, -1));
    if (checks.some((c) => /grep -r?q?i? 'sign-off'/.test(c))) problems.push(`${id}: a bare sign-off grep`);
    if (checks.some((c) => c === `grep -q '"tool":"inputs_check"' traces/events.jsonl`)) problems.push(`${id}: a bare inputs_check grep`);
    const dod = flat(section(body, /^##\s+Definition of done\s*$/));
    if (/sign-off/i.test(dod)) {
      if (!checks.includes(signOff)) problems.push(`${id}: the definition of done asks for a sign-off and no check reads one`);
      if (!dod.includes("`SIGN-OFF:`")) problems.push(`${id}: the definition of done does not say how a sign-off starts`);
    }
    if (/inputs\/` is unchanged/.test(dod) && !checks.includes(inputsCheck)) problems.push(`${id}: inputs/ must be unchanged and no check reads inputs_check`);
    // The harness assigns nobody anything (worker-system.md), so a goal that
    // says seats are assigned, or lists them, contradicts the contract the
    // agents read beside it: the c09 goal still did, and agents spent turns on it.
    for (const seat of [/seats are assigned/i, /^##\s+Seats\s*$/m, /\bseats are\s+suggestions\b/i, /\bthe (?:timeline|critic) seat\b/i, /\bSuggested seats\b/i, /\bruns \w+ seats\b/i, /\bone seat\b/i]) {
      if (seat.test(body)) problems.push(`${id}: seat language (${seat.source}); nobody is given a seat`);
    }
    // A goal whose report answers numbered questions is held to the library's model (ledger version 4):
    // the report author and the critic, an answer entry per question plus the summary and the narrative,
    // the critic's attest or dispute on each, and the answers check naming every question.
    const loop = /for n in ((?:\d+ ?)+); do grep -q "\^## \$n\\\." work\/report\.md/.exec(body);
    if (!loop) continue;
    if (/SIGN-OFF/.test(body)) problems.push(`${id}: still asks for a SIGN-OFF post; the sign-off is the critic's acts on the answers`);
    const divide = flat(section(body, /^##\s+How to divide the work\s*$/));
    for (const must of ["**Report author and critic.**", "`record(kind=answer)`", "`summary` and `narrative`", "`attest`", "`dispute`", "The critic writes no answer; the author attests nothing of their own. The sign-off is these acts, not a post."]) {
      if (!divide.includes(must)) problems.push(`${id}: the division of work does not say: ${must}`);
    }
    for (const must of ["one `answer` entry per question", "one each for `summary` and `narrative`", "named by a limitation", "has recorded `attest` or `dispute` on each answer"]) {
      if (!dod.includes(must)) problems.push(`${id}: the definition of done does not mention ${must}`);
    }
    const ids = [...loop[1].trim().split(/\s+/), ...(checks.includes("grep -q '^## Bonus' work/report.md") ? ["bonus"] : [])];
    const answers = checks.find((c) => c.includes("scripts/check-answers.ts")) ?? "";
    if (!answers.endsWith(`--sections ${[...ids, "summary", "narrative"].join(",")}`)) problems.push(`${id}: the answers check does not name questions ${ids.join(",")}, summary and narrative: ${answers || "(none)"}`);
  }
  assert.deepEqual(problems, [], `goal problems:\n  ${problems.join("\n  ")}`);
});

// The joint review's prompt list (2026-09-27): the lead register in the
// worker prompt, the library's guidance and the three hardest CTF goals.
test("the worker prompt, the library and the three CTF goals carry lead-first coordination", async () => {
  const flat = (t: string) => t.replace(/\s+/g, " ");
  const prompt = flat(await readFile(join(REPO, "prompts", "worker-system.md"), "utf8"));
  for (const must of [
    "Lead first: before you start work a peer could also be doing, read `leads` and claim the lead",
    "`take: true`",
    "Interpret every job you run",
    "A citation in refs alone does not interpret it",
    "When your slice ends, take the ready lead the header ranks first",
    "Never leave a lead active and silent",
    "needs_operator is for anything outside the evidence and the allowlist",
    "A turn that ended in a provider error frees nothing",
  ]) {
    assert.ok(prompt.includes(must), `prompts/worker-system.md does not say: ${must}`);
  }
  const readme = flat(await readFile(join(REPO, "library", "README.md"), "utf8"));
  assert.ok(readme.includes("**Leads.** The work you find along the way goes in the lead register."), "library/README.md has no leads paragraph");
  assert.ok(readme.includes("--existence <n>"), "library/README.md does not say how an existence question is named");
  for (const goal of ["belkactf6-bogus-bill.md", "dfir-c10-meeting-location.md", "dfir-c09-encrypt-them-all.md"]) {
    const body = flat(await readFile(join(REPO, "prompts", "goals", goal), "utf8"));
    for (const must of ["**Leads.**", "`lead_open`", "`interprets`", "take the ready lead the header ranks first", "`needs_operator`"]) {
      assert.ok(body.includes(must), `${goal} does not say: ${must}`);
    }
  }
});
