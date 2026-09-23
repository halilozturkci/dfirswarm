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
    for (const must of ["read-only", "work/extracted/<your id>/", "`record`", "kind=ioc", "labelled as one", "Never make a network request", "make_tool", "English", "`skill` is in your tool list", "never a credential", "never running"]) {
      if (!rules.includes(must)) bad(id, `ground rules do not say: ${must}`);
    }
    const divide = flat(section(body, /^##\s+How to divide the work\s*$/));
    for (const must of ["name(name, doing)", "sign-off", "ledger/ledger.md", "cannot be the one who certifies"]) {
      if (!divide.includes(must)) bad(id, `division of work does not say: ${must}`);
    }
    const dod = flat(section(body, /^##\s+Definition of done\s*$/));
    for (const must of ["work/report.md", "sign-off", "work/timeline.md", "inputs/` is unchanged"]) {
      if (!dod.includes(must)) bad(id, `definition of done does not mention ${must}`);
    }

    // The checks: parseable, runnable, and none of the known traps.
    const checks = checksOf(body);
    if (checks.length < 6) bad(id, `${checks.length} checks; the standard set alone is seven`);
    if (countChecks(body) !== checks.length) bad(id, "the console would count the checks differently from this test");
    const text = checks.join("\n");
    for (const must of ["test -f work/report.md", "test -f work/timeline.md", "ledger/entries.jsonl", "grep -rqi 'sign-off' threads/main/", `grep -q '"tool":"inputs_check"' traces/events.jsonl`]) {
      if (!text.includes(must)) bad(id, `standard check missing: ${must}`);
    }
    if (/find +inputs\b/.test(text) && !/find -[HL] inputs/.test(text)) bad(id, "a check walks inputs/ with a bare find");
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
