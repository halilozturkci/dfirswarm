/**
 * The console's words for a team that bills nothing per token. The kickoff
 * records why next to `metered: false` (`unmetered_why`: local or
 * subscription, from the facts its own CLI line reads); one pure function
 * (ui/src/lib/metering.ts) turns the record into the words, and every label
 * site of the console uses it: a subscription team is "subscription · not
 * billed per token" with Pi's dollars an estimate, a local team keeps "local
 * models", and a record without the reason (a run from before it was
 * written) says "unmetered (reason not recorded)", never "free".
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { meteringWords } from "../ui/src/lib/metering.ts";

const ROOT = join(import.meta.dirname, "..");

test("a local team keeps its words, a subscription team says it is not billed per token and that Pi's dollars are an estimate", () => {
  const local = meteringWords({ metered: false, unmetered_why: "local" });
  assert.deepEqual([local.metered, local.label, local.note, local.dollars_estimate], [false, "free", "no metered cost · local models", false]);
  assert.match(local.sentence, /served from this machine or network/);
  const sub = meteringWords({ metered: false, unmetered_why: "subscription" });
  assert.deepEqual([sub.metered, sub.label, sub.note, sub.dollars_estimate], [false, "subscription", "subscription · not billed per token", true]);
  assert.match(sub.sentence, /dollars Pi computes are an estimate/);
  assert.doesNotMatch(`${sub.label} ${sub.note} ${sub.sentence}`, /\bfree\b|local models/);
});

test("a record without the reason says unmetered with the reason not recorded, never free; a metered team has no words", () => {
  for (const record of [{ metered: false }, { metered: false, unmetered_why: null }, { metered: false, unmetered_why: "something else" }]) {
    const old = meteringWords(record);
    assert.equal(old.metered, false);
    assert.equal(old.note, "unmetered (reason not recorded)");
    assert.notEqual(old.label, "free");
    assert.doesNotMatch(`${old.label} ${old.note} ${old.sentence}`, /\bfree\b|local models|subscription/);
  }
  for (const record of [{ metered: true }, {}, null, undefined]) assert.deepEqual(meteringWords(record), { metered: true, label: "", note: "", dollars_estimate: false, sentence: "" });
});

/** The kickoff's word, lifted from swarm.sh as tests/model-teams.test.sh lifts its helpers: the same facts the CLI line reads. */
function kickoffWord(metered: string, subscriptions: string): string {
  const r = spawnSync("bash", ["-c", `set -euo pipefail\neval "$(sed -n '/^unmetered_why_word() {/,/^}/p' "${join(ROOT, "scripts", "swarm.sh")}")"\nunmetered_why_word "$1" "$2"`, "x", metered, subscriptions], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim();
}

test("the kickoff records subscription when any model runs on a subscription, local when none does, and nothing for a metered team", () => {
  assert.equal(kickoffWord("0", ""), "local");
  assert.equal(kickoffWord("0", "anthropic/claude-x"), "subscription");
  assert.equal(kickoffWord("0", "openai-codex/x,anthropic/claude-x"), "subscription", "a mixed team of local and subscription models");
  assert.equal(kickoffWord("1", ""), "");
  assert.equal(kickoffWord("1", "anthropic/claude-x"), "");
});

test("no label site of the console says free or local models by hand: they all ask meteringWords", () => {
  for (const f of ["ui/src/components/team-strip.tsx", "ui/src/screens/detail/budget-panel.tsx", "ui/src/screens/swarm-detail.tsx", "ui/src/screens/detail/threads-panel.tsx", "ui/src/screens/overview.tsx"]) {
    const text = readFileSync(join(ROOT, f), "utf8");
    assert.match(text, /meteringWords/, f);
    assert.doesNotMatch(text, /"free"|`free ·|>\s*free\s*<|free · <|no metered cost · local models|served from this machine or network, so Pi computes/, `${f} still says it by hand`);
  }
});
