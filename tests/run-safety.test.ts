/**
 * The run-safety items from the Breadcrumbs run (2026-10-01), the parts a
 * kickoff in a shell suite cannot reach: the token marks budget.json keeps
 * through every fold and the claim that tells each once
 * (tests/vm-hub.test.ts runs it through the hub); what a provider said
 * answered a call against the model asked for; the derived catalogue's
 * ceiling the kickoff hands the hub; and whose credential each seat used, as
 * custody reads it from the anchor. tests/run-safety.test.sh holds the
 * kickoff's own refusals and records.
 */
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { anchoredCredentials, credentialsWords } from "../scripts/custody.ts";
import { parseJobsConfig } from "../scripts/vm-hub.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function sandbox(): Promise<string> {
  const base = await mkdtemp(join(tmpdir(), "run-safety-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "rs1", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30 });
  return S;
}

test("token marks: whole numbers above zero, ascending, each once; budget.json keeps them through a usage fold", async () => {
  assert.deepEqual(P.tokenMarks([5_000, "1000", 1_000, 0, -3, 2.5, "x", null]), [1_000, 5_000]);
  assert.deepEqual(P.tokenMarks(undefined), []);
  const S = await sandbox();
  const b = await P.readBudget(S);
  await P.writeBudget(S, { ...b, token_alerts: [200_000_000, 100_000_000] });
  assert.deepEqual((await P.readBudget(S)).token_alerts, [100_000_000, 200_000_000]);
  // A seat's usage folded in rewrites the record: the marks stay.
  await P.applySessionUsage(S, "a0", { ...P.emptyAgentBudget(), tokens: 10, calls: 1 });
  assert.deepEqual((await P.readBudget(S)).token_alerts, [100_000_000, 200_000_000]);
  // A run without marks has none: budget.json reads as it always did.
  const plain = await sandbox();
  assert.equal("token_alerts" in (await P.readBudget(plain)), false);
});

test("claimTokenAlerts tells each crossed mark once, in one board post for the marks crossed together, and nothing below a mark", async () => {
  const S = await sandbox();
  const budget = { tokens: 0, token_alerts: [1_000, 2_000, 3_000] };
  assert.deepEqual(await P.claimTokenAlerts(S, { ...budget, tokens: 999 }), []);
  assert.deepEqual(await P.claimTokenAlerts(S, { ...budget, tokens: 2_500 }), [{ mark: 1_000, tokens: 2_500 }, { mark: 2_000, tokens: 2_500 }]);
  assert.deepEqual(await P.claimTokenAlerts(S, { ...budget, tokens: 2_600 }), [], "told already");
  assert.deepEqual(await P.claimTokenAlerts(S, { ...budget, tokens: 3_000 }), [{ mark: 3_000, tokens: 3_000 }]);
  const posts: string[] = [];
  for (const f of await readdir(join(S, "threads", "main"))) posts.push(await readFile(join(S, "threads", "main", f), "utf8"));
  const alerts = posts.filter((p) => p.includes("TOKEN ALERT"));
  assert.equal(alerts.length, 2);
  assert.match(alerts.join("\n"), /past the operator's marks of 1,000, 2,000 \(--token-alert\)/);
  assert.match(alerts.join("\n"), /The next mark is 3,000\./);
  assert.deepEqual((await readdir(join(S, "traces", "token-alerts"))).sort(), ["1000", "2000", "3000"]);
});

test("the model that answered, against the one asked for: the same, an alias resolved to a dated id, or a substitution", () => {
  assert.equal(P.modelAnswered("claude-x", undefined), "same", "a provider that reports nothing is taken at its word");
  assert.equal(P.modelAnswered("claude-x", ""), "same");
  assert.equal(P.modelAnswered("gpt-4o", "gpt-4o"), "same");
  assert.equal(P.modelAnswered("openai/gpt-4o", "GPT-4o"), "same");
  assert.equal(P.modelAnswered("gpt-4o", "gpt-4o-2024-08-06"), "resolved");
  assert.equal(P.modelAnswered("claude-sonnet-x-latest", "claude-sonnet-x-20260101"), "resolved");
  assert.equal(P.modelAnswered("claude-sonnet-x-latest", "claude-haiku-x-20260101"), "substituted");
  assert.equal(P.modelAnswered("claude-x", "claude-x-mini"), "substituted", "a sibling is not a dated form");
  assert.equal(P.modelAnswered("deepseek-v4-pro", "deepseek-v3"), "substituted");
});

test("the derived catalogue's ceiling the kickoff gives reaches the job service; none given leaves the service's default", () => {
  const base = { image: "dfirswarm-base:dev", workers: 2, cpus: 2, memoryMib: 2048, allowHosts: [], openNet: false, packDirs: [] };
  assert.equal(parseJobsConfig({ ...base, derived: true, derivedGenerations: 120 })?.derivedGenerations, 120);
  assert.equal(parseJobsConfig({ ...base, derived: true })?.derivedGenerations, undefined);
  for (const bad of [0, -1, 2.5, "120"]) assert.equal(parseJobsConfig({ ...base, derived: true, derivedGenerations: bad })?.derivedGenerations, undefined, String(bad));
});

test("custody reads whose credential each seat used from the anchor, and says it in one line; an older anchor says nothing", () => {
  const c = anchoredCredentials({
    customer_case: false,
    seats: [
      { seat: "s0", model: "openai-codex/gpt-x", provider: "openai-codex", credential: "oauth", owner: null, plan: "consumer plan; not for customer data" },
      { seat: "s1", model: "openai-codex/gpt-x", provider: "openai-codex", credential: "oauth", owner: null, plan: "consumer plan; not for customer data" },
      { seat: "s2", model: "anthropic/claude-x", provider: "anthropic", credential: "api_key", owner: "ACME Ltd" },
      { seat: "summary", model: "llama.cpp/m", provider: "llama.cpp", credential: "local", owner: null },
    ],
  });
  assert.ok(c);
  assert.equal(credentialsWords(c), "credentials: openai-codex subscription (OAuth: consumer plan; not for customer data), owner not named (2 seats); anthropic API key, the key of ACME Ltd (1 seat); llama.cpp local model, no key (1 seat)");
  assert.equal(credentialsWords({ customer_case: true, seats: [{ seat: "s0", model: "openai/gpt-x", provider: "openai", credential: "api_key", owner: "the customer" }] }), "credentials (a customer's case: API keys only): openai API key, the key of the customer (1 seat)");
  assert.equal(credentialsWords({ customer_case: false, seats: [{ seat: "s0", model: "anthropic/claude-x", provider: "anthropic", credential: "env", owner: null, variable: "ANTHROPIC_API_KEY" }, { seat: "s1", model: "x/m", provider: "x", credential: "other", owner: null }] }), "credentials: anthropic key from ANTHROPIC_API_KEY, owner not named (1 seat); x key from models.json, owner not named (1 seat)");
  assert.equal(anchoredCredentials(undefined), null);
  assert.equal(anchoredCredentials({ seats: "no" }), null);
});

test("the operator sets the token marks again while the run goes on: parsed as the kickoff parses them, kept by the folds, the change recorded; a finished run's stay", async () => {
  assert.deepEqual(P.parseTokenMarks("1.4G, 200M,200M,5000,2k"), [2_000, 5_000, 200_000_000, 1_400_000_000]);
  assert.deepEqual(P.parseTokenMarks("none"), []);
  for (const bad of ["", "0", "1.5", "-3", "12x", "2M,,3M", "soon"]) assert.equal(P.parseTokenMarks(bad), null, bad);
  const S = await sandbox();
  const b = await P.readBudget(S);
  await P.writeBudget(S, { ...b, token_alerts: [200_000_000] });
  const r = await P.setTokenAlerts(S, [1_400_000_000, 1_600_000_000], "operator");
  assert.deepEqual(r, { before: [200_000_000], after: [1_400_000_000, 1_600_000_000] });
  await P.applySessionUsage(S, "a0", { ...P.emptyAgentBudget(), tokens: 10, calls: 1 });
  const now = await P.readBudget(S);
  assert.deepEqual(now.token_alerts, [1_400_000_000, 1_600_000_000], "a usage fold keeps them");
  assert.deepEqual(now.token_alert_changes?.map((c) => [c.by, c.marks]), [["operator", [1_400_000_000, 1_600_000_000]]]);
  await P.setTokenAlerts(S, [], "operator");
  assert.equal("token_alerts" in (await P.readBudget(S)), false, "none clears them");
  await writeFile(join(S, "done", "SWARM_DONE"), "---\nby: a0\n---\n");
  await assert.rejects(P.setTokenAlerts(S, [5], "operator"), /the run is finished/);
});
