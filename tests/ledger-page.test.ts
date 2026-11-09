/**
 * The `ledger` tool answers one page of whole entries under the inbox page bound. A ledger of 1,000 entries at the per-field maxima
 * (extensions/protocol-core.ts LEDGER_*_MAX_CHARS) used to come back as one reply of megabytes (Batman II saw 654,942 characters), which
 * locked a seat's context for a quarter of an hour. Now the reply carries `next`, `remaining` and `kept_as` (the whole result on disk,
 * with its size and sha256); following `next` reaches every entry once, also when entries are appended between pages; an entry larger
 * than the bound comes whole, alone on its page; `ids` reads exact entries.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import extension from "../extensions/agent-swarm.ts";
import { inboxPageChars, initSandbox, itemBudget, pageWholeItems, recordEntry, replyCost } from "../extensions/protocol.ts";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Tool = { execute: (id: string, params: Json, signal: undefined, update: undefined, ctx: { cwd: string }) => Promise<{ content: Array<{ text: string }>; details: Json; isError?: boolean }> };

/** The extension loaded against a stand-in for Pi that only records the tools it registers. */
function load(agentId: string): Map<string, Tool> {
  const tools = new Map<string, Tool>();
  const base: Record<string, unknown> = { registerTool: (t: { name: string }) => tools.set(t.name, t as unknown as Tool) };
  const pi = new Proxy(base, { get: (target, key) => (key in target ? target[key as string] : () => undefined) });
  const saved = process.env.AGENT_ID;
  process.env.AGENT_ID = agentId;
  try {
    extension(pi as never);
  } finally {
    if (saved === undefined) delete process.env.AGENT_ID;
    else process.env.AGENT_ID = saved;
  }
  return tools;
}

const MAX = { value: 2000, source: 1000, evidence: 4000 };
const pad = (tag: string, n: number): string => (tag + " " + "x".repeat(n)).slice(0, n);

async function sandbox(entries: number, size = MAX): Promise<{ root: string }> {
  const root = await mkdtemp(join(tmpdir(), "ledger-page-"));
  await initSandbox(root, { reset: true, agentIds: ["a0", "a1"] });
  const a0 = { sandboxRoot: root, agentId: "a0" };
  for (let i = 1; i <= entries; i++) {
    const r = await recordEntry(a0, { kind: "event", ts: "2026-02-14T09:00:00Z", value: pad(`event ${i}`, size.value), source: pad(`source ${i}`, size.source), evidence: pad(`evidence ${i}`, size.evidence) });
    assert.ok(r.ok, (r as { reason?: string }).reason);
  }
  return { root };
}

const text = (r: { content: Array<{ text: string }> }): string => r.content[0]!.text;
const seqs = (d: Json): number[] => (d.entries as Array<{ seq: number }>).map((e) => e.seq);

test("the default call on a ledger of 1,000 entries at the field maxima is one page under the bound, with next, remaining and kept_as whose sha256 matches the file", { timeout: 600_000 }, async () => {
  const { root } = await sandbox(1000);
  const ledger = load("a0").get("ledger")!;
  const r = await ledger.execute("c1", {}, undefined, undefined, { cwd: root });
  const bound = inboxPageChars();
  assert.ok(text(r).length <= bound, `the reply is ${text(r).length} characters, over the bound of ${bound}`);
  const d = r.details;
  assert.ok(d.n >= 1 && d.n < 200, `${d.n} entries on the page`);
  assert.equal(d.n + d.remaining, 200, "the default window is the newest 200, and the page and the rest are all of it");
  assert.match(d.next, /^E-\d+$/);
  assert.equal(d.next, `E-${seqs(d).at(-1)! + 1}`, "next is the entry after the page's last");
  assert.ok(d.kept_as && d.kept_as.path.startsWith("tool-output/a0/"), JSON.stringify(d.kept_as));
  const file = await readFile(join(root, d.kept_as.path));
  assert.equal(file.length, d.kept_as.bytes);
  assert.equal(createHash("sha256").update(file).digest("hex"), d.kept_as.sha256);
  const kept = file.toString("utf8").trimEnd().split("\n").map((l) => JSON.parse(l) as { seq: number });
  assert.equal(kept.length, 200, "the whole filtered result is in the file");
  assert.deepEqual(kept.map((e) => e.seq), Array.from({ length: 200 }, (_, i) => 801 + i), "the newest 200, in order");
  // What the page shows is the start of what the file holds.
  assert.deepEqual(seqs(d), kept.slice(0, d.n).map((e) => e.seq));
});

test("following next reaches every entry of the window exactly once, also with entries appended between pages", { timeout: 600_000 }, async () => {
  const { root } = await sandbox(300);
  const ledger = load("a0").get("ledger")!;
  const a1 = { sandboxRoot: root, agentId: "a1" };
  const seen: number[] = [];
  let from: string | undefined;
  let appended = 0;
  for (let guard = 0; guard < 200; guard++) {
    const r = await ledger.execute("c", from ? { from, limit: 300 } : { limit: 300 }, undefined, undefined, { cwd: root });
    assert.ok(text(r).length <= inboxPageChars());
    seen.push(...seqs(r.details));
    if (guard === 1 && appended === 0) {
      for (let i = 0; i < 3; i++) assert.ok((await recordEntry(a1, { kind: "event", ts: "2026-02-14T09:00:00Z", value: pad(`late ${i}`, 300), source: "late", evidence: "late" })).ok);
      appended = 3;
    }
    if (!r.details.next) break;
    from = r.details.next;
  }
  assert.equal(new Set(seen).size, seen.length, "no entry is repeated");
  assert.deepEqual(seen, Array.from({ length: 300 + appended }, (_, i) => 1 + i), "every seq once, in order, the appended ones last");
});

test("an entry larger than the bound comes whole, alone on its page", () => {
  const big = { seq: 1, blob: "y".repeat(120_000) };
  const small = { seq: 2, blob: "z" };
  const { page, remaining } = pageWholeItems([big, small], itemBudget(40_000), replyCost);
  assert.deepEqual(page, [big]);
  assert.equal(remaining, 1);
  assert.equal(pageWholeItems([small, big], itemBudget(40_000)).page.length, 1, "the large one does not squeeze onto a page that holds another");
  assert.deepEqual(pageWholeItems([big, small], 0).page, [big, small], "0 means no bound");
});

test("ids reads exact entries with their hash and names the ones that do not exist; a refused id is named", async () => {
  const { root } = await sandbox(5, { value: 100, source: 50, evidence: 100 });
  const ledger = load("a0").get("ledger")!;
  const r = await ledger.execute("c", { ids: ["E-3", "E-999999"] }, undefined, undefined, { cwd: root });
  assert.deepEqual(seqs(r.details), [3]);
  assert.match(String(r.details.entries[0].hash), /^[0-9a-f]{16,}$/);
  assert.deepEqual(r.details.not_found, ["E-999999"]);
  const bad = await ledger.execute("c", { ids: ["three"] }, undefined, undefined, { cwd: root });
  assert.equal(bad.isError, true);
  assert.match(text(bad), /exact ledger ids written E-<seq>/);
  const badFrom = await ledger.execute("c", { from: "3" }, undefined, undefined, { cwd: root });
  assert.equal(badFrom.isError, true);
});
