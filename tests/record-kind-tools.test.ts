/**
 * A tool a kind, beside `record` (the review of the Batman III runs, S-01 and
 * S-04): record_finding, record_answer, record_coverage, record_limitation
 * and record_absence each carry that kind's fields, its required list as the
 * check has it and its rules only, where `record` carries 60 properties and
 * every kind's rules in one description. They go through the same check and
 * write the same row on the trace (tool "record", so custody and the metrics
 * read one name). A field left out or misspelt is answered by the check, in
 * a line, never by Pi's echo of the whole call.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import extension from "../extensions/agent-swarm.ts";
import { EVENTS_REL, readLedger } from "../extensions/protocol.ts";
import { F, run } from "./negative-bar-fixture.ts";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Tool = {
  name: string;
  description: string;
  promptGuidelines?: string[];
  parameters: { required?: string[]; properties: Record<string, Json> };
  prepareArguments?: (args: unknown) => Json;
  execute: (id: string, params: Json, signal: undefined, update: undefined, ctx: { cwd: string }) => Promise<{ content: Array<{ text: string }>; details: Json; isError?: boolean }>;
};

const ROOT = join(import.meta.dirname, "..");
const KINDS = ["finding", "answer", "coverage", "limitation", "absence"] as const;

/** The extension loaded against a stand-in for Pi that only records the tools it registers. */
function load(agentId: string): Map<string, Tool> {
  const tools = new Map<string, Tool>();
  const base: Record<string, unknown> = { registerTool: (t: Tool) => tools.set(t.name, t) };
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

/** A call as Pi makes it: the arguments through the tool's prepareArguments, then execute. */
const call = (t: Tool, args: Json, cwd: string) => t.execute("c", t.prepareArguments ? t.prepareArguments(args) : args, undefined, undefined, { cwd });
const text = (r: { content: Array<{ text: string }> }) => r.content[0]!.text;

async function traceRows(S: string): Promise<Json[]> {
  return (await readFile(join(S, EVENTS_REL), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as Json);
}

test("each kind's tool is registered with that kind's required list and its rules only, beside record", () => {
  const tools = load("a0");
  const record = tools.get("record")!;
  assert.ok(record, "record stays");
  assert.deepEqual(record.parameters.required, ["kind", "value"]);
  assert.ok(Object.keys(record.parameters.properties).length >= 60, "record takes every kind's fields");
  const required: Record<(typeof KINDS)[number], string[]> = {
    finding: ["value", "source", "evidence", "basis", "confidence", "confidence_why", "indicates"],
    answer: ["section", "value", "reasoning", "result", "confidence", "confidence_why", "alternatives_open", "would_change"],
    coverage: ["value", "refs", "answers", "time_range", "search_method", "settings", "coverage_actual", "skipped", "failures", "result_refs", "alternatives", "detection_opportunity"],
    limitation: ["value", "source", "evidence", "reason"],
    absence: ["value", "source", "evidence"],
  };
  for (const k of KINDS) {
    const t = tools.get(`record_${k}`)!;
    assert.ok(t, `record_${k} is registered`);
    assert.deepEqual(t.parameters.required, required[k], `record_${k}'s required list is the check's`);
    assert.equal("kind" in t.parameters.properties, false, `record_${k} takes no kind`);
    assert.ok(Object.keys(t.parameters.properties).length <= 31, `record_${k} carries its own fields (${Object.keys(t.parameters.properties).length}), not record's ${Object.keys(record.parameters.properties).length}`);
    assert.ok(t.description.length < record.description.length * 0.5, `record_${k}'s description (${t.description.length}) holds its kind's rules, under half of record's ${record.description.length}`);
    assert.match(t.description, /A refusal names every defect of the entry at once/);
    // The schema is plain JSON Schema: nothing of the builder leaks into what the model is shown.
    assert.doesNotMatch(JSON.stringify(t.parameters), /~kind|~optional/);
    assert.equal(typeof t.prepareArguments, "function");
  }
  // Another kind's rules are not in a kind's tool.
  assert.doesNotMatch(tools.get("record_limitation")!.description, /detection_opportunity|alternatives_open|looked_for|basis observed/);
  assert.doesNotMatch(tools.get("record_finding")!.description, /time_range|question_rev|would_change/);
  for (const f of ["section", "reasoning", "result", "time_range", "result_refs"]) assert.equal(f in tools.get("record_finding")!.parameters.properties, false, `record_finding has no ${f}`);
  for (const f of ["refs", "basis", "indicates", "answers"]) assert.equal(f in tools.get("record_answer")!.parameters.properties, false, `record_answer has no ${f}`);
  // What each kind's tool says of the rules that are its own.
  assert.match(tools.get("record_answer")!.description, /value is the asked string alone, in the format the question asks \(its Format line\): the first line of value is what is graded/);
  assert.match(tools.get("record_answer")!.description, /A revision that lowers confidence or result keeps value/);
  assert.match(tools.get("record_absence")!.description, /names its control: control \{ref, found\}, a job in which the same scanner, with the same pattern and layout, found a planted or known value/);
  assert.match(tools.get("record_finding")!.description, /carriers \[\{carrier, state: decoded \| undecodable \| not_examined, why\}\]/);
  // The answer's own fields are on record too, and the review form carries its link.
  for (const f of ["qualifier", "value_changed_because", "control", "images_read", "carriers"]) assert.ok(f in record.parameters.properties, `record takes ${f}`);
  const attest = tools.get("attest")!;
  assert.deepEqual(attest.parameters.properties.answer_review!.required, ["reproduced", "read", "link", "parts", "inference", "alternatives", "other_family"]);
  assert.ok(attest.promptGuidelines!.some((g) => /compare the first line of its value with the question's Format line/.test(g)), "the critic's list says to hold value to the Format line");
  assert.match(tools.get("dispute")!.description, /A dispute about a reading \(a transcription, a glyph, a look-alike character\) adds a candidate/);
});

test("a kind's tool records through the same check and writes the trace row record writes; a field left out is named by the check, with every other defect, and nothing is echoed", async () => {
  const c = await run();
  const tools = load("a0");
  const finding = tools.get("record_finding")!;
  const ok = await call(finding, { ...F, value: "alice logged on at 09:14", source: "the log", evidence: "line 12", refs: ["store/jobs/j000001/out/hits.txt"], answers: ["question:1"] }, c.S);
  assert.equal(ok.isError, undefined, text(ok));
  assert.equal(ok.details.seq, 1);
  const [entry] = await readLedger(c.S);
  assert.equal(entry!.kind, "finding");
  assert.deepEqual(entry!.refs, ["job:j000001/hits.txt"]);
  let rows = (await traceRows(c.S)).filter((r) => r.tool === "record" || String(r.tool).startsWith("record_"));
  assert.equal(rows.length, 1, "one row, under record's name");
  assert.equal(rows[0]!.tool, "record");
  assert.equal(rows[0]!.args.kind, "finding");
  assert.equal(rows[0]!.result.via, "record_finding");
  assert.equal(rows[0]!.result.hash, entry!.hash, "the entry's hash is on the trace, as custody reads it");
  // Four required fields left out, a confidence its schema would not take, a ref that does not resolve: Pi would refuse this and echo it; the check names all of it.
  const sent = { value: "bob logged on at 09:20", source: "the log", confidence: "certain", refs: ["job:j000001/hitz.txt"], padding: "x".repeat(4000) };
  const prepared = finding.prepareArguments!(sent);
  for (const k of finding.parameters.required!) assert.ok(k in prepared, `${k} is there for Pi's check`);
  const r = await call(finding, sent, c.S);
  assert.equal(r.isError, true);
  assert.match(text(r), /^record_finding refused: 6 things to fix, every one named here, so one more call is enough \(fix them all, then record once\)\. A finding also needs evidence, basis, indicates, confidence_why\./);
  for (const must of [/confidence must be one of high, medium, low/, /evidence is required/, /basis observed or inferred/, /indicates is required on a finding/, /confidence_why is required on a finding/, /ref "job:j000001\/hitz\.txt" does not resolve.*nearest: job:j000001\/hits\.txt/]) assert.match(text(r), must);
  assert.ok(text(r).length < 2500, `the refusal is ${text(r).length} characters: no echo of the ${JSON.stringify(sent).length} sent`);
  assert.doesNotMatch(text(r), /Received arguments|xxxxxxxxxx/);
  rows = (await traceRows(c.S)).filter((x) => x.tool === "record");
  assert.equal(rows.at(-1)!.result.ok, false);
  assert.equal(rows.at(-1)!.result.defects, 6);
  assert.equal(rows.at(-1)!.args.confidence, "certain", "the trace holds what was sent, not the placeholder");
  assert.equal("basis" in rows.at(-1)!.args, false);
  // record itself, with kind left out: the kind its fields allow, said in the reply.
  const lim = await call(tools.get("record")!, { value: "The second volume was not opened", source: "the disk", evidence: "no recovery key", reason: "unavailable" }, c.S);
  assert.equal(lim.isError, undefined, text(lim));
  assert.match(String(lim.details.note), /kind was left out: taken as limitation, the one kind these fields allow/);
  assert.equal((await readLedger(c.S)).at(-1)!.kind, "limitation");
  // Each of the other tools records its kind.
  const l2 = await call(tools.get("record_limitation")!, { value: "The pagefile was not carved", source: "the disk", evidence: "no carver in the image", reason: "not_examined" }, c.S);
  assert.equal(l2.isError, undefined, text(l2));
  const abs = await call(tools.get("record_absence")!, { value: "a remote tool", source: "inputs/disk.E01", evidence: "a keyword search", refs: ["job:j000001/hits.txt"] }, c.S);
  assert.match(text(abs), /^record_absence refused: this absence rests on your own scanner \(job:j000001\/hits\.txt: the output of a command job/);
  const abs2 = await call(tools.get("record_absence")!, { value: "a remote tool", source: "inputs/disk.E01", evidence: "a keyword search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000002/hits.txt", found: "the same search finds the planted name in the log" } }, c.S);
  assert.equal(abs2.isError, undefined, text(abs2));
  assert.deepEqual((await readLedger(c.S)).map((e) => e.kind), ["finding", "limitation", "limitation", "absence"]);
});

test("the new tools are the extension's own on the trace, and a pack's tool says whose it is", async () => {
  const src = await readFile(join(ROOT, "extensions", "agent-swarm.ts"), "utf8");
  const owned = /const SWARM_TOOLS = new Set\(\[([\s\S]*?)\]\);/.exec(src)![1]!;
  for (const k of KINDS) assert.match(owned, new RegExp(`"record_${k}"`), `record_${k} writes its own trace row: the generic hook leaves it alone`);
  // A pack's tool is described as the pack's: seats took "forged by <id>" for a peer's untested script.
  assert.match(src, /\$\{manifest\.pack \? `a tool of the pack \$\{manifest\.pack\}` : `forged by \$\{manifest\.by\}`\}, v\$\{manifest\.version\}/);
});

test("scripts/swarm.sh names the kind tools for Pi, so that a seat is offered them", async () => {
  const sh = await readFile(join(ROOT, "scripts", "swarm.sh"), "utf8");
  const named = new Set((sh.match(/local PI_TOOLS="([a-z_,]+)"/)?.[1] ?? "").split(","));
  assert.deepEqual(KINDS.map((k) => `record_${k}`).filter((t) => !named.has(t)), []);
});
