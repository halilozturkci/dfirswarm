/**
 * The negative bar's test run: a sandbox with a goal of six questions (the
 * second asks whether something exists), three evidence files, six jobs
 * (one over the disk, one over a log, one over a catalogue member, one that
 * failed, the recipe that made generation g0001 of the disk, one over
 * everything) and the generation itself; the helpers that record into it.
 * Shared by tests/negative-bar.test.ts and tests/negative-bar-review.test.ts.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";

export const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

export const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export const F = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
/**
 * The source-first part of an established review (docs/adr/0015): the
 * strongest rival and the test that separates it, and how the value was
 * derived (j000001 over the disk, which every run here holds).
 */
export const SOURCE_FIRST = {
  discriminator: { rival: "a copy of the record written later by a backup process", test: "read the record's own write time against the backup's run times", favours_if: "the answer if the write time falls outside every backup run; the rival if it falls inside one", outcome: "the write time falls outside every backup run", refs: ["job:j000001/hits.txt"] },
  derivation: { job: "j000001", inputs: ["input:disk.E01"] },
} as const;
/** How a critic attests an answer to a question since B2: established, with the review part by part, naming an alternative it weighed and why the evidence rules it out (an established review that names none is recorded best_candidate), and source-first: the discriminator and the derivation. */
export const ESTABLISHED = { strength: "established", answer_review: { reproduced: "re-derived the cited finding from its sealed ref", read: "nothing beyond the cited entries", parts: [{ part: "the question as asked", established: true, why: "the cited finding shows it" }], inference: "the finding is the answer", alternatives: [{ explanation: "a copy of the record left by another process", why: "the cited record's own metadata ties it to the event, and no copy exists in the objects searched", evidence: ["E-1"] }], other_family: { checked: false, text: "no other source family holds it in this fixture" }, ...SOURCE_FIRST } } as const;
export const A = { confidence: "medium", confidence_why: "The cited entries are direct.", alternatives_open: "none open", would_change: "a second source that disagrees" } as const;
/**
 * A partial answer's claim and open-part rows (docs/adr/0013, "Claim and
 * open-part rows"): the part `finding` establishes, and the part left open
 * by what bounds it (`openBy`: a limitation or a coverage record E-<seq>,
 * an acquisition ask R-<n>, a route L-<n>).
 */
export const partialParts = (finding: number, openBy: string) => [
  { id: "shown", part: "what the finding shows", status: "established", refs: [`E-${finding}`] },
  { id: "open", part: "what it leaves open", status: "open", open_by: openBy },
];
/** A review of an answer carrying those rows, each weighed by its id: the open one held open (as the answer declares it), or held established too. */
export function partsReview<T extends { answer_review: Record<string, unknown> }>(review: T, open: "held_open" | "held_established" = "held_open"): T {
  return {
    ...review,
    answer_review: {
      ...review.answer_review,
      parts: [
        { id: "shown", part: "what the finding shows", established: true, why: "the cited finding shows it" },
        { id: "open", part: "what it leaves open", established: open === "held_established", why: open === "held_established" ? "the cited finding shows that too" : "nothing the run holds settles it" },
      ],
    },
  };
}
export const REVIEW = {
  detection: { done: true, text: "a logon on this host writes an event the log keeps for its whole range" },
  reproduced: { done: true, text: "ran the decisive query again over the same objects: nothing" },
  other_route: { done: false, text: "no second source for logons in the case" },
} as const;

export const GOAL = [
  "## Goal",
  "",
  "Examine the host.",
  "",
  "### Questions",
  "",
  "1. Who logged on?",
  "2. Was a remote tool installed?",
  "3. What was deleted?",
  "4. When did it start?",
  "5. Which account ran the tool?",
  "6. What left the network?",
  "",
  "## Definition of done",
  "",
  "d",
  "",
  "## Checks",
  "",
  '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6 --existence 2`',
  "",
].join("\n");

export async function job(root: string, id: string, file: string, record: Record<string, unknown>): Promise<void> {
  const staging = join(root, "..", `staging-${id}-${Math.random().toString(16).slice(2)}`);
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, file), `${id}\n`);
  await sealTree(root, staging, join(storePaths(root).jobs, id, "out"), id, 1);
  await writeFile(join(storePaths(root).jobs, id, "job.json"), JSON.stringify({ id, state: "committed", requester: { agent: "a0" }, status: "ok", exit: 0, ...record }));
}

export async function run(o: { goal?: string } = {}) {
  const base = await mkdtemp(join(tmpdir(), "negative-bar-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "nb1", agentIds: ["a0", "a1", "a2", "a3"], capUsd: 5, wallClockMinutes: 30, goal: o.goal ?? GOAL });
  await writeFile(
    join(S, "inputs.json"),
    JSON.stringify({ files: [{ path: "inputs/disk.E01", sha256: sha("disk"), bytes: 10 }, { path: "inputs/logs/a.log", sha256: sha("a"), bytes: 10 }, { path: "inputs/logs/b.log", sha256: sha("b"), bytes: 10 }] }),
  );
  await job(S, "j000001", "hits.txt", { spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "search" } });
  await job(S, "j000002", "hits.txt", { spec: { kind: "command", scope: "declared", inputs: ["input:logs/a.log"], command: "search" } });
  await job(S, "j000003", "hits.txt", { spec: { kind: "command", scope: "declared", inputs: ["member:g0001#2"], command: "search" } });
  await job(S, "j000004", "hits.txt", { spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "search" }, status: "failed", exit: 1 });
  await job(S, "j000005", "volumes.tsv", { spec: { kind: "recipe", scope: "declared", inputs: ["input:disk.E01"] }, requester: { agent: "system" } });
  await job(S, "j000006", "hits.txt", { spec: { kind: "command", scope: "all", inputs: ["all"], command: "search" } });
  await mkdir(join(S, "catalog", "gen", "g0001"), { recursive: true });
  await writeFile(join(S, "catalog", "gen", "g0001", "generation.json"), JSON.stringify({ id: "g0001", job: "j000005", target: { ref: "input:disk.E01", name: "disk.E01" } }));
  await writeFile(join(S, "catalog", "gen", "g0001", "members.tsv"), "1\tvolume 1\n2\tvolume 2\n3\tvolume 3\n");
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  return { S, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2"), a3: ctx("a3") };
}

export type Ok = { ok: true; entry: P.LedgerEntry; merged: boolean; total: number; note?: string } & P.WarningsDelivered;
export const ok = (r: Awaited<ReturnType<typeof P.recordEntry>>): Ok => {
  assert.ok(r.ok, (r as { reason?: string }).reason);
  return r as Ok;
};
export const okq = <T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> => {
  assert.equal(r.ok, true, (r as unknown as { reason?: string }).reason);
  return r as Extract<T, { ok: true }>;
};
export const refused = (r: { ok: boolean }, re: RegExp) => {
  assert.equal(r.ok, false, "expected a refusal");
  assert.match((r as unknown as { reason: string }).reason, re);
};
export const rec = (c: { sandboxRoot: string; agentId: string }, input: Record<string, unknown>) => P.recordEntry(c, input as unknown as P.LedgerInput);

/** A coverage record's fields, for question `q`, over `refs`, resting on `results`. */
export const coverage = (q: string, refs: string[], results: string[], o: Record<string, unknown> = {}) => ({
  kind: "coverage",
  proposition: `The event question ${q} asks about happened`,
  refs,
  answers: [q],
  time_range: "the whole of each object, no time bound",
  search_method: "a keyword search",
  settings: "case-insensitive, every encoding the tool offers",
  coverage_actual: "every byte of the objects named",
  skipped: "none: the search ran to its end",
  failures: "none",
  result_refs: results,
  alternatives: "the event may have left its trace only in memory, which the case does not hold",
  detection_opportunity: { trace_expected: "yes", why: "the event writes to the objects searched, and they keep it" },
  // The store sweep's strings, or why there are none: a test that sweeps gives looked_for.
  ...(o.looked_for === undefined ? { looked_for_none_why: "the fixture's event has no literal form a byte search could find" } : {}),
  ...o,
});

/** A lead under question `q` holding a route plan, held by `who`. */
export async function planned(c: { sandboxRoot: string; agentId: string }, q: string, routes = [{ source: "input:disk.E01", method: "search the disk" }]): Promise<string> {
  const r = await L.openLead(c, { title: `Work question ${q}`, why: "it is asked", answers: [q], take: true, routes });
  assert.ok(r.ok, (r as { reason?: string }).reason);
  return (r as { lead: { id: string } }).lead.id;
}

/** Every area of a disk searched, one not applicable: what a coverage record over a source says when nothing was left unsearched. */
export const ALL_AREAS = { allocated: "searched", deleted: "searched", unallocated: "searched", slack: "searched", secondary: "not_applicable" } as const;

/**
 * The coverage record that covers the disk (input:disk.E01) for question `q`:
 * every area searched, and a job over the disk among its results. The
 * rival-area check (docs/adr/0013) runs for every established attest of an
 * answer to a material question, so an answer whose findings rest on a job
 * over a source needs a record that covers it to be held established.
 */
export async function covers(c: { sandboxRoot: string; agentId: string }, q: string, source = "input:disk.E01", job = "j000001"): Promise<Ok> {
  return ok(await rec(c, coverage(q, [source], [`job:${job}/hits.txt`], { areas: ALL_AREAS })));
}

/** The disk and the first log, both covered for question `q`: a review that derives from the disk (SOURCE_FIRST) over a finding read from the log. */
export async function coversDiskAndLog(c: { sandboxRoot: string; agentId: string }, q: string): Promise<void> {
  await covers(c, q);
  await covers(c, q, "input:logs/a.log", "j000002");
}
