/**
 * A ledger locator on a sensitive output does not tell the file's size or
 * where a value is (docs/adr/0016, docs/adr/0015 "A source-first review").
 *
 * An attest's `reproduced_at` locator is read at its offset in the sealed
 * file. For a file that is not sensitive a miss says how long the file is,
 * where the value is nearby and what the bytes read as. For a sensitive
 * output each of those is what the harness withholds (the size of a file a
 * tool writes only under a withheld condition is a bit of that condition),
 * and "past the end" against "inside the file" would bisect the size by
 * offset. A locator that misses a sensitive output gets one sentence whatever
 * the file's size and whichever way it missed.
 *
 * A `sha256:` ref to a sensitive output is recorded as before: it resolves,
 * and the entry is recorded sensitive (the second test pins that, and why:
 * the digest names a file in the read-only store a seat's VM mounts).
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { Journal, sealTree, storePaths } from "../scripts/evidence-store.ts";
import { A, coverage, ESTABLISHED, F, ok, planned, rec, run, SOURCE_FIRST } from "./negative-bar-fixture.ts";

const HIGH = { ...A, confidence: "high" } as const;
const { discriminator: _d, derivation: _v, ...BARE } = ESTABLISHED.answer_review;
const ALL_AREAS = { allocated: "searched", deleted: "searched", unallocated: "searched", slack: "searched", secondary: "not_applicable" } as const;

/** A sealed job whose one output holds `bytes`; with `sensitive`, its record and its job_committed line say it ran with secret_output. */
async function sealedJob(S: string, id: string, file: string, bytes: Buffer, sensitive: boolean): Promise<void> {
  const staging = join(S, "..", `staging-${id}`);
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, file), bytes);
  const sealed = await sealTree(S, staging, join(storePaths(S).jobs, id, "out"), id, 1);
  const mark = sensitive ? { sensitive: { why: "secret_output", from: [], note: "n" } } : {};
  await writeFile(join(storePaths(S).jobs, id, "job.json"), JSON.stringify({ id, state: "committed", requester: { agent: "a0" }, status: "ok", exit: 0, spec: { kind: "tool", tool: "x", scope: "declared", inputs: ["input:disk.E01"] }, ...mark }));
  const j = await Journal.open(S);
  await j.append({ type: "job_committed", job: id, attempt: 1, status: "ok", exit: 0, outputs: { manifest_sha256: sealed.manifestSha256, files: 1, bytes: bytes.length, rejected: 0, path: `store/jobs/${id}/out` }, logs: {}, ...mark });
}

const attest = async (c: Awaited<ReturnType<typeof run>>["a2"], input: Record<string, unknown>) => {
  const r = await P.attestEntry(c, input as unknown as P.LedgerActInput);
  assert.ok(r.ok, (r as { reason?: string }).reason);
  return r as { ok: true; line: P.LedgerAttestation & { capped?: string }; note?: string };
};

type Locator = { ref: string; offset: number; length?: number; value?: string };

/** What the attest says of one locator on `job:j000010/values.jsonl` when the file is `size` bytes: the capped text and the reply's note. */
async function said(size: number, sensitive: boolean, locator: Omit<Locator, "ref">): Promise<string> {
  const c = await run();
  await sealedJob(c.S, "j000010", "values.jsonl", Buffer.alloc(size, 0x76), sensitive);
  const ref = "job:j000010/values.jsonl";
  await planned(c.a0, "1");
  ok(await rec(c.a0, coverage("1", ["input:disk.E01"], [ref], { areas: ALL_AREAS })));
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "a value is in the export", source: "the export", evidence: "its row", refs: [ref], answers: ["1"] })).entry;
  const ans = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "a value", reasoning: `E-${f.seq}`, ...HIGH, result: "established" })).entry;
  const out = await attest(c.a2, { seq: ans.seq, how: "x", strength: "established", answer_review: { ...BARE, discriminator: SOURCE_FIRST.discriminator, reproduced_at: [{ ref, ...locator }] } });
  return JSON.stringify({ capped: out.line.capped, note: out.note });
}

const VARIANTS: Array<[string, Omit<Locator, "ref">]> = [
  ["an offset past the end of every file here", { offset: 5_000_000, length: 5 }],
  ["bytes inside the larger files, none in the empty one", { offset: 10, length: 5 }],
  ["a value that is not at the offset", { offset: 10, value: "a value" }],
  ["a value near the end of the file", { offset: 250, value: "a value" }],
  ["a length that runs past what the file holds", { offset: 295, length: 40 }],
];

test("a locator that misses a sensitive output gets one sentence: no size, no position, the same at 0, 299 and 70,000 bytes and for every way of missing", async () => {
  const replies = new Set<string>();
  for (const [what, locator] of VARIANTS) {
    const at = [] as string[];
    for (const size of [0, 299, 70000]) at.push(await said(size, true, locator));
    assert.equal(new Set(at).size, 1, `${what}: the reply is the same whatever the size (${at.map((t) => t.slice(0, 200)).join(" | ")})`);
    for (const t of at) {
      for (const n of ["299", "70000", "bytes)", "past the end", "begins at offset", "nor within", "UTF-8 or UTF-16LE text", "holds "]) assert.equal(t.includes(n), false, `${what}: ${n} is not in the reply`);
      assert.match(t, /is sensitive output/);
    }
    replies.add(at[0].replace(new RegExp(`\\b(at|offset) ${locator.offset}\\b`, "g"), "$1 <offset>"));
  }
  assert.equal(replies.size, 1, "and the same sentence for every way a locator can miss (the offset the seat gave aside)");
});

test("a locator that misses a file that is not sensitive says, as before, how long it is and where the value is", async () => {
  const past = await said(299, false, { offset: 5_000_000, length: 5 });
  assert.match(past, /offset 5000000 is past the end of job:j000010\/values\.jsonl \(299 bytes\)/);
  const near = await said(299, false, { offset: 10, value: "a value" });
  assert.match(near, /the value is not at offset 10 of job:j000010\/values\.jsonl in UTF-8 or UTF-16LE, nor within \d+ bytes of it/);
  const short = await said(299, false, { offset: 295, length: 40 });
  assert.match(short, /holds 4 bytes from offset 295, fewer than the length 40 given/);
});

test("a sha256 ref to a sensitive output still resolves and records the entry sensitive: the digest names a file in the read-only store, so a refusal would hide nothing", async () => {
  const c = await run();
  const body = Buffer.alloc(299, 0x76);
  await sealedJob(c.S, "j000010", "values.jsonl", body, true);
  const digest = createHash("sha256").update(body).digest("hex");
  const guess = (h: string) => rec(c.a1, { kind: "finding", ...F, value: "a value is in the export", source: "the export", evidence: "its row", refs: [`sha256:${h}`], answers: ["1"] });
  const right = await guess(digest);
  assert.ok(right.ok, JSON.stringify(right));
  assert.equal(right.entry.sensitive, true);
  assert.match(String(right.note), /recorded sensitive: it cites sensitive output \(sha256:[0-9a-f]{64}, job j000010 ran with secret_output\)/);
  const wrong = await guess(createHash("sha256").update("nope").digest("hex"));
  assert.equal(wrong.ok, false);
  assert.match(String((wrong as { reason?: string }).reason), /does not resolve|not in the store|no sealed/i);
  // The residual, as documented: the file is in the store under its digest, which a seat's VM mounts read-only.
  assert.ok(existsSync(join(storePaths(c.S).blobs, digest)), "store/blobs/<sha256> names the sealed file");
});
