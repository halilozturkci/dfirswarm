/**
 * The `inputs` tool answers one page of whole rows under the inbox page bound. A manifest of 20,000 files used to come back as one reply
 * with every row (path, size, hash prefix): megabytes in a seat's context. Now the per-set counts and the totals are whole, the files are
 * a page with `next`, `remaining` and `kept_as` (the whole list on disk, with its size and sha256), and paging reaches every path once.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import extension from "../extensions/agent-swarm.ts";
import { inboxPageChars, initSandbox } from "../extensions/protocol.ts";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Tool = { execute: (id: string, params: Json, signal: undefined, update: undefined, ctx: { cwd: string }) => Promise<{ content: Array<{ text: string }>; details: Json; isError?: boolean }> };

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

const FILES = 20_000;

async function sandbox(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "inputs-reply-"));
  await initSandbox(root, { reset: true, agentIds: ["a0"] });
  const files = Array.from({ length: FILES }, (_, i) => ({
    path: `inputs/set${i % 2}/dir${String(Math.floor(i / 100)).padStart(3, "0")}/file-${String(i).padStart(6, "0")}.bin`,
    bytes: 1000 + i,
    sha256: createHash("sha256").update(`file ${i}`).digest("hex"),
  }));
  await writeFile(
    join(root, "inputs.json"),
    JSON.stringify({
      source: "a test directory",
      bytes: files.reduce((n, f) => n + f.bytes, 0),
      enforce: "none",
      guard: "none",
      sets: [
        { name: "set0", path: "inputs/set0", source: "first", files: FILES / 2, bytes: 1 },
        { name: "set1", path: "inputs/set1", source: "second", files: FILES / 2, bytes: 2 },
      ],
      files,
    }),
  );
  return root;
}

test("a manifest of 20,000 files gives a reply under the bound, with per-set counts, next and the whole list on disk; paging reaches every path once", { timeout: 300_000 }, async () => {
  const root = await sandbox();
  const inputs = load("a0").get("inputs")!;
  const first = await inputs.execute("c", {}, undefined, undefined, { cwd: root });
  assert.ok(first.content[0]!.text.length <= inboxPageChars(), `${first.content[0]!.text.length} characters`);
  const d = first.details;
  assert.equal(d.count, FILES);
  assert.deepEqual(d.sets.map((s: Json) => [s.name, s.count]), [["set0", FILES / 2], ["set1", FILES / 2]], "the per-set counts are whole");
  assert.ok(d.n >= 1 && d.n < FILES && d.remaining === FILES - d.n);
  assert.equal(d.next, (d.files as Array<{ path: string }>).length ? `inputs/set${d.n % 2}/dir${String(Math.floor(d.n / 100)).padStart(3, "0")}/file-${String(d.n).padStart(6, "0")}.bin` : undefined, "next is the first path held back");
  const file = await readFile(join(root, d.kept_as.path));
  assert.equal(createHash("sha256").update(file).digest("hex"), d.kept_as.sha256);
  assert.equal(file.length, d.kept_as.bytes);
  const kept = file.toString("utf8").trimEnd().split("\n").map((l) => JSON.parse(l) as { path: string; sha256: string });
  assert.equal(kept.length, FILES, "the whole list is in the file, with whole hashes");
  assert.equal(kept[0]!.sha256.length, 64);

  const seen: string[] = d.files.map((f: { path: string }) => f.path);
  let from: string | undefined = d.next;
  for (let guard = 0; from && guard < 1000; guard++) {
    const r = await inputs.execute("c", { from }, undefined, undefined, { cwd: root });
    assert.ok(r.content[0]!.text.length <= inboxPageChars());
    seen.push(...r.details.files.map((f: { path: string }) => f.path));
    from = r.details.next;
  }
  assert.equal(seen.length, FILES);
  assert.equal(new Set(seen).size, FILES, "no path is repeated");
  assert.deepEqual(seen, kept.map((f) => f.path), "in the manifest's order, every path once");
});

test("a small manifest is one whole page with no next, and a from that names no input is refused", async () => {
  const root = await mkdtemp(join(tmpdir(), "inputs-reply-"));
  await initSandbox(root, { reset: true, agentIds: ["a0"] });
  await writeFile(join(root, "inputs.json"), JSON.stringify({ source: "x", bytes: 10, enforce: "none", guard: "none", files: [{ path: "inputs/a.bin", bytes: 10, sha256: "a".repeat(64) }] }));
  const inputs = load("a0").get("inputs")!;
  const r = await inputs.execute("c", {}, undefined, undefined, { cwd: root });
  assert.equal(r.details.remaining, 0);
  assert.equal(r.details.next, undefined);
  assert.equal(r.details.kept_as, undefined);
  assert.deepEqual(r.details.files, [{ path: "inputs/a.bin", bytes: 10, sha256: "a".repeat(12) }]);
  const bad = await inputs.execute("c", { from: "inputs/nowhere" }, undefined, undefined, { cwd: root });
  assert.equal(bad.isError, true);
});
