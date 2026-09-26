/**
 * A package made with --redact holds none of what a sensitive ledger entry
 * says, nor the objects it cites, and every chain it carries still walks:
 * a redacted line keeps its own hash, which the next line names. The
 * package's verify re-walks the trace, the ledger, its attestations and the
 * journal against the custody verdict's seal.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initSandbox, recordEntry } from "../extensions/protocol.ts";
import { redactPackage, verifyPackage } from "../scripts/package-tools.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const SECRET = "123456-654321-111222-333444-555666-777888-999000-121212";

function chained(objs: unknown[]): string {
  let prev = "";
  let out = "";
  for (const o of objs) {
    const line = JSON.stringify({ ...(o as Record<string, unknown>), prev });
    out += `${line}\n`;
    prev = sha(line);
  }
  return out;
}

async function packaged(): Promise<{ root: string; pkg: string }> {
  const root = await mkdtemp(join(tmpdir(), "pkg-tools-"));
  dirs.push(root);
  await initSandbox(root, { reset: true, agentIds: ["a0", "a1"] });
  const a0 = { sandboxRoot: root, agentId: "a0" };
  await recordEntry(a0, { kind: "finding", value: "The laptop was imaged on 2024-04-05", source: "E01 header", evidence: "ewfinfo" });
  await recordEntry(a0, { kind: "ioc", value: `BitLocker recovery key ${SECRET}`, source: "notes app", evidence: "sqlite3 NoteStore row 11", sensitive: true });
  await recordEntry({ sandboxRoot: root, agentId: "a1" }, { kind: "ioc", value: `BitLocker recovery key ${SECRET}`, source: "notes app", evidence: "sqlite3 NoteStore row 11", sensitive: true });
  const pkg = join(root, "package");
  await mkdir(join(pkg, "trace"), { recursive: true });
  await mkdir(join(pkg, "board"), { recursive: true });
  await mkdir(join(pkg, "store", "jobs", "j000001"), { recursive: true });
  await cp(join(root, "ledger", "entries.jsonl"), join(pkg, "ledger.jsonl"));
  await cp(join(root, "ledger", "attestations.jsonl"), join(pkg, "ledger-attestations.jsonl"));
  await cp(join(root, "ledger", "ledger.md"), join(pkg, "ledger.md"));
  const trace = chained([
    { ts: "t", agent: "a0", tool: "bash", args: { command: "sqlite3 NoteStore.sqlite" }, result: { ok: true } },
    { ts: "t", agent: "a0", tool: "record", args: { kind: "ioc", value: `BitLocker recovery key ${SECRET}` }, result: { ok: true } },
    { ts: "t", agent: "a1", tool: "post", args: { body: "the vault opens" }, result: { ok: true } },
  ]);
  await writeFile(join(pkg, "trace", "events.jsonl"), trace);
  await writeFile(join(pkg, "board", "main.md"), `a0: the key is ${SECRET}\n`);
  await writeFile(join(pkg, "store", "jobs", "j000001", "stdout.log"), `recovery key: ${SECRET}\n`);
  // The store's journal, chained: one line's command carries the key.
  let prev: string | null = null;
  let journal = "";
  for (const [i, l] of [{ type: "store_opened" }, { type: "job_accepted", job: "j000001", spec: { kind: "command", command: `pybde --key ${SECRET}` } }, { type: "job_committed", job: "j000001" }].entries()) {
    const raw = JSON.stringify({ v: 1, seq: i, at: "t", ...l, prev });
    journal += `${raw}\n`;
    prev = sha(raw);
  }
  await writeFile(join(pkg, "store", "journal.jsonl"), journal);
  const lines = trace.trim().split("\n");
  await writeFile(join(pkg, "custody.json"), JSON.stringify({ seal: { trace: { lines: 3, last_line_sha256: sha(lines[2]) } } }));
  return { root, pkg };
}

test("a redacted package holds none of a sensitive entry's words, and its chains still walk", async () => {
  const { root, pkg } = await packaged();
  // The job log is cited by the sensitive entry through its refs in a real run; here it carries the words.
  const r = await redactPackage(root, pkg);
  assert.equal(r.entries, 1, "a1 recorded the same entry word for word: an attestation, not a second entry");
  assert.equal(r.lines, 3, "one ledger entry, one trace line and one journal line");
  for (const f of ["ledger.jsonl", "trace/events.jsonl", "board/main.md", "store/jobs/j000001/stdout.log", "ledger.md", "store/journal.jsonl"]) {
    assert.doesNotMatch(await readFile(join(pkg, f), "utf8"), new RegExp(SECRET), `${f} holds no secret`);
  }
  const log = await readFile(join(pkg, "REDACTIONS.txt"), "utf8");
  assert.match(log, /1 ledger entry was marked sensitive \(seq 2\)/);
  assert.match(log, /[0-9a-f]{64}  [0-9a-f]{64}  trace\/events\.jsonl  1 line\(s\)/);
  const v = verifyPackage(pkg);
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines.join("\n"), /Trace:        3 lines, chain intact, 1 redacted \(their hashes kept\); the 3 lines the verdict sealed are there, 0 after/);
  assert.match(v.lines.join("\n"), /Ledger:       2 entries, chain intact, 1 redacted/);
  assert.match(v.lines.join("\n"), /Attestations: 1 lines, chain intact/);
  assert.match(v.lines.join("\n"), /Journal:      3 lines, chain intact, 1 redacted/);
  assert.match(v.lines.join("\n"), /Redacted:     this package was made with --redact/);
});

test("the package's verify finds a chain edited after it was packaged, and a trace that is not the one sealed", async () => {
  const { pkg } = await packaged();
  assert.equal(verifyPackage(pkg).ok, true);
  const ledger = await readFile(join(pkg, "ledger.jsonl"), "utf8");
  await writeFile(join(pkg, "ledger.jsonl"), ledger.replace("imaged on 2024-04-05", "imaged on 2024-04-06"));
  const v = verifyPackage(pkg);
  assert.equal(v.ok, false);
  assert.match(v.lines.join("\n"), /Ledger:       broken at entry 1/);
  await writeFile(join(pkg, "ledger.jsonl"), ledger);
  const trace = await readFile(join(pkg, "trace", "events.jsonl"), "utf8");
  await writeFile(join(pkg, "trace", "events.jsonl"), trace.split("\n").slice(0, 2).join("\n") + "\n");
  const w = verifyPackage(pkg);
  assert.equal(w.ok, false);
  assert.match(w.lines.join("\n"), /THE SEALED LINE IS NOT THE ONE THE VERDICT NAMES/);
  assert.ok((await readdir(pkg)).length > 0);
});
