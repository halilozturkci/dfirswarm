/**
 * A run directory for the access-record suites, as the run writes it, held as text so a suite can damage it before it is written
 * (tests/sensitive-access.test.ts, tests/sensitive-access-fuzz.test.ts).
 */
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { accessLineArgs, type AccessHit, type SensitiveWhy } from "../scripts/sensitive-access.ts";

export const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export const VALUES = sha("values-of-j1");
export const KEY = sha("key-of-j34");
export const jl = (...rows: unknown[]) => `${rows.map((r) => JSON.stringify(r)).join("\n")}\n`;
export const T = (min: number, sec = 0) => `2026-10-21T14:${String(min).padStart(2, "0")}:${String(sec).padStart(2, "0")}.000Z`;

/** A seat's trace row, as the seat's extension writes it. */
export const traceRow = (agent: string, seq: number, tool: string, args: Record<string, unknown>, ts: string, result: Record<string, unknown> = { ok: true }) => ({ ts, agent, tool, args, result, sid: `sid-${agent}`, seq });

/** The hub's line for one hit of one seat row, as the hub writes it after the row. */
export function hubLine(ts: string, seat: string, hit: AccessHit, row?: { sid?: string; seq?: number; ts?: string; tool: string }, o: { why?: SensitiveWhy; kept_as?: string; api?: { fn: string; offset: number; bytes: number; total: number }; rules?: number } = {}): Record<string, unknown> {
  const args = accessLineArgs(seat, hit, { why: o.why ?? "secret_output", ...(row ? { row } : {}), ...(o.api ? { api: o.api } : {}) });
  return { ts, agent: "system", tool: "sensitive_access", args: o.rules === undefined ? args : { ...args, rules: o.rules }, result: { ok: true, ...(o.kept_as ? { kept_as: o.kept_as } : {}) } };
}

export const READ_HIT: AccessHit = { job: "j000001", via: "path", certainty: "path", part: "out", paths: ["store/jobs/j000001/out/values.jsonl"] };

export type Extra = { trace?: unknown[]; ledger?: unknown[]; audit?: unknown[]; skip?: Array<"trace" | "journal" | "ledger" | "audit"> };

/**
 * The files of the run, by path relative to the directory that holds the runs directory's audit: `run1/…` is the run (its sandbox),
 * `operator-audit.jsonl` is the operator's audit beside it.
 *   j000001   a tool run as secret output (agent-2), one file, values.jsonl
 *   j000034  made from j000001 by a declared scope (agent-3); its output is a key file
 *   j000037  made from j000001 by a job with no scope whose command names it (agent-4)
 *   j000040  made from j000034 by digest (agent-3)
 *   j000010 and j000050 are not sensitive; j000060 declared no scope and named nothing
 */
export function fixtureFiles(extra: Extra = {}): Record<string, string> {
  const files: Record<string, string> = {};
  const manifest = (id: string, list: Array<{ path: string; sha256: string; bytes: number }>) => (files[`run1/store/jobs/${id}/manifest.json`] = JSON.stringify({ files: list }));
  manifest("j000001", [{ path: "values.jsonl", sha256: VALUES, bytes: 412 }]);
  manifest("j000034", [{ path: "decrypted/key.bin", sha256: KEY, bytes: 32 }]);
  manifest("j000037", []);
  manifest("j000040", []);
  const sens = (why: string, from: string[], because?: unknown[]) => ({ why, from, note: "n", ...(because ? { because } : {}) });
  if (!extra.skip?.includes("journal")) {
    files["run1/store/journal.jsonl"] = jl(
      { v: 1, seq: 0, at: T(0), type: "job_accepted", job: "j000001", spec: { kind: "tool", secret_output: true }, requester: { agent: "agent-2", name: "n", doing: "d" } },
      { v: 1, seq: 1, at: T(1), type: "job_committed", job: "j000001", status: "ok", sensitive: sens("secret_output", []) },
      { v: 1, seq: 2, at: T(2), type: "job_accepted", job: "j000034", spec: { kind: "command" }, requester: { agent: "agent-3" } },
      { v: 1, seq: 3, at: T(3), type: "job_started", job: "j000034", scope: { kind: "declared" } },
      { v: 1, seq: 4, at: T(4), type: "job_committed", job: "j000034", status: "ok", sensitive: sens("derived", ["j000001"], [{ from: "j000001", how: "declared", object: "store/jobs/j000001/out/values.jsonl" }]) },
      { v: 1, seq: 5, at: T(5), type: "job_accepted", job: "j000037", spec: { kind: "command" }, requester: { agent: "agent-4" } },
      { v: 1, seq: 6, at: T(6), type: "job_started", job: "j000037", scope: { kind: "all", auto_declared: [{ from: "j000001", how: "named_in_text", matched: "store/jobs/j000001/out/values.jsonl" }], could_read_sensitive: ["j000001", "j000034"] } },
      { v: 1, seq: 7, at: T(7), type: "job_committed", job: "j000037", status: "ok", sensitive: sens("derived", ["j000001"], [{ from: "j000001", how: "named_in_text", object: "store/jobs/j000001/out/values.jsonl" }]) },
      { v: 1, seq: 8, at: T(8), type: "job_accepted", job: "j000040", spec: { kind: "command" }, requester: { agent: "agent-3" } },
      { v: 1, seq: 9, at: T(9), type: "job_committed", job: "j000040", status: "ok", sensitive: sens("derived", ["j000034"], [{ from: "j000034", how: "digest", object: "work/agent-3/key.bin" }]) },
      { v: 1, seq: 10, at: T(20), type: "job_accepted", job: "j000060", spec: { kind: "command" }, requester: { agent: "agent-2" } },
      { v: 1, seq: 11, at: T(21), type: "job_started", job: "j000060", scope: { kind: "all", could_read_sensitive: ["j000001", "j000034", "j000037", "j000040"] } },
      { v: 1, seq: 12, at: T(22), type: "job_committed", job: "j000060", status: "ok" },
    );
  }
  const row = traceRow;
  if (!extra.skip?.includes("trace")) {
    files["run1/traces/events.jsonl"] = jl(
      ...(extra.trace ?? [
        row("agent-2", 1, "read", { path: "store/jobs/j000001/out/values.jsonl" }, T(10)),
        hubLine(T(10, 1), "agent-2", READ_HIT, { sid: "sid-agent-2", seq: 1, tool: "read" }),
        row("agent-3", 2, "bash", { command: "ls store/jobs/j000034/out/decrypted" }, T(11)),
        row("agent-2", 3, "read", { path: "store/jobs/j000010/out/x" }, T(12)),
      ]),
    );
  }
  if (!extra.skip?.includes("ledger")) {
    files["run1/ledger/entries.jsonl"] = jl(
      ...(extra.ledger ?? [
        { v: 4, seq: 57, kind: "finding", value: "recovery password from E-52 opened the volume in j000034", refs: ["job:j000001/values.jsonl", "job:j000034/decrypted/key.bin", "input:disk.E01"], sensitive: true, by: "agent-3", authors: ["agent-3"], at: T(15) },
        { v: 4, seq: 58, kind: "finding", value: "a note", refs: ["input:disk.E01"], sensitive: true, by: "agent-4", authors: ["agent-4"], at: T(16) },
      ]),
    );
  }
  files["run1/team.json"] = JSON.stringify({ swarm_id: "run1", n: 3, agents: [] });
  if (!extra.skip?.includes("audit")) {
    files["operator-audit.jsonl"] = jl(
      ...(extra.audit ?? [
        { at: T(30), command: "start", argv: ["run1"], cwd: "/x", os_user: "examiner", host: "h1", via: "cli", prev: null },
        { at: T(31), command: "console_view", argv: ["run1"], cwd: "/x", os_user: "examiner", host: "h1", via: "console", detail: { job: "j000001", path: "values.jsonl" }, prev: "a" },
        { at: T(32), command: "console_view", argv: ["other-run"], cwd: "/y", os_user: "examiner", host: "h1", via: "console", detail: { job: "j000001", path: "values.jsonl" }, prev: "b" },
      ]),
    );
  }
  return files;
}

/** Write files (paths relative to base) and return the sandbox. */
export async function writeFiles(base: string, files: Record<string, string>): Promise<string> {
  for (const [rel, text] of Object.entries(files)) {
    await mkdir(dirname(join(base, rel)), { recursive: true });
    await writeFile(join(base, rel), text);
  }
  return join(base, "run1");
}

export async function tempBase(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}
