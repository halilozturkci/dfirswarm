/**
 * Resolve a sandbox to the registry row that named it.
 *
 * The summary and the report both need this, and they used to disagree:
 * summary compared through `realpath`, the report through `resolve()`, so a
 * symlinked sandbox matched one document and missed the other.
 */
import { readFile, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";

export type RegistryRun = {
  id?: string;
  label?: string;
  state?: string;
  sandbox?: string;
  n?: number;
  model?: string;
  cap_usd?: number;
  cap_per_agent_usd?: number | null;
  /** model id → USD: a ceiling on the combined spend of that model's agents. */
  cap_per_model_usd?: Record<string, number> | null;
  wall_clock_minutes?: number;
  case_id?: string;
  examiner?: string;
  catalog?: boolean;
  toolbox?: string;
  quarantine?: boolean;
  allow_hosts?: string;
  netguard?: boolean;
  /** netns (enforced) · proxy-only (advisory) · off — what the host could give, measured at kickoff. */
  netguard_mode?: string;
  /** seatbelt · mountns · none — where the panes could write. */
  write_guard?: string;
  /** "sealed", "open" or "unenforced": could a pane reach Herdr's control socket. */
  herdr_socket?: string;
  /** "read-only", "writable" or "not-applicable": could a pane drop code into Pi's extensions/. */
  pi_extensions?: string;
  /** What the host could enforce, probed at kickoff: seatbelt, userns, netns, pidns, landlock_abi, bwrap. */
  host_caps?: Record<string, unknown>;
  /** The packs this run carried, with the checksum of each manifest. */
  packs?: Array<{ id: string; version: string; manifest_sha256: string }>;
  /** "token", "ancestry" or "token-exposed": how the collector decided whose line each one was. */
  attribution?: string;
  /** "kernel", "partial", "none" or "unmeasured": what the panes' own probes said the guard was. */
  write_guard_measured?: string;
  started_at?: string;
  inputs?: { source?: string; files?: number; bytes?: number; enforce?: string; guard?: string; held?: string };
  /** The kickoff's self-compaction options; absent on runs older than the feature. */
  self_compact?: { enabled?: boolean; notice_at?: string; warn_at?: string; compact_at?: string; prompt?: string | null; set?: { notice_at?: boolean; warn_at?: boolean; compact_at?: boolean } } | null;
};

export async function readJsonFile<T>(file: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(file, "utf8")) as T;
  } catch {
    return null;
  }
}

export async function samePath(a: string, b: string): Promise<boolean> {
  if (!a || !b) return false;
  const ra = await realpath(a).catch(() => resolve(a));
  const rb = await realpath(b).catch(() => resolve(b));
  return ra === rb;
}

export async function findRunBySandbox(sandbox: string, runsDir: string): Promise<RegistryRun | null> {
  const registry = await readJsonFile<{ runs?: RegistryRun[] }>(join(runsDir, "registry.json"));
  const runs = Array.isArray(registry?.runs) ? registry.runs : [];
  for (const run of [...runs].reverse()) {
    if (run?.sandbox && (await samePath(run.sandbox, sandbox))) return run;
  }
  return null;
}
