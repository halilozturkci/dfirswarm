/**
 * Shell actions for the web app. Every mutation goes through the same
 * `scripts/swarm.sh` the operator would type; the server never writes the
 * sandbox itself (file restore is the one exception and it uses protocol.ts).
 */
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { appendFileSync, chmodSync, mkdirSync, readFileSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

export type JobKind = "start" | "stop" | "reap" | "hold" | "release" | "export" | "package" | "verify" | "purge" | "review" | "lead" | "question" | "extend" | "unpause" | "resume" | "net" | "requests";
export type JobStatus = "running" | "ok" | "failed";

export type Job = {
  id: string;
  kind: JobKind;
  argv: string[];
  status: JobStatus;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  started_at: string;
  finished_at: string | null;
  swarm_id: string | null;
  /** An export's file, served once the job is done. */
  output_file?: string;
  /**
   * The job's whole output, kept on disk as it came (the console's own
   * directory, 0600): stdout and stderr above carry at most the last
   * OUTPUT_CAP of each, saying so and where the whole is, and
   * GET /api/jobs/<id>/output?stream=stdout|stderr serves it whole.
   */
  output?: { stdout: { file: string; bytes: number }; stderr: { file: string; bytes: number } };
};

export type StopParams = { no_custody?: boolean; custody_timeout?: number };

export type StartParams = {
  model: string;
  /**
   * Mixed team, e.g. "openai-codex/gpt-6-astra=3,deepseek/deepseek-v4-pro=2".
   * Set instead of `model`; N then comes from the counts.
   */
  models?: string;
  cap_usd: number;
  n: number;
  goal?: string;
  label?: string;
  playwright?: boolean;
  /**
   * What the panes may reach. `guarded` is netguard's allowlist and nothing
   * else, which is the default and the only safe setting for evidence:
   * anything the agents pull in, and anything they could send out, is a
   * question the report has to answer. `hosts` is that allowlist plus the
   * names in `allow_hosts` — a package index, a symbol server, the one site a
   * case needs. `open` takes the guard off entirely.
   */
  net?: NetMode;
  /** Host names for `net: "hosts"`, one `--allow-host` each. */
  allow_hosts?: string[];
  /** Legacy: false means `open`. Kept so older clients still work. */
  netguard?: boolean;
  hard_kill?: boolean;
  /** Let agents write tools with make_tool and share them. Off by default. */
  tool_forging?: boolean;
  /**
   * Agents compact their own context: three lines against a per-model
   * ceiling, a lock at the last one, a note that comes back verbatim. On by
   * default, which is why the server reads `!== false` rather than `=== true`.
   */
  self_compact?: boolean;
  /**
   * The three lines, each a token count (150k) or a percentage of the
   * ceiling (60%), optionally followed by per-model overrides
   * (`60%,openai/gpt-5.4-mini=55%`); unset means the extension's default.
   */
  compact_notice_at?: string;
  compact_warn_at?: string;
  compact_at?: string;
  /** The model every summary call goes to (`provider/id`); unset means the agent's own. */
  compact_model?: string;
  /** How much post text one inbox/wait delivery carries, whole posts only; 0 removes the bound; unset means the extension's default. */
  inbox_page_chars?: number;
  /** Let agents pip-install into the sandbox from the package index. Off by default. */
  allow_install?: boolean;
  /** A set name from the inputs library; the route resolves it to a path. With several sets, the first of `inputs_sets`. */
  inputs?: string;
  /**
   * Several sets, in order, when the request's `inputs` is a list of more
   * than one: each lands at inputs/<name>/. Names, never paths; absent for
   * one set, which is `inputs` alone as it always was.
   */
  inputs_sets?: string[];
  inputs_enforce?: InputsEnforce;
  /** The resolved directory, set by the server only, never from a client body. */
  inputs_dir?: string;
  /** The resolved directories of `inputs_sets`, in order, set by the server only. */
  inputs_dirs?: string[];
  /**
   * How the evidence is attached. `copy` (the default) puts a read-only copy
   * under inputs/. `bind` makes no copy: the source itself is held read-only by
   * the kernel, for evidence too large to copy; the harness refuses it on a
   * host without a kernel guard.
   */
  inputs_attach?: "copy" | "bind";
  /** A disk image inside the set, `<setref>/<file>`; attached read-only instead of a directory (macOS). */
  inputs_image?: string;
  /** The resolved image path, set by the server only. */
  inputs_image_path?: string;
  /** Refuse an inputs directory above this many MB. Unset means no ceiling. */
  inputs_max_mb?: number;
  /** With a toolbox: refuse to start when a tool it names is missing, instead of warning. */
  toolbox_required?: boolean;
  /** With allow_install: keep the package index off the allowlist; installs come from what is already cached. */
  no_pypi?: boolean;
  /** A run id whose forged tools seed this swarm's tools/; the route resolves it to the run's tools directory. */
  tools_from?: string;
  /** The resolved tools directory, set by the server only. */
  tools_from_dir?: string;
  /** Run ids whose directories are held unreadable in every pane: the clean room for a re-run on the same evidence. */
  no_read?: string[];
  /** The resolved directories, set by the server only. */
  no_read_dirs?: string[];
  wall_clock?: number;
  /** Prepare the sandbox but do not launch Herdr/Pi (fixtures, dry runs). */
  no_start?: boolean;
  /**
   * A cap in tokens over every turn: the brake for a team of local models,
   * which bill nothing and so cannot be stopped by cap_usd; a second brake
   * for any other team. The kickoff decides which case it is.
   */
  cap_tokens?: number;
  /** What one agent may spend before it is steered to finish and stopped. */
  cap_per_agent?: number;
  /** Run the standard first pass over the inputs into catalog/ before agents start. */
  catalog?: boolean;
  /** Tool sets to check for: "dfir", "dfir,crypto", "auto", "off". */
  toolbox?: string;
  /** Nothing under work/extracted/ or work/quarantine/ may execute. */
  quarantine?: boolean;
  /** Case identifier, recorded in the registry, the contract and the summary. */
  case_id?: string;
  /** Who is running it, recorded alongside the case. */
  examiner?: string;
  /** Installed packs, by id: their skills and tools, and under microvm the image that serves them. */
  packs?: string[];
  /** Where the agents live: one microVM each (the default), or host processes (unisolated). */
  isolation?: "host" | "microvm";
  /** The VM image, when not the one the packs pick. */
  image?: string;
  vm_cpus?: number;
  vm_memory?: number;
  vm_disk?: number;
  /** false: remove each VM at stop without keeping its disk. */
  vm_snapshot?: boolean;
  /**
   * Let a subscription (OAuth) provider into the VMs (--allow-oauth-in-vm).
   * Its token is the operator's whole account at the provider, so the
   * kickoff refuses one under microvm unless this is set, and records it.
   */
  allow_oauth_in_vm?: boolean;
  /**
   * `provider=host`, one --provider-host each: the host a provider is called
   * on when the harness cannot know it (a gateway, a region, an account). A
   * microVM run is refused when a provider still has none.
   */
  provider_hosts?: string[];
  /** Where each VM's disk is kept at stop, an absolute path (--vm-snapshot-dir). */
  vm_snapshot_dir?: string;
  /** Hand the packs' secrets over (--allow-pack-secrets): in a VM as placeholders bound to each secret's hosts. */
  allow_pack_secrets?: boolean;
  /** A copy of the evidence or the VMs' disks may go into a synced folder (--allow-synced-folder). */
  allow_synced_folder?: boolean;
  /** The deadline of the host's custody check at stop, seconds (--custody-timeout). */
  custody_timeout?: number;
  /** Seconds a seat may sit quiet before the idle watchdog nudges it; 0 turns the watchdog off (--idle-nudge-sec). */
  idle_nudge_sec?: number;
  /** Refuse an evidence set with more files than this (--inputs-max-files). */
  inputs_max_files?: number;
  /** A command the harness runs, with one JSON line on stdin, when the run finishes, fails to finish, hits its cap or its evidence changes (--notify). */
  notify?: string;
  /**
   * Extra environment for every pane or VM (--env KEY=VALUE, repeatable).
   * The console checks only the shape; what may not go in (a credential's
   * name, a password in a URL, the guard's own variables) is swarm.sh's
   * rule, and its refusal is what the operator sees.
   */
  env?: string[];
  /** A finished run whose ledger this one gets as hypotheses to test (--ledger-from). */
  ledger_from?: string;
  /** Check the copy against its source by names, kinds and sizes only, not by content (--no-verify-copy). */
  no_verify_copy?: boolean;
  /** Start a host run as root anyway (--allow-root); refused by the kickoff otherwise. */
  allow_root?: boolean;
  /** Route the VMs' model calls through the host's model gateway (--model-gateway), when this harness has one. */
  model_gateway?: boolean;
};

/** guarded: the providers' hosts · hosts: plus named ones · open: no guard · local: the local endpoints and nothing else. */
export type NetMode = "guarded" | "hosts" | "open" | "local";

export const NET_MODES: readonly NetMode[] = ["guarded", "hosts", "open", "local"];

const HOST_LABEL = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i;

/**
 * A host we are willing to put on a command line, and nothing else: a name
 * with at least one dot, `localhost`, an IPv4 address, an IPv6 literal in
 * brackets, any of them with `:port`; or a suffix, `*.name` or `.name`, which
 * matches the name itself and everything under it (the proxy and msb read it
 * the same way). A suffix of one label (`*.com`) is refused: that is a whole
 * top-level domain. A local model server is usually one of the address forms.
 */
export function isHostName(raw: string): boolean {
  if (raw.length > 260) return false;
  let host = raw;
  let port: string | null = null;
  const v6 = raw.match(/^\[([0-9a-f:.]+)\](?::(\d{1,5}))?$/i);
  if (v6) {
    host = v6[1];
    port = v6[2] ?? null;
    if (!host.includes(":")) return false;
  } else {
    const m = raw.match(/^(.*):(\d{1,5})$/);
    if (m) {
      host = m[1];
      port = m[2];
    }
  }
  if (port !== null && (Number(port) < 1 || Number(port) > 65535)) return false;
  if (v6) return true;
  if (host.toLowerCase() === "localhost") return true;
  if (host.startsWith("*.")) host = host.slice(2);
  else if (host.startsWith(".")) host = host.slice(1);
  const labels = host.split(".");
  return labels.length >= 2 && host.length <= 253 && labels.every((l) => HOST_LABEL.test(l));
}

/**
 * Whether a host is this machine or this network. The same rule as
 * host_is_local in swarm.sh, so the console and the kickoff never disagree
 * about which model is local.
 */
export function isLocalHost(raw: string): boolean {
  const h = raw.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h === "localhost.localdomain" || h.endsWith(".localhost")) return true;
  if (h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  if (/^(127|10)\./.test(h) || /^192\.168\./.test(h) || /^169\.254\./.test(h)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(h)) return true;
  if (/^fe80:/.test(h) || /^f[cd][0-9a-f]{2}:/.test(h)) return true;
  return /\.(local|lan|home|internal)$/.test(h);
}

/** One model a local server serves, as models.json describes it. */
export type LocalModel = {
  model: string;
  provider: string;
  base_url: string;
  /** Pi lists the provider only when it has some apiKey, even one the server ignores. */
  has_key: boolean;
  /** False when the cost block is absent or all zero: Pi will report $0. */
  metered: boolean;
};

function hostOfUrl(url: string): string {
  const m = url.match(/^[a-z]+:\/\/(\[[^\]]+\]|[^/:]+)/i);
  return m ? m[1].replace(/^\[|\]$/g, "") : "";
}

/**
 * The local providers in Pi's models.json. A keyless one is invisible to
 * `pi --list-models`, which is exactly when the picker most needs to show it
 * — with the hint that fixes it — rather than pretend it does not exist.
 */
export function readLocalProviders(agentDir = process.env.PI_CODING_AGENT_DIR || join(homedir(), ".pi", "agent")): LocalModel[] {
  let data: unknown;
  try {
    data = JSON.parse(readFileSync(join(agentDir, "models.json"), "utf8").replace(/^\uFEFF/, ""));
  } catch {
    return [];
  }
  const providers = (data as { providers?: Record<string, unknown> })?.providers;
  if (!providers || typeof providers !== "object") return [];
  const out: LocalModel[] = [];
  for (const [name, raw] of Object.entries(providers)) {
    if (!raw || typeof raw !== "object") continue;
    const p = raw as { baseUrl?: unknown; apiKey?: unknown; models?: unknown };
    const baseUrl = typeof p.baseUrl === "string" ? p.baseUrl : "";
    if (!baseUrl || !isLocalHost(hostOfUrl(baseUrl))) continue;
    const hasKey = typeof p.apiKey === "string" && p.apiKey.trim().length > 0;
    for (const m of Array.isArray(p.models) ? p.models : []) {
      if (!m || typeof m !== "object" || typeof (m as { id?: unknown }).id !== "string") continue;
      const cost = (m as { cost?: unknown }).cost as Record<string, unknown> | undefined;
      const metered =
        !!cost &&
        typeof cost === "object" &&
        (["input", "output", "cacheRead", "cacheWrite"].some((k) => typeof cost[k] === "number" && (cost[k] as number) > 0) || !!cost.tiers);
      out.push({ model: `${name}/${(m as { id: string }).id}`, provider: name, base_url: baseUrl, has_key: hasKey, metered });
    }
  }
  return out;
}

export type ReapParams = { stall_sec?: number; stop?: boolean };

/** More room for a going (or paused) run: swarm.sh extend. */
export type ExtendParams = { minutes?: number; tokens?: number; usd?: number };

/** "Continue this run": swarm.sh resume, with the questions asked for the continuation. */
export type ResumeParams = ExtendParams & { questions?: string[]; why?: string; as?: string };

export class RunRequestError extends Error {}

function capNumbers(body: Record<string, unknown>): ExtendParams {
  const out: ExtendParams = {};
  for (const k of ["minutes", "tokens", "usd"] as const) {
    const v = body[k];
    if (v === undefined || v === null || v === "") continue;
    const n = Number(v);
    const whole = k !== "usd";
    if (!Number.isFinite(n) || n <= 0 || (whole && !Number.isInteger(n))) throw new RunRequestError(`${k} is ${whole ? "a whole number" : "a number"} above zero`);
    out[k] = n;
  }
  return out;
}

/** An Extend request as swarm.sh extend arguments: at least one of minutes, tokens, usd. */
export function extendArgv(swarmId: string, body: Record<string, unknown>): string[] {
  const c = capNumbers(body);
  if (!Object.keys(c).length) throw new RunRequestError("give minutes, tokens or usd to add");
  return ["extend", swarmId, ...(c.minutes ? ["--minutes", String(c.minutes)] : []), ...(c.tokens ? ["--tokens", String(c.tokens)] : []), ...(c.usd ? ["--usd", String(c.usd)] : [])];
}

/**
 * A "Continue this run" request as swarm.sh resume arguments: the questions
 * asked for the continuation (each one line, at most 4000 characters: a
 * longer one is refused, never cut), why, more caps, and the console
 * session's person as --as.
 */
export function resumeArgv(swarmId: string, body: Record<string, unknown>): string[] {
  const argv = ["resume", swarmId];
  const qs = body.questions === undefined || body.questions === null ? [] : body.questions;
  if (!Array.isArray(qs)) throw new RunRequestError("questions is a list of questions");
  if (qs.length > 20) throw new RunRequestError("at most 20 questions at a resume; more are asked on the Questions tab once the run goes on");
  for (const q of qs) {
    if (typeof q !== "string" || !q.trim()) throw new RunRequestError("a question is text");
    const t = q.trim();
    if (/[\r\n]/.test(t)) throw new RunRequestError("a question is one line");
    if (t.length > 4000) throw new RunRequestError("a question is over 4000 characters: nothing is cut, so a longer one is refused");
    argv.push("--question", t);
  }
  const why = typeof body.why === "string" ? body.why.trim() : "";
  if (why.length > 2000 || /[\x00-\x1f\x7f]/.test(why)) throw new RunRequestError("why: one line, at most 2000 characters");
  if (why) argv.push("--why", why);
  const c = capNumbers(body);
  if (c.minutes) argv.push("--minutes", String(c.minutes));
  if (c.tokens) argv.push("--tokens", String(c.tokens));
  if (c.usd) argv.push("--usd", String(c.usd));
  const as = typeof body.as === "string" ? body.as.trim() : "";
  if (as) {
    if (!/^[a-z0-9][a-z0-9-]{0,47}$/.test(as)) throw new RunRequestError("as is an enrolled person's id");
    argv.push("--as", as);
  }
  return argv;
}

/** An examiner's decision on one ledger entry. The sign-off is a release, signed from the Release panel (scripts/ui/signing.ts), never a job. */
export type ReviewParams = { action: "accept" | "reject" | "amend"; entry_seq?: number; note?: string; examiner: string };

/** A review from the console's body, checked: a reject or an amend needs a note. */
export function validateReview(input: unknown): { ok: true; params: ReviewParams } | { ok: false; error: string } {
  if (!input || typeof input !== "object") return { ok: false, error: "body must be an object" };
  const b = input as Record<string, unknown>;
  const action = b.action;
  if (action === "sign") return { ok: false, error: "a sign-off is the examiner's release, signed from the Release panel with the examiner's own secret (or swarm.sh review <id> --sign): never a background job" };
  if (action !== "accept" && action !== "reject" && action !== "amend") return { ok: false, error: "action must be accept, reject or amend" };
  const examiner = typeof b.examiner === "string" ? b.examiner.trim() : "";
  if (!examiner || examiner.length > 200 || /[\x00-\x1f\x7f]/.test(examiner)) return { ok: false, error: "examiner: the name the review is signed with, one line" };
  const note = typeof b.note === "string" ? b.note.trim() : "";
  if (note.length > 4000 || /[\x00-\x08\x0b-\x1f\x7f]/.test(note)) return { ok: false, error: "note: at most 4000 characters, no control characters" };
  if ((action === "reject" || action === "amend") && !note) return { ok: false, error: `${action} needs a note saying why` };
  const seq = Number(b.entry_seq);
  if (!Number.isInteger(seq) || seq < 1) return { ok: false, error: "entry_seq must be the ledger entry's seq" };
  return { ok: true, params: { action, entry_seq: seq, examiner, note: note || undefined } };
}

export type ModelList = {
  source: "pi" | "static";
  models: string[];
  /** Models served from this machine or network, from models.json, whether or not Pi lists them yet. */
  local?: LocalModel[];
};

export const STATIC_MODELS = [
  "deepseek/deepseek-v4-pro",
  "deepseek/deepseek-v4-flash",
  "openai/gpt-5.4",
  "openai/gpt-5.4-mini",
  "anthropic/claude-sonnet-4.5",
  "anthropic/claude-haiku-4.5",
  "google/gemini-3.7-flash",
  "google/gemini-3.7-pro",
  "xai/grok-4.1",
  "openrouter/z-ai/glm-5.3",
];

/** How much of a job's output travels in the job list and the event stream; the whole is kept on disk (Job.output). */
export const OUTPUT_CAP = 64 * 1024;

/** Goal documents are whole markdown files now, not one-line descriptions. */
export const GOAL_MAX_CHARS = 32_000;
const HAS_DEFINITION_OF_DONE = /^##[ \t]*Definition of done[ \t]*$/im;
const MODEL_REF = /^[a-z0-9_.-]+\/[A-Za-z0-9_.:/-]+$/;
/**
 * One compaction line as the kickoff accepts it: a token count or a
 * percentage, optionally followed by per-model overrides
 * (`60%,openai/gpt-5.4-mini=55%,grok-4.6=70%`). The shape only; the order
 * against the window is the extension's to check, per seat.
 */
const COMPACT_SPEC_LIST = /^(?:[A-Za-z0-9][A-Za-z0-9._:-]*(?:\/[A-Za-z0-9][A-Za-z0-9._:-]*)?=)?\d+(?:\.\d+)?[kKmM%]?(?:\s*,\s*(?:[A-Za-z0-9][A-Za-z0-9._:-]*(?:\/[A-Za-z0-9][A-Za-z0-9._:-]*)?=)?\d+(?:\.\d+)?[kKmM%]?)*$/;

/**
 * "provider/id=3,other/id=2" -> how many agents in total, or why not.
 * Mirrors parse_model_teams in swarm.sh so the form fails here, in the
 * browser, rather than in a shell job the operator has to go and read.
 */
export function parseModelTeam(
  spec: string,
): { ok: true; total: number; entries: { model: string; count: number; cap?: number }[] } | { ok: false; error: string } {
  const entries: { model: string; count: number; cap?: number }[] = [];
  for (const raw of spec.split(",")) {
    const entry = raw.replace(/\s+/g, "");
    if (!entry) continue;
    // provider/id[=count][@cap]: the cap is USD for every agent on that model together.
    // Model ids may carry ':' and '.', so the cap is what follows the LAST '@'.
    const cut = entry.lastIndexOf("@");
    const head = cut >= 0 ? entry.slice(0, cut) : entry;
    const capText = cut >= 0 ? entry.slice(cut + 1) : "";
    const at = head.lastIndexOf("=");
    const name = at >= 0 ? head.slice(0, at) : head;
    const countText = at >= 0 ? head.slice(at + 1) : "1";
    if (!MODEL_REF.test(name)) {
      return { ok: false, error: `"${entry}" does not look like provider/id=count@cap` };
    }
    const count = Number(countText);
    if (!Number.isInteger(count) || count < 1) {
      return { ok: false, error: `"${entry}" needs a count of at least 1` };
    }
    let cap: number | undefined;
    if (cut >= 0) {
      cap = Number(capText);
      if (!capText || !Number.isFinite(cap) || cap <= 0) return { ok: false, error: `"${entry}" needs a cap in USD above zero after @` };
    }
    entries.push(cap === undefined ? { model: name, count } : { model: name, count, cap });
  }
  if (entries.length === 0) return { ok: false, error: "no models in the team" };
  const total = entries.reduce((sum, e) => sum + e.count, 0);
  if (total > 30) return { ok: false, error: `a team of ${total} is over the limit of 30` };
  return { ok: true, total, entries };
}

export type InputsEnforce = "auto" | "on" | "off";
// A set reference: `0:brief` (root 0, set brief), or a bare name for root 0.
const INPUT_SET = /^(?:\d{1,2}:)?[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
// A disk image in a set: `0:brief/laptop.dmg`.
const INPUT_IMAGE = /^(?:\d{1,2}:)?[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}\.(dmg|iso|img|sparseimage)$/i;
// A run id as the registry writes it.
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
// `provider=host`, the pattern swarm.sh start checks --provider-host against.
const PROVIDER_HOST = /^[a-z0-9][a-z0-9._-]*=[^=,\s]+$/;

export function validateStart(input: unknown): { ok: true; params: StartParams } | { ok: false; error: string } {
  if (typeof input !== "object" || input === null) return { ok: false, error: "body must be a JSON object" };
  const body = input as Record<string, unknown>;
  const n = Number(body.n);
  if (!Number.isInteger(n) || n < 1 || n > 30) return { ok: false, error: "n must be an integer 1..30" };
  // Two brakes. A team that bills nothing cannot be stopped by dollars, so a
  // token cap stands in for the USD cap; the kickoff is the one that knows
  // which team this is and refuses the wrong combination with its reasons.
  const cap = body.cap_usd === undefined || body.cap_usd === null || body.cap_usd === "" ? 0 : Number(body.cap_usd);
  if (!Number.isFinite(cap) || cap < 0) return { ok: false, error: "cap_usd must be a number of USD" };
  let capTokens: number | undefined;
  if (body.cap_tokens !== undefined && body.cap_tokens !== null && body.cap_tokens !== "") {
    capTokens = Number(body.cap_tokens);
    if (!Number.isInteger(capTokens) || capTokens < 1 || capTokens > 1e10) return { ok: false, error: "cap_tokens must be a whole number of tokens above zero" };
  }
  if (cap <= 0 && !capTokens) return { ok: false, error: "cap_usd must be a positive number, or cap_tokens must be set for a team that bills nothing" };
  const noStart = body.no_start === true;
  const model = typeof body.model === "string" ? body.model.trim() : "";
  const models = typeof body.models === "string" ? body.models.trim() : "";
  if (models) {
    // A mixed team. The counts decide N, so they have to agree with the n the
    // form sent, or the operator gets a swarm of a size they did not ask for.
    const team = parseModelTeam(models);
    if (!team.ok) return { ok: false, error: team.error };
    if (team.total !== n) {
      return { ok: false, error: `models add up to ${team.total} agents, but n is ${n}` };
    }
    // A per-model cap above the swarm's cap could never bind; the harness refuses it too.
    for (const e of team.entries) {
      if (e.cap !== undefined && cap > 0 && e.cap > cap) return { ok: false, error: `${e.model} has a cap of $${e.cap}, above the swarm's $${cap}` };
    }
  } else if (!noStart && !MODEL_REF.test(model)) {
    return { ok: false, error: "model must look like provider/id" };
  }
  const goal = typeof body.goal === "string" ? body.goal.trim() : "";
  if (goal.length > GOAL_MAX_CHARS) {
    return { ok: false, error: `goal is longer than ${GOAL_MAX_CHARS} characters` };
  }
  // Same rule as the CLI: a swarm with no finish line does not start. An
  // empty goal is fine — the kickoff falls back to the default goal file,
  // which has its own definition of done.
  if (goal && !HAS_DEFINITION_OF_DONE.test(goal)) {
    return {
      ok: false,
      error: 'goal needs a "## Definition of done" section (see prompts/goals/hello.md)',
    };
  }
  const label = typeof body.label === "string" ? body.label.trim() : "";
  if (label && !/^[A-Za-z0-9_-]{1,40}$/.test(label)) return { ok: false, error: "label must be [A-Za-z0-9_-]{1,40}" };
  // One set is a name; several are a list of names, each to land at
  // inputs/<name>/ (a list of one is one set).
  const inputsList = Array.isArray(body.inputs) ? body.inputs.map((x) => (typeof x === "string" ? x.trim() : "")) : typeof body.inputs === "string" && body.inputs.trim() ? [body.inputs.trim()] : [];
  if (inputsList.some((x) => !INPUT_SET.test(x))) return { ok: false, error: `inputs must name ${inputsList.length > 1 ? "sets" : "a set"} from the inputs library` };
  const inputsName = inputsList[0] ?? "";
  if (inputsList.length > 1) {
    const seen = new Map<string, string>();
    for (const ref of inputsList) {
      // `brief` is root 0's, like `0:brief`; a set lands under its own name,
      // so two sets of one name (in two roots) would be one directory.
      const qualified = ref.includes(":") ? ref : `0:${ref}`;
      const name = qualified.slice(qualified.indexOf(":") + 1).toLowerCase();
      const other = seen.get(name);
      if (other !== undefined) {
        return {
          ok: false,
          error: other === qualified ? `inputs names ${ref} twice` : `two sets would both be inputs/${qualified.slice(qualified.indexOf(":") + 1)}/ (${other}, ${qualified}): a set lands under its own name`,
        };
      }
      seen.set(name, qualified);
    }
  }
  let inputsEnforce: InputsEnforce | undefined;
  if (body.inputs_enforce !== undefined && body.inputs_enforce !== null && body.inputs_enforce !== "") {
    if (body.inputs_enforce !== "auto" && body.inputs_enforce !== "on" && body.inputs_enforce !== "off") {
      return { ok: false, error: "inputs_enforce must be auto, on or off" };
    }
    inputsEnforce = body.inputs_enforce;
  }
  if (inputsEnforce && !inputsName) return { ok: false, error: "inputs_enforce needs inputs" };
  // The network setting: the new three-way one wins, the old boolean still
  // answers for clients that have not been updated.
  let net: NetMode = body.netguard === false ? "open" : "guarded";
  if (body.net !== undefined && body.net !== null && body.net !== "") {
    if (typeof body.net !== "string" || !NET_MODES.includes(body.net as NetMode)) {
      return { ok: false, error: "net must be guarded, hosts, open or local" };
    }
    net = body.net as NetMode;
  }
  let allowHosts: string[] = [];
  if (body.allow_hosts !== undefined && body.allow_hosts !== null && body.allow_hosts !== "") {
    const raw = Array.isArray(body.allow_hosts)
      ? body.allow_hosts
      : String(body.allow_hosts).split(/[\s,]+/);
    allowHosts = raw.map((h) => String(h).trim().toLowerCase()).filter(Boolean);
    const bad = allowHosts.find((h) => !isHostName(h));
    if (bad) return { ok: false, error: `allow_hosts: ${bad} is not a host name` };
    if (allowHosts.length > 20) return { ok: false, error: "allow_hosts: at most 20 hosts" };
  }
  if (net === "hosts" && allowHosts.length === 0) {
    return { ok: false, error: "net: hosts needs at least one host in allow_hosts" };
  }
  let wall: number | undefined;
  if (body.wall_clock !== undefined && body.wall_clock !== null && body.wall_clock !== "") {
    wall = Number(body.wall_clock);
    if (!Number.isInteger(wall) || wall < 1 || wall > 240) return { ok: false, error: "wall_clock must be 1..240 minutes" };
  }
  // The case settings. They are what turns a task into an investigation: the
  // first pass over the evidence, the tools the case needs, the no-exec rule
  // over anything carved out of it, and the identifiers a report is filed
  // under. The CLI has had them since the first forensic run; without them
  // here the console could only start the toy goals.
  let capPerAgent: number | undefined;
  if (body.cap_per_agent !== undefined && body.cap_per_agent !== null && body.cap_per_agent !== "") {
    capPerAgent = Number(body.cap_per_agent);
    if (!Number.isFinite(capPerAgent) || capPerAgent <= 0) return { ok: false, error: "cap_per_agent must be a positive number of USD" };
    if (cap > 0 && capPerAgent > cap) return { ok: false, error: `cap_per_agent ($${capPerAgent}) is above the swarm's own cap ($${cap})` };
  }
  let toolbox: string | undefined;
  if (body.toolbox !== undefined && body.toolbox !== null && body.toolbox !== "") {
    const raw = String(body.toolbox).trim().toLowerCase();
    const sets = raw.split(",").map((s) => s.trim()).filter(Boolean);
    if (sets.length === 0) return { ok: false, error: "toolbox must name at least one set" };
    const known = ["dfir", "crypto", "linux", "auto", "off"];
    const bad = sets.find((s) => !known.includes(s));
    if (bad) return { ok: false, error: `toolbox: ${bad} is not one of ${known.join(", ")}` };
    if (sets.length > 1 && (sets.includes("auto") || sets.includes("off"))) {
      return { ok: false, error: "toolbox: auto and off stand alone" };
    }
    toolbox = sets.join(",");
  }
  const caseId = typeof body.case_id === "string" ? body.case_id.trim() : "";
  if (caseId && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/.test(caseId)) {
    return { ok: false, error: "case_id must be [A-Za-z0-9._-]{1,40}" };
  }
  const examiner = typeof body.examiner === "string" ? body.examiner.trim() : "";
  if (examiner && !/^[\w .'-]{1,60}$/u.test(examiner)) {
    return { ok: false, error: "examiner must be 1..60 characters of letters, digits, space, dot, apostrophe or dash" };
  }
  const catalog = body.catalog === true;
  const quarantine = body.quarantine === true;
  if (catalog && !inputsName) return { ok: false, error: "catalog needs inputs: there is nothing to catalogue without evidence" };
  let inputsAttach: "copy" | "bind" | undefined;
  if (body.inputs_attach !== undefined && body.inputs_attach !== null && body.inputs_attach !== "") {
    if (body.inputs_attach !== "copy" && body.inputs_attach !== "bind") return { ok: false, error: "inputs_attach must be copy or bind" };
    inputsAttach = body.inputs_attach;
  }
  if (inputsAttach === "bind" && !inputsName) return { ok: false, error: "inputs_attach needs inputs" };
  const inputsImage = typeof body.inputs_image === "string" ? body.inputs_image.trim() : "";
  if (inputsImage && !INPUT_IMAGE.test(inputsImage)) return { ok: false, error: "inputs_image must be <set>/<file>, a dmg, iso, img or sparseimage in a set from the inputs library" };
  if (inputsImage && inputsAttach === "bind") return { ok: false, error: "an image is attached as an image; inputs_attach does not apply" };
  if (inputsImage && inputsList.length > 1) return { ok: false, error: "an image is one set's disk image; hand several sets over as directories" };
  let inputsMaxMb: number | undefined;
  if (body.inputs_max_mb !== undefined && body.inputs_max_mb !== null && body.inputs_max_mb !== "") {
    inputsMaxMb = Number(body.inputs_max_mb);
    if (!Number.isInteger(inputsMaxMb) || inputsMaxMb < 1 || inputsMaxMb > 1e7) return { ok: false, error: "inputs_max_mb must be a whole number of MB above zero" };
    if (!inputsName) return { ok: false, error: "inputs_max_mb needs inputs" };
  }
  const toolboxRequired = body.toolbox_required === true;
  const noPypi = body.no_pypi === true;
  if (noPypi && body.allow_install !== true) return { ok: false, error: "no_pypi only means something with allow_install" };
  const toolsFrom = typeof body.tools_from === "string" ? body.tools_from.trim() : "";
  if (toolsFrom && !RUN_ID.test(toolsFrom)) return { ok: false, error: "tools_from must be a run id" };
  let noRead: string[] | undefined;
  if (body.no_read !== undefined && body.no_read !== null) {
    if (!Array.isArray(body.no_read) || body.no_read.length > 10 || !body.no_read.every((x) => typeof x === "string" && RUN_ID.test(x))) {
      return { ok: false, error: "no_read must be up to ten run ids" };
    }
    noRead = [...new Set(body.no_read as string[])];
    if (noRead.length === 0) noRead = undefined;
  }
  // Self-compaction is on unless the form said off. The three lines are
  // checked for shape here and for order against the model's window by the
  // extension, where the answer depends on the seat.
  const selfCompact = body.self_compact !== false;
  const compactSpec = (key: "compact_notice_at" | "compact_warn_at" | "compact_at"): string | undefined | { error: string } => {
    const raw = body[key];
    if (raw === undefined || raw === null || raw === "") return undefined;
    const text = String(raw).trim();
    if (!COMPACT_SPEC_LIST.test(text)) return { error: `${key} must be a token count (150000, 150k, 0.5m) or a percentage of the ceiling (60%), optionally with per-model overrides (60%,openai/gpt-5.4-mini=55%)` };
    return text;
  };
  const specs: Record<"compact_notice_at" | "compact_warn_at" | "compact_at", string | undefined> = { compact_notice_at: undefined, compact_warn_at: undefined, compact_at: undefined };
  for (const key of ["compact_notice_at", "compact_warn_at", "compact_at"] as const) {
    const value = compactSpec(key);
    if (value && typeof value === "object") return { ok: false, error: value.error };
    specs[key] = value;
  }
  // The summary model: a model ref like a seat's, and only with the feature on.
  const compactModel = typeof body.compact_model === "string" ? body.compact_model.trim() : "";
  if (compactModel && !MODEL_REF.test(compactModel)) return { ok: false, error: "compact_model must be provider/id" };
  if (compactModel && !selfCompact) return { ok: false, error: "compact_model names the summary model of self-compaction, which is off" };
  // The inbox page: a whole number of characters, 0 for no bound.
  let inboxPageChars: number | undefined;
  if (body.inbox_page_chars !== undefined && body.inbox_page_chars !== null && body.inbox_page_chars !== "") {
    const n = Number(body.inbox_page_chars);
    if (!Number.isInteger(n) || n < 0 || n > 999_999_999) return { ok: false, error: "inbox_page_chars must be a whole number of characters (0 for no bound)" };
    inboxPageChars = n;
  }
  // Isolation: a microVM per agent unless the form asks for host processes,
  // as swarm.sh itself defaults. The image is an OCI reference; the harness
  // checks the host can boot it.
  const isolation = body.isolation === "host" ? "host" : body.isolation === undefined || body.isolation === null || body.isolation === "" || body.isolation === "microvm" ? "microvm" : null;
  if (!isolation) return { ok: false, error: "isolation must be host or microvm" };
  const image = typeof body.image === "string" ? body.image.trim() : "";
  if (image && !/^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$/.test(image)) return { ok: false, error: "image must be an OCI reference (registry/name:tag or name@sha256:...)" };
  if (image && isolation !== "microvm") return { ok: false, error: "image names a VM image; it needs isolation microvm" };
  const vmNumber = (key: "vm_cpus" | "vm_memory" | "vm_disk", min: number, max: number): number | undefined | { error: string } => {
    const raw = body[key];
    if (raw === undefined || raw === null || raw === "") return undefined;
    const v = Number(raw);
    if (!Number.isInteger(v) || v < min || v > max) return { error: `${key} must be a whole number from ${min} to ${max}` };
    if (isolation !== "microvm") return { error: `${key} needs isolation microvm` };
    return v;
  };
  // The kickoff's own ranges (--vm-cpus 1-99, --vm-memory from 512 MiB,
  // --vm-disk from 2048 MiB): the form refuses what the kickoff would.
  const vmCpus = vmNumber("vm_cpus", 1, 99);
  if (vmCpus && typeof vmCpus === "object") return { ok: false, error: vmCpus.error };
  const vmMemory = vmNumber("vm_memory", 512, 262144);
  if (vmMemory && typeof vmMemory === "object") return { ok: false, error: vmMemory.error };
  const vmDisk = vmNumber("vm_disk", 2048, 1048576);
  if (vmDisk && typeof vmDisk === "object") return { ok: false, error: vmDisk.error };
  const vmSnapshot = body.vm_snapshot === false ? false : undefined;
  if (vmSnapshot === false && isolation !== "microvm") return { ok: false, error: "vm_snapshot needs isolation microvm" };
  // A host guard's setting means nothing in a VM, which the kickoff refuses.
  if (isolation === "microvm" && inputsEnforce && inputsEnforce !== "auto") return { ok: false, error: "inputs_enforce sets a host guard; a microVM run has none (the evidence is read-only in each VM)" };
  // The kickoff asks for this switch only when a VM would hold a subscription
  // token, and records it only on a VM run; on a host run it would say
  // nothing and read as if it had.
  const allowOauthInVm = body.allow_oauth_in_vm === true;
  if (allowOauthInVm && isolation !== "microvm") return { ok: false, error: "allow_oauth_in_vm needs isolation microvm" };
  // Where the VMs' disks are kept: an absolute path, VM runs only.
  const vmSnapshotDir = typeof body.vm_snapshot_dir === "string" ? body.vm_snapshot_dir.trim() : "";
  if (vmSnapshotDir) {
    if (isolation !== "microvm") return { ok: false, error: "vm_snapshot_dir needs isolation microvm" };
    if (!vmSnapshotDir.startsWith("/") || /[\x00-\x1f\x7f]/.test(vmSnapshotDir) || vmSnapshotDir.length > 1024) return { ok: false, error: "vm_snapshot_dir must be an absolute path" };
  }
  const allowRoot = body.allow_root === true;
  // Root weakens the host guards: a host run refuses it unless told, and a
  // VM run is only warned about it, so the flag is the host mode's.
  if (allowRoot && isolation !== "host") return { ok: false, error: "allow_root is for a host run (isolation host); a VM run as root is only warned about" };
  const intField = (key: string, min: number, max: number): number | undefined | { error: string } => {
    if (body[key] === undefined || body[key] === null || body[key] === "") return undefined;
    const v = Number(body[key]);
    if (!Number.isInteger(v) || v < min || v > max) return { error: `${key} must be a whole number from ${min} to ${max}` };
    return v;
  };
  const custodyTimeout = intField("custody_timeout", 60, 7 * 24 * 3600);
  if (typeof custodyTimeout === "object") return { ok: false, error: custodyTimeout.error };
  const idleNudgeSec = intField("idle_nudge_sec", 0, 24 * 3600);
  if (typeof idleNudgeSec === "object") return { ok: false, error: idleNudgeSec.error };
  const inputsMaxFiles = intField("inputs_max_files", 1, 1e9);
  if (typeof inputsMaxFiles === "object") return { ok: false, error: inputsMaxFiles.error };
  // The notify command runs as the operator with the run's events on stdin:
  // one line, no control characters, and only through the token-holding form.
  const notify = typeof body.notify === "string" ? body.notify.trim() : "";
  if (notify && (notify.length > 1024 || /[\x00-\x1f\x7f]/.test(notify))) return { ok: false, error: "notify must be one command line, at most 1024 characters" };
  // --env: KEY=VALUE, one line each. The shape only; swarm.sh refuses what
  // may not go in, in its own words, before anything is written.
  const envList = body.env === undefined || body.env === null ? [] : body.env;
  if (!Array.isArray(envList) || envList.length > 64) return { ok: false, error: "env must be a list of at most 64 KEY=VALUE entries" };
  const env: string[] = [];
  for (const item of envList) {
    if (typeof item !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*=/.test(item) || item.length > 4096 || /[\x00-\x1f\x7f]/.test(item)) {
      return { ok: false, error: "each env entry must be one line of KEY=VALUE, the key a shell variable name" };
    }
    env.push(item);
  }
  const ledgerFrom = typeof body.ledger_from === "string" ? body.ledger_from.trim() : "";
  if (ledgerFrom && !RUN_ID.test(ledgerFrom)) return { ok: false, error: "ledger_from must be a run id" };
  // provider=host: the kickoff's own pattern, and the host part the same
  // check allow_hosts gets, since both end up on the same allowlist. Valid in
  // either mode: a host run puts the host on netguard's list too.
  let providerHosts: string[] | undefined;
  if (body.provider_hosts !== undefined && body.provider_hosts !== null && body.provider_hosts !== "") {
    const raw = Array.isArray(body.provider_hosts) ? body.provider_hosts : String(body.provider_hosts).split(/[\s,]+/);
    providerHosts = [...new Set(raw.map((e) => String(e).trim()).filter(Boolean))];
    const bad = providerHosts.find((e) => !PROVIDER_HOST.test(e) || !isHostName(e.slice(e.indexOf("=") + 1).toLowerCase()));
    if (bad) return { ok: false, error: `provider_hosts: ${bad} is not provider=host (a lower-case provider id, then the host its base URL names)` };
    if (providerHosts.length > 20) return { ok: false, error: "provider_hosts: at most 20" };
    if (!providerHosts.length) providerHosts = undefined;
  }
  // Packs by id; whether each is installed is the kickoff's to say (pack.sh
  // resolve), with its dependencies.
  let packs: string[] | undefined;
  if (body.packs !== undefined && body.packs !== null && body.packs !== "") {
    const raw = Array.isArray(body.packs) ? body.packs : String(body.packs).split(/[\s,]+/);
    packs = [...new Set(raw.map((p) => String(p).trim()).filter(Boolean))];
    const bad = packs.find((p) => !/^[a-z0-9][a-z0-9-]{1,63}$/.test(p));
    if (bad) return { ok: false, error: `packs: ${bad} is not a pack id` };
    if (packs.length > 12) return { ok: false, error: "packs: at most 12" };
    if (!packs.length) packs = undefined;
  }
  return {
    ok: true,
    params: {
      model,
      models: models || undefined,
      cap_usd: cap,
      n,
      goal: goal || undefined,
      label: label || undefined,
      playwright: body.playwright === true,
      net,
      allow_hosts: net === "hosts" ? allowHosts : undefined,
      netguard: net !== "open",
      hard_kill: body.hard_kill === true,
      tool_forging: body.tool_forging === true,
      self_compact: selfCompact,
      compact_notice_at: specs.compact_notice_at,
      compact_warn_at: specs.compact_warn_at,
      compact_at: specs.compact_at,
      compact_model: compactModel || undefined,
      inbox_page_chars: inboxPageChars,
      allow_install: body.allow_install === true,
      inputs: inputsName || undefined,
      inputs_sets: inputsList.length > 1 ? inputsList : undefined,
      inputs_enforce: inputsEnforce,
      inputs_attach: inputsAttach,
      inputs_image: inputsImage || undefined,
      inputs_max_mb: inputsMaxMb,
      toolbox_required: toolboxRequired || undefined,
      no_pypi: noPypi || undefined,
      tools_from: toolsFrom || undefined,
      no_read: noRead,
      wall_clock: wall,
      no_start: noStart,
      cap_tokens: capTokens,
      cap_per_agent: capPerAgent,
      catalog: catalog || undefined,
      toolbox,
      quarantine: quarantine || undefined,
      case_id: caseId || undefined,
      examiner: examiner || undefined,
      packs,
      isolation,
      image: image || undefined,
      vm_cpus: vmCpus as number | undefined,
      vm_memory: vmMemory as number | undefined,
      vm_disk: vmDisk as number | undefined,
      vm_snapshot: vmSnapshot,
      allow_oauth_in_vm: allowOauthInVm || undefined,
      provider_hosts: providerHosts,
      vm_snapshot_dir: vmSnapshotDir || undefined,
      allow_pack_secrets: body.allow_pack_secrets === true || undefined,
      allow_synced_folder: body.allow_synced_folder === true || undefined,
      custody_timeout: custodyTimeout,
      idle_nudge_sec: idleNudgeSec,
      inputs_max_files: inputsMaxFiles,
      notify: notify || undefined,
      env: env.length ? env : undefined,
      ledger_from: ledgerFrom || undefined,
      no_verify_copy: body.no_verify_copy === true || undefined,
      allow_root: allowRoot || undefined,
      model_gateway: body.model_gateway === true && isolation === "microvm" ? true : undefined,
    },
  };
}

/**
 * A job's argv as the console shows it: an --env value and the --notify
 * command are the operator's and may carry a secret, so the job list, the
 * event stream and the drawer show `KEY=…` and that a command was given,
 * never the value. swarm.sh gets the argv whole.
 */
export function publicArgv(argv: readonly string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    out.push(argv[i]);
    if (i + 1 >= argv.length) continue;
    if (argv[i] === "--env") {
      i += 1;
      const eq = argv[i].indexOf("=");
      out.push(eq > 0 ? `${argv[i].slice(0, eq)}=…` : "…");
    } else if (argv[i] === "--notify") {
      i += 1;
      out.push("<command not shown>");
    }
  }
  return out;
}

/**
 * What swarm.sh said, with the operator's own secrets taken out: each --env
 * value and the --notify command. swarm.sh names a refused variable by its
 * key and never echoes a value, but the console does not rely on that: the
 * page, the job list and the event stream never carry one.
 */
export function scrubSecrets(text: string, p: Pick<StartParams, "env" | "notify">): string {
  let out = text;
  if (p.notify && p.notify.length >= 3) out = out.split(p.notify).join("<notify command>");
  for (const e of p.env ?? []) {
    const eq = e.indexOf("=");
    const value = eq > 0 ? e.slice(eq + 1) : "";
    if (value.length >= 3) out = out.split(value).join("…");
  }
  return out;
}

/** What `swarm.sh start --check` said: exit 0 the start would go ahead, 2 it would be refused. */
export type StartCheck = {
  exit: number;
  ok: boolean;
  /** BLOCKER lines, each with the indented lines that follow it. */
  blockers: string[];
  warnings: string[];
  /** The whole output in the order swarm.sh wrote it, secrets taken out. */
  said: string[];
  checked_at: string;
};

/** Sort swarm.sh's output into blockers, warnings and the rest; an indented line belongs to the line before it. */
export function parseCheckOutput(text: string): { blockers: string[]; warnings: string[]; said: string[] } {
  const said = text.split("\n").filter((l) => l.trim());
  const blockers: string[] = [];
  const warnings: string[] = [];
  let last: string[] | null = null;
  for (const line of said) {
    if (/^BLOCKER:/.test(line)) {
      blockers.push(line);
      last = blockers;
    } else if (/^WARN:/.test(line)) {
      warnings.push(line);
      last = warnings;
    } else if (/^\s/.test(line) && last?.length) {
      last[last.length - 1] += `\n${line}`;
    } else last = null;
  }
  return { blockers, warnings, said };
}

/** `swarm.sh image-for`: the image a kickoff with these packs boots, and why. */
export type ImagePreview = {
  ref: string | null;
  digest: string | null;
  profile: string | null;
  arch: string | null;
  packs: string[];
  pinned_by: string | null;
  reason: string | null;
  /** The job images, when the agents boot the base and the packs' programs run in jobs: each profile, its reference and the packs it serves. */
  jobs: ImageJob[];
  /** What swarm.sh said beside the JSON (a WARN, a BLOCKER), whole. */
  said: string[];
  /** Why no image was named, in swarm.sh's or pack.sh's words; null when one was. */
  error: string | null;
};

export type ImageJob = { profile: string; ref: string; packs: string[] };

export type ImagePreviewQuery = { packs: string[]; playwright: boolean; tools_from_dir?: string };

export function startArgv(p: StartParams): string[] {
  const argv = ["start"];
  if (p.cap_usd > 0) argv.push("--cap-usd", String(p.cap_usd));
  argv.push("--n", String(p.n));
  if (p.cap_tokens) argv.push("--cap-tokens", String(p.cap_tokens));
  if (p.cap_per_agent) argv.push("--cap-per-agent", String(p.cap_per_agent));
  if (p.models) argv.push("--models", p.models);
  else if (p.model) argv.push("--model", p.model);
  if (p.goal) argv.push("--goal", p.goal);
  if (p.label) argv.push("--label", p.label);
  if (p.wall_clock) argv.push("--wall-clock", String(p.wall_clock));
  if (p.playwright) argv.push("--playwright");
  const net: NetMode = p.net ?? (p.netguard === false ? "open" : "guarded");
  if (net === "open") argv.push("--no-netguard");
  if (net === "local") argv.push("--local-only");
  if (net === "hosts") for (const host of p.allow_hosts ?? []) argv.push("--allow-host", host);
  for (const entry of p.provider_hosts ?? []) argv.push("--provider-host", entry);
  if (p.hard_kill) argv.push("--hard-kill");
  if (p.tool_forging) argv.push("--allow-tool-forging");
  // On is the kickoff's default, so only "off" and the explicit lines travel.
  if (p.self_compact === false) argv.push("--no-self-compact");
  if (p.inbox_page_chars !== undefined) argv.push("--inbox-page-chars", String(p.inbox_page_chars));
  if (p.self_compact !== false) {
    if (p.compact_notice_at) argv.push("--compact-notice-at", p.compact_notice_at);
    if (p.compact_warn_at) argv.push("--compact-warn-at", p.compact_warn_at);
    if (p.compact_at) argv.push("--compact-at", p.compact_at);
    if (p.compact_model) argv.push("--compact-model", p.compact_model);
  }
  if (p.allow_install) argv.push("--allow-install");
  if (p.inputs_image_path) {
    // An image is attached read-only in place of a directory; the harness forces the kernel guard on.
    argv.push("--inputs-image", p.inputs_image_path);
  } else if (p.inputs_dir) {
    // Several sets: one --inputs each, in order; the flags below are all of theirs.
    for (const dir of p.inputs_dirs && p.inputs_dirs.length > 1 ? p.inputs_dirs : [p.inputs_dir]) argv.push("--inputs", dir);
    if (p.inputs_attach === "bind") argv.push("--inputs-bind");
    // A VM run mounts --inputs in place unless told to copy it, so "copy",
    // the form's default, has to say so there, or it quietly becomes a bind.
    else if (p.isolation === "microvm") argv.push("--inputs-copy");
    if (p.inputs_enforce) argv.push("--inputs-enforce", p.inputs_enforce);
    if (p.inputs_max_mb) argv.push("--inputs-max-mb", String(p.inputs_max_mb));
    if (p.inputs_max_files) argv.push("--inputs-max-files", String(p.inputs_max_files));
    // The content check is the copy's; a bind has nothing to check against.
    if (p.no_verify_copy && p.inputs_attach !== "bind") argv.push("--no-verify-copy");
  }
  if (p.allow_synced_folder) argv.push("--allow-synced-folder");
  if (p.allow_pack_secrets) argv.push("--allow-pack-secrets");
  if (p.custody_timeout) argv.push("--custody-timeout", String(p.custody_timeout));
  if (p.idle_nudge_sec !== undefined) argv.push("--idle-nudge-sec", String(p.idle_nudge_sec));
  if (p.notify) argv.push("--notify", p.notify);
  for (const e of p.env ?? []) argv.push("--env", e);
  if (p.ledger_from) argv.push("--ledger-from", p.ledger_from);
  if (p.tools_from_dir) argv.push("--tools-from", p.tools_from_dir);
  for (const dir of p.no_read_dirs ?? []) argv.push("--no-read", dir);
  if (p.catalog) argv.push("--catalog");
  if (p.toolbox) argv.push("--toolbox", p.toolbox);
  if (p.toolbox_required && p.toolbox && p.toolbox !== "off") argv.push("--toolbox-required");
  if (p.no_pypi && p.allow_install) argv.push("--no-pypi");
  if (p.quarantine) argv.push("--quarantine");
  if (p.case_id) argv.push("--case-id", p.case_id);
  if (p.examiner) argv.push("--examiner", p.examiner);
  if (p.packs?.length) argv.push("--pack", p.packs.join(","));
  // Always named: the kickoff's own default must not decide what the form chose.
  argv.push("--isolation", p.isolation === "host" ? "host" : "microvm");
  if (p.isolation !== "host") {
    if (p.image) argv.push("--image", p.image);
    if (p.vm_cpus) argv.push("--vm-cpus", String(p.vm_cpus));
    if (p.vm_memory) argv.push("--vm-memory", String(p.vm_memory));
    if (p.vm_disk) argv.push("--vm-disk", String(p.vm_disk));
    if (p.vm_snapshot === false) argv.push("--no-vm-snapshot");
    if (p.allow_oauth_in_vm) argv.push("--allow-oauth-in-vm");
    if (p.vm_snapshot_dir) argv.push("--vm-snapshot-dir", p.vm_snapshot_dir);
    if (p.model_gateway) argv.push("--model-gateway");
  } else if (p.allow_root) {
    argv.push("--allow-root");
  }
  if (p.no_start) argv.push("--no-start");
  return argv;
}

export type ActionRunnerOptions = {
  root: string;
  runsDir: string;
  swarmSh?: string;
  onUpdate?: (job: Job) => void;
  env?: NodeJS.ProcessEnv;
};

export class ActionRunner {
  private jobs = new Map<string, Job>();
  private secrets = new Map<string, Pick<StartParams, "env" | "notify">>();
  private readonly swarmSh: string;
  private readonly opts: ActionRunnerOptions;

  constructor(opts: ActionRunnerOptions) {
    this.opts = opts;
    this.swarmSh = opts.swarmSh ?? join(opts.root, "scripts", "swarm.sh");
  }

  list(): Job[] {
    return [...this.jobs.values()].sort((a, b) => (a.started_at < b.started_at ? 1 : -1));
  }

  get(id: string): Job | undefined {
    return this.jobs.get(id);
  }

  start(params: StartParams): Job {
    return this.run("start", startArgv(params), null, undefined, params);
  }

  /**
   * `swarm.sh start --check` with the form's options: the real start's own
   * checks, nothing written (no sandbox, registry, hub, audit line, VM or
   * pull). Not a job: the form waits for its answer and shows it.
   */
  check(params: StartParams, timeoutMs = 240_000): Promise<StartCheck> {
    const argv = startArgv(params);
    return this.exec(["start", "--check", ...argv.slice(1)], timeoutMs).then(({ code, output }) => {
      const parsed = parseCheckOutput(scrubSecrets(output, params));
      if (code !== 0 && code !== 2 && !parsed.blockers.length) parsed.blockers.push(`BLOCKER: the check itself did not finish (exit ${code})`);
      return { exit: code, ok: code === 0, ...parsed, checked_at: new Date().toISOString() };
    });
  }

  /** `swarm.sh image-for`: read only. */
  imageFor(q: ImagePreviewQuery, timeoutMs = 60_000): Promise<ImagePreview> {
    const argv = ["image-for", ...q.packs.flatMap((p) => ["--pack", p]), ...(q.tools_from_dir ? ["--tools-from", q.tools_from_dir] : []), ...(q.playwright ? ["--playwright"] : [])];
    return this.exec(argv, timeoutMs).then(({ code, stdout, stderr }) => {
      const said = stderr.split("\n").map((l) => l.trimEnd()).filter((l) => l.trim());
      const none: ImagePreview = { ref: null, digest: null, profile: null, arch: null, packs: q.packs, pinned_by: null, reason: null, jobs: [], said, error: null };
      const line = stdout.trim().split("\n").pop() ?? "";
      let parsed: Record<string, unknown> | null = null;
      try {
        parsed = JSON.parse(line) as Record<string, unknown>;
      } catch {
        parsed = null;
      }
      if (code !== 0 || !parsed || typeof parsed.ref !== "string" || !parsed.ref) {
        return { ...none, error: said.find((l) => /^BLOCKER/.test(l)) ?? said.at(-1) ?? `swarm.sh image-for named no image (exit ${code})` };
      }
      const str = (v: unknown) => (typeof v === "string" && v ? v : null);
      return {
        ref: parsed.ref,
        digest: str(parsed.digest),
        profile: str(parsed.profile),
        arch: str(parsed.arch),
        packs: Array.isArray(parsed.packs) ? parsed.packs.map(String) : q.packs,
        pinned_by: str(parsed.pinned_by),
        reason: str(parsed.reason),
        jobs: Array.isArray(parsed.jobs)
          ? parsed.jobs.flatMap((j: unknown) => {
              const o = (j ?? {}) as Record<string, unknown>;
              return typeof o.profile === "string" && typeof o.ref === "string" ? [{ profile: o.profile, ref: o.ref, packs: Array.isArray(o.packs) ? o.packs.map(String) : [] }] : [];
            })
          : [],
        said,
        error: null,
      };
    });
  }

  /**
   * The environment every swarm.sh the console runs gets. `swarm.sh` has no
   * use for the console's own mutation token, and what it starts is a pane:
   * a credential that travels that far ends up inside the sandbox. Nor does a
   * kickoff take its isolation from the console's environment: the form says
   * host or microvm and the argv names it; an exported SWARM_ISOLATION once
   * turned a host form into a VM run. Everything else is passed as it is.
   */
  private childEnv(): NodeJS.ProcessEnv {
    const { SWARM_UI_TOKEN: _token, SWARM_ISOLATION: _isolation, ...env } = process.env;
    return { ...env, ...this.opts.env, SWARM_RUNS_DIR: this.opts.runsDir, SWARM_OPERATOR_VIA: "console" };
  }

  /** Run swarm.sh and wait: its output whole, in the order it came, and apart. */
  private exec(argv: string[], timeoutMs: number): Promise<{ code: number; output: string; stdout: string; stderr: string }> {
    return new Promise((done) => {
      const child = spawn("bash", [this.swarmSh, ...argv], { cwd: this.opts.root, env: this.childEnv(), stdio: ["ignore", "pipe", "pipe"] });
      let output = "";
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (c: Buffer) => {
        output += c.toString("utf8");
        stdout += c.toString("utf8");
      });
      child.stderr.on("data", (c: Buffer) => {
        output += c.toString("utf8");
        stderr += c.toString("utf8");
      });
      const timer = setTimeout(() => {
        output += `\nBLOCKER: swarm.sh ${argv[0]} did not answer within ${Math.round(timeoutMs / 1000)} s; it was stopped.\n`;
        child.kill("SIGTERM");
      }, timeoutMs);
      child.on("error", (err) => {
        clearTimeout(timer);
        done({ code: -1, output: `${output}\n${err.message}`, stdout, stderr: `${stderr}\n${err.message}` });
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        done({ code: code ?? -1, output, stdout, stderr });
      });
    });
  }

  /** Stop a run; `no_custody` skips the host's custody check, `custody_timeout` bounds it (seconds). */
  stop(swarmId: string, opts: StopParams = {}): Job {
    const argv = ["stop", swarmId];
    if (opts.no_custody) argv.push("--no-custody");
    else if (opts.custody_timeout) argv.push("--custody-timeout", String(opts.custody_timeout));
    return this.run("stop", argv, swarmId);
  }

  reap(swarmId: string, params: ReapParams = {}): Job {
    const argv = ["reap", swarmId];
    if (params.stall_sec !== undefined) argv.push("--stall-sec", String(params.stall_sec));
    if (params.stop) argv.push("--stop");
    return this.run("reap", argv, swarmId);
  }

  /** A legal hold on the run, with its reason: purge and reap refuse it until released. */
  hold(swarmId: string, reason?: string): Job {
    return this.run("hold", ["hold", swarmId, ...(reason ? ["--reason", reason] : [])], swarmId);
  }

  release(swarmId: string): Job {
    return this.run("release", ["release", swarmId], swarmId);
  }

  /**
   * The operator's answer to a lead (swarm.sh lead <id> note L-n TEXT
   * [--allow-host HOST]), or a reopen: recorded on the register, posted to
   * the board as the examiner, on the trace and the operator's record.
   */
  lead(swarmId: string, p: { action: "note" | "reopen"; lead: string; text?: string; allowHost?: string }): Job {
    const args = p.action === "note" ? ["lead", swarmId, "note", p.lead, p.text ?? "", ...(p.allowHost ? ["--allow-host", p.allowHost] : [])] : ["lead", swarmId, "reopen", p.lead, ...(p.text ? [p.text] : [])];
    return this.run("lead", args, swarmId);
  }

  /**
   * A directive (swarm.sh lead <id> direct): an unheld lead under a question
   * (or under one asked in the same act), with its product and acceptance.
   */
  direct(swarmId: string, argv: string[]): Job {
    return this.run("lead", ["lead", swarmId, "direct", ...argv], swarmId);
  }

  /**
   * An act on the question register (swarm.sh question <id> <sub> …): the
   * CLI's own checks, the chain write, the acknowledgement after it, the
   * delivery, the trace and the operator's record twice (attempt, outcome).
   */
  question(swarmId: string, sub: string, argv: string[]): Job {
    return this.run("question", ["question", swarmId, sub, ...argv], swarmId);
  }

  /**
   * The operator's act on the dynamic network (swarm.sh net <id> grant|deny|revoke,
   * docs/adr/0012): a reason always; on the trace and the operator's record,
   * and posted to whoever asked, like the CLI's.
   */
  net(swarmId: string, p: { action: "grant" | "deny" | "revoke" | "socket"; target?: string; why: string; host?: string; lead?: string }): Job {
    const args =
      p.action === "socket"
        ? ["net", swarmId, "grant", "--socket", p.host ?? "", ...(p.lead ? ["--lead", p.lead] : []), "--why", p.why]
        : ["net", swarmId, p.action, p.target ?? "", "--why", p.why];
    return this.run("net", args, swarmId);
  }

  /**
   * An act on an operator request (swarm.sh requests <id> <sub> R-n …,
   * docs/adr/0014): acknowledge, answer, decline, withdraw, or an
   * acquisition's stage; on the trace and the operator's record, and said on
   * the board to whoever asked.
   */
  requests(swarmId: string, sub: string, argv: string[]): Job {
    return this.run("requests", ["requests", swarmId, sub, ...argv], swarmId);
  }

  /** The ledger as CSV or a Timesketch import, written to `out` (a file of the console's own). */
  export(swarmId: string, format: "csv" | "timesketch", out: string): Job {
    return this.run("export", ["export", swarmId, "--format", format, "--out", out], swarmId, out);
  }

  /** The handover package, signed with the operator's SSH key when asked. */
  package(swarmId: string, sign: boolean): Job {
    return this.run("package", ["package", swarmId, ...(sign ? ["--sign"] : [])], swarmId);
  }

  /** Re-hash a package against its manifest and check its signature. */
  verify(swarmId: string, pkg: string): Job {
    return this.run("verify", ["verify", pkg], swarmId);
  }

  /** More room for a going or paused run (swarm.sh extend): a paused run whose caps then leave room goes on. */
  extend(swarmId: string, argv: string[]): Job {
    return this.run("extend", argv, swarmId);
  }

  /** Lift a pause whose cause is gone (swarm.sh unpause): on the operator's record as the console's, like every job here. */
  unpause(swarmId: string): Job {
    return this.run("unpause", ["unpause", swarmId], swarmId);
  }

  /** "Continue this run" (swarm.sh resume): the same run, in the same sandbox, on the same chains. */
  resume(swarmId: string, argv: string[]): Job {
    return this.run("resume", argv, swarmId);
  }

  /**
   * A job's whole output, as it came, with the operator's own secrets taken
   * out as they are from the job list; null when there is no such job or
   * its output was never kept.
   */
  async output(id: string, stream: "stdout" | "stderr"): Promise<string | null> {
    const job = this.jobs.get(id);
    const file = job?.output?.[stream]?.file;
    if (!job || !file) return null;
    const text = await readFile(file, "utf8").catch(() => null);
    if (text === null) return null;
    const secrets = this.secrets.get(id);
    return secrets ? scrubSecrets(text, secrets) : text;
  }

  /** Delete a run's sandbox, disks and hub directory, keeping its record and a destruction record. swarm.sh refuses a running or held run. */
  purge(swarmId: string): Job {
    return this.run("purge", ["purge", swarmId, "--yes"], swarmId);
  }

  /** One examiner review line, written by scripts/review.ts through swarm.sh (its one writer). */
  review(swarmId: string, r: ReviewParams): Job {
    const argv = ["review", swarmId, `--${r.action}`, String(r.entry_seq)];
    if (r.note) argv.push("--note", r.note);
    argv.push("--examiner", r.examiner);
    return this.run("review", argv, swarmId);
  }

  private run(kind: JobKind, argv: string[], swarmId: string | null, outputFile?: string, secrets?: Pick<StartParams, "env" | "notify">): Job {
    const job: Job = {
      ...(outputFile ? { output_file: outputFile } : {}),
      id: `${kind}-${randomBytes(3).toString("hex")}`,
      kind,
      argv: publicArgv(argv),
      status: "running",
      exit_code: null,
      stdout: "",
      stderr: "",
      started_at: new Date().toISOString(),
      finished_at: null,
      swarm_id: swarmId,
    };
    this.jobs.set(job.id, job);
    if (secrets) this.secrets.set(job.id, secrets);
    if (this.jobs.size > 50) {
      const oldest = this.list().at(-1);
      if (oldest && oldest.status !== "running") {
        this.jobs.delete(oldest.id);
        this.secrets.delete(oldest.id);
      }
    }
    // The whole output, on disk as it comes: the job list carries the last
    // OUTPUT_CAP of each stream, and says so and where the whole is.
    const dir = join(this.opts.runsDir, "console-jobs");
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      for (const f of ["stdout", "stderr"] as const) {
        const file = join(dir, `${job.id}.${f}.log`);
        appendFileSync(file, "", { mode: 0o600 });
        chmodSync(file, 0o600);
      }
      job.output = { stdout: { file: join(dir, `${job.id}.stdout.log`), bytes: 0 }, stderr: { file: join(dir, `${job.id}.stderr.log`), bytes: 0 } };
    } catch {
      // No directory of its own: the output is still shown, bounded, and says it was not kept.
    }
    const tail = { stdout: "", stderr: "" };
    const child = spawn("bash", [this.swarmSh, ...argv], {
      cwd: this.opts.root,
      // The operator's record says the console was the way in.
      env: this.childEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const append = (field: "stdout" | "stderr", chunk: Buffer) => {
      const kept = job.output?.[field];
      if (kept) {
        try {
          appendFileSync(kept.file, chunk);
          kept.bytes += chunk.length;
        } catch {
          delete job.output;
        }
      }
      tail[field] = (tail[field] + chunk.toString("utf8")).slice(-OUTPUT_CAP);
      const shown = secrets ? scrubSecrets(tail[field], secrets) : tail[field];
      const whole = job.output?.[field];
      const earlier = whole ? whole.bytes - Buffer.byteLength(tail[field], "utf8") : 0;
      job[field] =
        earlier > 0 && whole
          ? `[${earlier} earlier byte(s) of ${whole.bytes} are not shown here; the whole ${field} is kept in ${whole.file} (GET /api/jobs/${job.id}/output?stream=${field})]\n${shown}`
          : !whole && tail[field].length >= OUTPUT_CAP
            ? `[only the last ${OUTPUT_CAP} characters are shown, and the whole ${field} could not be kept on disk]\n${shown}`
            : shown;
      if (kind === "start" && !job.swarm_id) {
        const m = job.stdout.match(/Swarm id:\s+(\S+)/);
        if (m) job.swarm_id = m[1];
      }
      this.opts.onUpdate?.(job);
    };
    child.stdout.on("data", (c: Buffer) => append("stdout", c));
    child.stderr.on("data", (c: Buffer) => append("stderr", c));
    child.on("error", (err) => {
      append("stderr", Buffer.from(`\n${err.message}`));
      job.status = "failed";
      job.exit_code = -1;
      job.finished_at = new Date().toISOString();
      this.opts.onUpdate?.(job);
    });
    child.on("close", (code) => {
      job.exit_code = code ?? -1;
      job.status = code === 0 ? "ok" : "failed";
      job.finished_at = new Date().toISOString();
      this.opts.onUpdate?.(job);
    });
    this.opts.onUpdate?.(job);
    return job;
  }
}

const PROVIDER = /^[a-z0-9_.-]+$/;
const MODEL_SLUG = /^[A-Za-z0-9_.:/-]+$/;

export function parseModelList(text: string): string[] {
  const out = new Set<string>();
  for (const line of text.split("\n")) {
    const parts = line.trim().split(/\s+/);
    const first = parts[0] ?? "";
    if (MODEL_REF.test(first)) {
      out.add(first);
      continue;
    }
    // Official `pi --list-models` is a table: provider, model, context, …
    const second = parts[1] ?? "";
    if (first === "provider" || second === "model") continue;
    if (parts.length >= 3 && PROVIDER.test(first) && MODEL_SLUG.test(second)) {
      const id = `${first}/${second}`;
      if (MODEL_REF.test(id)) out.add(id);
    }
  }
  return [...out];
}

/**
 * `pi --list-models` when the binary exists; otherwise a static list. Either
 * way the local providers from models.json are folded in, because Pi omits a
 * keyless one entirely and the picker has to be able to name it.
 */
export function listModels(timeoutMs = 4000, piBin = process.env.SWARM_PI_BIN || "pi", agentDir?: string): Promise<ModelList> {
  const local = readLocalProviders(agentDir);
  const withLocal = (value: ModelList): ModelList => {
    const models = [...value.models];
    for (const l of local) if (!models.includes(l.model)) models.push(l.model);
    return { ...value, models, ...(local.length ? { local } : {}) };
  };
  return new Promise((resolveList) => {
    let settled = false;
    const finish = (value: ModelList) => {
      if (settled) return;
      settled = true;
      resolveList(withLocal(value));
    };
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(piBin, ["--list-models"], { stdio: ["ignore", "pipe", "pipe"] });
    } catch {
      finish({ source: "static", models: STATIC_MODELS });
      return;
    }
    let out = "";
    child.stdout?.on("data", (c: Buffer) => {
      out += c.toString("utf8");
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish({ source: "static", models: STATIC_MODELS });
    }, timeoutMs);
    child.on("error", () => {
      clearTimeout(timer);
      finish({ source: "static", models: STATIC_MODELS });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      const models = parseModelList(out);
      if (code === 0 && models.length) finish({ source: "pi", models });
      else finish({ source: "static", models: STATIC_MODELS });
    });
  });
}

/**
 * Whether a provider can be used right now, from `pi auth check`. The kickoff
 * form defaults to a model that is actually ready instead of the first in the
 * list, and marks the rest — the same gate swarm.sh runs before it spends.
 */
export type ProviderReadiness = {
  /** `local`: a server on this machine or network that Pi will not list until models.json gives it a placeholder apiKey. */
  status: "ready" | "not_ready" | "invalid" | "unknown" | "local";
  provider: string;
  /** oauth (a subscription) or api_key, when Pi says. */
  auth_type?: string;
  reason?: string;
  /** Served from this machine or network: no key to log in with, no metered cost. */
  local?: boolean;
  base_url?: string;
  /** The hosts a microVM would be told of for this provider, found the way swarm.sh provider_known_hosts finds them; empty when none is known, or for a local server (reached through the host gateway). */
  vm_hosts?: string[];
  /** What `swarm.sh start --isolation microvm` refuses about this provider; empty when it can go into a VM. Ready on the host is not ready in a VM. */
  vm_blockers?: VmBlocker[];
};

/**
 * One reason the VM kickoff refuses a provider, and the form setting that
 * lifts it; none lifts a provider that signs its own requests.
 */
export type VmBlocker = {
  kind: "oauth" | "signing" | "unknown_host";
  lifted_by?: "allow_oauth_in_vm" | "provider_hosts";
  reason: string;
};

export type ReadinessReport = {
  checked_at: string;
  /** Keyed by provider: auth is per provider, not per model. */
  providers: Record<string, ProviderReadiness>;
};

function providerOf(model: string): string {
  const slash = model.indexOf("/");
  return slash === -1 ? model : model.slice(0, slash);
}

function checkOneProvider(model: string, timeoutMs: number, piBin: string): Promise<ProviderReadiness> {
  const provider = providerOf(model);
  return new Promise((resolveCheck) => {
    let settled = false;
    const finish = (value: ProviderReadiness) => {
      if (settled) return;
      settled = true;
      resolveCheck(value);
    };
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(piBin, ["auth", "check", "--model", model, "--json"], { stdio: ["ignore", "pipe", "pipe"] });
    } catch {
      finish({ status: "unknown", provider, reason: "pi not found" });
      return;
    }
    let out = "";
    child.stdout?.on("data", (c: Buffer) => {
      out += c.toString("utf8");
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish({ status: "unknown", provider, reason: "auth check timed out" });
    }, timeoutMs);
    child.on("error", () => {
      clearTimeout(timer);
      finish({ status: "unknown", provider, reason: "pi not found" });
    });
    // `pi auth check` exits 1 for not_ready and 2 for invalid; the JSON on
    // stdout is the answer either way.
    child.on("close", () => {
      clearTimeout(timer);
      try {
        const parsed = JSON.parse(out) as { status?: unknown; provider?: unknown; authType?: unknown; reason?: unknown };
        const status = parsed.status === "ready" || parsed.status === "not_ready" || parsed.status === "invalid" ? parsed.status : "unknown";
        finish({
          status,
          provider: typeof parsed.provider === "string" ? parsed.provider : provider,
          ...(typeof parsed.authType === "string" ? { auth_type: parsed.authType } : {}),
          ...(typeof parsed.reason === "string" ? { reason: parsed.reason } : {}),
        });
      } catch {
        finish({ status: "unknown", provider, reason: "unreadable auth check output" });
      }
    });
  });
}

export async function checkReadiness(models: string[], timeoutMs = 8000, piBin = process.env.SWARM_PI_BIN || "pi", agentDir?: string): Promise<ReadinessReport> {
  // One check per provider, with the first model that names it.
  const firstModel = new Map<string, string>();
  for (const m of models) {
    const p = providerOf(m);
    if (!firstModel.has(p)) firstModel.set(p, m);
  }
  const providers: Record<string, ProviderReadiness> = {};
  const localByProvider = new Map<string, LocalModel>();
  for (const l of readLocalProviders(agentDir)) if (!localByProvider.has(l.provider)) localByProvider.set(l.provider, l);
  const results = (await Promise.all([...firstModel.values()].map((m) => checkOneProvider(m, timeoutMs, piBin)))).map((r) => {
    // "Not logged in" is the wrong diagnosis for a local server: there is no
    // login. Pi wants a placeholder apiKey in models.json, and that is what
    // the console has to say.
    const local = localByProvider.get(r.provider);
    if (!local) return r;
    if (r.status === "not_ready" && r.reason === "credentials_not_configured") {
      return { ...r, status: "local" as const, local: true, base_url: local.base_url, reason: "needs a placeholder apiKey in models.json" };
    }
    return { ...r, local: true, base_url: local.base_url };
  });
  for (const [i, [provider, model]] of [...firstModel.entries()].entries()) {
    const vm = await vmReadiness(model, results[i].auth_type, { agentDir });
    providers[provider] = { ...results[i], ...vm };
  }
  return { checked_at: new Date().toISOString(), providers };
}

/** The hosts the kickoff knows by heart for Pi's built-in cloud providers (swarm.sh provider_known_hosts). */
const BUILTIN_HOSTS: Record<string, string[]> = {
  openai: ["api.openai.com"],
  deepseek: ["api.deepseek.com"],
  xai: ["api.x.ai"],
  google: ["generativelanguage.googleapis.com"],
  anthropic: ["api.anthropic.com", "platform.claude.com"],
  "openai-codex": ["chatgpt.com", "auth.openai.com"],
  openrouter: ["openrouter.ai"],
};
/** Providers that sign every request with their secret inside the client: the kickoff never puts one in a VM. */
const SIGNING_PROVIDERS = new Set(["amazon-bedrock", "google-vertex"]);

type VmCheckOptions = {
  agentDir?: string;
  env?: NodeJS.ProcessEnv;
  /** The hosts Pi's own model list gives a provider; tests pass one so no `pi` is looked for. */
  piHosts?: (model: string) => Promise<string[]>;
};

function readJsonObject(file: string): Record<string, unknown> | null {
  try {
    const data = JSON.parse(readFileSync(file, "utf8").replace(/^﻿/, "")) as unknown;
    return data && typeof data === "object" ? (data as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function field(obj: unknown, ...path: string[]): unknown {
  let cur = obj;
  for (const key of path) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}

/**
 * The allowlist entry for a URL, as swarm.sh allow_entry_of_url writes it:
 * the host alone for HTTPS on 443, `host:port` off 443 or on a local host.
 */
export function allowEntryOfUrl(url: string): string {
  const m = url.match(/^([a-z]+):\/\/(\[[^\]]+\]|[^/:]+)(?::(\d+))?/i);
  if (!m) return "";
  const host = m[2].replace(/^\[|\]$/g, "").toLowerCase();
  const port = m[3] ?? (m[1].toLowerCase() === "http" ? "80" : "443");
  return isLocalHost(host) || port !== "443" ? `${host}:${port}` : host;
}

/** Pi's own model list, through the script the kickoff runs (scripts/provider-hosts.mjs), loaded once. */
let piHostLookup: Promise<(model: string) => string[]> | null = null;
function piProviderHosts(model: string): Promise<string[]> {
  // A computed specifier: the module is plain JavaScript with no types, and
  // it is the kickoff's own, so both ask Pi the same question.
  const spec = new URL("../provider-hosts.mjs", import.meta.url).href;
  piHostLookup ??= import(spec).then((m: { providerHosts?: (model: string) => string[] }) => m.providerHosts ?? (() => [])).catch(() => () => []);
  return piHostLookup.then((lookup) => {
    try {
      return lookup(model);
    } catch {
      return [];
    }
  });
}

/**
 * The base URL a provider is served from when the harness can know it, the
 * way swarm.sh provider_base_url reads it: llama.cpp's own default, nothing
 * for the cloud providers Pi knows, models.json for every other one.
 */
function providerBaseUrl(provider: string, models: Record<string, unknown> | null, env: NodeJS.ProcessEnv): string {
  if (provider === "llama.cpp") return env.LLAMA_BASE_URL || "http://127.0.0.1:8080";
  if (BUILTIN_HOSTS[provider] || provider === "azure") return "";
  const base = field(models, "providers", provider, "baseUrl");
  return typeof base === "string" ? base : "";
}

/**
 * The hosts a VM is told of for a model before any --provider-host: the
 * same places, in the same order, as swarm.sh provider_known_hosts. Empty
 * means the kickoff would ask for --provider-host.
 */
export async function vmProviderHosts(model: string, opts: VmCheckOptions = {}): Promise<string[]> {
  const env = opts.env ?? process.env;
  const agentDir = opts.agentDir ?? (env.PI_CODING_AGENT_DIR || join(homedir(), ".pi", "agent"));
  const provider = providerOf(model);
  const models = readJsonObject(join(agentDir, "models.json"));
  const builtin = BUILTIN_HOSTS[provider];
  if (builtin) {
    // A built-in provider pointed elsewhere by models.json is called there, beside its own hosts.
    const override = field(models, "providers", provider, "baseUrl");
    return [...new Set([...(typeof override === "string" && override ? [allowEntryOfUrl(override)] : []), ...builtin].filter(Boolean))];
  }
  if (provider === "azure") {
    // The customer's own resource: the shell first, then the provider's env block in Pi's store.
    let base = env.AZURE_OPENAI_BASE_URL || "";
    let name = env.AZURE_OPENAI_RESOURCE_NAME || "";
    if (!base && !name) {
      const auth = readJsonObject(join(agentDir, "auth.json"));
      const b = field(auth, "azure", "env", "AZURE_OPENAI_BASE_URL");
      const n = field(auth, "azure", "env", "AZURE_OPENAI_RESOURCE_NAME");
      base = typeof b === "string" ? b : "";
      name = typeof n === "string" ? n : "";
    }
    if (base) return [allowEntryOfUrl(base)].filter(Boolean);
    return name ? [`${name}.openai.azure.com`.toLowerCase()] : [];
  }
  const base = providerBaseUrl(provider, models, env);
  if (base) return [allowEntryOfUrl(base)].filter(Boolean);
  return (opts.piHosts ?? piProviderHosts)(model);
}

/**
 * What the VM kickoff would say about one model's provider, before it
 * writes anything: a subscription token refused without the switch, a
 * provider that signs its own requests refused outright, a provider with no
 * known host refused until one is named. The same checks, in the same
 * order, as swarm.sh start under --isolation microvm, so a model the host
 * calls ready is not shown as ready for a VM it cannot enter.
 */
export async function vmReadiness(model: string, authType: string | undefined, opts: VmCheckOptions = {}): Promise<{ vm_hosts: string[]; vm_blockers: VmBlocker[] }> {
  const env = opts.env ?? process.env;
  const agentDir = opts.agentDir ?? (env.PI_CODING_AGENT_DIR || join(homedir(), ".pi", "agent"));
  const provider = providerOf(model);
  const blockers: VmBlocker[] = [];
  // vm_oauth_providers reads the type from Pi's store; `pi auth check`
  // stands in only when the store has no entry for the provider.
  const stored = field(readJsonObject(join(agentDir, "auth.json")), provider, "type");
  if (stored === "oauth" || (stored === undefined && authType === "oauth")) {
    blockers.push({
      kind: "oauth",
      lifted_by: "allow_oauth_in_vm",
      reason: "a subscription (OAuth) provider: its token is the operator's whole account, and a VM holding its placeholder could use it beyond inference. Use an API key, or allow OAuth in the VMs to accept that",
    });
  }
  // A local server is reached through the host gateway; no host to name.
  const base = providerBaseUrl(provider, readJsonObject(join(agentDir, "models.json")), env);
  const baseHost = base ? hostOfUrl(base) : "";
  if (baseHost && isLocalHost(baseHost)) return { vm_hosts: [], vm_blockers: blockers };
  if (SIGNING_PROVIDERS.has(provider)) {
    blockers.push({
      kind: "signing",
      reason: "signs every request with its secret inside the client, so a VM would have to hold the secret itself. Run it on the host, or through a gateway that takes a key",
    });
    return { vm_hosts: [], vm_blockers: blockers };
  }
  const hosts = await vmProviderHosts(model, opts);
  if (!hosts.length) {
    blockers.push({
      kind: "unknown_host",
      lifted_by: "provider_hosts",
      reason: `no host is known for it, and a VM reaches nothing it is not told of. Name one: ${provider}=<the host its base URL names>`,
    });
  }
  return { vm_hosts: hosts, vm_blockers: blockers };
}

/** An installed pack, as the kickoff form lists it. */
export type PackRow = {
  id: string;
  name: string;
  version: string;
  description: string;
  depends: string[];
  /** The secrets the pack declares, by name and title: the form asks for consent (--allow-pack-secrets) when a chosen pack has any. Never a value. */
  secrets: Array<{ name: string; title: string; required: boolean }>;
};

/**
 * The packs installed under DFIRSWARM_HOME (pack.sh's store), for the form.
 * Read-only: installing, verifying and removing stay with pack.sh.
 */
export async function listPacks(home: string = process.env.DFIRSWARM_HOME || join(process.env.HOME || "", ".dfirswarm")): Promise<PackRow[]> {
  const dir = join(home, "packs");
  const out: PackRow[] = [];
  for (const id of (await readdir(dir).catch(() => [] as string[])).sort()) {
    try {
      const m = JSON.parse(await readFile(join(dir, id, "pack.json"), "utf8")) as {
        id?: string;
        name?: string;
        version?: string;
        description?: string;
        depends?: string[];
        secrets?: Array<{ name?: unknown; title?: unknown; required?: unknown }>;
      };
      if (m.id !== id) continue;
      const secrets = (Array.isArray(m.secrets) ? m.secrets : [])
        .filter((x) => x && typeof x.name === "string")
        .map((x) => ({ name: String(x.name), title: typeof x.title === "string" ? x.title : String(x.name), required: x.required === true }));
      out.push({ id, name: m.name ?? id, version: m.version ?? "?", description: m.description ?? "", depends: (m.depends ?? []).map((d) => d.split(/[<>=!~ ]/)[0]), secrets });
    } catch {
      // not a pack
    }
  }
  return out;
}
