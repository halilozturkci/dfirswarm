#!/usr/bin/env node
/**
 * One microVM per agent, with Pi inside, brought up and put away by the
 * harness. Agents never make VMs; they get the one the kickoff gave them.
 *
 * What goes in, and why each is shaped the way it is:
 *
 * **The same paths as the host.** The sandbox, the harness code and the
 * evidence are mounted in the guest at the paths they have on the host, so
 * every path a pane, the trace, the registry or a check names means the same
 * file on both sides and nothing is ever translated.
 *
 * **A read-only floor with writable holes, never the reverse.** The sandbox
 * is mounted read-only as a whole, `work/` with it; each agent's own
 * `work/<id>/`, `work/extracted/<id>/` and `work/quarantine/<id>/` (the last
 * two no-exec, inside the whole extracted and quarantine shares mounted
 * read-only and no-exec), its own `tool-output/<id>/` and its own Pi session
 * directory are mounted writable on top. A read-only mount inside a writable
 * one is not a boundary — guest root unmounted one and wrote through the
 * parent (measured, spikes/microvm-smoke) — while a writable mount inside a
 * read-only one, unmounted, leaves the read-only floor. The board's files and
 * the shared part of `work/` are written by the hub (scripts/vm-hub.ts,
 * publish_file), which never opens a file under a seat's own directory.
 *
 * **Structured, not parsed.** Mounts, network rules and secrets go through
 * the SDK's builders. `msb create --mount-dir` misparsed a long mount spec
 * (`…/sbx:ro` became a read-write mount at `…/sbxo`, measured) and would put
 * every value on argv.
 *
 * **No credential enters a guest.** A provider key or subscription token is
 * resolved on the host by Pi itself (`pi auth print-api-key`,
 * `pi auth print-bearer-token --min-expiry`, which refreshes a subscription
 * on the host for the whole run) and handed to msb as a secret bound to the
 * provider's hosts. The guest's Pi holds a placeholder; msb swaps in the
 * value on the way out over TLS, to those hosts only.
 *
 *   node --experimental-strip-types scripts/vm.ts probe  [--image REF]
 *   node --experimental-strip-types scripts/vm.ts pull   --image REF
 *   node --experimental-strip-types scripts/vm.ts create --spec FILE
 *   node --experimental-strip-types scripts/vm.ts gateway-plan --spec FILE --out FILE
 *   node --experimental-strip-types scripts/vm.ts image-digest --image REF
 *   node --experimental-strip-types scripts/vm.ts finish --run ID --sandbox DIR [--no-snapshot] [--agent ID] [--registry FILE]
 *   node --experimental-strip-types scripts/vm.ts reap   [--run ID] [--registry FILE] [--only ID]
 *   node --experimental-strip-types scripts/vm.ts list   [--run ID]
 *   node --experimental-strip-types scripts/vm.ts capacity --n N --cpus N --memory MIB
 *   node --experimental-strip-types scripts/vm.ts netcheck --image REF [--allow-host H]...
 *   node --experimental-strip-types scripts/vm.ts check-allow ENTRIES...
 *   node --experimental-strip-types scripts/vm.ts toolbox --image REF --out FILE [--preset SETS] [--required] [--packs DIRS]
 *   node --experimental-strip-types scripts/vm.ts catalog --image REF --sandbox DIR [--evidence DIR]... [--allow-host H]... [--memory MIB] [--run ID] [--registry FILE]
 *   node --experimental-strip-types scripts/vm.ts msb-path
 *
 * SWARM_MSB_BIN names another msb (tests stand one in).
 */
import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createReadStream, existsSync, readFileSync, realpathSync } from "node:fs";
import { isIPv4, isIPv6 } from "node:net";
import { availableParallelism, totalmem } from "node:os";
import { chmod, mkdir, readFile, rename, rm, stat, utimes, writeFile, readdir } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { guestProviders, planGateway, type GatewayConfig } from "./model-gateway.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
/** The vsock port every VM's hub link uses; the host end is the agent's own socket. */
export const HUB_PORT = 5000;
/** Where the extension in the guest finds the hub (the bridge listens here). */
export const GUEST_HUB_SOCKET = "/run/dfirswarm/hub.sock";
export const LABEL_RUN = "dev.dfirswarm.run";
export const LABEL_AGENT = "dev.dfirswarm.agent";
/**
 * Which registry the run is in, as a short digest of its path. One machine
 * can hold several (a worktree's runs/, a case under --sandbox, a test's
 * temp directory), and a reap reads only one: it may remove only the VMs of
 * runs that registry knows about.
 */
export const LABEL_REGISTRY = "dev.dfirswarm.registry";

export function registryLabel(registryPath: string): string {
  return createHash("sha256").update(resolve(registryPath)).digest("hex").slice(0, 16);
}
/** An OAuth credential in a guest never refreshes: its expiry is set past any run. */
const GUEST_OAUTH_EXPIRES = Date.UTC(2099, 0, 1);

export type Mount = { host: string; guest?: string; readonly?: boolean; noexec?: boolean };

export type ProviderSpec = {
  provider: string;
  /** `api_key` (Pi's store, models.json or the environment), `oauth`, or `local` (no credential). */
  kind: "api_key" | "oauth" | "local";
  /** Hosts the credential may go to, and the only hosts this provider's traffic may reach. */
  hosts: string[];
  /** For `local`: the host's port the guest may reach through the host gateway. */
  port?: number;
  /** For a LAN model named by a name the guest cannot resolve: the address the host resolved it to. */
  resolved?: { name: string; ip: string };
};

export type PackSecretSpec = { name: string; value_file?: string; hosts: string[] };

export type VmSpec = {
  run: string;
  sandbox: string;
  image: string;
  pull?: "always" | "if-missing" | "never";
  cpus?: number;
  memory_mib?: number;
  root_disk_mib?: number;
  max_duration_sec?: number;
  /** Where the hub's per-agent sockets are. */
  hub_dir: string;
  /** Mounted into every VM, at the same path unless `guest` says otherwise. */
  mounts: Mount[];
  /** Mounted after the agent's own writable directories: no-exec holes inside work/. */
  late_mounts?: Mount[];
  /** `--no-netguard`: every public host, as the operator asked. */
  open_net?: boolean;
  env: Record<string, string>;
  agents: Array<{ id: string; model: string; env?: Record<string, string> }>;
  /** Hosts every VM may reach on 443: provider hosts, `--allow-host`, install indexes. */
  allow_hosts: string[];
  providers: ProviderSpec[];
  pack_secrets?: PackSecretSpec[];
  /** The host's `pi`, which resolves credentials. */
  pi_bin?: string;
  /** How long a subscription token must stay valid (Pi's duration syntax, `90m`). */
  min_token_validity?: string;
  /** Pi's agent directory on the host: models.json and settings.json are read from it. */
  pi_agent_dir?: string;
  records_dir: string;
  snapshot_dir?: string;
  /** The run registry this run is recorded in (labels the VMs for the reaper). */
  registry?: string;
  /** The image's digest as the kickoff resolved it, once: every VM must boot this. */
  image_digest?: string;
  /**
   * Where the seats' hub tokens are: a 0600 JSON file ({agent id: 32 hex})
   * in the run's hub directory, which no VM mounts. The spec names the file
   * and never holds a token; each VM gets its own as SWARM_SEAT_TOKEN.
   */
  seat_tokens_file?: string;
  /**
   * The model gateway (`--model-gateway`): where the VMs reach it (msb's
   * host gateway and this port) and its config, which holds each seat's
   * gateway token and is read here, never mounted. `declined` names the
   * providers left to msb's placeholder path and why.
   */
  model_gateway?: { port: number; config: string; declined?: Array<{ provider: string; reason: string }> };
};

/**
 * This seat's hub token from the spec's seat-tokens file: what every
 * connection a VM process opens to its seat's socket shows first
 * (`{"t":"auth","token":…}`), beside the socket it arrives on. Null when the
 * run has none (an older kickoff); a missing or malformed token for a seat
 * of a run that has them is an error, not a seat that goes without.
 */
export function seatTokenFor(spec: Pick<VmSpec, "seat_tokens_file">, agent: string): string | null {
  if (!spec.seat_tokens_file) return null;
  const tokens = JSON.parse(readFileSync(spec.seat_tokens_file, "utf8")) as Record<string, unknown>;
  const token = tokens[agent];
  if (typeof token !== "string" || !/^[0-9a-f]{32}$/.test(token)) throw new Error(`no hub token for ${agent} in the run's seat-tokens file`);
  return token;
}

/**
 * Why this host cannot run the agents' VMs, before msb is asked: microsandbox
 * ships for Apple silicon and for glibc Linux on x64 and arm64. A Windows or
 * musl host used to be mapped to the glibc Linux binary and fail at the probe
 * with an error that named neither. Null when the platform is one msb runs on.
 */
// `glibc` null is a host with none; left out, this host's own is read.
export function vmPlatformProblem(platform: string = process.platform, arch: string = process.arch, glibc: string | null = glibcVersion() ?? null): string | null {
  if (platform === "darwin") return arch === "arm64" ? null : "microVMs on macOS need Apple silicon; this Mac is Intel";
  if (platform !== "linux") return `microVMs need macOS on Apple silicon or Linux with KVM; this host is ${platform}`;
  if (arch !== "x64" && arch !== "arm64") return `microVMs on Linux need x64 or arm64; this host is ${arch}`;
  if (!glibc) return "microVMs on Linux need a glibc system; this host's C library is not glibc (musl?)";
  return null;
}

function glibcVersion(): string | undefined {
  try {
    const report = process.report?.getReport() as unknown as { header?: { glibcVersionRuntime?: string } } | undefined;
    return report?.header?.glibcVersionRuntime;
  } catch {
    return undefined;
  }
}

/** The msb binary this repository pins, for the pane's `msb exec` and the CLI calls. */
export function msbBinary(): string {
  // A stand-in for tests of what the harness does with msb's answers.
  if (process.env.SWARM_MSB_BIN) return process.env.SWARM_MSB_BIN;
  const plat = process.platform === "darwin" ? `darwin-${process.arch}` : `linux-${process.arch === "x64" ? "x64" : process.arch}-gnu`;
  const require = createRequire(import.meta.url);
  try {
    const pkg = require.resolve(`@superradcompany/microsandbox-${plat}/package.json`);
    const bin = join(dirname(pkg), "bin", "msb");
    if (existsSync(bin)) return bin;
  } catch {
    // fall through to PATH
  }
  return "msb";
}

export function vmName(run: string, agent: string): string {
  return `dfs-${run}-${agent}`;
}

function base64url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/**
 * The string the guest's Pi holds instead of a credential. msb replaces it
 * with the real value in a request's headers, to the secret's hosts only.
 * Two providers look inside the credential, so their placeholders are shaped
 * like one: Pi sends an Anthropic token as a subscription bearer only when it
 * contains `sk-ant-oat`, and reads the ChatGPT account id out of the Codex
 * token's JWT payload. The account id is an identifier, not a secret.
 */
export function placeholderFor(provider: string, kind: ProviderSpec["kind"], accountId?: string): string {
  const salt = randomBytes(12).toString("hex");
  if (kind === "oauth" && provider === "anthropic") return `sk-ant-oat01-dfirswarm-${salt}`;
  if (kind === "oauth" && provider === "openai-codex") {
    const header = base64url(JSON.stringify({ alg: "none", typ: "JWT" }));
    const payload = base64url(JSON.stringify({ "https://api.openai.com/auth": { chatgpt_account_id: accountId ?? "" }, dfirswarm: "placeholder" }));
    return `${header}.${payload}.dfirswarm${salt}`;
  }
  return `dfirswarm-secret-${provider.replace(/[^a-zA-Z0-9]/g, "")}-${salt}`;
}

function run(cmd: string, args: string[], options: { timeoutMs?: number; env?: NodeJS.ProcessEnv } = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((done) => {
    const child = execFile(cmd, args, { timeout: options.timeoutMs ?? 120_000, maxBuffer: 64 * 1024 * 1024, env: options.env ?? process.env }, (err, stdout, stderr) => {
      const code = err ? (typeof (err as { code?: unknown }).code === "number" ? ((err as { code: number }).code) : 1) : 0;
      done({ code, stdout: String(stdout), stderr: String(stderr) });
    });
    // Nothing is ever written to a command's stdin here, and `msb exec`
    // streams stdin into the guest: left open, the exec never ends
    // (measured: the stop-time inventory waited out its whole timeout).
    child.stdin?.end();
  });
}

/** The variable msb holds a provider's credential under in the VM (its placeholder is the value there). */
export function secretEnvName(s: { provider: string; envKey?: string }): string {
  const label = s.envKey ? s.envKey.replace(/^header:/, "HEADER_") : `${s.provider}_CREDENTIAL`;
  return `DFIRSWARM_${label.replace(/[^A-Za-z0-9]/g, "_").toUpperCase()}`;
}

export type ResolvedSecret = {
  provider: string;
  kind: ProviderSpec["kind"];
  placeholder: string;
  value: string;
  hosts: string[];
  accountId?: string;
  /** Set when this is one variable of the provider's `env` block in Pi's store (an Azure key, say), not the provider's key itself. */
  envKey?: string;
};

/** A name under which a value is a credential: what may not cross into a VM in clear. */
export function secretLikeName(name: string): boolean {
  return /key|token|secret|password|passwd|credential|auth|cookie|session/i.test(name);
}

/** What a local server's `apiKey` says when it is a stand-in and no credential (Ollama, LM Studio, llama.cpp, vLLM without one). */
const LOCAL_DUMMY_KEYS = new Set(["", "ollama", "lm-studio", "lmstudio", "llama.cpp", "local", "none", "dummy", "empty", "no-key", "sk-no-key-required", "not-needed", "x"]);

/**
 * Every header of a provider's config that carries a credential, wherever
 * Pi reads headers from: the provider's own, each model's, and each model
 * override's. Pi's config schema (model-config.ts) has all three.
 */
export function credentialHeaders(config: unknown): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  const visit = (node: unknown) => {
    if (Array.isArray(node)) {
      for (const n of node) visit(n);
      return;
    }
    if (!node || typeof node !== "object") return;
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (k === "headers" && v && typeof v === "object" && !Array.isArray(v)) {
        for (const [name, value] of Object.entries(v as Record<string, unknown>)) {
          if (typeof value === "string" && value && secretLikeName(name)) out.push({ name, value });
        }
      } else visit(v);
    }
  };
  visit(config);
  return out;
}

/** The same config with each credential header's value swapped for its placeholder, at every depth. */
function swapHeaders(config: unknown, swap: Map<string, string>): unknown {
  if (Array.isArray(config)) return config.map((c) => swapHeaders(c, swap));
  if (!config || typeof config !== "object") return config;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(config as Record<string, unknown>)) {
    if (k === "headers" && v && typeof v === "object" && !Array.isArray(v)) {
      const headers: Record<string, unknown> = {};
      for (const [name, value] of Object.entries(v as Record<string, unknown>)) {
        headers[name] = typeof value === "string" && secretLikeName(name) && swap.has(value) ? swap.get(value) : value;
      }
      out[k] = headers;
    } else out[k] = swapHeaders(v, swap);
  }
  return out;
}

/**
 * Every credential the team needs, resolved on the host by Pi's own commands
 * and held in this process's memory only. Throws with the reason when Pi
 * cannot produce one — the kickoff turns that into a BLOCKER.
 */
export async function resolveSecrets(spec: VmSpec): Promise<ResolvedSecret[]> {
  const pi = spec.pi_bin || "pi";
  // Pi reads the store the kickoff chose (--env PI_CODING_AGENT_DIR), not this process's.
  const env = spec.pi_agent_dir ? { ...process.env, PI_CODING_AGENT_DIR: spec.pi_agent_dir } : process.env;
  const dir = spec.pi_agent_dir || join(process.env.HOME || "", ".pi", "agent");
  const out: ResolvedSecret[] = [];
  let store: Record<string, Record<string, unknown>> = {};
  try {
    store = JSON.parse(readFileSync(join(dir, "auth.json"), "utf8")) as Record<string, Record<string, unknown>>;
  } catch {
    store = {};
  }
  let models: Record<string, Record<string, unknown>> = {};
  try {
    models = ((JSON.parse(readFileSync(join(dir, "models.json"), "utf8")) as { providers?: Record<string, Record<string, unknown>> }).providers ?? {});
  } catch {
    models = {};
  }
  for (const p of spec.providers) {
    if (p.kind === "local") {
      // A local server is reached over plain HTTP through the host gateway,
      // where there is no TLS for msb to intercept and so no measured place
      // to swap a placeholder for a value: a real credential in its config
      // would sit in the VM in clear. A stand-in key is not one.
      const custom = models[p.provider] ?? {};
      const key = typeof custom.apiKey === "string" ? custom.apiKey : "";
      const headers = credentialHeaders(custom);
      if ((key && !LOCAL_DUMMY_KEYS.has(key.toLowerCase())) || headers.length) {
        throw new Error(`models.json: the local provider ${p.provider} carries a credential (${key && !LOCAL_DUMMY_KEYS.has(key.toLowerCase()) ? "apiKey" : `header ${headers[0].name}`}); a VM would hold it in clear, since a local server is reached without TLS for msb to swap a placeholder on. Drop it for this run, or run this model on the host.`);
      }
      continue;
    }
    let value = "";
    let accountId: string | undefined;
    if (p.kind === "oauth") {
      const r = await run(pi, ["auth", "print-bearer-token", "--provider", p.provider, "--min-expiry", spec.min_token_validity || "2h"], { env });
      if (r.code !== 0 || !r.stdout.trim()) throw new Error(`pi could not produce a ${p.provider} subscription token valid for the run: ${r.stderr.trim() || `exit ${r.code}`}`);
      value = r.stdout.trim();
      if (p.provider === "openai-codex") accountId = codexAccountId(value, spec.pi_agent_dir);
    } else {
      const r = await run(pi, ["auth", "print-api-key", "--provider", p.provider], { env });
      if (r.code !== 0 || !r.stdout.trim()) throw new Error(`pi has no key for ${p.provider}: ${r.stderr.trim() || `exit ${r.code}`}`);
      value = r.stdout.trim();
    }
    out.push({ provider: p.provider, kind: p.kind, placeholder: placeholderFor(p.provider, p.kind, accountId), value, hosts: p.hosts, ...(accountId ? { accountId } : {}) });
    // The provider's `env` block in Pi's store (Azure keeps its resource and
    // version there, and may keep a key): a variable named like a credential
    // is one, and crosses as its own placeholder bound to the same hosts.
    const block = store[p.provider]?.env;
    if (block && typeof block === "object") {
      for (const [k, v] of Object.entries(block as Record<string, unknown>)) {
        if (typeof v !== "string" || !v || !secretLikeName(k)) continue;
        out.push({ provider: p.provider, kind: "api_key", placeholder: `dfirswarm-secret-${k.toLowerCase().replace(/[^a-z0-9]/g, "")}-${randomBytes(12).toString("hex")}`, value: v, hosts: p.hosts, envKey: k });
      }
    }
    // A custom provider's headers (models.json): a literal under a credential
    // name is a credential and crosses as a placeholder; a value Pi would
    // resolve at request time ($ENV, !command) has no host-side value to
    // swap in, and is refused rather than sent in clear.
    // Headers at every depth Pi reads them: the provider's, each model's,
    // each model override's.
    const seen = new Set<string>();
    for (const { name: k, value: v } of credentialHeaders(models[p.provider])) {
      if (/^\s*[$!]/.test(v)) throw new Error(`models.json: provider ${p.provider} header ${k} is resolved by Pi at request time (${v.slice(0, 1)}…), which a VM cannot do without the value; put the literal in the store or the header`);
      if (seen.has(v)) continue;
      seen.add(v);
      out.push({ provider: p.provider, kind: "api_key", placeholder: `dfirswarm-secret-hdr-${k.toLowerCase().replace(/[^a-z0-9]/g, "")}-${randomBytes(12).toString("hex")}`, value: v, hosts: p.hosts, envKey: `header:${k}` });
    }
  }
  return out;
}

/** The Codex account id: in Pi's store beside the token, or in the token's own payload. */
function codexAccountId(token: string, piAgentDir?: string): string {
  try {
    const auth = JSON.parse(readFileSync(join(piAgentDir || join(process.env.HOME || "", ".pi", "agent"), "auth.json"), "utf8"));
    const stored = auth?.["openai-codex"]?.accountId;
    if (typeof stored === "string" && stored) return stored;
  } catch {
    // read it from the token instead
  }
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));
    const id = payload?.["https://api.openai.com/auth"]?.chatgpt_account_id;
    if (typeof id === "string") return id;
  } catch {
    // nothing to read
  }
  return "";
}

/**
 * The guest's own Pi configuration: an auth store of placeholders, the
 * operator's custom providers with their keys swapped for placeholders and
 * a local server reached through the host gateway, and the operator's
 * settings. Nothing in these files is a credential.
 */
export function guestPiConfig(spec: VmSpec, secrets: ResolvedSecret[]): { auth: string; models: string | null; settings: string | null; modelsStore?: string | null } {
  const dir = spec.pi_agent_dir || join(process.env.HOME || "", ".pi", "agent");
  const auth: Record<string, unknown> = {};
  let models: Record<string, unknown> | null = null;
  try {
    models = JSON.parse(readFileSync(join(dir, "models.json"), "utf8")) as Record<string, unknown>;
  } catch {
    models = null;
  }
  const providers = (models?.providers ?? {}) as Record<string, Record<string, unknown>>;
  const keep: Record<string, Record<string, unknown>> = {};
  let store: Record<string, Record<string, unknown>> = {};
  try {
    store = JSON.parse(readFileSync(join(dir, "auth.json"), "utf8")) as Record<string, Record<string, unknown>>;
  } catch {
    store = {};
  }
  for (const p of spec.providers) {
    const secret = secrets.find((s) => s.provider === p.provider && !s.envKey);
    const extras = secrets.filter((s) => s.provider === p.provider && s.envKey);
    const custom = providers[p.provider];
    if (custom) {
      const swap = new Map(extras.filter((s) => s.envKey?.startsWith("header:")).map((s) => [s.value, s.placeholder]));
      const copy = swapHeaders(custom, swap) as Record<string, unknown>;
      if (secret && "apiKey" in copy) copy.apiKey = secret.placeholder;
      if (p.kind === "local" && typeof copy.baseUrl === "string") copy.baseUrl = hostGatewayUrl(copy.baseUrl);
      if (p.kind === "local" && p.resolved && typeof copy.baseUrl === "string") {
        try {
          const u = new URL(copy.baseUrl);
          if (u.hostname.toLowerCase() === p.resolved.name.toLowerCase()) {
            u.hostname = p.resolved.ip;
            copy.baseUrl = u.toString().replace(/\/$/, String(custom.baseUrl).endsWith("/") ? "/" : "");
          }
        } catch {
          // left as the operator wrote it
        }
      }
      keep[p.provider] = copy;
    }
    if (!secret) continue;
    // The provider's env block travels with its non-credential settings as
    // they are (a resource name, an API version) and its credentials as
    // placeholders; nothing else of the store's entry does.
    const block = store[p.provider]?.env;
    const guestEnv: Record<string, string> = {};
    if (block && typeof block === "object") {
      for (const [k, v] of Object.entries(block as Record<string, unknown>)) {
        if (typeof v !== "string") continue;
        const swapped = extras.find((s) => s.envKey === k);
        if (swapped) guestEnv[k] = swapped.placeholder;
        else if (!secretLikeName(k)) guestEnv[k] = v;
      }
    }
    const env = Object.keys(guestEnv).length ? { env: guestEnv } : {};
    if (secret.kind === "oauth") {
      auth[p.provider] = {
        type: "oauth",
        access: secret.placeholder,
        refresh: "dfirswarm-vm-never-refreshes",
        expires: GUEST_OAUTH_EXPIRES,
        ...(secret.accountId ? { accountId: secret.accountId } : {}),
        ...env,
      };
    } else if (!custom || !("apiKey" in custom)) {
      auth[p.provider] = { type: "api_key", key: secret.placeholder, ...env };
    } else if (Object.keys(guestEnv).length) {
      auth[p.provider] = { type: "api_key", key: secret.placeholder, ...env };
    }
  }
  // The operator's settings, less what names this host: a proxy the guest
  // cannot reach, package and extension paths that are not in the image.
  let settings: string | null = null;
  try {
    const parsed = JSON.parse(readFileSync(join(dir, "settings.json"), "utf8")) as Record<string, unknown>;
    for (const k of ["httpProxy", "packages", "extensions", "shellPath"]) delete parsed[k];
    settings = `${JSON.stringify(parsed, null, 2)}\n`;
  } catch {
    settings = null;
  }
  // Pi's model catalog cache (models-store.json: each provider's model list
  // as last fetched), so a model the host knows from a refreshed catalog is
  // one the guest knows. It holds no credential; anything named like one is
  // dropped anyway.
  let store2: string | null = null;
  try {
    const parsed = JSON.parse(readFileSync(join(dir, "models-store.json"), "utf8")) as unknown;
    const clean = (node: unknown): unknown => {
      if (Array.isArray(node)) return node.map(clean);
      if (!node || typeof node !== "object") return node;
      return Object.fromEntries(Object.entries(node as Record<string, unknown>).filter(([k]) => !/^(apiKey|key|token|secret|password|authorization|headers)$/i.test(k)).map(([k, v]) => [k, clean(v)]));
    };
    store2 = `${JSON.stringify(clean(parsed), null, 2)}\n`;
  } catch {
    store2 = null;
  }
  return {
    auth: `${JSON.stringify(auth, null, 2)}\n`,
    models: Object.keys(keep).length ? `${JSON.stringify({ ...(models ?? {}), providers: keep }, null, 2)}\n` : null,
    settings,
    modelsStore: store2,
  };
}

/** A local server's URL as the guest reaches it: through msb's host gateway. */
export function hostGatewayUrl(url: string): string {
  try {
    const u = new URL(url);
    if (["127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0"].includes(u.hostname)) u.hostname = "host.microsandbox.internal";
    return u.toString().replace(/\/$/, url.endsWith("/") ? "/" : "");
  } catch {
    return url;
  }
}

/**
 * The guest's side of the hub link: a socat bridge from a Unix socket to the
 * vsock port. The SDK mounts a script as written — no shebang is added.
 */
export const BRIDGE_SCRIPT = `#!/bin/sh
set -e
mkdir -p /run/dfirswarm
if [ ! -S ${GUEST_HUB_SOCKET} ]; then
  # -t 600: a caller that sends its request and closes its writing side
  # still gets the answer; socat's default gives the hub half a second.
  setsid socat -t 600 UNIX-LISTEN:${GUEST_HUB_SOCKET},fork,mode=600,backlog=256 VSOCK-CONNECT:2:${HUB_PORT} </dev/null >>/run/dfirswarm/bridge.log 2>&1 &
  i=0
  while [ ! -S ${GUEST_HUB_SOCKET} ] && [ "$i" -lt 100 ]; do sleep 0.05; i=$((i + 1)); done
fi
[ -S ${GUEST_HUB_SOCKET} ]
`;

/**
 * What the pane runs inside the VM: the bridge, then Pi in the sandbox with
 * the kickoff as its first message. A pane that is restarted asks for the
 * kickoff again, which is what a fresh Pi needs.
 */
export const PI_SCRIPT = `#!/bin/sh
/.msb/scripts/dfirswarm-bridge
cd "$SWARM_SANDBOX"
if [ "$SWARM_ALLOW_INSTALL" = 1 ] && [ -n "$SWARM_TOOLCHAIN" ]; then
  # --allow-install: pip lays packages into this VM's own disk, on its own
  # PATH and import path. Never a directory shared with the other VMs: a
  # shared prefix at the head of every seat's PATH let one seat put code in
  # front of every other's python. The seat's extension inventories it and
  # sends the list to the hub for toolchain.json.
  pyv=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  mkdir -p "$SWARM_TOOLCHAIN"
  export PIP_PREFIX="$SWARM_TOOLCHAIN"
  export PYTHONPATH="$SWARM_TOOLCHAIN/lib/python$pyv/site-packages\${PYTHONPATH:+:$PYTHONPATH}"
  export PATH="$SWARM_TOOLCHAIN/bin:$PATH"
fi
if [ -n "$SWARM_KICKOFF" ] && [ -f "$SWARM_KICKOFF" ]; then
  exec pi "$@" "$(cat "$SWARM_KICKOFF")"
fi
exec pi "$@"
`;

/**
 * Measured, not assumed: what this VM can write, whether it reaches the hub,
 * and what it is running. The kickoff refuses a VM whose answers are wrong.
 */
export const PROBE_SCRIPT = `#!/bin/sh
/.msb/scripts/dfirswarm-bridge >/dev/null 2>&1 || true
exec python3 - <<'PY'
import errno, json, os, shutil, socket, subprocess, time
S = os.environ.get("SWARM_SANDBOX", "")
A = os.environ.get("AGENT_ID", "")
def can_write(path):
    try:
        with open(path, "w") as f:
            f.write("probe")
        os.unlink(path)
        return "rw"
    except OSError as e:
        return "ro" if e.errno in (errno.EROFS, errno.EACCES, errno.EPERM) else "error:" + errno.errorcode.get(e.errno, str(e.errno))
out = {"agent": A, "sandbox": S}
def can_exec(path):
    try:
        with open(path, "w") as f:
            f.write("#!/bin/sh\\necho ran\\n")
        os.chmod(path, 0o755)
        r = subprocess.run([path], capture_output=True, text=True, timeout=30)
        os.unlink(path)
        return "exec" if "ran" in r.stdout else "noexec"
    except PermissionError:
        try:
            os.unlink(path)
        except OSError:
            pass
        return "noexec"
    except OSError as e:
        return "error:" + errno.errorcode.get(e.errno, str(e.errno))
def mount_noexec(path):
    # The options of the mount a path is on: the longest mount point that
    # holds it, from the kernel's own table.
    best, opts = "", ""
    try:
        for line in open("/proc/self/mountinfo"):
            parts = line.split()
            point = parts[4].replace("\\040", " ")
            if (path == point or path.startswith(point.rstrip("/") + "/")) and len(point) > len(best):
                best, opts = point, parts[5]
    except OSError as e:
        return "error:" + str(e)
    return "noexec" if "noexec" in opts.split(",") else "exec"
out["base"] = can_write(os.path.join(S, ".vm-probe-" + A))
out["work"] = can_write(os.path.join(S, "work", ".vm-probe-" + A))
out["scratch"] = can_write(os.path.join(S, "work", A, ".vm-probe"))
out["extracted"] = can_write(os.path.join(S, "work", "extracted", A, ".vm-probe"))
out["extracted_exec"] = can_exec(os.path.join(S, "work", "extracted", A, ".vm-probe.sh"))
out["quarantine_exec"] = can_exec(os.path.join(S, "work", "quarantine", A, ".vm-probe.sh"))
# A peer's corner is read-only here, so it is not written to test: its mount says.
out["peers_extracted_exec"] = mount_noexec(os.path.join(S, "work", "extracted", ".peer"))
out["peers_quarantine_exec"] = mount_noexec(os.path.join(S, "work", "quarantine", ".peer"))
out["tool_output"] = can_write(os.path.join(S, "tool-output", A, ".vm-probe"))
out["session"] = can_write(os.path.join(S, ".pi-sessions", A, ".vm-probe"))
inputs = os.path.join(S, "inputs")
if os.path.exists(inputs):
    out["inputs"] = can_write(os.path.join(os.path.realpath(inputs), ".vm-probe"))
    # Names, the way the manifest counts them: files, and links as links
    # (never followed — a link loop would never end).
    n = 0
    for root, dirs, files in os.walk(os.path.realpath(inputs)):
        n += len(files) + sum(1 for d in dirs if os.path.islink(os.path.join(root, d)))
    out["inputs_files"] = n
    out["inputs_exec"] = mount_noexec(os.path.join(os.path.realpath(inputs), ".probe"))
else:
    out["inputs"] = "absent"
# The model's hosts, reached the way Pi will: a TCP connection through the
# VM's policy (a name the policy denies does not resolve). No request is
# sent, so no credential is spent and no TLS question is asked.
reach = []
for target in [t for t in os.environ.get("SWARM_PROBE_TARGETS", "").split(",") if t]:
    host, _, port = target.rpartition(":")
    host = host.strip("[]")
    try:
        socket.create_connection((host, int(port)), timeout=10).close()
        reach.append({"target": target, "ok": True})
    except Exception as e:
        reach.append({"target": target, "ok": False, "error": str(e)})
out["reach"] = reach
# Up to five tries, three seconds apart: on a host bringing up its third run
# beside eighteen running VMs, two seats of eight had their connection close
# with no answer, twice, and the kickoff stopped (sixth CTF round). What the
# hub said, or that it said nothing, is kept for the record.
out["hub"] = False
for attempt in range(5):
    if attempt:
        time.sleep(3)
    try:
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(10)
        s.connect("${GUEST_HUB_SOCKET}")
        # The seat's token first, when the run has one: the hub takes nothing
        # else on this seat's socket before it.
        token = os.environ.get("SWARM_SEAT_TOKEN", "")
        if token:
            s.sendall(json.dumps({"t": "auth", "token": token}).encode() + b"\\n")
        s.sendall(b'{"t":"rpc","fn":"swarmDoneExists","args":[null]}\\n')
        data = b""
        while not data.endswith(b"\\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        reply = data.decode(errors="replace")
        if json.loads(reply or "{}").get("ok") is True:
            out["hub"] = True
            out.pop("hub_error", None)
            break
        out["hub_error"] = "the hub answered " + reply.strip() if reply.strip() else "the connection closed with no answer"
    except (BrokenPipeError, ConnectionResetError) as e:
        # A hub that closes without answering reads as a clean close, a
        # reset or a broken pipe, by platform and by timing: one meaning.
        out["hub_error"] = "the connection closed with no answer (" + str(e) + ")"
    except Exception as e:
        out["hub_error"] = str(e)
out["hub_attempts"] = attempt + 1
try:
    out["pi"] = subprocess.run(["pi", "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
except Exception as e:
    out["pi"] = "error: " + str(e)
try:
    out["image"] = json.load(open("/etc/dfirswarm/image.json"))
except Exception:
    out["image"] = None
out["kernel"] = os.uname().release
# The run's packs' required programs, looked for the way an agent's shell
# would find them: the image's venv first, then PATH.
want = [b for b in os.environ.get("SWARM_REQUIRED_BINARIES", "").split(",") if b]
search = "/opt/dfir/venv/bin:" + os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
out["missing_binaries"] = [b for b in want if not shutil.which(b, path=search)]
tool_want = [b for b in os.environ.get("SWARM_TOOL_PROGRAMS", "").split(",") if b]
out["missing_tool_programs"] = [b for b in tool_want if not shutil.which(b, path=search)]
# What a pack tool that mounts something would find: FUSE and loop devices.
out["fuse"] = os.path.exists("/dev/fuse")
out["loop"] = any(n.startswith("loop") for n in os.listdir("/dev")) or os.path.exists("/dev/loop-control")
mounts = []
for line in open("/proc/mounts"):
    parts = line.split()
    if len(parts) > 3 and parts[2] == "virtiofs" and parts[1] != "/.msb":
        mounts.append({"path": parts[1].replace("\\\\040", " "), "mode": "ro" if "ro" in parts[3].split(",") else "rw"})
out["mounts"] = mounts
# Last, so the host compares it with its own clock the moment this returns.
out["guest_time"] = time.time()
print(json.dumps(out))
PY
`;

/** What one of the run's packs needs of an image: its version, its seal, the programs it requires. */
export type PackNeed = { id: string; version: string; seal: string; required: string[] };

/** The seal of a pack: the sha256 of its sorted checksums, as `pack.sh seal` wrote them. */
export function packSeal(manifest: { checksums?: { sha256?: Record<string, string> } }): string {
  const sums = manifest.checksums?.sha256 ?? {};
  const sorted = Object.fromEntries(Object.keys(sums).sort().map((k) => [k, sums[k]]));
  return createHash("sha256").update(JSON.stringify(sorted)).digest("hex");
}

/** The run's packs, read from their installed directories. */
export function packNeeds(packDirs: string[]): PackNeed[] {
  const out: PackNeed[] = [];
  for (const dir of packDirs.filter(Boolean)) {
    try {
      const manifest = JSON.parse(readFileSync(join(dir, "pack.json"), "utf8")) as { id?: string; version?: string; checksums?: { sha256?: Record<string, string> } };
      let required: string[] = [];
      try {
        const host = JSON.parse(readFileSync(join(dir, "requires", "host.json"), "utf8")) as { binaries?: Array<{ name?: string; optional?: boolean; not_in_image?: string }> };
        // Another system's program (not_in_image) is asked of no image.
        required = (host.binaries ?? []).filter((b) => b.name && !b.optional && !b.not_in_image).map((b) => b.name as string);
      } catch {
        required = [];
      }
      out.push({ id: manifest.id ?? dir.split("/").pop() ?? dir, version: manifest.version ?? "?", seal: packSeal(manifest), required: [...new Set(required)] });
    } catch {
      // an unreadable pack was refused at kickoff already
    }
  }
  return out;
}

/**
 * Whether the image fits the run's packs. A program a pack requires and the
 * VM does not have is a blocker, unless the agents may install (then they
 * are told). An image built from another version of a pack, or one that
 * records no pack versions at all, is said and recorded.
 */
export function imageFit(probe: Record<string, unknown>, needs: PackNeed[], allowInstall: boolean): { blockers: string[]; warnings: string[] } {
  const blockers: string[] = [];
  const warnings: string[] = [];
  const missing = new Set(Array.isArray(probe.missing_binaries) ? (probe.missing_binaries as string[]) : []);
  const image = (probe.image ?? {}) as { pack_versions?: Record<string, { version?: string; seal?: string }> };
  if (needs.length && !image.pack_versions) warnings.push("the image records no pack versions (built before images recorded them): which version of each pack it was built for is unknown");
  for (const need of needs) {
    const lacks = need.required.filter((b) => missing.has(b));
    if (lacks.length) {
      const text = `the image lacks ${lacks.join(", ")}, which pack ${need.id} requires`;
      if (allowInstall) warnings.push(`${text}; the agents may install it (--allow-install)`);
      else blockers.push(`${text}: build an image for these packs (images/README.md), pass --image, or let the agents install with --allow-install`);
    }
    const built = image.pack_versions?.[need.id];
    if (image.pack_versions && !built) warnings.push(`the image was not built with pack ${need.id}; its required programs are there, its optional ones may not be`);
    else if (built && (built.version !== need.version || (built.seal && built.seal !== need.seal))) {
      warnings.push(`the image was built with ${need.id} ${built.version ?? "?"}${built.seal && built.seal !== need.seal ? " (another seal)" : ""}; this run has ${need.version}`);
    }
  }
  return { blockers, warnings };
}

/** What each agent's VM must find, or the kickoff stops. */
/** One isolation check of a VM's probe: what it is, what it wants, what was found, and what that means. */
export type ProbeCheck = { check: string; want: string; got: string; ok: boolean; meaning: string };

/**
 * Every isolation check a VM's probe made, one row each, in the order the
 * kickoff reports them: its name, what it wants, what the probe found
 * ("not measured" when it did not), whether it holds, and what that means:
 * what is held when it holds, the reason the VM is refused when it does
 * not. The one list the kickoff (probeVerdict) and the console both read.
 */
export function probeChecks(probe: Record<string, unknown>, expectInputs: boolean, expectedInputFiles?: number | null): ProbeCheck[] {
  const rows: ProbeCheck[] = [];
  const add = (check: string, want: string, got: unknown, ok: boolean, held: string, refused: string) =>
    rows.push({ check, want, got: got === undefined ? "not measured" : String(got), ok, meaning: ok ? held : refused });
  add("the sandbox floor", "ro", probe.base, probe.base === "ro", "the run's files are read-only in the VM", `the sandbox floor is ${String(probe.base)}, not read-only`);
  add("the shared work/", "ro", probe.work, probe.work === "ro", "what peers wrote is read-only here; a shared file is published through the hub", `the shared work/ is ${String(probe.work)}, not read-only`);
  add("its own work/<id>/", "rw", probe.scratch, probe.scratch === "rw", "the seat can write its own scratch", `its own work/<id>/ is ${String(probe.scratch)}, not writable`);
  add("its own work/extracted/<id>/", "rw", probe.extracted, probe.extracted === "rw", "the seat can extract into its own corner", `its own work/extracted/<id>/ is ${String(probe.extracted)}, not writable`);
  add("work/extracted/<id>/ executes", "noexec", probe.extracted_exec, probe.extracted_exec === "noexec", "what the seat extracts cannot run", `work/extracted/<id>/ can execute (${String(probe.extracted_exec)})`);
  add("work/quarantine/<id>/ executes", "noexec", probe.quarantine_exec, probe.quarantine_exec === "noexec", "what the seat quarantines cannot run", `work/quarantine/<id>/ can execute (${String(probe.quarantine_exec)})`);
  if (probe.peers_extracted_exec !== undefined) add("a peer's work/extracted/ executes", "noexec", probe.peers_extracted_exec, probe.peers_extracted_exec === "noexec", "what a peer extracted cannot run here", `a peer's work/extracted/ can execute here (${String(probe.peers_extracted_exec)})`);
  if (probe.peers_quarantine_exec !== undefined) add("a peer's work/quarantine/ executes", "noexec", probe.peers_quarantine_exec, probe.peers_quarantine_exec === "noexec", "what a peer quarantined cannot run here", `a peer's work/quarantine/ can execute here (${String(probe.peers_quarantine_exec)})`);
  add("its tool-output/", "rw", probe.tool_output, probe.tool_output === "rw", "the seat's whole tool outputs are kept", `its tool-output/ is ${String(probe.tool_output)}, not writable`);
  add("its Pi session directory", "rw", probe.session, probe.session === "rw", "the seat's Pi sessions are kept", `its Pi session directory is ${String(probe.session)}, not writable`);
  if (expectInputs) {
    add("inputs/", "ro", probe.inputs, probe.inputs === "ro", "the evidence is read-only in the VM", `inputs/ is ${String(probe.inputs)}, not read-only`);
    if (probe.inputs_exec !== undefined) add("the evidence executes", "noexec", probe.inputs_exec, probe.inputs_exec === "noexec", "nothing in the evidence can run", `the evidence can execute in the VM (${String(probe.inputs_exec)})`);
  }
  for (const r of Array.isArray(probe.reach) ? (probe.reach as Array<{ target?: unknown; ok?: unknown; error?: unknown }>) : []) {
    const ok = r.ok === true;
    add(`the model's host ${String(r.target ?? "?")}`, "reachable", ok ? "reachable" : String(r.error ?? "no connection"), ok, "the seat reaches its model", `the model's host ${String(r.target)} is not reachable from the VM (${String(r.error ?? "no connection")})`);
  }
  if (expectInputs && typeof expectedInputFiles === "number" && typeof probe.inputs_files === "number") {
    add("evidence names seen", String(expectedInputFiles), probe.inputs_files, probe.inputs_files === expectedInputFiles, "the VM sees every name the manifest lists", `the VM sees ${probe.inputs_files} evidence name(s) where the manifest lists ${expectedInputFiles}`);
  }
  add("the hub", "reachable", probe.hub === true ? "reachable" : String(probe.hub_error ?? "no answer"), probe.hub === true, "the seat reaches the board, the trace and the harness through the hub", `the hub is not reachable (${String(probe.hub_error ?? "no answer")})`);
  const piOk = typeof probe.pi === "string" && /^\d+\.\d+/.test(probe.pi);
  add("pi", "runs", probe.pi, piOk, "Pi runs in the VM", `pi does not run (${String(probe.pi)})`);
  return rows;
}

/** Why a VM is refused: each failed probe check's meaning, in order; empty when every check holds. */
export function probeVerdict(probe: Record<string, unknown>, expectInputs: boolean, expectedInputFiles?: number): string[] {
  return probeChecks(probe, expectInputs, expectedInputFiles).filter((c) => !c.ok).map((c) => c.meaning);
}

/**
 * What a seat's probe connects to: each model host it needs, as `host:port`
 * — a local model on this machine through msb's host gateway, a named host
 * on its own port. Suffix entries name no host to try.
 */
export function probeTargets(providers: ProviderSpec[]): string[] {
  const out = new Set<string>();
  for (const p of providers) {
    const entries = p.hosts.map((h) => parseAllowEntry(h));
    if (p.kind === "local" && p.port && (entries.length === 0 || entries.every((e) => e.loopback))) {
      out.add(`host.microsandbox.internal:${p.port}`);
      continue;
    }
    const first = entries.find((e) => e.kind === "domain" || e.kind === "ip");
    if (first) out.add(`${first.value.includes(":") ? `[${first.value}]` : first.value}:${p.kind === "local" && p.port ? p.port : first.port}`);
  }
  return [...out].sort();
}

/** Every mount one agent's VM gets: the run's own, then this agent's writable holes. */
export function mountsFor(spec: VmSpec, agent: string): Mount[] {
  const S = spec.sandbox;
  // `work/` is part of the read-only floor: the agent's own directories are
  // the writable holes on it, and what a peer wrote is read-only here. One
  // writable `work/` shared by every VM let any seat rewrite any other's
  // findings without a record (measured, and the ADR's own finding). A
  // shared deliverable is published through the hub (protocol.ts
  // publishFile). The extracted and quarantined material is mounted
  // noexec — a peer's as well as one's own: the floor under it is not, and a
  // file a peer extracted and made executable would otherwise run here. (A
  // guest mount flag stops an accident, not a root that means to run it.)
  return [
    { host: S, readonly: true },
    ...spec.mounts,
    { host: join(S, "work", "extracted"), readonly: true, noexec: true },
    { host: join(S, "work", "quarantine"), readonly: true, noexec: true },
    { host: join(S, "work", agent) },
    { host: join(S, "work", "extracted", agent), noexec: true },
    { host: join(S, "work", "quarantine", agent), noexec: true },
    { host: join(S, "tool-output", agent) },
    { host: join(S, ".pi-sessions", agent) },
    ...(spec.late_mounts ?? []),
  ];
}

type SdkModule = typeof import("microsandbox");
/** The SDK's secret builder, as far as this file uses it. */
type SecretB = { env(v: string): SecretB; value(v: string): SecretB; placeholder(p: string): SecretB; allow(h: string): SecretB };
type TlsB = { interceptedPorts(p: number[]): TlsB; bypass(h: string): TlsB };
type PolicyB = InstanceType<SdkModule["NetworkPolicyBuilder"]>;

/** Egress to the allowlist's hosts, one msb rule per port and kind (see egressRules). */
function allowEgress(policy: PolicyB, hosts: string[]): PolicyB {
  for (const rule of egressRules(hosts)) {
    if (rule.domains.length) policy.egress((r) => r.tcp().port(rule.port).allowDomains(rule.domains));
    if (rule.suffixes.length) policy.egress((r) => r.tcp().port(rule.port).allowDomainSuffixes(rule.suffixes));
    for (const ip of rule.ips) policy.egress((r) => r.tcp().port(rule.port).allow((d) => d.ip(ip)));
    for (const cidr of rule.cidrs) policy.egress((r) => r.tcp().port(rule.port).allow((d) => d.cidr(cidr)));
  }
  // The host's own loopback, which a VM reaches only through the gateway.
  for (const port of gatewayPorts(hosts)) policy.egress((r) => r.tcp().port(port).allowHost());
  return policy;
}

/** How long one VM may take to come up before the kickoff says so rather than wait. */
const CREATE_TIMEOUT_MS = Number(process.env.SWARM_VM_CREATE_TIMEOUT_MS ?? 10 * 60_000);

/** A promise that settles, or rejects with `why` once `ms` have passed. */
function withTimeout<T>(p: Promise<T>, ms: number, why: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([
    p.finally(() => clearTimeout(timer)),
    new Promise<T>((_, reject) => {
      timer = setTimeout(() => reject(new Error(why)), ms);
      timer.unref?.();
    }),
  ]);
}

async function sdk(): Promise<SdkModule> {
  return import("microsandbox");
}

async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

export type VmRecord = {
  agent: string;
  name: string;
  run: string;
  runtime: { name: "microsandbox"; version: string };
  image: { ref: string; manifest_digest: string | null; expected_digest?: string; description: unknown };
  cpus: number;
  memory_mib: number;
  max_duration_sec: number | null;
  mounts: Array<{ host: string; guest: string; mode: "ro" | "rw"; noexec?: boolean }>;
  network: { default: "deny" | "public"; allow_hosts: string[]; host_ports: number[] };
  secrets: Array<{ name: string; env?: string; hosts: string[] }>;
  /** Which of its providers this VM reaches through the model gateway, never the seat's token. */
  model_gateway?: { port: number; providers: string[]; declined: Array<{ provider: string; reason: string }> };
  probe: Record<string, unknown>;
  created_at: string;
  stopped_at?: string;
  snapshot?: { path: string; sha256: string; bytes: number; integrity: boolean } | { error: string };
};

async function msbVersion(): Promise<string> {
  const r = await run(msbBinary(), ["--version"], { timeoutMs: 20_000 });
  return r.stdout.trim().replace(/^msb\s+/, "") || "unknown";
}

/**
 * A seat's guest Pi config with the providers the model gateway fronts
 * pointed at it: each one's models.json entry keeps the operator's settings
 * (its model list, its API), takes the gateway's base URL and the seat's
 * gateway token as its key, and loses every credential header (the values
 * were already placeholders, which msb would no longer swap); its auth.json
 * entry goes, since a stored credential wins over models.json's key in Pi.
 */
export function gatewayPiConfig(
  config: ReturnType<typeof guestPiConfig>,
  fronted: Record<string, { baseUrl: string; apiKey: string }>,
  placeholders: string[],
): ReturnType<typeof guestPiConfig> {
  const auth = JSON.parse(config.auth || "{}") as Record<string, unknown>;
  const models = (config.models ? JSON.parse(config.models) : {}) as { providers?: Record<string, Record<string, unknown>> } & Record<string, unknown>;
  const providers = { ...(models.providers ?? {}) };
  const isCredential = (name: string, value: unknown) =>
    secretLikeName(name) || /^authorization$/i.test(name) || (typeof value === "string" && placeholders.some((ph) => ph && value.includes(ph)));
  for (const [p, gw] of Object.entries(fronted)) {
    delete auth[p];
    const entry: Record<string, unknown> = { ...(providers[p] ?? {}) };
    delete entry.apiKey;
    if (entry.headers && typeof entry.headers === "object") {
      const headers = Object.fromEntries(Object.entries(entry.headers as Record<string, unknown>).filter(([k, v]) => !isCredential(k, v)));
      if (Object.keys(headers).length) entry.headers = headers;
      else delete entry.headers;
    }
    providers[p] = { ...entry, baseUrl: gw.baseUrl, apiKey: gw.apiKey };
  }
  return { ...config, auth: `${JSON.stringify(auth, null, 2)}\n`, models: `${JSON.stringify({ ...models, providers }, null, 2)}\n` };
}

/**
 * What one seat's VM is given for its models, worked out before msb is
 * asked: its providers, the credentials msb binds for it (as placeholders),
 * its guest Pi config, the hosts and host ports it may reach and what its
 * probe tries. With the model gateway, a provider the gateway fronts is
 * reached through the gateway on this host instead: no msb secret and no
 * auth.json entry for it in the VM, no route to its hosts, the gateway's
 * port through msb's host gateway. A provider the gateway does not front
 * keeps the placeholder path, and without the gateway nothing changes.
 */
export function seatPlan(
  spec: VmSpec,
  agent: VmSpec["agents"][number],
  allSecrets: ResolvedSecret[],
  gateway?: GatewayConfig | null,
): { providers: ProviderSpec[]; secrets: ResolvedSecret[]; piConfig: ReturnType<typeof guestPiConfig>; allowHosts: string[]; hostPorts: number[]; probeTargets: string[]; fronted: string[] } {
  // Least privilege per seat: this VM holds the credentials of the model it
  // runs and of the summary model, reaches those providers' hosts, and no
  // other seat's.
  const providers = seatProviders(spec, agent);
  const mine = new Set(providers.map((p) => p.provider));
  const seatSecrets = allSecrets.filter((s) => mine.has(s.provider));
  const gw = gateway && spec.model_gateway ? guestProviders(gateway, agent.id, spec.model_gateway.port) : {};
  const fronted = Object.keys(gw).filter((p) => mine.has(p)).sort();
  let piConfig = guestPiConfig({ ...spec, providers }, seatSecrets);
  if (fronted.length) {
    piConfig = gatewayPiConfig(
      piConfig,
      Object.fromEntries(fronted.map((p) => [p, gw[p]])),
      seatSecrets.filter((s) => fronted.includes(s.provider)).map((s) => s.placeholder),
    );
  }
  const secrets = seatSecrets.filter((s) => !fronted.includes(s.provider));
  const reached = providers.filter((p) => !fronted.includes(p.provider));
  // A local model on this machine is reached through msb's host gateway; one
  // elsewhere on the LAN is an address and a port like any other entry.
  const localLoopback = (p: ProviderSpec) => p.hosts.length === 0 || p.hosts.every((h) => parseAllowEntry(h).loopback);
  const hostPorts = [
    ...reached.filter((p) => p.kind === "local" && p.port && localLoopback(p)).map((p) => p.port as number),
    ...(fronted.length && spec.model_gateway ? [spec.model_gateway.port] : []),
  ];
  const allowHosts = [...new Set([...spec.allow_hosts, ...reached.flatMap((p) => (p.kind === "local" && localLoopback(p) ? [] : p.hosts)), ...(spec.pack_secrets ?? []).flatMap((s) => s.hosts ?? [])])].sort();
  const targets = [...probeTargets(reached), ...(fronted.length && spec.model_gateway ? [`host.microsandbox.internal:${spec.model_gateway.port}`] : [])];
  return { providers, secrets, piConfig, allowHosts, hostPorts: [...new Set(hostPorts)], probeTargets: [...new Set(targets)].sort(), fronted };
}

/** The providers one seat's VM needs: its own model's, the summary model's, and every local one (no credential). */
export function seatProviders(spec: VmSpec, agent: VmSpec["agents"][number]): ProviderSpec[] {
  const mine = new Set([agent.model.split("/")[0], ...(spec.env?.SWARM_COMPACT_MODEL ? [spec.env.SWARM_COMPACT_MODEL.split("/")[0]] : [])]);
  return spec.providers.filter((p) => p.kind === "local" || mine.has(p.provider));
}

async function createOne(
  M: SdkModule,
  spec: VmSpec,
  agent: VmSpec["agents"][number],
  allSecrets: ResolvedSecret[],
  gateway: GatewayConfig | null = null,
): Promise<VmRecord> {
  const name = vmName(spec.run, agent.id);
  const mounts = mountsFor(spec, agent.id);
  for (const m of mounts) if (!m.readonly) await mkdir(m.host, { recursive: true });
  // The shares every seat's corner sits in exist before they are mounted.
  for (const d of ["extracted", "quarantine"]) await mkdir(join(spec.sandbox, "work", d), { recursive: true });
  const plan = seatPlan(spec, agent, allSecrets, gateway);
  const { secrets, piConfig, hostPorts, allowHosts } = plan;
  // A pack's secrets: the value is read here, on the host, from the store
  // `pack install` wrote (KEY=VALUE lines, or one bare value), and the VM
  // gets a placeholder under the secret's own name, which the pack's tool
  // reads from its environment and msb swaps for the value on the way to
  // the pack's hosts and nowhere else.
  const packSecrets: Array<{ name: string; value: string; hosts: string[]; placeholder: string }> = [];
  for (const s of spec.pack_secrets ?? []) {
    if (!s.hosts?.length) continue;
    let value = process.env[s.name] ?? "";
    if (s.value_file) {
      const text = await readFile(s.value_file, "utf8").catch(() => "");
      const line = text.split(/\r?\n/).find((l) => l.startsWith(`${s.name}=`));
      value = line ? line.slice(s.name.length + 1) : text.includes("=") ? "" : text.trim();
    }
    if (value) packSecrets.push({ name: s.name, value, hosts: s.hosts, placeholder: `dfirswarm-secret-${s.name.toLowerCase().replace(/[^a-z0-9]/g, "")}-${randomBytes(12).toString("hex")}` });
  }

  const policy = new M.NetworkPolicyBuilder().defaultDeny();
  if (spec.open_net) policy.egress((r) => r.allowPublic());
  allowEgress(policy, allowHosts);
  for (const port of hostPorts) policy.egress((r) => r.tcp().port(port).allowHost());

  const env: Record<string, string> = {
    ...spec.env,
    ...(agent.env ?? {}),
    AGENT_ID: agent.id,
    SWARM_SANDBOX: spec.sandbox,
    SWARM_BOARD_SOCKET: GUEST_HUB_SOCKET,
    SWARM_TRACE_SOCKET: GUEST_HUB_SOCKET,
    SWARM_NUDGE_SOCKET: GUEST_HUB_SOCKET,
    SWARM_ISOLATION: "microvm",
    // What the probe reaches: each of this seat's model hosts, as Pi will.
    SWARM_PROBE_TARGETS: plan.probeTargets.join(","),
    // What the probe looks for: every program the run's packs require.
    SWARM_REQUIRED_BINARIES: [...new Set(packNeeds((spec.env.SWARM_PACK_DIRS ?? "").split(":")).flatMap((n) => n.required))].join(","),
    // The hosts msb swaps a placeholder in for: the extension sends a request
    // body to them chunked (extensions/vm-egress.ts says why).
    SWARM_SECRET_HOSTS: [...new Set([...secrets.flatMap((s) => s.hosts), ...packSecrets.flatMap((s) => s.hosts)].map((h) => parseAllowEntry(h).value))].sort().join(","),
  };
  // This seat's own hub token. It rests in msb's database with the secret
  // values while the VM lives (scrubbed after finish), never in the spec,
  // the record or a log.
  const seatToken = seatTokenFor(spec, agent.id);
  if (seatToken) env.SWARM_SEAT_TOKEN = seatToken;

  // A secret is bound to named hosts only: bound to a suffix, msb would put
  // its value on any host under it, and any host under a suffix is one an
  // agent can name.
  for (const h of [...secrets.flatMap((s) => s.hosts), ...packSecrets.flatMap((s) => s.hosts)]) {
    if (parseAllowEntry(h).kind === "suffix") throw new Error(`a secret is bound to the suffix ${h}; msb would substitute its value for any host under it. Name the host.`);
  }
  // Never `.replace()`: a VM of this name is another run's, or this run's
  // twin on another registry, and replacing it sends it SIGTERM. Run ids
  // are short, and the same one on two registries is a collision to refuse.
  if ((await runVms()).some((v) => v.name === name)) throw new Error(`a VM named ${name} exists already (another run with this id?); refusing to replace it`);
  let builder = M.Sandbox.builder(name)
    .image(spec.image)
    .pullPolicy(spec.pull ?? "if-missing")
    .cpus(spec.cpus ?? 2)
    .memory(spec.memory_mib ?? 2048)
    .rootDisk(spec.root_disk_mib ?? 8192)
    .detached(true)
    .workdir(spec.sandbox)
    .labels({ [LABEL_RUN]: spec.run, [LABEL_AGENT]: agent.id, ...(spec.registry ? { [LABEL_REGISTRY]: registryLabel(spec.registry) } : {}) })
    .envs(env)
    .vsock(join(spec.hub_dir, `${agent.id}.sock`), HUB_PORT)
    .scripts({ "dfirswarm-bridge": BRIDGE_SCRIPT, "dfirswarm-pi": PI_SCRIPT, "dfirswarm-probe": PROBE_SCRIPT })
    .patch((p) => {
      p.mkdir("/root/.pi/agent");
      p.text("/root/.pi/agent/auth.json", piConfig.auth, { mode: 0o600 });
      if (piConfig.models) p.text("/root/.pi/agent/models.json", piConfig.models);
      if (piConfig.settings) p.text("/root/.pi/agent/settings.json", piConfig.settings);
      if (piConfig.modelsStore) p.text("/root/.pi/agent/models-store.json", piConfig.modelsStore);
      return p;
    })
    .network((n) => {
      n.policyFromBuilder(policy);
      // A secret is swapped in on the way out over TLS, so the hosts that
      // receive one are intercepted — the SDK leaves interception off unless
      // it is configured (the CLI turns it on by itself). Every other allowed
      // host keeps its own TLS end to end: a package index verified against
      // the tool's own CA bundle, not msb's.
      const secretHosts = [...new Set([...secrets.flatMap((s) => s.hosts), ...packSecrets.flatMap((s) => s.hosts)])];
      if (secretHosts.length) {
        n.tls((t: TlsB) => {
          // Every port a secret travels on, not only 443: a provider on
          // :8443 would otherwise get its placeholder, never its key.
          t.interceptedPorts(interceptPorts(secretHosts));
          for (const h of tlsBypass(allowHosts, secretHosts)) t.bypass(h);
          return t;
        });
      }
      // A placeholder on its way anywhere but its own hosts is stopped and
      // written to the VM's runtime log, which custody reads at stop.
      n.secretViolationAction("block-and-log");
      // msb binds a secret to a host name or a `*.suffix` pattern; the port
      // is the policy's business.
      const nameOf = (h: string) => {
        const e = parseAllowEntry(h);
        return e.kind === "suffix" ? `*${e.value}` : e.value;
      };
      for (const s of secrets) {
        n.secret((b: SecretB) => {
          b.env(secretEnvName(s)).value(s.value).placeholder(s.placeholder);
          for (const h of new Set(s.hosts.map(nameOf))) b.allow(h);
          return b;
        });
      }
      for (const s of packSecrets) {
        n.secret((b: SecretB) => {
          b.env(s.name).value(s.value).placeholder(s.placeholder);
          for (const h of new Set(s.hosts.map(nameOf))) b.allow(h);
          return b;
        });
      }
      return n;
    });
  if (spec.max_duration_sec) builder = builder.maxDuration(spec.max_duration_sec);
  for (const m of mounts) {
    // The guest path is the path as the harness names it; the host side is
    // resolved, because msb does not follow a symlink on the way to a share
    // (/var -> /private/var on macOS failed the boot with ENOTDIR, measured).
    const hostPath = realpathSync(m.host);
    builder = builder.volume(m.guest ?? m.host, (v) => {
      v.bind(hostPath);
      if (m.readonly) v.readonly();
      if (m.noexec) v.noexec();
      return v;
    });
  }
  const sandbox = await withTimeout(builder.create(), CREATE_TIMEOUT_MS, `${name} was not up within ${CREATE_TIMEOUT_MS / 1000} s`);
  let probe: Record<string, unknown> = {};
  try {
    const out = await sandbox.exec("/.msb/scripts/dfirswarm-probe", []);
    const hostNow = Date.now() / 1000;
    const text = out.stdout().trim().split("\n").pop() ?? "";
    probe = JSON.parse(text) as Record<string, unknown>;
    // The guest's clock stamps every line an agent sends (`ts`); the
    // collector stamps the host's (`recv_ts`). How far apart they started is
    // recorded, so a gap in the record can be read against it.
    if (typeof probe.guest_time === "number") probe.clock_skew_s = Math.round((probe.guest_time - hostNow) * 10) / 10;
  } catch (err) {
    probe = { error: err instanceof Error ? err.message : String(err) };
  }
  let digest: string | null = null;
  try {
    const cfg = (await sandbox.config()) as unknown as { image?: { Oci?: { reference?: string } }; manifest_digest?: string; manifestDigest?: string };
    digest = cfg.manifest_digest ?? cfg.manifestDigest ?? null;
  } catch {
    digest = null;
  }
  if (!digest) {
    const r = await run(msbBinary(), ["inspect", name, "--format", "json"], { timeoutMs: 30_000 });
    try {
      digest = (JSON.parse(r.stdout) as { config?: { manifest_digest?: string } }).config?.manifest_digest ?? null;
    } catch {
      digest = null;
    }
  }
  const record: VmRecord = {
    agent: agent.id,
    name,
    run: spec.run,
    runtime: { name: "microsandbox", version: await msbVersion() },
    image: { ref: spec.image, manifest_digest: digest, ...(spec.image_digest ? { expected_digest: spec.image_digest } : {}), description: probe.image ?? null },
    cpus: spec.cpus ?? 2,
    memory_mib: spec.memory_mib ?? 2048,
    max_duration_sec: spec.max_duration_sec ?? null,
    mounts: mounts.map((m) => ({ host: m.host, guest: m.guest ?? m.host, mode: m.readonly ? "ro" : "rw", ...(m.noexec ? { noexec: true } : {}) })),
    network: { default: spec.open_net ? "public" : "deny", allow_hosts: allowHosts, host_ports: hostPorts },
    // With the variable msb holds each under: its runtime log names a
    // stopped placeholder by that variable, and custody tells a stop on the
    // credential's own host from one aimed elsewhere by it.
    secrets: [
      ...secrets.map((s) => ({ name: `${s.provider} (${s.kind === "oauth" ? "subscription token" : "API key"})`, env: secretEnvName(s), hosts: s.hosts })),
      ...packSecrets.map((s) => ({ name: s.name, env: s.name, hosts: s.hosts })),
    ],
    ...(spec.model_gateway ? { model_gateway: { port: spec.model_gateway.port, providers: plan.fronted, declined: spec.model_gateway.declined ?? [] } } : {}),
    probe,
    created_at: new Date().toISOString(),
  };
  await mkdir(spec.records_dir, { recursive: true });
  await writeRecord(join(spec.records_dir, `${agent.id}.json`), record);
  return record;
}

export async function createVms(spec: VmSpec): Promise<{ records: VmRecord[]; failures: Array<{ agent: string; reasons: string[] }>; warnings: string[] }> {
  const M = await sdk();
  // msb's database holds a live VM's secret values (scrubMsbDatabase): its
  // directory is the run's user's alone, whatever mode msb created it with.
  await chmod(msbHome(), 0o700).catch(() => undefined);
  const secrets = await resolveSecrets(spec);
  const expectInputs = existsSync(join(spec.sandbox, "inputs"));
  let expectedInputFiles: number | undefined;
  try {
    expectedInputFiles = (JSON.parse(readFileSync(join(spec.sandbox, "inputs.json"), "utf8")) as { files?: unknown[] }).files?.length;
  } catch {
    expectedInputFiles = undefined;
  }
  const needs = packNeeds((spec.env.SWARM_PACK_DIRS ?? "").split(":"));
  const allowInstall = spec.env.SWARM_ALLOW_INSTALL === "1";
  // The model gateway's config, read once: each seat's gateway token is in
  // it, and it reaches a VM only as that seat's own models.json key.
  const gateway = spec.model_gateway ? (JSON.parse(await readFile(spec.model_gateway.config, "utf8")) as GatewayConfig) : null;
  const settled = await Promise.allSettled(spec.agents.map((a) => createOne(M, spec, a, secrets, gateway)));
  const records: VmRecord[] = [];
  const failures: Array<{ agent: string; reasons: string[] }> = [];
  const warnings = new Set<string>();
  for (const [i, r] of settled.entries()) {
    const agent = spec.agents[i].id;
    if (r.status === "rejected") {
      failures.push({ agent, reasons: [r.reason instanceof Error ? r.reason.message : String(r.reason)] });
      continue;
    }
    records.push(r.value);
    const fit = imageFit(r.value.probe, needs, allowInstall);
    const wrong = [...probeVerdict(r.value.probe, expectInputs, expectedInputFiles), ...fit.blockers];
    // One image for the whole run, by digest: a tag moved between two VMs'
    // boots would give two agents two different toolsets under one name.
    if (spec.image_digest && r.value.image.manifest_digest && r.value.image.manifest_digest !== spec.image_digest) {
      wrong.push(`booted ${r.value.image.manifest_digest}, not ${spec.image_digest}, which ${spec.image} was when the run started`);
    }
    if (wrong.length) failures.push({ agent, reasons: wrong });
    for (const w of fit.warnings) warnings.add(w);
    // The seeded tools' own programs (their manifests' `requires`): a tool
    // that calls one the image lacks fails when an agent calls it, so it is
    // said now; it does not stop the run, the tool is one of many.
    const lacking = Array.isArray(r.value.probe.missing_tool_programs) ? (r.value.probe.missing_tool_programs as string[]) : [];
    if (lacking.length) warnings.add(`the seeded tools call ${lacking.join(", ")}, which this image does not hold: those tools will fail`);
    // The fit is part of what the VM was: recorded beside the probe.
    (r.value as VmRecord & { image_fit?: unknown }).image_fit = { packs: needs.map((n) => ({ id: n.id, version: n.version })), ...fit };
    await writeRecord(join(spec.records_dir, `${agent}.json`), r.value).catch(() => undefined);
  }
  return { records, failures, warnings: [...warnings] };
}

/** This run's VMs, from msb's own list by label. */
export async function runVms(runId?: string): Promise<Array<{ name: string; status: string; run: string; agent: string; registry: string }>> {
  // A bare-key label filter matches nothing in msb 0.7.2; without a run,
  // every VM is listed and its labels decide.
  const args = ["list", "--format", "json"];
  if (runId) args.push("--label", `${LABEL_RUN}=${runId}`);
  const r = await run(msbBinary(), args, { timeoutMs: 30_000 });
  // A list that failed is not an empty list: read as one, `stop` said a run
  // was put away while its VMs were up.
  if (r.code !== 0) throw new Error(`msb list failed: ${(r.stderr || r.stdout).trim() || `exit ${r.code}`}`);
  let rows: unknown;
  try {
    rows = JSON.parse(r.stdout || "[]");
  } catch {
    throw new Error("msb list answered something that is not JSON");
  }
  const list = Array.isArray(rows) ? rows : Array.isArray((rows as { sandboxes?: unknown[] })?.sandboxes) ? (rows as { sandboxes: unknown[] }).sandboxes : [];
  const out: Array<{ name: string; status: string; run: string; agent: string; registry: string }> = [];
  for (const row of list) {
    const o = row as Record<string, unknown>;
    const name = String(o.name ?? "");
    if (!name) continue;
    // `msb list` filters by label and does not print them (0.7.2); a VM's
    // labels are in its own configuration.
    let labels = (o.labels ?? {}) as Record<string, string>;
    if (!Object.keys(labels).length) {
      const inspect = await run(msbBinary(), ["inspect", name, "--format", "json"], { timeoutMs: 30_000 });
      try {
        labels = (JSON.parse(inspect.stdout) as { config?: { labels?: Record<string, string> } }).config?.labels ?? {};
      } catch {
        labels = {};
      }
    }
    const vm = { name, status: String(o.status ?? "").toLowerCase(), run: labels[LABEL_RUN] ?? "", agent: labels[LABEL_AGENT] ?? "", registry: labels[LABEL_REGISTRY] ?? "" };
    if (vm.run && (!runId || vm.run === runId)) out.push(vm);
  }
  return out;
}

/**
 * Put a run's VMs away: stop each, keep its disk as a snapshot with msb's
 * integrity record (unless told not to), remove it, and write down where the
 * snapshot is and its sha256. Safe to run twice.
 */
export type FinishEntry = { agent: string; name: string; snapshot?: string; error?: string; kept?: true };

/** Free space below which a VM's disk is not snapshotted (and the VM not removed). */
const SNAPSHOT_MIN_FREE_BYTES = Number(process.env.SWARM_SNAPSHOT_MIN_FREE_BYTES ?? 4 * 1024 ** 3);

/** Free bytes on the file system that holds `dir` (or its nearest existing parent); null when unknown. */
async function freeBytes(dir: string): Promise<number | null> {
  const { statfs } = await import("node:fs/promises");
  let probe = dir;
  for (;;) {
    try {
      const st = await statfs(probe);
      return Number(st.bavail) * Number(st.bsize);
    } catch {
      const parent = dirname(probe);
      if (parent === probe) return null;
      probe = parent;
    }
  }
}

/** msb's own directory: its database, each sandbox's configuration and logs. */
function msbHome(): string {
  return process.env.MSB_HOME || join(process.env.HOME || "", ".microsandbox");
}

/**
 * msb keeps each VM's configuration in its own SQLite database, a secret's
 * value included while the VM exists (measured on Linux, msb 0.7.2), and a
 * removed VM's rows leave their bytes in the file's free pages and its
 * write-ahead log until SQLite reuses them (measured: test values from runs
 * long finished, still in msb.db and msb.db-wal). Once a finish has removed
 * VMs the free pages are dropped: a checkpoint, a VACUUM (which rewrites the
 * file from the live rows only) and a checkpoint again. Nothing live is
 * changed; a database another msb is writing just then is left for the next
 * finish (busy), and a host with no sqlite3 says so.
 *
 * "scrubbed" only when the last checkpoint really completed and no free
 * page is left: sqlite3 reports a checkpoint a reader held back in its
 * result row (busy = 1), not in its exit code, and the free pages and the
 * log then still hold the removed rows.
 */
export async function scrubMsbDatabase(): Promise<"scrubbed" | "busy" | "no sqlite3" | "no database"> {
  const db = join(msbHome(), "db", "msb.db");
  if (!existsSync(db)) return "no database";
  if ((await run("sh", ["-c", "command -v sqlite3"], { timeoutMs: 10_000 })).code !== 0) return "no sqlite3";
  const r = await run("sqlite3", ["-batch", db, "PRAGMA busy_timeout=3000; PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE); PRAGMA freelist_count;"], { timeoutMs: 120_000 });
  return r.code === 0 && scrubCompleted(r.stdout) ? "scrubbed" : "busy";
}

/**
 * Whether sqlite3's answer to the scrub says it completed: the last
 * `wal_checkpoint` row (busy|log|checkpointed) not busy and, in WAL mode,
 * every frame of the log checkpointed; and no free page left.
 */
export function scrubCompleted(stdout: string): boolean {
  const lines = stdout.trim().split("\n").map((l) => l.trim()).filter(Boolean);
  const free = Number(lines.at(-1));
  const rows = lines.filter((l) => /^-?\d+\|-?\d+\|-?\d+$/.test(l)).map((l) => l.split("|").map(Number));
  const last = rows.at(-1);
  if (!last || !Number.isFinite(free)) return false;
  const [busy, log, done] = last;
  return busy === 0 && (log === -1 || log === done) && free === 0;
}

/** How long a finish waits for another finish of the same run that is still alive. */
const FINISH_LOCK_WAIT_MS = 45 * 60_000;
/**
 * A finish touches its lock every so often while it works (a snapshot can
 * take a quarter of an hour); a lock not touched for this long belongs to a
 * finish that is gone, whatever process now has its pid.
 */
const FINISH_LOCK_STALE_MS = Number(process.env.SWARM_FINISH_LOCK_STALE_MS ?? 10 * 60_000);

/**
 * Put a run's VMs away: stop, snapshot, keep the logs, remove, record. One
 * finish at a time per run (the hub's own and an operator's `stop` used to
 * race on the same snapshot file); a VM whose snapshot failed is stopped and
 * kept, never removed, since removing it is the one step that cannot be
 * undone; and every msb step's outcome is in the entry, not swallowed.
 */

export async function finishRun(runId: string, sandbox: string, options: { snapshot?: boolean; agent?: string; registry?: string } = {}): Promise<FinishEntry[]> {
  const msb = msbBinary();
  const records = join(sandbox, "vm");
  const snapDir = `${sandbox}.vm-snapshots`;
  const out: FinishEntry[] = [];
  await mkdir(records, { recursive: true });
  const lock = join(records, ".finish.lock");
  let held = false;
  let heartbeat: ReturnType<typeof setInterval> | undefined;
  // A finish in progress (the hub putting a seat away, or the swarm) holds
  // the lock for as long as its snapshots take: wait for it while its owner
  // lives, rather than give up after a minute and leave the run half put away.
  const deadline = Date.now() + FINISH_LOCK_WAIT_MS;
  while (!held && Date.now() < deadline) {
    try {
      await mkdir(lock);
      // Whose it is: a stop interrupted with ^C leaves the lock, and the
      // next stop must see its owner is gone rather than wait half an hour.
      await writeFile(join(lock, "pid"), `${process.pid}\n`).catch(() => undefined);
      held = true;
      // Alive and working, said by the lock's own time: a finish still
      // snapshotting after half an hour was taken for a dead one, and a
      // second finish then worked the same VMs.
      heartbeat = setInterval(() => {
        const now = new Date();
        void utimes(lock, now, now).catch(() => undefined);
      }, Math.max(250, Math.min(30_000, FINISH_LOCK_STALE_MS / 4)));
      heartbeat.unref();
    } catch {
      const owner = Number.parseInt(await readFile(join(lock, "pid"), "utf8").catch(() => ""), 10);
      let ownerAlive = false;
      if (Number.isInteger(owner) && owner > 0) {
        try {
          process.kill(owner, 0);
          ownerAlive = true;
        } catch {
          ownerAlive = false;
        }
      }
      // Broken only when its owner is gone: dead, or silent past the
      // heartbeat (a pid another process now has). A live owner's lock is
      // never broken for being old.
      const age = await stat(lock).then((s) => Date.now() - s.mtimeMs).catch(() => 0);
      if ((Number.isInteger(owner) && owner > 0 && !ownerAlive) || age > FINISH_LOCK_STALE_MS) await rm(lock, { recursive: true, force: true });
      else await new Promise((r) => setTimeout(r, Math.min(3000, Math.max(100, FINISH_LOCK_STALE_MS / 4))));
    }
  }
  if (!held) throw new Error(`another finish of run ${runId} is in progress (${lock})`);
  try {
  // Another registry's run can carry the same id: only this registry's VMs.
  const mine = options.registry ? registryLabel(options.registry) : "";
  for (const vm of await runVms(runId)) {
    if (mine && vm.registry && vm.registry !== mine) continue;
    const agent = vm.agent || vm.name.replace(`dfs-${runId}-`, "");
    if (options.agent && agent !== options.agent) continue;
    const entry: FinishEntry = { agent, name: vm.name };
    // What the VM holds now against what its image held: a package its root
    // installed outside the seat's recorded toolchain (apt, or pip into the
    // image's own venv) is named before the disk is kept.
    const inventory = await run(msb, ["exec", vm.name, "--", "python3", "-c", INVENTORY_SCRIPT], { timeoutMs: 90_000 });
    let outside: Record<string, unknown>;
    try {
      outside = inventory.code === 0 ? (JSON.parse(inventory.stdout.trim().split("\n").pop() ?? "{}") as Record<string, unknown>) : { error: (inventory.stderr || inventory.stdout).trim() || `exit ${inventory.code}` };
    } catch {
      outside = { error: "the inventory said something that is not JSON" };
    }
    const stopped = await run(msb, ["stop", vm.name], { timeoutMs: 120_000 });
    if (stopped.code !== 0 && !/not running|already stopped|stopped/i.test(`${stopped.stdout}${stopped.stderr}`)) {
      entry.error = `msb stop: ${(stopped.stderr || stopped.stdout).trim() || `exit ${stopped.code}`}`;
      entry.kept = true;
      out.push(entry);
      continue;
    }
    const recordFile = join(records, `${agent}.json`);
    let record: VmRecord | null = null;
    try {
      record = JSON.parse(await readFile(recordFile, "utf8")) as VmRecord;
    } catch {
      record = null;
    }
    // A snapshot that runs out of disk half-way is a lost disk if the VM is
    // then removed: below the floor the VM is kept, stopped, for a stop run
    // again once there is room.
    // The floor is the larger of the fixed one and what this VM's disk
    // holds: a --vm-disk bigger than the floor could still run out.
    const room = options.snapshot !== false ? await freeBytes(snapDir) : null;
    const need = Math.max(SNAPSHOT_MIN_FREE_BYTES, await allocatedBytes(join(msbHome(), "sandboxes", vm.name, "upper.ext4")));
    const file = join(snapDir, `${agent}.msb`);
    // A disk an earlier finish kept (its VM then failed to go) is kept
    // until a new one has replaced it: a failed second attempt must not
    // leave the run with no disk at all.
    const earlier = record?.snapshot && "path" in record.snapshot && existsSync(file) ? record.snapshot : null;
    if (options.snapshot !== false && room !== null && room < need) {
      entry.error = `only ${room} bytes free where the disks are kept (${snapDir}), and this VM's disk needs ${need}; the VM is kept, not snapshotted and not removed. Free space and run stop again.`;
      entry.kept = true;
      if (record) {
        if (earlier) (record as VmRecord & { snapshot_retry_error?: string }).snapshot_retry_error = entry.error;
        else record.snapshot = { error: entry.error };
      }
    } else if (options.snapshot !== false) {
      await mkdir(snapDir, { recursive: true });
      const fresh = `${file}.new`;
      await rm(fresh, { force: true });
      const r = await run(msb, ["snapshot", "create", "--from-sandbox", vm.name, "--integrity", "--label", `run=${runId}`, "--label", `agent=${agent}`, "-o", fresh, "--quiet"], { timeoutMs: 15 * 60_000 });
      if (r.code === 0 && existsSync(fresh)) {
        await rename(fresh, file);
        const bytes = (await stat(file)).size;
        const sha = await sha256File(file);
        entry.snapshot = file;
        if (record) {
          record.snapshot = { path: file, sha256: sha, bytes, integrity: true };
          delete (record as VmRecord & { snapshot_retry_error?: string }).snapshot_retry_error;
        }
      } else {
        await rm(fresh, { force: true });
        entry.error = (r.stderr || r.stdout).trim() || `snapshot exit ${r.code}`;
        entry.kept = true;
        if (record) {
          if (earlier) (record as VmRecord & { snapshot_retry_error?: string }).snapshot_retry_error = entry.error;
          else record.snapshot = { error: entry.error };
        }
      }
    }
    // The VM's own logs (the runtime's, the guest kernel's, its execs) go
    // with it when it is removed; keep them beside the disk.
    const logs = join(msbHome(), "sandboxes", vm.name, "logs");
    if (existsSync(logs)) {
      const keep = join(snapDir, `${agent}.logs`);
      await mkdir(keep, { recursive: true });
      const { readdir: ls, copyFile } = await import("node:fs/promises");
      // A log that could not be kept is named on the record, not dropped.
      const lost: string[] = [];
      for (const f of await ls(logs).catch(() => [])) await copyFile(join(logs, f), join(keep, f)).catch((err: Error) => lost.push(`${f}: ${err.message}`));
      if (record) {
        (record as VmRecord & { logs?: string }).logs = keep;
        if (lost.length) (record as VmRecord & { logs_not_kept?: string[] }).logs_not_kept = lost;
      }
    }
    if (!entry.kept) {
      const removed = await run(msb, ["rm", vm.name], { timeoutMs: 60_000 });
      if (removed.code !== 0) {
        entry.error = `msb rm: ${(removed.stderr || removed.stdout).trim() || `exit ${removed.code}`}`;
        entry.kept = true;
      }
    }
    if (record) {
      (record as VmRecord & { installed_outside_image?: unknown }).installed_outside_image = outside;
      // The runtime that put the VM away against the one that made it: msb
      // upgraded under a live run changes how the disk is kept and checked.
      const nowVersion = await msbVersion();
      if (record.runtime?.version && nowVersion && record.runtime.version !== nowVersion) {
        (record as VmRecord & { runtime_changed?: unknown }).runtime_changed = { from: record.runtime.version, to: nowVersion };
      }
      record.stopped_at = new Date().toISOString();
      if (entry.kept) (record as VmRecord & { kept?: string }).kept = entry.error;
      await writeRecord(recordFile, record).catch(() => undefined);
    }
    out.push(entry);
  }
  } finally {
    if (heartbeat) clearInterval(heartbeat);
    await rm(lock, { recursive: true, force: true });
  }
  // What the removed VMs' configuration left in msb's database goes too,
  // and the outcome goes on each removed VM's record: most runs are put
  // away by the hub, and the record is what custody, the report and a
  // later stop read.
  if (out.some((e) => !e.kept)) {
    const scrub = await scrubMsbDatabase().catch(() => "busy" as const);
    for (const e of out) {
      if (e.kept) continue;
      (e as FinishEntry & { msb_db?: string }).msb_db = scrub;
      const recordFile = join(records, `${e.agent}.json`);
      try {
        const record = JSON.parse(await readFile(recordFile, "utf8")) as VmRecord & { msb_db?: string };
        record.msb_db = scrub;
        await writeRecord(recordFile, record);
      } catch {
        // no record to carry it: the entry still does
      }
    }
  }
  return out;
}

/**
 * A VM's record, written whole: to a temporary file beside it, then renamed
 * over it. Written in place, a finish killed half-way (a stop's deadline, a
 * ^C) left a torn record, and custody then read the VM as having none.
 */
async function writeRecord(file: string, record: unknown): Promise<void> {
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, `${JSON.stringify(record, null, 2)}\n`);
  await rename(tmp, file);
}

/** Bytes a (sparse) file really holds on disk; 0 when it cannot be read. */
async function allocatedBytes(file: string): Promise<number> {
  try {
    const st = await stat(file);
    return Number(st.blocks) * 512;
  } catch {
    return 0;
  }
}

/**
 * Run in each VM at stop: the packages it holds that its image did not, by
 * the image's own record. apt against `dpkg_all` (an image built before that
 * field says it has no baseline), the image's venv against `pip`.
 */
export const INVENTORY_SCRIPT = `
import json, subprocess
rec = json.load(open("/etc/dfirswarm/image.json"))
def dpkg():
    out = subprocess.run(["dpkg-query", "-W", "-f", "\${Package}\\t\${Version}\\n"], capture_output=True, text=True).stdout
    return dict(l.split("\\t", 1) for l in out.splitlines() if "\\t" in l)
def venv():
    try:
        out = subprocess.run(["/opt/dfir/venv/bin/pip", "list", "--format=json"], capture_output=True, text=True, timeout=60).stdout
        return {p["name"]: p["version"] for p in json.loads(out or "[]")}
    except Exception:
        return {}
def diff(base, now):
    return {k: v for k, v in now.items() if base.get(k) != v}
res = {"baseline": "dpkg_all" in rec}
if "dpkg_all" in rec:
    res["apt"] = diff(rec["dpkg_all"], dpkg())
res["venv"] = diff(rec.get("pip") or {}, venv())
print(json.dumps(res))
`;

/**
 * VMs whose run is over: this registry recorded them and does not say the
 * run is running (or still being prepared). Removed without a snapshot — a
 * run that was stopped properly already has one. A VM labelled for another
 * registry, or for none, is never touched; `--run` names one run outright.
 */
/** A kickoff still preparing its run after this long died without saying so. */
export const PREPARED_STALE_MS = 2 * 3600_000;

/** The throwaway VMs the harness boots for one step, by their run label, or by their agent label (the catalog carries its run's id). */
const THROWAWAY_RUNS = new Set(["catalog", "toolbox", "netcheck"]);
const THROWAWAY_AGENTS = new Set(["catalog", "toolbox", "netcheck"]);

export async function reapVms(options: { run?: string; registry?: string; only?: string; now?: number } = {}): Promise<string[]> {
  const live = new Set<string>();
  const sandboxOf = new Map<string, string>();
  let mine = "";
  if (!options.run) {
    if (!options.registry || !existsSync(options.registry)) return [];
    mine = registryLabel(options.registry);
    try {
      const reg = JSON.parse(readFileSync(options.registry, "utf8")) as { runs?: Array<{ id?: string; state?: string; started_at?: string; sandbox?: string; hold?: unknown }> };
      const now = options.now ?? Date.now();
      for (const r of reg.runs ?? []) {
        if (!r.id) continue;
        if (r.sandbox) sandboxOf.set(r.id, r.sandbox);
        // A run on hold (`swarm.sh hold`) keeps what it has, its VMs too,
        // until the operator releases it.
        if (r.hold && typeof r.hold === "object") {
          live.add(r.id);
          continue;
        }
        // `prepared` is a kickoff between writing its record and starting its
        // agents; one that stayed there for hours is a kickoff that died.
        const started = Date.parse(r.started_at ?? "");
        const stale = r.state === "prepared" && Number.isFinite(started) && now - started > PREPARED_STALE_MS;
        if ((r.state === "running" || r.state === "prepared") && !stale) live.add(r.id);
      }
    } catch {
      // an unreadable registry reaps nothing
      return [];
    }
  }
  const removed: string[] = [];
  const kept = new Set<string>();
  let direct = false;
  for (const vm of await runVms(options.run)) {
    if (!options.run) {
      // A throwaway VM (the catalog's, the toolbox check's, netcheck's) that
      // is no longer running was left by a step that died.
      const throwaway = (THROWAWAY_RUNS.has(vm.run) || THROWAWAY_AGENTS.has(vm.agent)) && vm.status !== "running";
      if (!throwaway && (vm.registry !== mine || live.has(vm.run))) continue;
      if (options.only && vm.run !== options.only) continue;
      // An orphan of a run this registry knows keeps its disk and its logs,
      // as a stop would have: whoever reads the run may need them.
      const sandbox = sandboxOf.get(vm.run);
      if (!throwaway && sandbox && existsSync(sandbox) && !kept.has(vm.run)) {
        kept.add(vm.run);
        const done = await finishRun(vm.run, sandbox, { snapshot: true, registry: options.registry }).catch(() => []);
        for (const e of done) if (!e.kept) removed.push(e.name);
        continue;
      }
      if (kept.has(vm.run)) continue;
    }
    await run(msbBinary(), ["stop", vm.name], { timeoutMs: 120_000 });
    const r = await run(msbBinary(), ["rm", vm.name], { timeoutMs: 60_000 });
    if (r.code === 0) {
      removed.push(vm.name);
      direct = true;
    }
  }
  // As a finish does: the removed VMs' rows leave no bytes in msb's database.
  if (direct) await scrubMsbDatabase().catch(() => undefined);
  return removed;
}

/**
 * A throwaway VM put away when this process is interrupted: its `finally`
 * does not run on a signal, and a ^C during the catalog left the VM up.
 */
function putAwayOnSignal(name: string): () => void {
  const handler = (sig: NodeJS.Signals) => {
    void (async () => {
      await run(msbBinary(), ["stop", name], { timeoutMs: 60_000 });
      await run(msbBinary(), ["rm", name], { timeoutMs: 60_000 });
      process.exit(sig === "SIGINT" ? 130 : 143);
    })();
  };
  process.once("SIGINT", handler);
  process.once("SIGTERM", handler);
  return () => {
    process.off("SIGINT", handler);
    process.off("SIGTERM", handler);
  };
}

/**
 * The toolbox check (scripts/toolbox.sh) run where the agents will run: in
 * a throwaway VM of the run's image, offline. On the host it described the
 * host, which an agent in a VM never touches. Returns the check's exit code
 * (3: a required tool is missing) and the toolbox.json it wrote.
 */
export async function imageToolbox(image: string, preset: string, required: boolean, packDirs: string[] = []): Promise<{ code: number; json: string; output: string; digest?: string }> {
  const M = await sdk();
  const { mkdtemp, copyFile } = await import("node:fs/promises");
  const tmp = await mkdtemp("/tmp/dfs-tb-");
  const name = `dfs-toolbox-${randomBytes(6).toString("hex")}`;
  const release = putAwayOnSignal(name);
  try {
    await copyFile(join(ROOT, "scripts", "toolbox.sh"), join(tmp, "toolbox.sh"));
    await mkdir(join(tmp, "sbx"), { recursive: true });
    // Every program the run's packs name, for the check to look for in the
    // image; one that belongs to another system (not_in_image) is said as
    // such, not looked for.
    const programs: Array<{ name: string; why: string; pack: string; required: boolean; not_in_image?: string }> = [];
    for (const dir of packDirs.filter(Boolean)) {
      try {
        const id = (JSON.parse(readFileSync(join(dir, "pack.json"), "utf8")) as { id?: string }).id ?? dir;
        const host = JSON.parse(readFileSync(join(dir, "requires", "host.json"), "utf8")) as { binaries?: Array<{ name?: string; why?: string; optional?: boolean; not_in_image?: string }> };
        for (const b of host.binaries ?? []) {
          if (b.name) programs.push({ name: b.name, why: b.why ?? "", pack: id, required: !b.optional && !b.not_in_image, ...(b.not_in_image ? { not_in_image: b.not_in_image } : {}) });
        }
      } catch {
        // a pack without host requirements names no program
      }
    }
    await writeFile(join(tmp, "image.json"), JSON.stringify({ image, programs }));
    const sandbox = await M.Sandbox.builder(name)
      .image(image)
      .pullPolicy("if-missing")
      .cpus(1)
      .memory(1024)
      .maxDuration(1800)
      .labels({ [LABEL_RUN]: "toolbox", [LABEL_AGENT]: "toolbox" })
      .disableNetwork()
      .detached(true)
      .volume("/tb", (v) => v.bind(realpathSync(tmp)))
      .create();
    const out = await sandbox.exec("bash", ["/tb/toolbox.sh", "/tb/sbx", preset, ...(required ? ["--required"] : []), "--image", "/tb/image.json"]);
    let json = await readFile(join(tmp, "sbx", "toolbox.json"), "utf8").catch(() => "");
    // Which image this was, by digest: the check describes that image, not a tag.
    const digest = await imageDigest(name);
    if (json && digest) {
      try {
        json = `${JSON.stringify({ ...(JSON.parse(json) as Record<string, unknown>), image_digest: digest }, null, 2)}\n`;
      } catch {
        // left as the check wrote it
      }
    }
    return { code: out.code, json, output: `${out.stdout()}${out.stderr()}`, ...(digest ? { digest } : {}) };
  } finally {
    release();
    await run(msbBinary(), ["stop", name], { timeoutMs: 60_000 });
    await run(msbBinary(), ["rm", name], { timeoutMs: 60_000 });
    await rm(tmp, { recursive: true, force: true });
  }
}

/**
 * The evidence catalog (scripts/evidence-catalog.sh) run in a throwaway VM of
 * the run's image, before any agent starts: the tools it calls are the
 * image's, and a host that holds no forensic tools (by design) still gets a
 * first pass. The sandbox is mounted writable for this one harness step; the
 * evidence read-only. The network is off unless the operator allowed hosts
 * for the run (`--allow-host`), which then reach the catalog as they reach
 * the agents: Volatility fetches a Windows kernel's symbols the first time,
 * and on the host the catalog had the host's network.
 */
export async function imageCatalog(
  image: string,
  sandbox: string,
  evidence: string[],
  options: { cpus?: number; memoryMib?: number; allowHosts?: string[]; openNet?: boolean; run?: string; maxDurationSec?: number; registry?: string; /** Tests only: a shell command run in the catalog's VM in place of the catalog, to show what that VM can reach. */ command?: string } = {},
): Promise<{ code: number; output: string; digest?: string }> {
  const M = await sdk();
  const name = `dfs-catalog-${randomBytes(6).toString("hex")}`;
  const release = putAwayOnSignal(name);
  // The parser runs over hostile evidence as root in this VM: it may write
  // catalog/ and nothing else of the run. The run's floor — the manifest
  // custody compares against, the contract, the trace — is read-only here.
  await mkdir(join(sandbox, "catalog"), { recursive: true });
  try {
    let builder = M.Sandbox.builder(name)
      .image(image)
      .pullPolicy("if-missing")
      .cpus(options.cpus ?? 2)
      .memory(options.memoryMib ?? 2048)
      .maxDuration(options.maxDurationSec ?? 4 * 3600)
      .labels({ [LABEL_RUN]: options.run ?? "catalog", [LABEL_AGENT]: "catalog", ...(options.registry ? { [LABEL_REGISTRY]: registryLabel(options.registry) } : {}) });
    if (options.openNet) {
      // --no-netguard: the catalog reaches what the agents reach.
      const policy = new M.NetworkPolicyBuilder().defaultDeny();
      policy.egress((r) => r.allowPublic());
      builder = builder.network((n) => n.policyFromBuilder(policy));
    } else if (options.allowHosts?.length) {
      const policy = allowEgress(new M.NetworkPolicyBuilder().defaultDeny(), options.allowHosts);
      builder = builder.network((n) => n.policyFromBuilder(policy));
    } else {
      builder = builder.disableNetwork();
    }
    builder = builder
      .detached(true)
      .workdir(sandbox)
      .envs({
        SWARM_CATALOG_STEP_TIMEOUT: process.env.SWARM_CATALOG_STEP_TIMEOUT ?? "900",
        ...(process.env.SWARM_CATALOG_MEMORY_PROBE_TIMEOUT ? { SWARM_CATALOG_MEMORY_PROBE_TIMEOUT: process.env.SWARM_CATALOG_MEMORY_PROBE_TIMEOUT } : {}),
      })
      .volume(sandbox, (v) => v.bind(realpathSync(sandbox)).readonly())
      .volume(join(sandbox, "catalog"), (v) => v.bind(realpathSync(join(sandbox, "catalog"))))
      .volume(join(ROOT, "scripts"), (v) => v.bind(realpathSync(join(ROOT, "scripts"))).readonly());
    for (const e of evidence) builder = builder.volume(e, (v) => v.bind(realpathSync(e)).readonly().noexec());
    const vm = await withTimeout(builder.create(), CREATE_TIMEOUT_MS, `the catalog VM was not up within ${CREATE_TIMEOUT_MS / 1000} s`);
    const out = options.command ? await vm.exec("sh", ["-c", options.command]) : await vm.exec("bash", [join(ROOT, "scripts", "evidence-catalog.sh"), sandbox]);
    const digest = await imageDigest(name);
    return { code: out.code, output: `${out.stdout()}${out.stderr()}`, ...(digest ? { digest } : {}) };
  } finally {
    release();
    await run(msbBinary(), ["stop", name], { timeoutMs: 120_000 });
    await run(msbBinary(), ["rm", name], { timeoutMs: 60_000 });
  }
}

/**
 * One allowlist entry, in the host allowlist's syntax (netguard-proxy.mjs):
 * `host`, `host:port`, `*.suffix` or `.suffix` (the apex included, as msb
 * matches it), an IPv4 or IPv6 address (`[v6]:port` with a port), or a CIDR
 * block (`10.0.0.0/8`, `10.0.0.0/8:8080`, `[fd00::/8]:443`). Anything else
 * throws with the reason: an entry the VM would read as nothing must stop
 * the kickoff, not leave a run that cannot reach what the operator named.
 */
export type AllowEntry = { kind: "domain" | "suffix" | "ip" | "cidr"; value: string; port: number; loopback: boolean };

const LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

/**
 * An address that means this machine: 127/8, ::1, and 0.0.0.0 (a server
 * bound to every interface is reached here on loopback). One definition,
 * so the allowlist, the gateway ports and hostGatewayUrl agree.
 */
export function isLoopbackIp(ip: string): boolean {
  return (isIPv4(ip) && (ip.startsWith("127.") || ip === "0.0.0.0")) || ip === "::1" || ip === "0:0:0:0:0:0:0:1" || ip === "::";
}

export function parseAllowEntry(raw: string): AllowEntry {
  const entry = raw.trim().toLowerCase();
  const bad = (why: string) => new Error(`--allow-host ${JSON.stringify(raw)}: ${why}`);
  if (!entry) throw bad("empty");
  if (/\s|@|:\/\//.test(entry)) throw bad("a host, not a URL: no scheme, no user, no spaces");
  const portOf = (p: string | undefined) => {
    if (p === undefined) return 443;
    const n = Number.parseInt(p, 10);
    if (!/^\d{1,5}$/.test(p) || n < 1 || n > 65535) throw bad(`port ${p} is not 1-65535`);
    return n;
  };
  // [v6] or [v6/prefix], with an optional port.
  const bracket = entry.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracket) {
    const [addr, prefix] = bracket[1].split("/");
    if (!isIPv6(addr)) throw bad(`${addr} is not an IPv6 address`);
    const port = portOf(bracket[2]);
    if (prefix !== undefined) {
      if (!/^\d{1,3}$/.test(prefix) || Number(prefix) > 128) throw bad(`/${prefix} is not an IPv6 prefix`);
      return { kind: "cidr", value: `${addr}/${prefix}`, port, loopback: false };
    }
    return { kind: "ip", value: addr, port, loopback: isLoopbackIp(addr) };
  }
  // A bare IPv6 address has colons of its own and so no port.
  if (isIPv6(entry)) return { kind: "ip", value: entry, port: 443, loopback: isLoopbackIp(entry) };
  const v6cidr = entry.match(/^([0-9a-f:.]+)\/(\d{1,3})$/);
  if (v6cidr && isIPv6(v6cidr[1])) {
    if (Number(v6cidr[2]) > 128) throw bad(`/${v6cidr[2]} is not an IPv6 prefix`);
    return { kind: "cidr", value: entry, port: 443, loopback: false };
  }
  const withPort = entry.match(/^(.*):(\d+)$/);
  const host = withPort ? withPort[1] : entry;
  const port = portOf(withPort?.[2]);
  const v4cidr = host.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (v4cidr) {
    if (!isIPv4(v4cidr[1]) || Number(v4cidr[2]) > 32) throw bad(`${host} is not an IPv4 block`);
    return { kind: "cidr", value: host, port, loopback: false };
  }
  if (host.includes("/")) throw bad("a host, not a URL: no path");
  if (isIPv4(host)) return { kind: "ip", value: host, port, loopback: isLoopbackIp(host) };
  if (/^\d+(\.\d+)*$/.test(host)) throw bad(`${host} is not an IPv4 address`);
  let name = host;
  let suffix = false;
  if (name.startsWith("*.")) {
    name = name.slice(2);
    suffix = true;
  } else if (name.startsWith(".")) {
    name = name.slice(1);
    suffix = true;
  }
  if (name.endsWith(".")) name = name.slice(0, -1);
  if (!name || name.length > 253 || !name.split(".").every((l) => LABEL.test(l))) {
    throw bad(name.includes("*") ? "a wildcard only as a leading *." : `${host} is not a host name`);
  }
  // A suffix of one label (`*.com`) is the whole of a top-level domain.
  if (suffix && !name.includes(".")) throw bad(`*.${name} would allow a whole top-level domain`);
  const loopback = !suffix && (name === "localhost" || name.endsWith(".localhost"));
  return { kind: suffix ? "suffix" : "domain", value: suffix ? `.${name}` : name, port, loopback };
}

/** Every entry parsed; the first that is not an entry throws. */
export function parseAllowList(hosts: string[]): AllowEntry[] {
  return hosts.filter((h) => h.trim()).map(parseAllowEntry);
}

/**
 * msb egress rules, one per port. Without this a `--allow-host
 * '*.blob.core.windows.net'` that works on the host would match nothing in a
 * VM. A loopback entry is not here: the VM's own loopback is not the host's,
 * so `127.0.0.1:8080` goes through msb's host gateway (gatewayPorts).
 */
export function egressRules(hosts: string[]): Array<{ port: number; domains: string[]; suffixes: string[]; ips: string[]; cidrs: string[] }> {
  const byPort = new Map<number, { port: number; domains: string[]; suffixes: string[]; ips: string[]; cidrs: string[] }>();
  for (const e of parseAllowList(hosts)) {
    if (e.loopback) continue;
    const rule = byPort.get(e.port) ?? { port: e.port, domains: [], suffixes: [], ips: [], cidrs: [] };
    byPort.set(e.port, rule);
    const list = e.kind === "domain" ? rule.domains : e.kind === "suffix" ? rule.suffixes : e.kind === "ip" ? rule.ips : rule.cidrs;
    if (!list.includes(e.value)) list.push(e.value);
  }
  return [...byPort.values()].sort((a, b) => a.port - b.port);
}

/** The ports of the allowlist's loopback entries: reached through msb's host gateway. */
export function gatewayPorts(hosts: string[]): number[] {
  return [...new Set(parseAllowList(hosts).filter((e) => e.loopback).map((e) => e.port))].sort((a, b) => a - b);
}

/** Does a TLS bypass pattern (`host` or `*.suffix`) cover this host name? */
export function bypassCovers(pattern: string, host: string): boolean {
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1);
    return host === suffix.slice(1) || host.endsWith(suffix);
  }
  return pattern === host;
}

/**
 * The same allowlist as TLS bypass patterns (a suffix is `*.suffix` to msb),
 * less every pattern that covers a host a secret goes to. A secret is swapped
 * in only where msb terminates TLS: a `*.openai.com` bypass would carry the
 * placeholder to api.openai.com untouched and the call would fail, or worse.
 */
export function tlsBypass(hosts: string[], secretHosts: string[] = []): string[] {
  const secrets = secretHosts.map((h) => parseAllowEntry(h));
  // A secret bound to a suffix covers every host under it: no bypass there.
  const covered = (p: string) =>
    secrets.some((e) => (e.kind === "suffix" ? bypassCovers(`*${e.value}`, p.replace(/^\*\./, "")) || bypassCovers(p, e.value.slice(1)) : bypassCovers(p, e.value)));
  return egressRules(hosts)
    .flatMap((r) => [...r.domains, ...r.suffixes.map((s) => `*${s}`)])
    .filter((p, i, all) => all.indexOf(p) === i && !covered(p));
}

/** The ports msb must terminate TLS on: 443 and every port a secret host is reached on. */
export function interceptPorts(secretHosts: string[]): number[] {
  return [...new Set([443, ...secretHosts.map((h) => parseAllowEntry(h).port)])].sort((a, b) => a - b);
}

/** catalog.json beside catalog/: the image and every file's sha256, written on the host after the VM is gone. */
export async function writeCatalogRecord(sandbox: string, image: string, digest: string | null): Promise<void> {
  const root = join(sandbox, "catalog");
  const files: Array<{ path: string; bytes: number; sha256: string }> = [];
  const walk = async (dir: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
      const abs = join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) await walk(abs);
      else if (e.isFile()) files.push({ path: `catalog/${abs.slice(root.length + 1)}`, bytes: (await stat(abs)).size, sha256: await sha256File(abs) });
    }
  };
  await walk(root);
  // By code unit, not by locale: the index is hashed, and four locales
  // gave four orders (and four digests) for the same files.
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  await writeFile(join(sandbox, "catalog.json"), `${JSON.stringify({ at: new Date().toISOString(), image, manifest_digest: digest, files }, null, 2)}\n`);
}

/**
 * What a run's VMs would reach, asked of a throwaway VM with the same policy:
 * every allowed host answers (any HTTP status is an answer; no answer is not),
 * a host outside the list does not resolve, and — as between two providers of
 * one VM — a placeholder bound to one host is stopped on its way to another
 * host that also holds a secret. (A host that holds none keeps its own TLS end
 * to end, so msb never reads what goes there: a placeholder can reach it, the
 * value it stands for cannot.) The host version of this (`swarm.sh netcheck`)
 * asks netguard; this asks msb.
 */
export async function netCheck(image: string, allowHosts: string[], options: { canary?: string } = {}): Promise<{ ok: boolean; rows: Array<{ check: string; host: string; result: string; ok: boolean }> }> {
  const M = await sdk();
  const name = `dfs-netcheck-${randomBytes(6).toString("hex")}`;
  const release = putAwayOnSignal(name);
  const canary = options.canary ?? "example.com";
  const entries = parseAllowList(allowHosts);
  const probe = entries.filter((e) => e.kind === "domain" && !e.loopback);
  const hostOf = (e: AllowEntry) => (e.port === 443 ? e.value : `${e.value}:${e.port}`);
  // Two stand-in secrets, one per host, as two providers of one VM would be.
  const pair = probe.slice(0, 2);
  const keys = pair.map((e, i) => ({ env: `NETCHECK_KEY${i}`, host: e, placeholder: `dfirswarm-secret-netcheck${i}-${randomBytes(8).toString("hex")}` }));
  const policy = allowEgress(new M.NetworkPolicyBuilder().defaultDeny(), allowHosts);
  const rows: Array<{ check: string; host: string; result: string; ok: boolean }> = [];
  try {
    const vm = await M.Sandbox.builder(name)
      .image(image)
      .pullPolicy("if-missing")
      .cpus(1)
      .memory(1024)
      .maxDuration(900)
      .labels({ [LABEL_RUN]: "netcheck", [LABEL_AGENT]: "netcheck" })
      .detached(true)
      .envs(Object.fromEntries(keys.map((k) => [k.env, k.placeholder])))
      .network((n) => {
        n.policyFromBuilder(policy);
        if (keys.length) {
          const secretHosts = keys.map((k) => hostOf(k.host));
          n.tls((t: TlsB) => {
            t.interceptedPorts(interceptPorts(secretHosts));
            for (const h of tlsBypass(allowHosts, secretHosts)) t.bypass(h);
            return t;
          });
          n.secretViolationAction("block-and-log");
          for (const k of keys) n.secret((b: SecretB) => b.env(k.env).value(`netcheck-not-a-secret-${k.env}`).placeholder(k.placeholder).allow(k.host.value));
        }
        return n;
      })
      .create();
    const curl = async (url: string, env?: string) => {
      const cmd = `curl -sS -o /dev/null -m 15 -w '%{http_code}' ${env ? `-H "x-netcheck: $${env}" ` : ""}'${url}' 2>&1; true`;
      const out = await vm.exec("sh", ["-c", cmd]);
      return `${out.stdout()}${out.stderr()}`.trim().replace(/\s+/g, " ");
    };
    const url = (e: AllowEntry) => `https://${hostOf(e)}/`;
    for (const e of probe) {
      const got = await curl(url(e));
      rows.push({ check: "allowed host answers", host: hostOf(e), result: got, ok: (got.match(/(\d{3})$/)?.[1] ?? "000") !== "000" });
    }
    for (const e of entries.filter((x) => x.kind !== "domain" || x.loopback)) {
      rows.push({ check: "allowed entry (not probed: a suffix, an address or the host gateway)", host: hostOf(e), result: "—", ok: true });
    }
    const denied = await curl(`https://${canary}/`);
    rows.push({ check: "a host outside the list is refused", host: canary, result: denied, ok: /000$/.test(denied) });
    if (keys.length === 2) {
      const own = await curl(url(keys[0].host), keys[0].env);
      rows.push({ check: `a placeholder goes to its own host (${keys[0].host.value}) and is swapped there`, host: hostOf(keys[0].host), result: own, ok: !/000$/.test(own) });
      const leak = await curl(url(keys[1].host), keys[0].env);
      rows.push({ check: `${keys[0].host.value}'s placeholder is stopped on its way to ${keys[1].host.value}`, host: hostOf(keys[1].host), result: leak, ok: /000$/.test(leak) });
    } else {
      rows.push({ check: "a placeholder is stopped on its way to another secret's host (needs two host names)", host: "—", result: "not checked", ok: true });
    }
  } catch (err) {
    rows.push({ check: "the check VM", host: image, result: err instanceof Error ? err.message : String(err), ok: false });
  } finally {
    release();
    await run(msbBinary(), ["stop", name], { timeoutMs: 120_000 });
    await run(msbBinary(), ["rm", name], { timeoutMs: 60_000 });
  }
  return { ok: rows.every((r) => r.ok), rows };
}

/** The manifest digest of the image a VM was made from, from msb's own record of it. */
export async function imageDigest(name: string): Promise<string | null> {
  const r = await run(msbBinary(), ["inspect", name, "--format", "json"], { timeoutMs: 30_000 });
  if (r.code !== 0) return null;
  try {
    return (JSON.parse(r.stdout) as { config?: { manifest_digest?: string } }).config?.manifest_digest ?? null;
  } catch {
    return null;
  }
}

/** Can this host run a VM at all, and is the image here? */
/** An image's digest as msb holds it locally, or null when msb does not have it. */
export async function imageRefDigest(ref: string): Promise<string | null> {
  const r = await run(msbBinary(), ["image", "inspect", ref, "--format", "json"], { timeoutMs: 30_000 });
  if (r.code !== 0) return null;
  try {
    const d = (JSON.parse(r.stdout) as { digest?: string }).digest;
    return typeof d === "string" && /^sha256:[0-9a-f]{64}$/.test(d) ? d : null;
  } catch {
    return null;
  }
}

/** What this host can give the agents' VMs: its memory and its cores. */
export function hostCapacity(): { mem_mib: number; cpus: number } {
  return { mem_mib: Math.floor(totalmem() / 1048576), cpus: availableParallelism() };
}

/**
 * Whether N VMs of a size fit this host. Memory is the hard limit (a VM's
 * memory is the host's, and a host out of it kills something); vCPUs are
 * shared, so only a count far past the cores is refused.
 */
export function capacityVerdict(n: number, cpusEach: number, memEach: number, host: { mem_mib: number; cpus: number }): { blockers: string[]; warnings: string[] } {
  const blockers: string[] = [];
  const warnings: string[] = [];
  const mem = n * memEach;
  if (mem > host.mem_mib * 0.85) blockers.push(`${n} VMs of ${memEach} MiB need ${mem} MiB, and this host has ${host.mem_mib} MiB: lower --vm-memory or --n`);
  else if (mem > host.mem_mib * 0.6) warnings.push(`${n} VMs of ${memEach} MiB take ${mem} of this host's ${host.mem_mib} MiB; whatever else it runs shares the rest`);
  const cpus = n * cpusEach;
  if (cpus > host.cpus * 4) blockers.push(`${n} VMs of ${cpusEach} vCPU are ${cpus} vCPUs on ${host.cpus} cores: lower --vm-cpus or --n`);
  else if (cpus > host.cpus) warnings.push(`${cpus} vCPUs on ${host.cpus} cores: the agents' tools will share them`);
  return { blockers, warnings };
}

export async function probeHost(image?: string): Promise<{ ok: boolean; msb: string; version: string; reasons: string[]; image_present?: boolean; image_digest?: string | null; doctor_output?: string; host?: { mem_mib: number; cpus: number } }>{
  const msb = msbBinary();
  const reasons: string[] = [];
  const platform = vmPlatformProblem();
  if (platform) return { ok: false, msb, version: "", reasons: [platform] };
  // An optional dependency: a host-only install (npm ci --omit=optional) has none.
  try {
    createRequire(import.meta.url).resolve("microsandbox");
  } catch {
    return { ok: false, msb, version: "", reasons: ["the microsandbox package is not installed (it is optional: run npm ci without --omit=optional)"] };
  }
  const v = await run(msb, ["--version"], { timeoutMs: 20_000 });
  if (v.code !== 0) return { ok: false, msb, version: "", reasons: [`msb does not run: ${v.stderr.trim() || v.code}`] };
  const doctor = await run(msb, ["doctor"], { timeoutMs: 60_000 });
  // The whole of what doctor said goes back with the refusal: its last lines
  // were once all an operator saw, and the check that failed was above them.
  let doctor_output: string | undefined;
  if (doctor.code !== 0) {
    doctor_output = `${doctor.stdout}${doctor.stderr}`.trim();
    reasons.push(`msb doctor failed (exit ${doctor.code}); its whole output follows`);
  }
  let image_present: boolean | undefined;
  let image_digest: string | null | undefined;
  if (image) {
    image_digest = await imageRefDigest(image);
    image_present = image_digest !== null;
  }
  return { ok: reasons.length === 0, msb, version: v.stdout.trim(), reasons, ...(image !== undefined ? { image_present, image_digest } : {}), ...(doctor_output !== undefined ? { doctor_output } : {}), host: hostCapacity() };
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  const opt = (name: string) => {
    const i = rest.indexOf(name);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  switch (cmd) {
    case "msb-path":
      console.log(msbBinary());
      return;
    case "image-digest": {
      // An image's digest as msb holds it here, or null: read only.
      const image = opt("--image");
      if (!image) throw new Error("image-digest needs --image REF");
      console.log(JSON.stringify({ image, digest: await imageRefDigest(image) }));
      process.exit(0);
    }
    case "netcheck": {
      const image = opt("--image");
      if (!image) throw new Error("netcheck needs --image REF [--allow-host H]... [--canary HOST]");
      const hosts: string[] = [];
      rest.forEach((a, i) => {
        if (a === "--allow-host" && rest[i + 1]) hosts.push(...rest[i + 1].split(",").filter(Boolean));
      });
      const r = await netCheck(image, hosts, { canary: opt("--canary") });
      for (const row of r.rows) console.log(`${row.ok ? "ok  " : "FAIL"}  ${row.check}: ${row.host} -> ${row.result}`);
      process.exit(r.ok ? 0 : 1);
    }
    case "capacity": {
      // n cpus-each mem-each: the kickoff's question, answered with this host's numbers.
      const [n, cpus, mem] = [opt("--n"), opt("--cpus"), opt("--memory")].map((v) => Number(v));
      const verdict = capacityVerdict(n, cpus, mem, hostCapacity());
      console.log(JSON.stringify({ ok: verdict.blockers.length === 0, host: hostCapacity(), ...verdict }));
      process.exit(verdict.blockers.length ? 2 : 0);
    }
    case "check-allow": {
      // The kickoff asks before anything is written: every --allow-host and
      // provider host, as the VM's policy will read it.
      const bad: string[] = [];
      for (const h of rest.flatMap((a) => a.split(",")).filter((a) => a.trim())) {
        try {
          parseAllowEntry(h);
        } catch (err) {
          bad.push(err instanceof Error ? err.message : String(err));
        }
      }
      console.log(JSON.stringify({ ok: bad.length === 0, refused: bad }));
      process.exit(bad.length ? 2 : 0);
    }
    case "pull": {
      // Before the run's clock starts, and loud about it: a multi-gigabyte
      // image pulled by N VMs at once used to eat the first minutes of the
      // wall clock in silence.
      const image = opt("--image");
      if (!image) throw new Error("pull needs --image REF");
      const r = await new Promise<number>((done) => {
        const child = spawn(msbBinary(), ["pull", image], { stdio: ["ignore", 2, 2] });
        child.on("close", (code) => done(code ?? 1));
        child.on("error", () => done(1));
      });
      const digest = r === 0 ? await imageRefDigest(image) : null;
      console.log(JSON.stringify({ ok: r === 0 && digest !== null, digest }));
      process.exit(r === 0 && digest ? 0 : 1);
    }
    case "probe": {
      const r = await probeHost(opt("--image"));
      console.log(JSON.stringify(r));
      process.exit(r.ok ? 0 : 1);
    }
    case "gateway-plan": {
      // The model gateway's config for a run, from its VM spec: which of the
      // team's providers it fronts (and which it leaves to msb, and why),
      // each seat's gateway token, the prices. Written 0600 by rename; the
      // declined list is what is printed.
      const file = opt("--spec");
      const out = opt("--out");
      if (!file || !out) throw new Error("gateway-plan needs --spec FILE --out FILE");
      const spec = JSON.parse(await readFile(file, "utf8")) as VmSpec;
      const planned = planGateway({
        run: spec.run,
        sandbox: spec.sandbox,
        providers: spec.providers.map((p) => ({ provider: p.provider, kind: p.kind })),
        seats: spec.agents.map((a) => ({ id: a.id, model: a.model, providers: seatProviders(spec, a).filter((p) => p.kind !== "local").map((p) => p.provider) })),
        piAgentDir: spec.pi_agent_dir,
        piBin: spec.pi_bin,
      });
      const tmp = `${out}.tmp.${process.pid}`;
      await writeFile(tmp, `${JSON.stringify(planned.config, null, 2)}\n`, { mode: 0o600 });
      await rename(tmp, out);
      console.log(JSON.stringify({ declined: planned.declined, providers: Object.keys(planned.config.providers) }));
      process.exit(0);
    }
    case "create": {
      const file = opt("--spec");
      if (!file) throw new Error("create needs --spec FILE");
      const spec = JSON.parse(await readFile(file, "utf8")) as VmSpec;
      let result;
      try {
        result = await createVms(spec);
      } catch (err) {
        console.log(JSON.stringify({ ok: false, error: err instanceof Error ? err.message : String(err) }));
        process.exit(1);
      }
      console.log(JSON.stringify({ ok: result.failures.length === 0, vms: result.records.map((r) => ({ agent: r.agent, name: r.name, digest: r.image.manifest_digest })), failures: result.failures, warnings: result.warnings }));
      process.exit(result.failures.length ? 1 : 0);
    }
    case "finish": {
      const runId = opt("--run");
      const sandbox = opt("--sandbox");
      if (!runId || !sandbox) throw new Error("finish needs --run ID --sandbox DIR");
      const out = await finishRun(runId, resolve(sandbox), { snapshot: !rest.includes("--no-snapshot"), agent: opt("--agent"), registry: opt("--registry") });
      const ok = out.every((o) => !o.error);
      console.log(JSON.stringify({ ok, vms: out }));
      process.exit(ok ? 0 : 1);
    }
    case "toolbox": {
      const image = opt("--image");
      const preset = opt("--preset") ?? "dfir";
      const out = opt("--out");
      if (!image || !out) throw new Error("toolbox needs --image REF --out FILE [--preset SETS] [--packs DIR:DIR] [--required]");
      const r = await imageToolbox(image, preset, rest.includes("--required"), (opt("--packs") ?? "").split(":"));
      if (r.json) await writeFile(out, r.json);
      // The script names the file at its guest path; the operator reads the host's.
      process.stderr.write(r.output.replaceAll("/tb/sbx/toolbox.json", out));
      process.exit(r.json ? r.code : 1);
    }
    case "catalog": {
      const image = opt("--image");
      const sandbox = opt("--sandbox");
      if (!image || !sandbox) throw new Error("catalog needs --image REF --sandbox DIR [--evidence DIR]... [--allow-host H]... [--open-net] [--memory MIB] [--cpus N] [--run ID] [--registry FILE]");
      const evidence: string[] = [];
      const allowHosts: string[] = [];
      rest.forEach((a, i) => {
        if (a === "--evidence" && rest[i + 1]) evidence.push(rest[i + 1]);
        if (a === "--allow-host" && rest[i + 1]) allowHosts.push(...rest[i + 1].split(",").filter(Boolean));
      });
      const r = await imageCatalog(image, resolve(sandbox), evidence, {
        memoryMib: opt("--memory") ? Number(opt("--memory")) : undefined,
        cpus: opt("--cpus") ? Number(opt("--cpus")) : undefined,
        allowHosts,
        openNet: rest.includes("--open-net"),
        run: opt("--run"),
        registry: opt("--registry"),
      });
      process.stdout.write(r.output);
      // What the catalog was built with, beside it: the image it booted and
      // the sha256 of every file it wrote, so a catalog cannot be changed
      // after the fact without it showing.
      await writeCatalogRecord(resolve(sandbox), image, r.digest ?? null).catch((err: Error) => process.stderr.write(`catalog record: ${err.message}\n`));
      process.exit(r.code);
    }
    case "list": {
      try {
        console.log(JSON.stringify({ ok: true, vms: await runVms(opt("--run")) }));
      } catch (err) {
        console.log(JSON.stringify({ ok: false, error: (err as Error).message }));
        process.exit(1);
      }
      return;
    }
    case "reap": {
      const removed = await reapVms({ run: opt("--run"), registry: opt("--registry"), only: opt("--only") });
      console.log(JSON.stringify({ ok: true, removed }));
      return;
    }
    default:
      console.error("usage: vm.ts probe|pull|create|finish|reap|toolbox|catalog|netcheck|check-allow|msb-path (see the header)");
      process.exit(2);
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((err) => {
    console.error(`vm: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}

export { ROOT };
