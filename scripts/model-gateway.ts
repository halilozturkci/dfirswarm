#!/usr/bin/env node
/**
 * The model gateway (`--model-gateway`): every model call a seat's VM makes
 * goes through this process on the host, which meters it and holds the key.
 *
 * Without it a VM run has two limits ADR 0009 names. Spend is what each seat
 * reports about itself: Pi in the guest counts its own usage, and the hub
 * folds the report into budget.json. And the budget check before a call is
 * the guest's own code, under the guest's root. The gateway moves both to
 * the host: the usage is read off the provider's own answer as it passes
 * through, and a call past a cap is refused before it leaves the host.
 *
 * **What the guest sees.** Its Pi is pointed here by `models.json`, which can
 * override a built-in provider's `baseUrl` and `apiKey` without redefining
 * its models (Pi's provider-composer.js `applyModelsJson`; docs/models.md
 * "Overriding Built-in Providers"). The base URL keeps the provider's own
 * host in its path, `http://host.microsandbox.internal:<port>/p/openai/
 * api.openai.com/v1`, because Pi decides some request fields from the base
 * URL's text (`baseUrl.includes("api.openai.com")` for OpenAI's prompt-cache
 * key, `openrouter.ai` for OpenRouter's dialect, and a dozen more in
 * openai-completions.js `detectCompat`). The key is this seat's gateway
 * token, which is worth nothing anywhere but here.
 *
 * **Who is asking is the token.** Each seat has its own, and the gateway
 * takes the seat from the token alone: no header, path or body a guest
 * writes can name another seat. The token is stripped before the call leaves,
 * and the provider's key is set in the header the provider reads.
 *
 * **No open proxy.** A route is `/p/<provider>/<host><base path>/<endpoint>`,
 * the host must be the provider's configured upstream, and the endpoint one
 * of the few a model client calls (chat completions, responses, messages,
 * token counting, the model list). Anything else is a 404 and never leaves.
 *
 * **Nothing of a call is kept but its numbers.** The log line of a call is
 * the seat, the model, the status, the tokens and the cost. No request or
 * response body is written anywhere.
 *
 *   node --experimental-strip-types scripts/model-gateway.ts --config FILE
 *        [--port N] [--ready FILE] [--quiet]
 *
 * The config (JSON, 0600, in the run's hub directory where no VM reaches) is
 * written by the kickoff from `planGateway()`. It holds each seat's token and
 * each provider's upstream, never a key: the keys are resolved here, at
 * start, by Pi's own `pi auth print-api-key`, and held in this process's
 * memory only. A restart (the keeper's) reads the same config and the saved
 * totals, and binds the same port, which the VMs were given at boot.
 */
import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { request as httpRequest, createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The APIs the gateway can front: the ones whose usage it can read and whose key it can set. */
export type GatewayApi = "openai-completions" | "openai-responses" | "azure-openai-responses" | "anthropic-messages";

export type GatewayProvider = {
  /** `https://api.openai.com`: scheme, host and port, no path. */
  upstream: string;
  /** The provider's base URL path, `/v1`, or "" for Anthropic's SDK, which adds `/v1` itself. */
  base_path: string;
  api: GatewayApi;
  /** Where the provider reads its key: `authorization` (with `Bearer `), `x-api-key`, or `api-key`. */
  auth_header: "authorization" | "x-api-key" | "api-key";
  /** Where the key comes from: Pi's store on the host, or (tests) an environment variable. */
  key: { source: "pi"; provider: string } | { source: "env"; name: string };
};

export type GatewaySeat = {
  token: string;
  /** The seat's model, `provider/id`: its model's cap is summed over the seats that run it. */
  model: string;
  /** The providers this seat may call: its model's and the summary model's. */
  providers: string[];
};

export type GatewayLimits = {
  /** A request body larger than this is refused (413): a model request with a long context and images fits well under it. */
  max_body_bytes: number;
  /** Calls in flight at once, per seat. */
  max_concurrent: number;
  /** A token bucket per seat: this many at once, refilled at `rate_per_minute`. */
  burst: number;
  rate_per_minute: number;
  /** A call that sends nothing for this long is cut. */
  upstream_idle_ms: number;
  /**
   * How long past a cap or the wall clock a seat may still call: the
   * harness's own grace (protocol.ts STOP_GRACE_MS, two minutes, in which a
   * steered agent posts its findings) and a minute more. The harness's stop
   * itself (a seat's done marker, the sentinel) is refused at once.
   */
  cap_grace_ms: number;
  /** Refusals logged per seat and reason a minute; the rest are counted. */
  refusal_log_per_minute: number;
};

export type GatewayConfig = {
  v: 1;
  run: string;
  sandbox: string;
  host?: string;
  port?: number;
  seats: Record<string, GatewaySeat>;
  providers: Record<string, GatewayProvider>;
  /** Per-model prices (USD per million tokens), `provider/id` → cost, when the kickoff read them; the catalogue otherwise. */
  prices?: Record<string, ModelCost>;
  pi_bin?: string;
  pi_agent_dir?: string;
  limits?: Partial<GatewayLimits>;
};

export type ModelCost = {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  tiers?: Array<{ inputTokensAbove: number; input: number; output: number; cacheRead: number; cacheWrite: number }>;
};

export type CallUsage = { input: number; output: number; cacheRead: number; cacheWrite: number; cacheWrite1h: number };

export type SeatTotals = {
  calls: number;
  refused: number;
  input: number;
  output: number;
  cache_read: number;
  cache_write: number;
  spent_usd: number;
  /** Calls whose cost could not be priced (a model the catalogue does not list) or whose usage the provider did not report. */
  unpriced_calls: number;
  model?: string;
};

export type GatewayState = {
  v: 1;
  run: string;
  seats: Record<string, SeatTotals>;
  spent_usd: number;
  updated_at: string;
  /** When each cap was first seen crossed (`run_cap`, `seat_cap:<id>`, `model_cap:<model>`, `run_token_cap`), for the grace. */
  crossed?: Record<string, string>;
};

export const DEFAULT_LIMITS: GatewayLimits = {
  max_body_bytes: 32 * 1024 * 1024,
  max_concurrent: 4,
  burst: 20,
  rate_per_minute: 60,
  upstream_idle_ms: 10 * 60_000,
  cap_grace_ms: 3 * 60_000,
  refusal_log_per_minute: 20,
};

/** The gateway's files, beside the trace: `traces/` is read-only to every VM. */
export const GATEWAY_LOG_REL = "traces/model-gateway.jsonl";
export const GATEWAY_STATE_REL = "traces/model-gateway.json";

/** The trace events the gateway writes (reserved: no agent tool may take these names). */
export const GATEWAY_EVENTS = ["model_gateway_refused", "model_gateway_started", "model_gateway_upstream_error"] as const;

/**
 * The endpoints a model client calls, by API. The route's path after the
 * base path must be one of these, method included.
 */
const ENDPOINTS: Record<GatewayApi, Array<{ method: string; path: string; metered: boolean }>> = {
  "openai-completions": [
    { method: "POST", path: "/chat/completions", metered: true },
    { method: "GET", path: "/models", metered: false },
  ],
  "openai-responses": [
    { method: "POST", path: "/responses", metered: true },
    { method: "POST", path: "/chat/completions", metered: true },
    { method: "GET", path: "/models", metered: false },
  ],
  "azure-openai-responses": [{ method: "POST", path: "/responses", metered: true }],
  "anthropic-messages": [
    { method: "POST", path: "/v1/messages", metered: true },
    { method: "POST", path: "/v1/messages/count_tokens", metered: false },
    { method: "GET", path: "/v1/models", metered: false },
  ],
};

/** Every header a guest may carry its seat token in: the ones Pi's clients set a key in. */
const TOKEN_HEADERS = ["authorization", "x-api-key", "api-key", "x-goog-api-key"];

/** Never forwarded either way: hop-by-hop, the guest's credentials, cookies. */
const DROP_REQUEST_HEADERS = new Set([
  "host", "connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te", "trailer",
  "transfer-encoding", "upgrade", "content-length", "accept-encoding", "cookie", "forwarded", "x-forwarded-for",
  "x-forwarded-host", "x-forwarded-proto", "x-real-ip", ...TOKEN_HEADERS,
  // Which organisation or project a multi-org key bills is the key holder's
  // choice, not the guest's.
  "openai-organization", "openai-project",
]);
const DROP_RESPONSE_HEADERS = new Set(["connection", "keep-alive", "transfer-encoding", "upgrade", "set-cookie", "proxy-authenticate", "trailer"]);

// ---------------------------------------------------------------------------
// Planning: what the kickoff builds the config and each guest's models.json from.
// ---------------------------------------------------------------------------

const API_AUTH: Record<GatewayApi, GatewayProvider["auth_header"]> = {
  "openai-completions": "authorization",
  "openai-responses": "authorization",
  "azure-openai-responses": "api-key",
  "anthropic-messages": "x-api-key",
};

/** Pi's model catalogue: one JSON file per built-in provider, each model with its API, base URL and price. */
export function catalogDirs(repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")): string[] {
  const rel = join("node_modules", "@earendil-works", "pi-coding-agent", "node_modules", "@earendil-works", "pi-ai", "dist", "providers", "data");
  const alt = join("node_modules", "@earendil-works", "pi-ai", "dist", "providers", "data");
  return [join(repoRoot, rel), join(repoRoot, alt)].filter((d) => existsSync(d));
}

type CatalogModel = { id: string; api?: string; baseUrl?: string; cost?: ModelCost; type?: string };

/** A provider's models from Pi's catalogue, or from the operator's models.json for a custom provider. */
export function catalogModels(provider: string, options: { dirs?: string[]; piAgentDir?: string } = {}): CatalogModel[] {
  const out: CatalogModel[] = [];
  for (const dir of options.dirs ?? catalogDirs()) {
    const file = join(dir, `${provider}.json`);
    if (!/^[a-z0-9][a-z0-9._-]*$/i.test(provider) || !existsSync(file)) continue;
    try {
      const data = JSON.parse(readFileSync(file, "utf8")) as Record<string, Record<string, CatalogModel>>;
      for (const group of Object.values(data)) {
        if (!group || typeof group !== "object") continue;
        // Since Pi 1.4 a provider's file also lists image and classifier models (`image:<id>`,
        // `classifier:<id>`); a seat's calls are chat calls, so only chat models (typed or not) count.
        for (const [id, m] of Object.entries(group)) {
          if (!m || typeof m !== "object" || (m.type !== undefined && m.type !== "chat")) continue;
          out.push({ ...m, id: m.id ?? id.replace(/^chat:/, "") });
        }
      }
    } catch {
      // a file Pi cannot read either
    }
    break;
  }
  if (options.piAgentDir) {
    try {
      const custom = (JSON.parse(readFileSync(join(options.piAgentDir, "models.json"), "utf8")) as { providers?: Record<string, { baseUrl?: string; api?: string; models?: CatalogModel[] }> }).providers?.[provider];
      for (const m of custom?.models ?? []) {
        const i = out.findIndex((o) => o.id === m.id);
        const merged = { ...(i >= 0 ? out[i] : {}), ...m, api: m.api ?? custom?.api ?? (i >= 0 ? out[i].api : undefined), baseUrl: m.baseUrl ?? custom?.baseUrl ?? (i >= 0 ? out[i].baseUrl : undefined) };
        if (i >= 0) out[i] = merged;
        else out.push(merged);
      }
      if (custom?.baseUrl) for (const m of out) if (!custom.models?.some((c) => c.id === m.id)) m.baseUrl = custom.baseUrl;
    } catch {
      // no operator models.json, or not this provider
    }
  }
  return out;
}

/**
 * Whether a provider can be fronted, and how: its upstream origin and base
 * path, its API and the header its key goes in. A provider the gateway
 * cannot front is left to msb's placeholder path, and said so: a
 * subscription (the guest's Pi decides the request's shape from the token's
 * own text, which a gateway token does not carry), a provider signed per
 * request (Bedrock, Vertex), an API whose usage the gateway does not read,
 * a local server (nothing to hold, and nothing billed), or a provider whose
 * models do not share one base URL.
 */
export function gatewayProviderFor(
  provider: string,
  kind: "api_key" | "oauth" | "local",
  options: { dirs?: string[]; piAgentDir?: string } = {},
): { ok: true; spec: GatewayProvider } | { ok: false; reason: string } {
  if (kind === "oauth") return { ok: false, reason: "a subscription: the guest's Pi shapes the request from the token itself" };
  if (kind === "local") return { ok: false, reason: "a local server: no key to hold and nothing billed" };
  const models = catalogModels(provider, options);
  if (!models.length) return { ok: false, reason: "not in Pi's catalogue or the operator's models.json" };
  const apis = new Set(models.map((m) => m.api).filter(Boolean));
  const bases = new Set(models.map((m) => m.baseUrl).filter(Boolean));
  if ([...apis].some((a) => a === "bedrock-converse-stream" || a === "google-vertex")) return { ok: false, reason: "it signs each request (AWS or Google credentials), which the gateway does not do" };
  if (apis.size === 1 && bases.size === 0) return { ok: false, reason: "its base URL is the operator's to set (an Azure resource), which the gateway does not read" };
  if (apis.size !== 1 || bases.size !== 1) return { ok: false, reason: `its models do not share one API and one base URL (${[...apis].join(", ") || "none"}; ${bases.size} base URLs)` };
  const api = [...apis][0] as string;
  if (!(api in API_AUTH)) return { ok: false, reason: `API ${api}: the gateway does not read its usage` };
  let url: URL;
  try {
    url = new URL([...bases][0] as string);
  } catch {
    return { ok: false, reason: "its base URL does not parse" };
  }
  if (/[{}]/.test(url.href) || /%7B|%7D/i.test(url.href)) return { ok: false, reason: "its base URL has a part only the operator fills in" };
  if (url.protocol !== "https:" && !isLoopbackHost(url.hostname)) return { ok: false, reason: "its base URL is not HTTPS" };
  return {
    ok: true,
    spec: {
      upstream: url.origin,
      base_path: url.pathname.replace(/\/+$/, ""),
      api: api as GatewayApi,
      auth_header: API_AUTH[api as GatewayApi],
      key: { source: "pi", provider },
    },
  };
}

/** One random token per seat, for the config and the seat's own guest config. */
export function seatToken(): string {
  return randomBytes(24).toString("hex");
}

/**
 * The gateway's config for a run, from the providers and seats the kickoff
 * resolved. `declined` names each provider left to msb's path and why.
 */
export function planGateway(input: {
  run: string;
  sandbox: string;
  providers: Array<{ provider: string; kind: "api_key" | "oauth" | "local" }>;
  seats: Array<{ id: string; model: string; providers: string[] }>;
  piAgentDir?: string;
  piBin?: string;
  dirs?: string[];
  port?: number;
}): { config: GatewayConfig; declined: Array<{ provider: string; reason: string }> } {
  const providers: Record<string, GatewayProvider> = {};
  const declined: Array<{ provider: string; reason: string }> = [];
  const prices: Record<string, ModelCost> = {};
  for (const p of input.providers) {
    const r = gatewayProviderFor(p.provider, p.kind, { dirs: input.dirs, piAgentDir: input.piAgentDir });
    if (!r.ok) {
      declined.push({ provider: p.provider, reason: r.reason });
      continue;
    }
    providers[p.provider] = r.spec;
    for (const m of catalogModels(p.provider, { dirs: input.dirs, piAgentDir: input.piAgentDir })) if (m.cost) prices[`${p.provider}/${m.id}`] = m.cost;
  }
  const seats: Record<string, GatewaySeat> = {};
  for (const s of input.seats) seats[s.id] = { token: seatToken(), model: s.model, providers: s.providers.filter((p) => p in providers) };
  return {
    config: {
      v: 1,
      run: input.run,
      sandbox: input.sandbox,
      host: "127.0.0.1",
      ...(input.port ? { port: input.port } : {}),
      seats,
      providers,
      prices,
      ...(input.piBin ? { pi_bin: input.piBin } : {}),
      ...(input.piAgentDir ? { pi_agent_dir: input.piAgentDir } : {}),
    },
    declined,
  };
}

/** Where a guest reaches the gateway: msb's name for the host, and the gateway's port. */
export const GUEST_GATEWAY_HOST = "host.microsandbox.internal";

/** The base URL a guest's Pi calls for one provider: the upstream's host and base path, under the gateway. */
export function guestBaseUrl(port: number, provider: string, spec: GatewayProvider, host = GUEST_GATEWAY_HOST): string {
  const up = new URL(spec.upstream);
  return `http://${host}:${port}/p/${provider}/${up.host}${spec.base_path}`;
}

/**
 * The `providers` block of one seat's guest models.json: each fronted
 * provider's base URL pointed here and its key the seat's token. Nothing
 * in it is a credential of the provider's. The guest's auth.json must not
 * hold these providers: a stored credential wins over models.json's apiKey
 * in Pi (provider-composer.js `composeApiKeyAuth`).
 */
export function guestProviders(config: GatewayConfig, seatId: string, port: number, host = GUEST_GATEWAY_HOST): Record<string, { baseUrl: string; apiKey: string }> {
  const seat = config.seats[seatId];
  if (!seat) throw new Error(`no seat ${seatId} in the gateway's config`);
  const out: Record<string, { baseUrl: string; apiKey: string }> = {};
  for (const provider of seat.providers) {
    const spec = config.providers[provider];
    if (spec) out[provider] = { baseUrl: guestBaseUrl(port, provider, spec, host), apiKey: seat.token };
  }
  return out;
}

// ---------------------------------------------------------------------------
// Usage: read off the provider's own answer, the way Pi reads it.
// ---------------------------------------------------------------------------

function num(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/** OpenAI chat completions `usage`, as pi-ai openai-completions.js `parseChunkUsage` reads it. */
export function openaiChatUsage(raw: Record<string, unknown>): CallUsage {
  const details = (raw.prompt_tokens_details ?? {}) as Record<string, unknown>;
  const cacheRead = num(details.cached_tokens ?? raw.prompt_cache_hit_tokens ?? raw.cached_tokens);
  const cacheWrite = num(details.cache_write_tokens);
  const input = Math.max(0, num(raw.prompt_tokens) - cacheRead - cacheWrite);
  return { input, output: num(raw.completion_tokens), cacheRead, cacheWrite, cacheWrite1h: 0 };
}

/** OpenAI responses `usage`, as pi-ai openai-responses-shared.js reads it. */
export function openaiResponsesUsage(raw: Record<string, unknown>): CallUsage {
  const details = (raw.input_tokens_details ?? {}) as Record<string, unknown>;
  const cacheRead = num(details.cached_tokens);
  const cacheWrite = num(details.cache_write_tokens);
  const input = Math.max(0, num(raw.input_tokens) - cacheRead - cacheWrite);
  return { input, output: num(raw.output_tokens), cacheRead, cacheWrite, cacheWrite1h: 0 };
}

/** Anthropic `usage`, as pi-ai anthropic-messages.js reads `message_start` and a whole message. */
export function anthropicUsage(raw: Record<string, unknown>): CallUsage {
  const creation = (raw.cache_creation ?? {}) as Record<string, unknown>;
  return {
    input: num(raw.input_tokens),
    output: num(raw.output_tokens),
    cacheRead: num(raw.cache_read_input_tokens),
    cacheWrite: num(raw.cache_creation_input_tokens),
    cacheWrite1h: num(creation.ephemeral_1h_input_tokens),
  };
}

/**
 * Reads usage from a response as it streams past, without holding it: an
 * SSE stream event by event (only the event being read is buffered, and one
 * past `maxEvent` is skipped), a JSON body whole up to `maxJson`.
 */
export class UsageReader {
  private api: GatewayApi;
  private sse: boolean;
  private pending = "";
  private skipping = false;
  private json: Buffer[] = [];
  private jsonBytes = 0;
  private jsonOver = false;
  usage: CallUsage | null = null;
  private readonly maxEvent: number;
  private readonly maxJson: number;
  constructor(api: GatewayApi, contentType: string, options: { maxEvent?: number; maxJson?: number } = {}) {
    this.api = api;
    this.sse = /text\/event-stream/i.test(contentType);
    this.maxEvent = options.maxEvent ?? 1024 * 1024;
    this.maxJson = options.maxJson ?? 16 * 1024 * 1024;
  }
  push(chunk: Buffer): void {
    if (!this.sse) {
      if (this.jsonOver) return;
      this.jsonBytes += chunk.length;
      if (this.jsonBytes > this.maxJson) {
        this.jsonOver = true;
        this.json = [];
        return;
      }
      this.json.push(chunk);
      return;
    }
    this.pending += chunk.toString("utf8");
    for (;;) {
      const m = /\r?\n\r?\n/.exec(this.pending);
      if (!m) break;
      const event = this.pending.slice(0, m.index);
      this.pending = this.pending.slice(m.index + m[0].length);
      if (this.skipping) {
        this.skipping = false;
        continue;
      }
      this.event(event);
    }
    if (this.pending.length > this.maxEvent) {
      // An event this long is not a usage event: drop what is held and skip to its end.
      this.pending = "";
      this.skipping = true;
    }
  }
  end(): CallUsage | null {
    if (this.sse) {
      if (this.pending.trim() && !this.skipping) this.event(this.pending);
      this.pending = "";
      return this.usage;
    }
    if (this.jsonOver || !this.json.length) return this.usage;
    try {
      const body = JSON.parse(Buffer.concat(this.json).toString("utf8")) as Record<string, unknown>;
      const raw = body.usage as Record<string, unknown> | undefined;
      if (raw && typeof raw === "object") this.usage = this.fromWhole(raw);
    } catch {
      // not JSON: an error page, say; nothing to meter
    }
    this.json = [];
    return this.usage;
  }
  private fromWhole(raw: Record<string, unknown>): CallUsage {
    if (this.api === "anthropic-messages") return anthropicUsage(raw);
    if ("input_tokens" in raw || "output_tokens" in raw) return openaiResponsesUsage(raw);
    return openaiChatUsage(raw);
  }
  private event(text: string): void {
    let data = "";
    for (const line of text.split(/\r?\n/)) if (line.startsWith("data:")) data += line.slice(5).replace(/^ /, "");
    if (!data || data === "[DONE]") return;
    let e: Record<string, unknown>;
    try {
      e = JSON.parse(data) as Record<string, unknown>;
    } catch {
      return;
    }
    if (this.api === "anthropic-messages") {
      if (e.type === "message_start") {
        const u = ((e.message ?? {}) as Record<string, unknown>).usage as Record<string, unknown> | undefined;
        if (u) this.usage = anthropicUsage(u);
      } else if (e.type === "message_delta" && e.usage && typeof e.usage === "object") {
        // Only the fields present are updated; output_tokens is the running total.
        const u = e.usage as Record<string, unknown>;
        const was = this.usage ?? { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cacheWrite1h: 0 };
        this.usage = {
          input: u.input_tokens != null ? num(u.input_tokens) : was.input,
          output: u.output_tokens != null ? num(u.output_tokens) : was.output,
          cacheRead: u.cache_read_input_tokens != null ? num(u.cache_read_input_tokens) : was.cacheRead,
          cacheWrite: u.cache_creation_input_tokens != null ? num(u.cache_creation_input_tokens) : was.cacheWrite,
          cacheWrite1h: was.cacheWrite1h,
        };
      }
      return;
    }
    // OpenAI responses: the finished response carries the usage.
    const response = e.response as Record<string, unknown> | undefined;
    if (response && typeof response === "object" && response.usage && typeof response.usage === "object") {
      this.usage = openaiResponsesUsage(response.usage as Record<string, unknown>);
      return;
    }
    // OpenAI chat completions: the usage chunk (stream_options.include_usage,
    // which Pi sets), or a choice's own usage (Moonshot), the way Pi reads it.
    if (e.usage && typeof e.usage === "object") {
      this.usage = openaiChatUsage(e.usage as Record<string, unknown>);
      return;
    }
    const choice = Array.isArray(e.choices) ? (e.choices[0] as Record<string, unknown> | undefined) : undefined;
    if (choice?.usage && typeof choice.usage === "object") this.usage = openaiChatUsage(choice.usage as Record<string, unknown>);
  }
}

/** A call's cost in USD, as pi-ai models.js `calculateCost` prices it (tiers, the 1h cache write). */
export function priceUsage(cost: ModelCost, usage: CallUsage): number {
  const inputTokens = usage.input + usage.cacheRead + usage.cacheWrite;
  let rates: { input: number; output: number; cacheRead: number; cacheWrite: number } = cost;
  let matched = -1;
  for (const tier of cost.tiers ?? []) {
    if (inputTokens > tier.inputTokensAbove && tier.inputTokensAbove > matched) {
      rates = tier;
      matched = tier.inputTokensAbove;
    }
  }
  const longWrite = usage.cacheWrite1h;
  const shortWrite = usage.cacheWrite - longWrite;
  const total =
    (rates.input / 1e6) * usage.input +
    (rates.output / 1e6) * usage.output +
    (rates.cacheRead / 1e6) * usage.cacheRead +
    (rates.cacheWrite * shortWrite + rates.input * 2 * longWrite) / 1e6;
  return Number(total.toFixed(8));
}

// ---------------------------------------------------------------------------
// Caps: the run's budget.json, read on every call, and the gateway's own totals.
// ---------------------------------------------------------------------------

type BudgetView = {
  cap_usd: number;
  cap_per_agent_usd: number;
  cap_per_model_usd: Record<string, number>;
  cap_tokens: number;
  metered: boolean;
  wall_clock_minutes: number;
  started_at: string;
  until_solved: boolean;
  /** The pause in force (its time, why, and the end the provider named), and the wall clock across pauses and resumes. */
  paused: string | null;
  paused_reason: string;
  paused_until: string;
  wall_used_ms: number;
  wall_base_at: string;
};

function readBudgetView(sandbox: string): BudgetView | null {
  try {
    const raw = JSON.parse(readFileSync(join(sandbox, "budget.json"), "utf8")) as Record<string, unknown>;
    return {
      cap_usd: num(raw.cap_usd),
      cap_per_agent_usd: num(raw.cap_per_agent_usd),
      cap_per_model_usd: raw.cap_per_model_usd && typeof raw.cap_per_model_usd === "object" ? (raw.cap_per_model_usd as Record<string, number>) : {},
      cap_tokens: num(raw.cap_tokens),
      metered: raw.metered !== false,
      wall_clock_minutes: num(raw.wall_clock_minutes),
      started_at: typeof raw.started_at === "string" ? raw.started_at : "",
      until_solved: raw.until_solved === true || raw.stop_policy === "operator",
      paused: raw.paused && typeof raw.paused === "object" && typeof (raw.paused as { at?: unknown }).at === "string" ? (raw.paused as { at: string }).at : null,
      paused_reason: raw.paused && typeof raw.paused === "object" ? String((raw.paused as { reason?: unknown }).reason ?? "") : "",
      paused_until: raw.paused && typeof raw.paused === "object" && typeof (raw.paused as { until?: unknown }).until === "string" ? (raw.paused as { until: string }).until : "",
      wall_used_ms: num(raw.wall_used_ms),
      wall_base_at: typeof raw.wall_base_at === "string" ? raw.wall_base_at : "",
    };
  } catch {
    return null;
  }
}

/**
 * Why a seat may not call now, or null. The same caps protocol.ts applies to
 * the spend each seat reports (`overCap`, `agentPressure`, `modelPressure`),
 * applied to the spend this process measured; and the stops the harness has
 * already made: the run's sentinel and the seat's done or dead marker, which
 * are refused at once. A cap or the wall clock is refused once it has been
 * crossed for `graceMs`: the harness steers an agent over a cap to post its
 * findings and gives it its grace period to do so, which takes model calls.
 * `state.crossed` records when each cap was first seen crossed. A
 * budget.json that does not read refuses nothing but the sentinel and the
 * markers: the caps are the run's, and are not guessed.
 */
export function refusalFor(
  sandbox: string,
  seatId: string,
  seat: GatewaySeat,
  state: GatewayState,
  now = Date.now(),
  graceMs = DEFAULT_LIMITS.cap_grace_ms,
): { code: string; message: string } | null {
  if (existsSync(join(sandbox, "done", "SWARM_DONE"))) return { code: "run_finished", message: "the run has finished; no more model calls" };
  for (const m of ["done", "dead"]) {
    if (existsSync(join(sandbox, "done", "agents", `${seatId}.${m}`))) return { code: "seat_stopped", message: `seat ${seatId} has been stopped (${m}); no more model calls from it` };
  }
  const b = readBudgetView(sandbox);
  if (!b) return null;
  // A paused run: no call goes out until the pause's cause is gone (the
  // operator's extension at a cap, the harness's try under the provider's
  // limit, the operator's unpause) or the operator stops it. The host holds
  // this brake in a VM run.
  if (b.paused) {
    const until = b.paused_until ? `, which the provider said lifts at ${b.paused_until}` : "";
    if (b.paused_reason === "provider_limit") return { code: "run_paused", message: `the run is paused (since ${b.paused}) for the model provider's limit${until}: no model call goes out until the harness tries again, the operator lifts it (swarm.sh unpause) or stops it` };
    if (b.paused_reason === "operator") return { code: "run_paused", message: `the run is paused (since ${b.paused}) by the operator: no model call goes out until the operator lifts it (swarm.sh unpause) or stops it` };
    return { code: "run_paused", message: `the run is paused (since ${b.paused}): no model call goes out until the operator extends it (swarm.sh extend) or stops it` };
  }
  // An until-solved run has no wall clock and advisory caps: a call is
  // refused only for the stops above, the run's end and a seat's own.
  if (b.until_solved) return null;
  if (b.wall_clock_minutes > 0 && b.started_at) {
    // The wall clock across pauses and resumes, as protocol.ts wallElapsedMs counts it.
    const base = Date.parse(b.wall_base_at || b.started_at);
    const used = b.wall_used_ms + (Number.isFinite(base) ? Math.max(0, now - base) : 0);
    if (used >= b.wall_clock_minutes * 60_000 + graceMs) return { code: "wall_clock", message: `the run's wall clock (${b.wall_clock_minutes} min) and its grace have run out` };
  }
  if (!b.metered) return null;
  const crossed = (state.crossed ??= {});
  const over = (key: string, isOver: boolean, message: string): { code: string; message: string } | null => {
    if (!isOver) {
      delete crossed[key];
      return null;
    }
    crossed[key] ??= new Date(now).toISOString();
    const since = now - Date.parse(crossed[key]);
    return since >= graceMs ? { code: key.split(":")[0], message: `${message}, and its grace has passed` } : null;
  };
  const mine = state.seats[seatId];
  const runTokens = Object.values(state.seats).reduce((a, s) => a + s.input + s.output + s.cache_read + s.cache_write, 0);
  const modelCap = num(b.cap_per_model_usd[seat.model]);
  const modelSpent = Object.values(state.seats).reduce((a, s) => a + (s.model === seat.model ? s.spent_usd : 0), 0);
  return (
    over("run_cap", b.cap_usd > 0 && state.spent_usd >= b.cap_usd, `the run has spent $${state.spent_usd.toFixed(2)} of its $${b.cap_usd} cap`) ??
    over("run_token_cap", b.cap_tokens > 0 && runTokens >= b.cap_tokens, `the run has used ${runTokens} of its ${b.cap_tokens} tokens`) ??
    over(`seat_cap:${seatId}`, b.cap_per_agent_usd > 0 && (mine?.spent_usd ?? 0) >= b.cap_per_agent_usd, `seat ${seatId} has spent $${(mine?.spent_usd ?? 0).toFixed(2)} of its own $${b.cap_per_agent_usd} cap`) ??
    over(`model_cap:${seat.model}`, modelCap > 0 && modelSpent >= modelCap, `${seat.model} has spent $${modelSpent.toFixed(2)} of its $${modelCap} cap across its seats`)
  );
}

// ---------------------------------------------------------------------------
// The server.
// ---------------------------------------------------------------------------

/** An error in the shape the provider's own client reads, so the agent sees the reason as the provider's message. */
export function providerError(api: GatewayApi | null, status: number, code: string, message: string): { status: number; body: string } {
  const text = `dfirswarm model gateway: ${message}`;
  if (api === "anthropic-messages") {
    const type = status === 401 ? "authentication_error" : status === 403 ? "permission_error" : status === 404 ? "not_found_error" : status === 413 ? "request_too_large" : status === 429 ? "rate_limit_error" : "api_error";
    return { status, body: JSON.stringify({ type: "error", error: { type, message: text } }) };
  }
  return { status, body: JSON.stringify({ error: { message: text, type: code, code } }) };
}

function seatOf(config: GatewayConfig, req: IncomingMessage): string | null {
  const offered: string[] = [];
  for (const h of TOKEN_HEADERS) {
    const v = req.headers[h];
    if (typeof v !== "string" || !v) continue;
    offered.push(h === "authorization" ? v.replace(/^Bearer\s+/i, "").trim() : v.trim());
  }
  for (const [id, seat] of Object.entries(config.seats)) {
    const want = Buffer.from(seat.token);
    for (const t of offered) {
      const got = Buffer.from(t);
      if (got.length === want.length && timingSafeEqual(got, want)) return id;
    }
  }
  return null;
}

type Route = { provider: string; spec: GatewayProvider; path: string; metered: boolean };

/** The route a request names, or null: a configured provider, its own upstream host, and one of its API's endpoints. */
export function routeOf(config: GatewayConfig, method: string, rawUrl: string): Route | null {
  // The path is compared as the guest wrote it: no encoded separators, no
  // dot segments, no backslashes. `new URL` would normalise `../` away first.
  const rawPath = rawUrl.split("?")[0];
  if (/%2f|%5c|%2e|\\/i.test(rawPath) || rawPath.split("/").some((s) => s === "." || s === "..")) return null;
  let url: URL;
  try {
    url = new URL(rawUrl, "http://gateway.invalid");
  } catch {
    return null;
  }
  const m = /^\/p\/([a-z0-9][a-z0-9._-]*)\/([^/]+)(\/.*)?$/i.exec(url.pathname);
  if (!m) return null;
  const [, provider, host, rest = ""] = m;
  const spec = config.providers[provider];
  if (!spec) return null;
  if (host.toLowerCase() !== new URL(spec.upstream).host.toLowerCase()) return null;
  if (spec.base_path && !(rest === spec.base_path || rest.startsWith(`${spec.base_path}/`))) return null;
  const endpoint = rest.slice(spec.base_path.length) || "/";
  const hit = ENDPOINTS[spec.api].find((e) => e.method === method && e.path === endpoint);
  if (!hit) return null;
  return { provider, spec, path: `${rest}${url.search}`, metered: hit.metered };
}

function isLoopbackHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h === "::1" || /^127\./.test(h);
}

function emptyTotals(model?: string): SeatTotals {
  return { calls: 0, refused: 0, input: 0, output: 0, cache_read: 0, cache_write: 0, spent_usd: 0, unpriced_calls: 0, ...(model ? { model } : {}) };
}

function writeAtomic(path: string, text: string): void {
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  writeFileSync(tmp, text, { mode: 0o644 });
  renameSync(tmp, path);
}

/** The API key of each fronted provider, resolved on the host: Pi's store, or (tests) the environment. */
export async function resolveKeys(config: GatewayConfig): Promise<Map<string, string>> {
  const keys = new Map<string, string>();
  const env = config.pi_agent_dir ? { ...process.env, PI_CODING_AGENT_DIR: config.pi_agent_dir } : process.env;
  for (const [provider, spec] of Object.entries(config.providers)) {
    if (spec.key.source === "env") {
      const v = process.env[spec.key.name];
      if (!v) throw new Error(`no key for ${provider}: ${spec.key.name} is not set`);
      keys.set(provider, v);
      continue;
    }
    const pi = config.pi_bin || "pi";
    const value = await new Promise<string>((done, fail) => {
      const child = execFile(pi, ["auth", "print-api-key", "--provider", spec.key.source === "pi" ? spec.key.provider : provider], { env, timeout: 60_000 }, (err, stdout, stderr) => {
        if (err || !String(stdout).trim()) fail(new Error(`pi has no key for ${provider}: ${String(stderr).trim() || (err ? err.message : "empty")}`));
        else done(String(stdout).trim());
      });
      child.stdin?.end();
    });
    keys.set(provider, value);
  }
  return keys;
}

export class ModelGateway {
  readonly config: GatewayConfig;
  private readonly keys: Map<string, string>;
  private readonly limits: GatewayLimits;
  private readonly logPath: string;
  private readonly statePath: string;
  private readonly quiet: boolean;
  private readonly traceEmit: ((record: Record<string, unknown>) => void) | null;
  state: GatewayState;
  private lastLogHash: string | null = null;
  private inFlight = new Map<string, number>();
  private buckets = new Map<string, { tokens: number; at: number }>();
  private refusalsThisMinute = new Map<string, { minute: number; count: number }>();
  private priceCache = new Map<string, ModelCost | null>();
  private server: Server | null = null;
  /** For tests and the ready file: the port bound. */
  port = 0;

  constructor(config: GatewayConfig, keys: Map<string, string>, options: { quiet?: boolean; traceEmit?: ((record: Record<string, unknown>) => void) | null } = {}) {
    this.config = config;
    this.keys = keys;
    this.limits = { ...DEFAULT_LIMITS, ...(config.limits ?? {}) };
    this.logPath = join(config.sandbox, GATEWAY_LOG_REL);
    this.statePath = join(config.sandbox, GATEWAY_STATE_REL);
    this.quiet = options.quiet ?? false;
    this.traceEmit = options.traceEmit ?? null;
    mkdirSync(dirname(this.logPath), { recursive: true });
    this.state = this.loadState();
    this.lastLogHash = this.loadLastHash();
  }

  private loadState(): GatewayState {
    try {
      const s = JSON.parse(readFileSync(this.statePath, "utf8")) as GatewayState;
      if (s && s.v === 1 && s.seats && typeof s.seats === "object") return s;
    } catch {
      // a first start
    }
    const seats: Record<string, SeatTotals> = {};
    for (const [id, seat] of Object.entries(this.config.seats)) seats[id] = emptyTotals(seat.model);
    return { v: 1, run: this.config.run, seats, spent_usd: 0, updated_at: new Date().toISOString() };
  }

  private loadLastHash(): string | null {
    try {
      const text = readFileSync(this.logPath, "utf8").trimEnd();
      const last = text.slice(text.lastIndexOf("\n") + 1);
      return last ? createHash("sha256").update(last).digest("hex") : null;
    } catch {
      return null;
    }
  }

  /** One line per call (or refusal), each chained to the one before it. */
  private log(record: Record<string, unknown>): void {
    const line = JSON.stringify({ ...record, prev: this.lastLogHash });
    appendFileSync(this.logPath, `${line}\n`);
    this.lastLogHash = createHash("sha256").update(line).digest("hex");
  }

  private saveState(): void {
    this.state.updated_at = new Date().toISOString();
    writeAtomic(this.statePath, `${JSON.stringify(this.state, null, 2)}\n`);
  }

  private refuse(res: ServerResponse, api: GatewayApi | null, status: number, code: string, message: string, seat: string | null, extra: Record<string, unknown> = {}): void {
    const e = providerError(api, status, code, message);
    res.writeHead(e.status, { "content-type": "application/json" });
    res.end(e.body);
    if (seat && this.state.seats[seat]) {
      this.state.seats[seat].refused += 1;
      this.saveState();
    }
    // A guest in a retry loop, or something without a token knocking, does
    // not grow the log or the trace without bound: the first refusals of a
    // seat and reason each minute are written, the rest counted, and the
    // count is written when the minute turns.
    const key = `${seat ?? "?"}:${code}`;
    const minute = Math.floor(Date.now() / 60_000);
    let seen = this.refusalsThisMinute.get(key);
    if (seen && seen.minute !== minute) {
      if (seen.count > this.limits.refusal_log_per_minute) this.log({ at: new Date().toISOString(), seat, refused: code, suppressed: seen.count - this.limits.refusal_log_per_minute, minute: new Date(seen.minute * 60_000).toISOString() });
      seen = undefined;
    }
    if (!seen) {
      seen = { minute, count: 0 };
      this.refusalsThisMinute.set(key, seen);
      this.traceEmit?.({ tool: "model_gateway_refused", args: { via: "model-gateway", agent: seat, code }, result: { ok: false, status, message } });
    }
    seen.count += 1;
    if (seen.count <= this.limits.refusal_log_per_minute) this.log({ at: new Date().toISOString(), seat, refused: code, status, message, ...extra });
  }

  private take(seat: string): boolean {
    const now = Date.now();
    const b = this.buckets.get(seat) ?? { tokens: this.limits.burst, at: now };
    b.tokens = Math.min(this.limits.burst, b.tokens + ((now - b.at) / 60_000) * this.limits.rate_per_minute);
    b.at = now;
    this.buckets.set(seat, b);
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const started = Date.now();
    const route = routeOf(this.config, req.method ?? "", req.url ?? "");
    const api = route?.spec.api ?? null;
    const seat = seatOf(this.config, req);
    if (!seat) return this.refuse(res, api, 401, "bad_token", "no valid seat token", null, { path_ok: Boolean(route) });
    if (!route) return this.refuse(res, null, 404, "not_a_route", "not a model endpoint this gateway fronts", seat);
    const seatCfg = this.config.seats[seat];
    if (!seatCfg.providers.includes(route.provider)) return this.refuse(res, api, 403, "provider_not_seats", `seat ${seat} does not run a ${route.provider} model`, seat, { provider: route.provider });
    if ((this.inFlight.get(seat) ?? 0) >= this.limits.max_concurrent) return this.refuse(res, api, 429, "concurrency", `more than ${this.limits.max_concurrent} calls at once from seat ${seat}`, seat);
    if (!this.take(seat)) return this.refuse(res, api, 429, "rate", `more than ${this.limits.rate_per_minute} calls a minute from seat ${seat}`, seat);
    this.inFlight.set(seat, (this.inFlight.get(seat) ?? 0) + 1);
    try {
      await this.forward(req, res, seat, seatCfg, route, started);
    } finally {
      this.inFlight.set(seat, Math.max(0, (this.inFlight.get(seat) ?? 1) - 1));
    }
  }

  private readBody(req: IncomingMessage): Promise<Buffer | "too_large" | "aborted"> {
    return new Promise((done) => {
      const declared = Number(req.headers["content-length"]);
      if (Number.isFinite(declared) && declared > this.limits.max_body_bytes) {
        req.resume();
        done("too_large");
        return;
      }
      const parts: Buffer[] = [];
      let bytes = 0;
      let over = false;
      req.on("data", (c: Buffer) => {
        if (over) return;
        bytes += c.length;
        if (bytes > this.limits.max_body_bytes) {
          over = true;
          parts.length = 0;
          return;
        }
        parts.push(c);
      });
      req.on("end", () => done(over ? "too_large" : Buffer.concat(parts)));
      req.on("error", () => done("aborted"));
      req.on("aborted", () => done("aborted"));
    });
  }

  private async forward(req: IncomingMessage, res: ServerResponse, seat: string, seatCfg: GatewaySeat, route: Route, started: number): Promise<void> {
    const api = route.spec.api;
    const body = req.method === "GET" ? Buffer.alloc(0) : await this.readBody(req);
    if (body === "aborted") return;
    if (body === "too_large") return this.refuse(res, api, 413, "body_too_large", `a request body over ${this.limits.max_body_bytes} bytes`, seat);
    let model = "";
    let stream = false;
    if (body.length) {
      try {
        const parsed = JSON.parse(body.toString("utf8")) as { model?: unknown; stream?: unknown };
        if (typeof parsed.model === "string") model = parsed.model;
        stream = parsed.stream === true;
      } catch {
        return this.refuse(res, api, 400, "not_json", "the request body is not JSON", seat);
      }
    }
    if (route.metered) {
      if (!model) return this.refuse(res, api, 400, "no_model", "the request names no model", seat);
      const why = refusalFor(this.config.sandbox, seat, seatCfg, this.state, Date.now(), this.limits.cap_grace_ms);
      if (why) return this.refuse(res, api, 403, why.code, why.message, seat, { model: `${route.provider}/${model}` });
    }
    const key = this.keys.get(route.provider);
    if (!key) return this.refuse(res, api, 502, "no_key", `the gateway holds no key for ${route.provider}`, seat);

    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (v === undefined || DROP_REQUEST_HEADERS.has(k.toLowerCase())) continue;
      headers[k] = Array.isArray(v) ? v.join(", ") : v;
    }
    // Plain bytes, so the usage can be read as they pass; the guest gets them as the provider sent them.
    headers["accept-encoding"] = "identity";
    if (route.spec.auth_header === "authorization") headers.authorization = `Bearer ${key}`;
    else headers[route.spec.auth_header] = key;
    if (body.length) headers["content-length"] = String(body.length);

    const up = new URL(route.spec.upstream);
    const send = up.protocol === "https:" ? httpsRequest : httpRequest;
    await new Promise<void>((done) => {
      const upstream = send(
        { protocol: up.protocol, hostname: up.hostname, port: up.port || (up.protocol === "https:" ? 443 : 80), method: req.method, path: route.path, headers, timeout: this.limits.upstream_idle_ms },
        (answer) => {
          const out: Record<string, string | string[]> = {};
          for (const [k, v] of Object.entries(answer.headers)) if (v !== undefined && !DROP_RESPONSE_HEADERS.has(k.toLowerCase())) out[k] = v;
          res.writeHead(answer.statusCode ?? 502, out);
          const reader = route.metered ? new UsageReader(api, String(answer.headers["content-type"] ?? "")) : null;
          let bytesOut = 0;
          answer.on("data", (c: Buffer) => {
            bytesOut += c.length;
            reader?.push(c);
            res.write(c);
          });
          const finish = (cut: boolean) => {
            res.end();
            if (route.metered) this.meter(seat, seatCfg, route, model, stream, answer.statusCode ?? 0, reader?.end() ?? null, Date.now() - started, body.length, bytesOut, cut);
            done();
          };
          answer.on("end", () => finish(false));
          answer.on("error", () => finish(true));
          answer.on("aborted", () => finish(true));
        },
      );
      upstream.on("timeout", () => upstream.destroy(new Error("the provider sent nothing for too long")));
      upstream.on("error", (err) => {
        if (!res.headersSent) {
          const e = providerError(api, 502, "upstream_unreachable", `the provider could not be reached (${err.message})`);
          res.writeHead(e.status, { "content-type": "application/json" });
          res.end(e.body);
        } else res.end();
        this.log({ at: new Date().toISOString(), seat, provider: route.provider, model: model ? `${route.provider}/${model}` : null, upstream_error: err.message });
        this.traceEmit?.({ tool: "model_gateway_upstream_error", args: { via: "model-gateway", agent: seat, provider: route.provider }, result: { ok: false, message: err.message } });
        done();
      });
      // A guest that goes away takes its call with it.
      res.on("close", () => {
        if (!res.writableFinished) upstream.destroy();
      });
      upstream.end(body.length ? body : undefined);
    });
  }

  private meter(seat: string, seatCfg: GatewaySeat, route: Route, model: string, stream: boolean, status: number, usage: CallUsage | null, ms: number, bytesIn: number, bytesOut: number, cut: boolean): void {
    const id = `${route.provider}/${model}`;
    let cost = this.config.prices?.[id] ?? this.priceCache.get(id);
    if (cost === undefined) {
      cost = catalogModels(route.provider, { piAgentDir: this.config.pi_agent_dir }).find((m) => m.id === model)?.cost ?? null;
      this.priceCache.set(id, cost);
    }
    const usd = usage && cost ? priceUsage(cost, usage) : null;
    const t = (this.state.seats[seat] ??= emptyTotals(seatCfg.model));
    t.calls += 1;
    if (usage) {
      t.input += usage.input;
      t.output += usage.output;
      t.cache_read += usage.cacheRead;
      t.cache_write += usage.cacheWrite;
    }
    if (usd !== null) t.spent_usd = Number((t.spent_usd + usd).toFixed(8));
    // A billed call the gateway could not price: said, never counted as free.
    if (usd === null && status >= 200 && status < 300) t.unpriced_calls += 1;
    this.state.spent_usd = Number(Object.values(this.state.seats).reduce((a, s) => a + s.spent_usd, 0).toFixed(8));
    this.saveState();
    this.log({
      at: new Date().toISOString(),
      seat,
      provider: route.provider,
      model: id,
      api: route.spec.api,
      status,
      stream,
      ...(usage ? { input: usage.input, output: usage.output, cache_read: usage.cacheRead, cache_write: usage.cacheWrite } : { usage: "not reported" }),
      cost_usd: usd,
      ...(usd === null && usage ? { cost: "unpriced: the catalogue does not list this model" } : {}),
      ms,
      bytes_in: bytesIn,
      bytes_out: bytesOut,
      ...(cut ? { cut: true } : {}),
    });
    if (!this.quiet) process.stderr.write(`model-gateway: ${seat} ${id} ${status} ${usd === null ? "unpriced" : `$${usd.toFixed(4)}`}\n`);
  }

  listen(port = this.config.port ?? 0, host = this.config.host ?? "127.0.0.1"): Promise<number> {
    const server = createServer((req, res) => {
      this.handle(req, res).catch((err) => {
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: { message: "dfirswarm model gateway: internal error", type: "gateway_error" } }));
        } else res.end();
        if (!this.quiet) process.stderr.write(`model-gateway: ${err instanceof Error ? err.message : String(err)}\n`);
      });
    });
    // A guest's slow request cannot hold a socket open forever.
    server.headersTimeout = 30_000;
    server.requestTimeout = 5 * 60_000;
    this.server = server;
    return new Promise((done, fail) => {
      server.once("error", fail);
      server.listen(port, host, () => {
        const addr = server.address();
        this.port = typeof addr === "object" && addr ? addr.port : port;
        this.traceEmit?.({ tool: "model_gateway_started", args: { via: "model-gateway" }, result: { ok: true, port: this.port, providers: Object.keys(this.config.providers), seats: Object.keys(this.config.seats).length } });
        done(this.port);
      });
    });
  }

  close(): Promise<void> {
    return new Promise((done) => {
      if (!this.server) return done();
      this.server.close(() => done());
      this.server.closeAllConnections?.();
    });
  }
}

/** Trace lines through the collector, the way the harness's own scripts send them (scripts/trace-emit.mjs). A line the collector does not take, for any reason, is kept in traces/system-spill.jsonl, as scripts/lib/trace.sh keeps one: never appended to events.jsonl. */
function collectorEmitter(sandbox: string): ((record: Record<string, unknown>) => void) | null {
  if (!process.env.SWARM_TRACE_TOKEN) return null;
  const script = join(dirname(fileURLToPath(import.meta.url)), "trace-emit.mjs");
  return (record) => {
    const line = JSON.stringify({ ts: new Date().toISOString(), agent: "system", ...record });
    let settled = false;
    const settle = (taken: boolean) => {
      if (settled) return;
      settled = true;
      if (taken) return;
      try {
        appendFileSync(join(sandbox, "traces", "system-spill.jsonl"), `${line}\n`);
      } catch {
        // no traces/ to keep it in: the run is gone
      }
    };
    const child = spawn(process.execPath, [script, sandbox], { stdio: ["pipe", "ignore", "ignore"], env: process.env });
    child.on("error", () => settle(false));
    child.on("close", (code) => settle(code === 0));
    child.stdin?.on("error", () => undefined);
    child.stdin?.end(line);
  };
}

async function main(argv: string[]): Promise<void> {
  const opt = (name: string) => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const configPath = opt("--config");
  if (!configPath) {
    console.error("model-gateway: usage: model-gateway.ts --config FILE [--port N] [--ready FILE] [--quiet]");
    process.exit(2);
  }
  const config = JSON.parse(readFileSync(configPath, "utf8")) as GatewayConfig;
  if (config.v !== 1 || !config.sandbox || !config.seats || !config.providers) throw new Error(`${configPath} is not a gateway config`);
  const keys = await resolveKeys(config);
  const gateway = new ModelGateway(config, keys, { quiet: argv.includes("--quiet"), traceEmit: collectorEmitter(config.sandbox) });
  const port = await gateway.listen(opt("--port") ? Number(opt("--port")) : config.port);
  const ready = opt("--ready");
  if (ready) writeAtomic(ready, `${JSON.stringify({ port, pid: process.pid })}\n`);
  if (!argv.includes("--quiet")) process.stderr.write(`model-gateway: run ${config.run} on 127.0.0.1:${port}, ${Object.keys(config.providers).join(", ") || "no provider"}\n`);
  const stop = () => {
    void gateway.close().then(() => process.exit(0));
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(`model-gateway: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
