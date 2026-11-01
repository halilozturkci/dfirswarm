/**
 * The model gateway (scripts/model-gateway.ts) against fake providers on
 * loopback: what passes through is the provider's own bytes, what is counted
 * is the provider's own usage, what is refused never leaves, and no key the
 * gateway holds is in anything a guest is given. Fake keys only.
 */
import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, request, type IncomingHttpHeaders, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import {
  GATEWAY_LOG_REL,
  GATEWAY_STATE_REL,
  gatewayProviderFor,
  guestBaseUrl,
  guestProviders,
  ModelGateway,
  planGateway,
  priceUsage,
  refusalFor,
  routeOf,
  UsageReader,
  type GatewayConfig,
  type GatewayState,
} from "../scripts/model-gateway.ts";

const OPENAI_KEY = "fake-openai-key-0123456789";
const ANTHROPIC_KEY = "fake-anthropic-key-9876543210";
const SECRET_PROMPT = "the-request-body-marker-7f3a";
const SECRET_ANSWER = "the-response-body-marker-91c2";

type Seen = { method: string; path: string; headers: IncomingHttpHeaders; body: string };

/** Bodies the fake providers send, kept so the test can compare bytes. */
const CHAT_JSON = JSON.stringify({ id: "c1", object: "chat.completion", model: "gpt-test", choices: [{ index: 0, message: { role: "assistant", content: SECRET_ANSWER }, finish_reason: "stop" }], usage: { prompt_tokens: 100, completion_tokens: 30, total_tokens: 130, prompt_tokens_details: { cached_tokens: 20 } } });
const CHAT_SSE = [
  `data: ${JSON.stringify({ id: "c2", choices: [{ index: 0, delta: { role: "assistant", content: SECRET_ANSWER }, finish_reason: null }] })}`,
  `data: ${JSON.stringify({ id: "c2", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}`,
  `data: ${JSON.stringify({ id: "c2", choices: [], usage: { prompt_tokens: 1000, completion_tokens: 50, prompt_tokens_details: { cached_tokens: 400 } } })}`,
  "data: [DONE]",
  "",
].join("\n\n");
const RESPONSES_SSE = [
  `event: response.created\ndata: ${JSON.stringify({ type: "response.created", response: { id: "r1", status: "in_progress" } })}`,
  `event: response.output_text.delta\ndata: ${JSON.stringify({ type: "response.output_text.delta", delta: SECRET_ANSWER })}`,
  `event: response.completed\ndata: ${JSON.stringify({ type: "response.completed", response: { id: "r1", status: "completed", usage: { input_tokens: 500, output_tokens: 70, input_tokens_details: { cached_tokens: 100 } } } })}`,
  "",
].join("\n\n");
const ANTHROPIC_JSON = JSON.stringify({ id: "m1", type: "message", role: "assistant", content: [{ type: "text", text: SECRET_ANSWER }], usage: { input_tokens: 40, output_tokens: 12, cache_read_input_tokens: 5, cache_creation_input_tokens: 0 } });
const ANTHROPIC_SSE = [
  `event: message_start\ndata: ${JSON.stringify({ type: "message_start", message: { id: "m2", usage: { input_tokens: 300, output_tokens: 1, cache_read_input_tokens: 60, cache_creation_input_tokens: 20 } } })}`,
  `event: content_block_delta\ndata: ${JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: SECRET_ANSWER } })}`,
  `event: message_delta\ndata: ${JSON.stringify({ type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 44 } })}`,
  `event: message_stop\ndata: ${JSON.stringify({ type: "message_stop" })}`,
  "",
].join("\n\n");

/** One loopback server playing every provider, recording what reached it. */
async function fakeProvider(): Promise<{ server: Server; port: number; seen: Seen[] }> {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    const parts: Buffer[] = [];
    req.on("data", (c: Buffer) => parts.push(c));
    req.on("end", () => {
      const body = Buffer.concat(parts).toString("utf8");
      seen.push({ method: req.method ?? "", path: req.url ?? "", headers: req.headers, body });
      const parsed = body ? (JSON.parse(body) as { stream?: boolean; model?: string }) : {};
      if (parsed.model === "fail") {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { message: "upstream is down", type: "server_error" } }));
        return;
      }
      const sse = (text: string) => {
        res.writeHead(200, { "content-type": "text/event-stream" });
        // In small pieces, split inside events, the way a network delivers them.
        let i = 0;
        const step = () => {
          if (i >= text.length) return res.end();
          res.write(text.slice(i, i + 37));
          i += 37;
          setImmediate(step);
        };
        step();
      };
      const json = (text: string) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(text);
      };
      if (req.url?.endsWith("/chat/completions")) return parsed.stream ? sse(CHAT_SSE) : json(CHAT_JSON);
      if (req.url?.endsWith("/responses")) return sse(RESPONSES_SSE);
      if (req.url?.endsWith("/v1/messages")) return parsed.stream ? sse(ANTHROPIC_SSE) : json(ANTHROPIC_JSON);
      res.writeHead(404);
      res.end();
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const addr = server.address();
  return { server, port: typeof addr === "object" && addr ? addr.port : 0, seen };
}

type Rig = { root: string; up: Awaited<ReturnType<typeof fakeProvider>>; config: GatewayConfig; gateway: ModelGateway; port: number };

async function rig(options: { limits?: GatewayConfig["limits"]; budget?: Record<string, unknown>; now?: () => number } = {}): Promise<Rig> {
  const root = await mkdtemp(join(tmpdir(), "model-gateway-"));
  mkdirSync(join(root, "traces"), { recursive: true });
  mkdirSync(join(root, "done", "agents"), { recursive: true });
  writeFileSync(join(root, "budget.json"), JSON.stringify({ cap_usd: 100, spent_usd: 0, wall_clock_minutes: 60, started_at: new Date().toISOString(), agents: {}, ...options.budget }));
  const up = await fakeProvider();
  const upstream = `http://127.0.0.1:${up.port}`;
  const config: GatewayConfig = {
    v: 1,
    run: "sgw0001",
    sandbox: root,
    seats: {
      s1: { token: "a".repeat(48), model: "openai/gpt-test", providers: ["openai", "resp", "anthropic"] },
      s2: { token: "b".repeat(48), model: "anthropic/claude-test", providers: ["anthropic"] },
    },
    providers: {
      openai: { upstream, base_path: "/v1", api: "openai-completions", auth_header: "authorization", key: { source: "env", name: "GW_TEST_OPENAI_KEY" } },
      resp: { upstream, base_path: "/v1", api: "openai-responses", auth_header: "authorization", key: { source: "env", name: "GW_TEST_OPENAI_KEY" } },
      anthropic: { upstream, base_path: "", api: "anthropic-messages", auth_header: "x-api-key", key: { source: "env", name: "GW_TEST_ANTHROPIC_KEY" } },
    },
    prices: {
      "openai/gpt-test": { input: 1, output: 2, cacheRead: 0.5, cacheWrite: 0 },
      "resp/gpt-r": { input: 2, output: 8, cacheRead: 0.5, cacheWrite: 0 },
      "anthropic/claude-test": { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
    },
    ...(options.limits ? { limits: options.limits } : {}),
  };
  const keys = new Map([["openai", OPENAI_KEY], ["resp", OPENAI_KEY], ["anthropic", ANTHROPIC_KEY]]);
  const gateway = new ModelGateway(config, keys, { quiet: true, ...(options.now ? { now: options.now } : {}) });
  const port = await gateway.listen(0);
  return { root, up, config, gateway, port };
}

async function close(r: Rig): Promise<void> {
  await r.gateway.close();
  await new Promise<void>((done) => r.up.server.close(() => done()));
  await rm(r.root, { recursive: true, force: true });
}

/** A request as a guest's client sends it: its seat token in the header its provider's client uses. */
function call(r: Rig, path: string, body: Record<string, unknown> | null, headers: Record<string, string> = {}, method = "POST"): Promise<{ status: number; body: string; headers: IncomingHttpHeaders }> {
  return new Promise((done, fail) => {
    const text = body ? JSON.stringify(body) : "";
    const req = request({ host: "127.0.0.1", port: r.port, method, path, headers: { "content-type": "application/json", ...(text ? { "content-length": String(Buffer.byteLength(text)) } : {}), ...headers } }, (res) => {
      const parts: Buffer[] = [];
      res.on("data", (c: Buffer) => parts.push(c));
      res.on("end", () => done({ status: res.statusCode ?? 0, body: Buffer.concat(parts).toString("utf8"), headers: res.headers }));
    });
    req.on("error", fail);
    req.end(text || undefined);
  });
}

const s1 = { authorization: `Bearer ${"a".repeat(48)}` };
const s1Anthropic = { "x-api-key": "a".repeat(48), "anthropic-version": "2023-06-01" };
const s2Anthropic = { "x-api-key": "b".repeat(48), "anthropic-version": "2023-06-01" };

function upHost(r: Rig): string {
  return `127.0.0.1:${r.up.port}`;
}

function logLines(r: Rig): Array<Record<string, unknown>> {
  return readFileSync(join(r.root, GATEWAY_LOG_REL), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

const cleanups: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of cleanups) await c();
});

test("an OpenAI chat call passes through byte for byte, is metered from the provider's usage, and carries the host's key, never the seat's token", async () => {
  process.env.GW_TEST_OPENAI_KEY = OPENAI_KEY;
  const r = await rig();
  cleanups.push(() => close(r));
  const res = await call(r, `/p/openai/${upHost(r)}/v1/chat/completions`, { model: "gpt-test", messages: [{ role: "user", content: SECRET_PROMPT }] }, s1);
  assert.equal(res.status, 200);
  assert.equal(res.body, CHAT_JSON, "the provider's bytes, unchanged");
  const got = r.up.seen.at(-1)!;
  assert.equal(got.path, "/v1/chat/completions");
  assert.equal(got.headers.authorization, `Bearer ${OPENAI_KEY}`, "the provider gets the host's key");
  assert.ok(!JSON.stringify(got.headers).includes("a".repeat(48)), "the seat's token never leaves the host");
  assert.equal(got.headers["accept-encoding"], "identity");
  const seat = r.gateway.state.seats.s1;
  assert.deepEqual([seat.input, seat.output, seat.cache_read, seat.calls], [80, 30, 20, 1], "prompt 100 with 20 cached: 80 input, 20 read from cache");
  assert.equal(seat.spent_usd, priceUsage({ input: 1, output: 2, cacheRead: 0.5, cacheWrite: 0 }, { input: 80, output: 30, cacheRead: 20, cacheWrite: 0, cacheWrite1h: 0 }));
  const log = readFileSync(join(r.root, GATEWAY_LOG_REL), "utf8");
  assert.ok(!log.includes(SECRET_PROMPT) && !log.includes(SECRET_ANSWER), "no body is written to the log");
  assert.ok(!log.includes(OPENAI_KEY), "no key is written to the log");
});

test("SSE streams pass through whole and are metered as they go: OpenAI chat, OpenAI responses, Anthropic messages", async () => {
  process.env.GW_TEST_OPENAI_KEY = OPENAI_KEY;
  process.env.GW_TEST_ANTHROPIC_KEY = ANTHROPIC_KEY;
  const r = await rig();
  cleanups.push(() => close(r));
  const chat = await call(r, `/p/openai/${upHost(r)}/v1/chat/completions`, { model: "gpt-test", stream: true, stream_options: { include_usage: true }, messages: [] }, s1);
  assert.equal(chat.body, CHAT_SSE);
  const resp = await call(r, `/p/resp/${upHost(r)}/v1/responses`, { model: "gpt-r", stream: true, input: [] }, s1);
  assert.equal(resp.body, RESPONSES_SSE);
  const msg = await call(r, `/p/anthropic/${upHost(r)}/v1/messages`, { model: "claude-test", stream: true, messages: [] }, s1Anthropic);
  assert.equal(msg.body, ANTHROPIC_SSE);
  assert.equal(r.up.seen.at(-1)!.headers["x-api-key"], ANTHROPIC_KEY, "Anthropic's key goes in x-api-key");
  const lines = logLines(r).filter((l) => l.seat === "s1" && typeof l.status === "number");
  const by = (model: string) => lines.find((l) => l.model === model)!;
  assert.deepEqual([by("openai/gpt-test").input, by("openai/gpt-test").output, by("openai/gpt-test").cache_read], [600, 50, 400], "the usage chunk, as Pi reads it");
  assert.deepEqual([by("resp/gpt-r").input, by("resp/gpt-r").output, by("resp/gpt-r").cache_read], [400, 70, 100], "response.completed's usage");
  assert.deepEqual([by("anthropic/claude-test").input, by("anthropic/claude-test").output, by("anthropic/claude-test").cache_read, by("anthropic/claude-test").cache_write], [300, 44, 60, 20], "message_start, then message_delta's running output");
  const total = lines.reduce((a, l) => a + Number(l.cost_usd), 0);
  assert.ok(Math.abs(r.gateway.state.seats.s1.spent_usd - total) < 1e-9, "the seat's total is the sum of its calls");
  const anthropicJson = await call(r, `/p/anthropic/${upHost(r)}/v1/messages`, { model: "claude-test", messages: [] }, s1Anthropic);
  assert.equal(anthropicJson.body, ANTHROPIC_JSON);
  assert.equal(logLines(r).at(-1)!.output, 12, "a whole Anthropic message is metered too");
});

test("the usage reader keeps only the event it is reading, and skips an event too long to be a usage event", () => {
  const reader = new UsageReader("openai-completions", "text/event-stream", { maxEvent: 64 });
  reader.push(Buffer.from(`data: ${JSON.stringify({ choices: [{ delta: { content: "x".repeat(500) } }] })}`));
  reader.push(Buffer.from(`\n\ndata: ${JSON.stringify({ choices: [], usage: { prompt_tokens: 10, completion_tokens: 2 } })}\n\n`));
  assert.deepEqual(reader.end(), { input: 10, output: 2, cacheRead: 0, cacheWrite: 0, cacheWrite1h: 0 });
});

test("a call with no seat token, another seat's provider, a route outside the fronted endpoints or another host is refused and never leaves", async () => {
  process.env.GW_TEST_OPENAI_KEY = OPENAI_KEY;
  const r = await rig();
  cleanups.push(() => close(r));
  const before = r.up.seen.length;
  const none = await call(r, `/p/openai/${upHost(r)}/v1/chat/completions`, { model: "gpt-test" });
  assert.equal(none.status, 401);
  assert.match(JSON.parse(none.body).error.message, /no valid seat token/);
  const wrong = await call(r, `/p/openai/${upHost(r)}/v1/chat/completions`, { model: "gpt-test" }, { authorization: `Bearer ${"c".repeat(48)}` });
  assert.equal(wrong.status, 401);
  const notMine = await call(r, `/p/openai/${upHost(r)}/v1/chat/completions`, { model: "gpt-test" }, { authorization: `Bearer ${"b".repeat(48)}` });
  assert.equal(notMine.status, 403, "seat s2 runs no OpenAI model");
  const s2shape = await call(r, `/p/openai/${upHost(r)}/v1/files`, { model: "gpt-test" }, s1);
  assert.equal(s2shape.status, 404, "an endpoint a model client does not call");
  const otherHost = await call(r, "/p/openai/evil.example/v1/chat/completions", { model: "gpt-test" }, s1);
  assert.equal(otherHost.status, 404, "no host but the provider's own");
  const dots = await call(r, `/p/openai/${upHost(r)}/v1/x/../chat/completions`, { model: "gpt-test" }, s1);
  assert.equal(dots.status, 404);
  const encoded = await call(r, `/p/openai/${upHost(r)}/v1%2fchat/completions`, { model: "gpt-test" }, s1);
  assert.equal(encoded.status, 404);
  const method = await call(r, `/p/openai/${upHost(r)}/v1/chat/completions`, null, s1, "GET");
  assert.equal(method.status, 404, "the method is part of the endpoint");
  assert.equal(r.up.seen.length, before, "nothing refused reached the provider");
  assert.equal(r.gateway.state.seats.s1.calls, 0);
  // An Anthropic route refuses in Anthropic's shape, which its client reads.
  const anth = await call(r, `/p/anthropic/${upHost(r)}/v1/messages`, { model: "claude-test" }, { "x-api-key": "nope" });
  assert.equal(JSON.parse(anth.body).type, "error");
  assert.equal(JSON.parse(anth.body).error.type, "authentication_error");
});

test("a seat past its cap, a model past its cap, a run past its clock or a stopped seat is refused before the call leaves", async () => {
  process.env.GW_TEST_OPENAI_KEY = OPENAI_KEY;
  process.env.GW_TEST_ANTHROPIC_KEY = ANTHROPIC_KEY;
  // No grace here: the grace itself is the next test's.
  const r = await rig({ budget: { cap_per_agent_usd: 0.0001 }, limits: { cap_grace_ms: 0 } });
  cleanups.push(() => close(r));
  const path = `/p/openai/${upHost(r)}/v1/chat/completions`;
  assert.equal((await call(r, path, { model: "gpt-test" }, s1)).status, 200, "under the cap: through");
  const hits = r.up.seen.length;
  const refused = await call(r, path, { model: "gpt-test" }, s1);
  assert.equal(refused.status, 403);
  assert.equal(JSON.parse(refused.body).error.code, "seat_cap");
  assert.match(JSON.parse(refused.body).error.message, /own \$0\.0001 cap/);
  assert.equal(r.up.seen.length, hits, "the refused call never left");
  assert.equal(r.gateway.state.seats.s1.refused, 1);
  assert.equal(logLines(r).at(-1)!.refused, "seat_cap");
  // The other seat is not held by s1's cap.
  assert.equal((await call(r, `/p/anthropic/${upHost(r)}/v1/messages`, { model: "claude-test" }, s2Anthropic)).status, 200);

  writeFileSync(join(r.root, "budget.json"), JSON.stringify({ cap_usd: 100, wall_clock_minutes: 60, started_at: new Date().toISOString(), cap_per_model_usd: { "anthropic/claude-test": 0.00001 } }));
  const model = await call(r, `/p/anthropic/${upHost(r)}/v1/messages`, { model: "claude-test" }, s2Anthropic);
  assert.equal(JSON.parse(model.body).error.type, "permission_error");
  assert.match(JSON.parse(model.body).error.message, /anthropic\/claude-test has spent/);

  writeFileSync(join(r.root, "budget.json"), JSON.stringify({ cap_usd: 100, wall_clock_minutes: 60, started_at: new Date(Date.now() - 2 * 3600_000).toISOString() }));
  assert.equal(JSON.parse((await call(r, path, { model: "gpt-test" }, s1)).body).error.code, "wall_clock");

  writeFileSync(join(r.root, "budget.json"), JSON.stringify({ cap_usd: 100, wall_clock_minutes: 60, started_at: new Date().toISOString() }));
  writeFileSync(join(r.root, "done", "agents", "s1.done"), "");
  assert.equal(JSON.parse((await call(r, path, { model: "gpt-test" }, s1)).body).error.code, "seat_stopped");
  writeFileSync(join(r.root, "done", "SWARM_DONE"), "");
  assert.equal(JSON.parse((await call(r, `/p/anthropic/${upHost(r)}/v1/messages`, { model: "claude-test" }, s2Anthropic)).body).error.type, "permission_error");
});

test("a seat past a cap may still call for the harness's grace, to post its findings; the harness's own stop is refused at once", async () => {
  const root = await mkdtemp(join(tmpdir(), "gw-grace-"));
  cleanups.push(() => rm(root, { recursive: true, force: true }));
  mkdirSync(join(root, "done", "agents"), { recursive: true });
  const t0 = Date.parse("2026-09-24T12:00:00Z");
  writeFileSync(join(root, "budget.json"), JSON.stringify({ cap_usd: 1, cap_per_agent_usd: 0.5, wall_clock_minutes: 60, started_at: new Date(t0 - 30 * 60_000).toISOString() }));
  const seat = { token: "t", model: "m/x", providers: ["m"] };
  const state: GatewayState = { v: 1, run: "r", seats: { a: { calls: 3, refused: 0, input: 0, output: 0, cache_read: 0, cache_write: 0, spent_usd: 0.6, unpriced_calls: 0, model: "m/x" } }, spent_usd: 0.6, updated_at: "" };
  const grace = 180_000;
  assert.equal(refusalFor(root, "a", seat, state, t0, grace), null, "first seen over its cap: told by the harness, still calling");
  assert.equal(state.crossed?.["seat_cap:a"], new Date(t0).toISOString(), "the crossing is recorded");
  assert.equal(refusalFor(root, "a", seat, state, t0 + grace - 1, grace), null, "within the grace");
  assert.equal(refusalFor(root, "a", seat, state, t0 + grace, grace)?.code, "seat_cap", "past the grace: refused");
  // The wall clock ends at started_at + 60 min = t0 + 30 min; refused after its grace too.
  const calm: GatewayState = { ...state, seats: { a: { ...state.seats.a, spent_usd: 0 } }, spent_usd: 0, crossed: {} };
  assert.equal(refusalFor(root, "a", seat, calm, t0 + 30 * 60_000 + 1000, grace), null);
  assert.equal(refusalFor(root, "a", seat, calm, t0 + 30 * 60_000 + grace, grace)?.code, "wall_clock");
  // The harness's own stop of the seat: refused at once, whatever the clock.
  writeFileSync(join(root, "done", "agents", "a.done"), "");
  assert.equal(refusalFor(root, "a", seat, calm, t0, grace)?.code, "seat_stopped");
});

test("refusals are logged a few a minute per seat and reason, and counted past that", async () => {
  process.env.GW_TEST_OPENAI_KEY = OPENAI_KEY;
  // The refusal log reads its minute from an injected clock, so the count
  // does not depend on where the host's wall clock stands in its minute.
  let clock = Date.parse("2026-09-24T12:00:10Z");
  const r = await rig({ limits: { refusal_log_per_minute: 2 }, now: () => clock });
  cleanups.push(() => close(r));
  const knock = () => call(r, `/p/openai/${upHost(r)}/v1/chat/completions`, { model: "gpt-test" }, { authorization: "Bearer nope" });
  for (let i = 0; i < 6; i++) await knock();
  const lines = logLines(r).filter((l) => l.refused === "bad_token");
  assert.equal(lines.length, 2, "a knocking loop does not grow the log");
  // The minute turns in the middle of a loop: the first minute's count is
  // written when it turns, and the new minute starts its own two lines.
  clock = Date.parse("2026-09-24T12:00:59Z");
  await knock();
  clock = Date.parse("2026-09-24T12:01:00Z");
  for (let i = 0; i < 3; i++) await knock();
  const after = logLines(r).filter((l) => l.refused === "bad_token");
  assert.equal(after.length, 5, "two in the first minute, one summary, two in the next");
  assert.equal(after.filter((l) => typeof l.suppressed === "number").length, 1);
  assert.equal(after.find((l) => typeof l.suppressed === "number")!.suppressed, 5, "six calls and one more in the first minute, two written: five counted");
  assert.equal(after.at(-1)!.at, "2026-09-24T12:01:00.000Z", "the line is stamped by the injected clock");
});

test("an upstream error reaches the guest as the provider sent it, and a body or a rate over the limit is refused", async () => {
  process.env.GW_TEST_OPENAI_KEY = OPENAI_KEY;
  const r = await rig({ limits: { max_body_bytes: 2048, burst: 3, rate_per_minute: 1 } });
  cleanups.push(() => close(r));
  const path = `/p/openai/${upHost(r)}/v1/chat/completions`;
  const down = await call(r, path, { model: "fail" }, s1);
  assert.equal(down.status, 500);
  assert.equal(JSON.parse(down.body).error.message, "upstream is down", "the provider's own error, unchanged");
  assert.equal(logLines(r).at(-1)!.usage, "not reported");
  assert.equal(r.gateway.state.seats.s1.unpriced_calls, 0, "a failed call is not a billed call");
  const big = await call(r, path, { model: "gpt-test", messages: [{ role: "user", content: "x".repeat(4096) }] }, s1);
  assert.equal(big.status, 413);
  await call(r, path, { model: "gpt-test" }, s1);
  await call(r, path, { model: "gpt-test" }, s1);
  const limited = await call(r, path, { model: "gpt-test" }, s1);
  assert.equal(limited.status, 429);
  assert.equal(JSON.parse(limited.body).error.code, "rate");
});

test("the totals survive a restart, and each log line is chained to the one before", async () => {
  process.env.GW_TEST_OPENAI_KEY = OPENAI_KEY;
  const r = await rig();
  cleanups.push(() => close(r));
  const path = `/p/openai/${upHost(r)}/v1/chat/completions`;
  await call(r, path, { model: "gpt-test" }, s1);
  await r.gateway.close();
  const again = new ModelGateway(r.config, new Map([["openai", OPENAI_KEY]]), { quiet: true });
  r.gateway = again;
  r.port = await again.listen(0);
  assert.equal(again.state.seats.s1.calls, 1, "the saved totals are read back");
  await call(r, path, { model: "gpt-test" }, s1);
  assert.equal(again.state.seats.s1.calls, 2);
  const state = JSON.parse(readFileSync(join(r.root, GATEWAY_STATE_REL), "utf8"));
  assert.equal(state.seats.s1.calls, 2);
  const raw = readFileSync(join(r.root, GATEWAY_LOG_REL), "utf8").trim().split("\n");
  for (let i = 1; i < raw.length; i++) assert.equal(JSON.parse(raw[i]).prev, createHash("sha256").update(raw[i - 1]).digest("hex"), `line ${i + 1} is chained`);
  assert.equal(JSON.parse(raw[0]).prev, null);
});

test("a guest's config points each fronted provider here with the seat's token, and holds no key of the provider's", async () => {
  process.env.GW_TEST_OPENAI_KEY = OPENAI_KEY;
  const r = await rig();
  cleanups.push(() => close(r));
  const guest = guestProviders(r.config, "s1", 47123);
  assert.deepEqual(Object.keys(guest).sort(), ["anthropic", "openai", "resp"]);
  assert.equal(guest.openai.baseUrl, `http://host.microsandbox.internal:47123/p/openai/${upHost(r)}/v1`);
  assert.equal(guest.anthropic.baseUrl, `http://host.microsandbox.internal:47123/p/anthropic/${upHost(r)}`);
  assert.equal(guest.openai.apiKey, "a".repeat(48));
  const text = JSON.stringify(guestProviders(r.config, "s2", 47123));
  assert.ok(!text.includes(OPENAI_KEY) && !text.includes(ANTHROPIC_KEY) && !text.includes("a".repeat(48)), "a seat's config holds no key and no other seat's token");
  assert.deepEqual(Object.keys(JSON.parse(text)), ["anthropic"]);
  // The provider's host stays in the path: Pi decides request fields from the base URL's text.
  assert.ok(guestBaseUrl(1, "openai", { upstream: "https://api.openai.com", base_path: "/v1", api: "openai-responses", auth_header: "authorization", key: { source: "pi", provider: "openai" } }).includes("api.openai.com"));
  assert.ok(routeOf(r.config, "POST", `/p/openai/${upHost(r)}/v1/chat/completions`));
});

test("the plan fronts a keyed provider with one API and one base URL, and says why it leaves the rest to msb", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gw-catalog-"));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  const put = (provider: string, models: Record<string, unknown>) => writeFileSync(join(dir, `${provider}.json`), JSON.stringify({ g: models }));
  put("uniform", { m1: { id: "m1", api: "openai-completions", baseUrl: "https://api.uniform.example/v1", cost: { input: 1, output: 2, cacheRead: 0, cacheWrite: 0 } }, m2: { id: "m2", api: "openai-completions", baseUrl: "https://api.uniform.example/v1" } });
  put("mixed", { a: { id: "a", api: "openai-completions", baseUrl: "https://mixed.example/api/v1" }, b: { id: "b", api: "anthropic-messages", baseUrl: "https://mixed.example/api" } });
  put("signed", { a: { id: "a", api: "bedrock-converse-stream", baseUrl: "https://bedrock.example" } });
  put("unread", { a: { id: "a", api: "google-generative-ai", baseUrl: "https://generativelanguage.example/v1beta" } });
  put("azureish", { a: { id: "a", api: "azure-openai-responses", baseUrl: "" } });
  put("filled", { a: { id: "a", api: "openai-completions", baseUrl: "https://{account}.example/v1" } });
  put("plain", { a: { id: "a", api: "openai-completions", baseUrl: "http://plain.example/v1" } });
  const ok = gatewayProviderFor("uniform", "api_key", { dirs: [dir] });
  assert.ok(ok.ok && ok.spec.upstream === "https://api.uniform.example" && ok.spec.base_path === "/v1" && ok.spec.auth_header === "authorization");
  for (const [p, kind, why] of [
    ["mixed", "api_key", /one API and one base URL/],
    ["signed", "api_key", /signs each request/],
    ["unread", "api_key", /does not read its usage/],
    ["azureish", "api_key", /operator's to set/],
    ["filled", "api_key", /operator fills in/],
    ["plain", "api_key", /not HTTPS/],
    ["uniform", "oauth", /subscription/],
    ["uniform", "local", /local server/],
    ["nowhere", "api_key", /not in Pi's catalogue/],
  ] as const) {
    const r = gatewayProviderFor(p, kind, { dirs: [dir] });
    assert.ok(!r.ok && why.test(r.reason), `${p}/${kind}: ${JSON.stringify(r)}`);
  }
  const plan = planGateway({
    run: "s1",
    sandbox: "/x",
    dirs: [dir],
    providers: [{ provider: "uniform", kind: "api_key" }, { provider: "mixed", kind: "api_key" }],
    seats: [{ id: "a0", model: "uniform/m1", providers: ["uniform"] }, { id: "a1", model: "mixed/a", providers: ["mixed"] }],
  });
  assert.deepEqual(Object.keys(plan.config.providers), ["uniform"]);
  assert.deepEqual(plan.declined.map((d) => d.provider), ["mixed"]);
  assert.deepEqual(plan.config.seats.a1.providers, [], "a seat whose provider is left to msb gets nothing from the gateway");
  assert.notEqual(plan.config.seats.a0.token, plan.config.seats.a1.token);
  assert.deepEqual(plan.config.prices?.["uniform/m1"], { input: 1, output: 2, cacheRead: 0, cacheWrite: 0 });
  assert.deepEqual(plan.config.providers.uniform.key, { source: "pi", provider: "uniform" }, "the config names where the key comes from, never the key");
});

test("Pi itself, with a built-in provider overridden in models.json, calls through the gateway and is metered from Pi's own request", async (t) => {
  try {
    execFileSync("pi", ["--version"], { stdio: "ignore" });
  } catch {
    t.skip("pi is not on PATH");
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "gw-pi-"));
  cleanups.push(() => rm(root, { recursive: true, force: true }));
  mkdirSync(join(root, "traces"), { recursive: true });
  writeFileSync(join(root, "budget.json"), JSON.stringify({ cap_usd: 10, wall_clock_minutes: 60, started_at: new Date().toISOString() }));
  const up = await fakeProvider();
  cleanups.push(() => new Promise<void>((done) => up.server.close(() => done())));
  // deepseek is a built-in provider on the chat completions API, base URL
  // https://api.deepseek.com. The fake stands in for that host.
  const config: GatewayConfig = {
    v: 1,
    run: "sgwpi01",
    sandbox: root,
    seats: { p0: { token: "c".repeat(48), model: "deepseek/deepseek-flash", providers: ["deepseek"] } },
    providers: { deepseek: { upstream: `http://127.0.0.1:${up.port}`, base_path: "", api: "openai-completions", auth_header: "authorization", key: { source: "env", name: "GW_TEST_DEEPSEEK_KEY" } } },
  };
  const gateway = new ModelGateway(config, new Map([["deepseek", "fake-deepseek-key-4242"]]), { quiet: true });
  const port = await gateway.listen(0);
  cleanups.push(() => gateway.close());
  const agentDir = join(root, "agent");
  mkdirSync(agentDir, { recursive: true });
  // What the kickoff writes into a guest: the built-in provider's base URL
  // and key overridden, nothing else, and no auth.json entry for it.
  const guest = guestProviders(config, "p0", port, "127.0.0.1");
  writeFileSync(join(agentDir, "models.json"), JSON.stringify({ providers: guest }));
  const env = { ...process.env, PI_CODING_AGENT_DIR: agentDir, PI_OFFLINE: "1" };
  delete (env as Record<string, string | undefined>).DEEPSEEK_API_KEY;
  const out = await new Promise<{ code: number; stdout: string; stderr: string }>((done) => {
    const child = execFile("pi", ["-p", "Say hello.", "--model", "deepseek/deepseek-flash", "--no-extensions", "--no-skills", "--no-prompt-templates", "--no-context-files", "--offline"], { cwd: root, env, timeout: 90_000 }, (err, stdout, stderr) => {
      done({ code: err ? 1 : 0, stdout: String(stdout), stderr: String(stderr) });
    });
    // Print mode reads piped stdin to its end before it calls the model.
    child.stdin?.end();
  });
  assert.equal(up.seen.length, 1, `Pi's request reached the provider through the gateway: ${out.stderr.slice(-400)}`);
  assert.equal(up.seen[0].path, "/chat/completions");
  assert.equal(up.seen[0].headers.authorization, "Bearer fake-deepseek-key-4242", "the host's key, set by the gateway");
  assert.ok(!JSON.stringify(up.seen[0].headers).includes("c".repeat(48)), "Pi's key in the guest (the seat token) never reached the provider");
  assert.match(out.stdout, new RegExp(SECRET_ANSWER), "Pi printed the provider's answer");
  const seat = gateway.state.seats.p0;
  assert.deepEqual([seat.calls, seat.input, seat.output, seat.cache_read], [1, 600, 50, 400], "metered from the usage chunk Pi asked for");
  assert.ok(seat.spent_usd > 0, "priced from Pi's own catalogue");
});
