/**
 * Does every download a pack pins still answer, with the bytes it pinned?
 *
 *   node --experimental-strip-types scripts/check-pins.ts [--root DIR] [--head-only] [--list]
 *                                                         [--retries N] [--retry-delay MS] [--timeout MS]
 *
 * It reads every `packs/<id>/requires/host.json` under the root and takes each
 * pinned artefact (`install.download`, `source`, `build` and `data`, and the
 * patches of a source or build): an object with an `https` URL and a sha256,
 * with the `version` of the entry it sits in. For each one:
 *
 *   - a HEAD request. A 404 or 410 is a rotted pin, a 5xx or a refused
 *     connection is tried again (`--retries`, default 3) and is then an error;
 *     a server that does not answer HEAD (403, 405, 501) is asked for the first
 *     byte instead;
 *   - when the URL does not contain the entry's version (Eric Zimmerman's
 *     `net/<tool>.zip` is replaced at the same address), the bytes are fetched
 *     and their sha256 compared: another digest is a changed pin. `--head-only`
 *     skips that fetch and says so (`unchecked`).
 *
 * One line per pin: `<state> <pack>/<program> <kind> <arch> <url> [detail]`, then
 * a summary. The exit status is 1 when any pin is rotted, changed or in error,
 * else 0. `--list` prints the pins and the way each would be checked, and makes
 * no request. Re-pinning is a manual change (images/README.md, "Re-pinning a
 * download").
 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export type Pin = {
  pack: string;
  program: string;
  kind: string;
  arch: string;
  url: string;
  sha256: string;
  /** The size the entry pins, when it does. */
  bytes?: number;
  version: string;
  /** The URL does not contain the entry's version, so the bytes can change under it. */
  unversioned: boolean;
};

export type State = "ok" | "rotted" | "changed" | "error" | "unchecked";
export type Result = { pin: Pin; state: State; detail: string };

const KINDS = ["download", "source", "build", "data"];
const ARCHES = new Set(["amd64", "arm64"]);

function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

/** Every pinned URL of one host.json entry, with the entry's version and the architecture it is for. */
function pinsOfKind(pack: string, program: string, kind: string, entry: unknown): Pin[] {
  const out: Pin[] = [];
  const walk = (node: unknown, version: string, arch: string): void => {
    if (Array.isArray(node)) {
      for (const x of node) walk(x, version, arch);
      return;
    }
    if (!isObject(node)) return;
    const v = typeof node.version === "string" ? node.version : version;
    if (typeof node.url === "string" && typeof node.sha256 === "string" && /^[0-9a-f]{64}$/i.test(node.sha256) && /^https?:\/\//.test(node.url)) {
      // A commit id in the address is as fixed as a version.
      const named = (v !== "" && node.url.includes(v)) || /[0-9a-f]{40}/.test(node.url);
      out.push({ pack, program, kind, arch: arch || "-", url: node.url, sha256: node.sha256.toLowerCase(), ...(typeof node.bytes === "number" ? { bytes: node.bytes } : {}), version: v, unversioned: !named });
    }
    for (const [k, child] of Object.entries(node)) {
      if (isObject(child) || Array.isArray(child)) walk(child, v, ARCHES.has(k) ? k : arch);
    }
  };
  walk(entry, "", "");
  return out;
}

/** The pins of every pack under root, one per URL and digest. */
export function collectPins(root: string): Pin[] {
  const packs = join(root, "packs");
  const pins: Pin[] = [];
  if (!existsSync(packs)) return pins;
  for (const id of readdirSync(packs).sort()) {
    const file = join(packs, id, "requires", "host.json");
    if (!existsSync(file)) continue;
    const host = JSON.parse(readFileSync(file, "utf8")) as { binaries?: Array<Record<string, unknown>> };
    for (const b of host.binaries ?? []) {
      const install = isObject(b.install) ? b.install : {};
      for (const kind of KINDS) {
        if (kind in install) pins.push(...pinsOfKind(id, String(b.name), kind, install[kind]));
      }
    }
  }
  const seen = new Set<string>();
  return pins.filter((p) => {
    const key = `${p.url}\n${p.sha256}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export type Options = { headOnly: boolean; retries: number; retryDelayMs: number; timeoutMs: number };

/** A pinned artefact above this many bytes is checked by its size, not fetched. */
const BIG = 64 * 1024 * 1024;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function request(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  return await fetch(url, { ...init, redirect: "follow", signal: AbortSignal.timeout(timeoutMs) });
}

async function sha256Of(res: Response): Promise<string> {
  const hash = createHash("sha256");
  if (!res.body) return hash.digest("hex");
  for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) hash.update(chunk);
  return hash.digest("hex");
}

/** HEAD (or the first byte), with retries for a server error; the bytes too when the URL names no version. */
export async function checkPin(pin: Pin, opt: Options): Promise<Result> {
  let lastError = "";
  for (let attempt = 0; attempt <= opt.retries; attempt++) {
    if (attempt > 0) await sleep(opt.retryDelayMs * attempt);
    try {
      let res = await request(pin.url, { method: "HEAD" }, opt.timeoutMs);
      if ([403, 405, 501].includes(res.status)) {
        res = await request(pin.url, { method: "GET", headers: { range: "bytes=0-0" } }, opt.timeoutMs);
        await res.body?.cancel();
      }
      if (res.status === 404 || res.status === 410) return { pin, state: "rotted", detail: `HTTP ${res.status}` };
      if (res.status >= 500) {
        lastError = `HTTP ${res.status}`;
        continue;
      }
      if (res.status >= 400) return { pin, state: "error", detail: `HTTP ${res.status}` };
      if (!pin.unversioned) return { pin, state: "ok", detail: `HTTP ${res.status}` };
      if (pin.bytes !== undefined && pin.bytes > BIG) {
        // Too large to fetch every week (Volatility's symbol bundle): the size it answers with is the check.
        const len = Number(res.headers.get("content-length") ?? NaN);
        if (len === pin.bytes) return { pin, state: "ok", detail: `size ${len} matches the pin; too large to fetch, so its bytes are not compared` };
        return Number.isNaN(len)
          ? { pin, state: "unchecked", detail: "too large to fetch and the server gave no size" }
          : { pin, state: "changed", detail: `size is now ${len}, pinned ${pin.bytes}` };
      }
      if (opt.headOnly) return { pin, state: "unchecked", detail: `HTTP ${res.status}; the URL names no version, so its bytes were not fetched (--head-only)` };
      const body = await request(pin.url, { method: "GET" }, opt.timeoutMs);
      if (body.status === 404 || body.status === 410) return { pin, state: "rotted", detail: `HTTP ${body.status}` };
      if (body.status >= 500) {
        await body.body?.cancel();
        lastError = `HTTP ${body.status}`;
        continue;
      }
      if (body.status >= 400) return { pin, state: "error", detail: `HTTP ${body.status}` };
      const got = await sha256Of(body);
      return got === pin.sha256
        ? { pin, state: "ok", detail: "same bytes" }
        : { pin, state: "changed", detail: `sha256 is now ${got}, pinned ${pin.sha256}` };
    } catch (e) {
      lastError = e instanceof Error ? (e.cause instanceof Error ? `${e.message}: ${e.cause.message}` : e.message) : String(e);
    }
  }
  return { pin, state: "error", detail: lastError || "no answer" };
}

export function line(r: Result): string {
  const p = r.pin;
  return `${r.state.padEnd(9)} ${p.pack}/${p.program} ${p.kind} ${p.arch} ${p.url} ${r.detail}`.trimEnd();
}

export async function checkAll(pins: Pin[], opt: Options, concurrency = 6): Promise<Result[]> {
  const results: Result[] = new Array(pins.length);
  let next = 0;
  const worker = async () => {
    while (next < pins.length) {
      const i = next++;
      results[i] = await checkPin(pins[i]!, opt);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, pins.length) }, worker));
  return results;
}

export function summary(results: Result[]): string {
  const n = (s: State) => results.filter((r) => r.state === s).length;
  return `${results.length} pins: ${n("ok")} ok, ${n("rotted")} rotted, ${n("changed")} changed, ${n("error")} in error, ${n("unchecked")} unchecked`;
}

function arg(argv: string[], name: string, fallback: string): string {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1]! : fallback;
}

export async function main(argv: string[]): Promise<number> {
  const root = resolve(arg(argv, "--root", resolve(fileURLToPath(new URL("..", import.meta.url)))));
  const opt: Options = {
    headOnly: argv.includes("--head-only"),
    retries: Number(arg(argv, "--retries", "3")),
    retryDelayMs: Number(arg(argv, "--retry-delay", "2000")),
    timeoutMs: Number(arg(argv, "--timeout", "120000")),
  };
  const pins = collectPins(root);
  if (pins.length === 0) {
    console.error(`check-pins: no pinned URL under ${root}/packs/*/requires/host.json`);
    return 2;
  }
  if (argv.includes("--list")) {
    for (const p of pins) console.log(`${p.unversioned ? "fetch" : "head "} ${p.pack}/${p.program} ${p.kind} ${p.arch} ${p.url}`);
    console.log(`${pins.length} pins, ${pins.filter((p) => p.unversioned).length} of them name no version and are fetched`);
    return 0;
  }
  const results = await checkAll(pins, opt);
  for (const r of results) console.log(line(r));
  console.log(summary(results));
  const bad = results.filter((r) => r.state === "rotted" || r.state === "changed" || r.state === "error");
  if (bad.length) {
    console.log("");
    console.log("Pins to look at (images/README.md, \"Re-pinning a download\"):");
    for (const r of bad) console.log(`- ${r.pin.pack}/${r.pin.program} (${r.state}): ${r.pin.url}`);
  }
  return bad.length ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (e) => {
    console.error(e);
    process.exit(2);
  });
}
