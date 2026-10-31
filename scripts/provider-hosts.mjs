#!/usr/bin/env node
// The hosts a Pi provider talks to, from Pi's own model list.
//
//   node scripts/provider-hosts.mjs <provider>/<model>
//
// Prints one allowlist entry per line: `host` for HTTPS on 443, `host:port`
// otherwise. Prints nothing when Pi does not know the provider, or when its
// base URL has a part only the operator can fill in (a Cloudflare account id,
// a Vertex location); the kickoff then asks for --provider-host.
//
// Pi keeps a JSON file per built-in provider (pi-ai's dist/providers/data),
// each model with the base URL it is called on. The file read is the one of
// the `pi` on PATH, the one that will run, and this repository's own copy
// only when that one cannot be found. A table kept by hand in the kickoff
// knew eight providers; Pi knows forty.
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const DATA_REL = join("node_modules", "@earendil-works", "pi-ai", "dist", "providers", "data");
// Where npm puts pi-ai beside pi-coding-agent rather than inside it: since Pi
// 1.0.1 ships no shrinkwrap, a project install hoists it; a global one nests it.
const HOISTED_DATA_REL = join("..", "pi-ai", "dist", "providers", "data");

/**
 * Hosts a provider calls that its models' base URLs do not name: where a
 * subscription's short-lived token is exchanged. GitHub Copilot trades its
 * GitHub login for an API token at api.github.com/copilot_internal/v2/token
 * (pi-ai auth/oauth/github-copilot.js). A VM never makes that exchange — the
 * host mints the token for the run — and the kickoff drops these for a VM.
 */
export const TOKEN_HOSTS = { "github-copilot": ["api.github.com"] };

function dataDirs() {
  const dirs = [];
  try {
    const bin = execFileSync("sh", ["-c", "command -v pi"], { encoding: "utf8" }).trim();
    if (bin) {
      // .../pi-coding-agent/dist/bundle/cli.js -> .../pi-coding-agent
      let dir = dirname(realpathSync(bin));
      for (let i = 0; i < 5 && dir !== dirname(dir); i++, dir = dirname(dir)) {
        if (!existsSync(join(dir, "package.json"))) continue;
        const found = [join(dir, DATA_REL), join(dir, HOISTED_DATA_REL)].find((d) => existsSync(d));
        if (found) {
          dirs.push(found);
          break;
        }
      }
    }
  } catch {
    // no pi on PATH: the repository's copy
  }
  const here = dirname(fileURLToPath(import.meta.url));
  const agent = join(here, "..", "node_modules", "@earendil-works", "pi-coding-agent");
  dirs.push(join(agent, DATA_REL), join(agent, HOISTED_DATA_REL));
  return dirs.filter((d) => existsSync(d));
}

/** Every base URL in a provider file, the named model's first when it is there. */
function baseUrls(file, modelId) {
  const data = JSON.parse(readFileSync(file, "utf8"));
  const all = [];
  let named = null;
  for (const group of Object.values(data)) {
    if (!group || typeof group !== "object") continue;
    for (const [id, model] of Object.entries(group)) {
      // A seat's calls are chat calls: an image or classifier model (Pi 1.4) names no host a seat needs.
      if (!model || typeof model.baseUrl !== "string" || (model.type !== undefined && model.type !== "chat")) continue;
      if (id === modelId || model.id === modelId) named = model.baseUrl;
      all.push(model.baseUrl);
    }
  }
  // The model Pi will call decides; a model Pi does not list (a newer id the
  // operator typed) gets every host the provider's models use.
  return named ? [named] : [...new Set(all)];
}

export function allowEntry(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  // A placeholder the operator fills in: nothing to allow until they do.
  if (/[{}]/.test(url) || /%7B|%7D/i.test(u.hostname)) return null;
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const port = u.port ? Number(u.port) : u.protocol === "http:" ? 80 : 443;
  // An IPv6 address with a port in brackets, the form both allowlists read.
  return port === 443 ? host : host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
}

export function providerHosts(model, dirs = dataDirs()) {
  const slash = model.indexOf("/");
  const provider = slash >= 0 ? model.slice(0, slash) : model;
  const modelId = slash >= 0 ? model.slice(slash + 1) : "";
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(provider)) return [];
  for (const dir of dirs) {
    const file = join(dir, `${provider}.json`);
    if (!existsSync(file)) continue;
    try {
      const entries = baseUrls(file, modelId).map(allowEntry);
      // One host that cannot be known makes the provider unknown: allowing the
      // others would pass a run that fails on its first call to the missing one.
      if (entries.some((e) => e === null)) return [];
      return [...new Set([...entries, ...(TOKEN_HOSTS[provider] ?? [])])];
    } catch {
      return [];
    }
  }
  return [];
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const model = process.argv[2];
  if (!model) {
    console.error("usage: provider-hosts.mjs <provider>/<model>");
    process.exit(2);
  }
  for (const entry of providerHosts(model)) console.log(entry);
}
