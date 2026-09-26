# Slice 2: stall reaping, network guard, real Playwright tool

Three additions on top of slice 1 (event log, live budget, `swarm.sh`, file
history, LAN UI). Everything is new files except: one import + a two-line
call in `extensions/agent-swarm.ts` (the `playwright` tool body), the
`playwright` devDependency in `package.json`, and one `.gitignore` line
(`sandbox/work/<agent>/.browser/`). Speculative choices are marked SPECULATIVE in the
source; unverified claims are listed at the end.

Verified against the installed Pi package `@earendil-works/pi-coding-agent`
**0.74.2** at the time (the package is 0.87.0 now) (`docs/extensions.md`, `docs/usage.md`,
`dist/core/extensions/types.d.ts`) and the Herdr CLI reference
(`herdr.dev/docs/cli-reference`):

| Fact used | Where |
| --- | --- |
| `pi.registerTool({ name, label, description, promptSnippet, promptGuidelines, parameters, execute })`; `execute(toolCallId, params, signal, onUpdate, ctx)` with `ctx.cwd`; throw to report an error | Pi extensions.md "Custom Tools" |
| `--tools <list>` allowlists built-in **and** extension tools (so `playwright` stays inactive unless `--playwright` adds it) | Pi usage.md "Tool Options" |
| `loadExtensions(paths, cwd)` exported from `dist/core/extensions/loader.js` (used by the optional loader test) | Pi loader.d.ts |
| There is **no** `herdr agent stop`; agents are stopped by closing their pane: `herdr agent get <name>` → `herdr pane close <pane_id>` | Herdr CLI reference "Agents" / "Panes" |

## Files

```
extensions/playwright-tool.ts   runBrowserCheck() + registerPlaywrightTool(pi, deps)
scripts/reap.sh                 stall reaper (bash + jq)
scripts/netguard.sh             egress allowlist wrapper (unshare + local proxy)
scripts/netguard-proxy.mjs      allowlisting HTTP proxy + netns bridge (Node, no deps)
scripts/test-slice2.sh          runs every fixture below
tests/playwright-tool.test.ts   node:test (browser steps skip without Chromium)
tests/pi-load.test.ts           node:test, loads agent-swarm.ts through Pi's real loader (skips without Pi)
tests/reap.test.sh              bash
tests/netguard.test.sh          bash, loopback-only
```

## Run the fixtures

```bash
npm install                      # adds playwright as a devDependency
npx playwright install chromium  # ~115 MB; only needed for the playwright tool
scripts/test-slice2.sh
# optional real-loader check:
PI_PACKAGE_DIR="$(npm root -g)/@earendil-works/pi-coding-agent" node --experimental-strip-types --test tests/pi-load.test.ts
```

## 1. Stall / timeout reaping — `scripts/reap.sh`

```
scripts/reap.sh [--sandbox DIR] [--timeout SECONDS] [--stop] [--dry-run] [--quiet]
```

For each `team.json` id without `done/agents/<id>.done` or `.dead`, last
activity is the newest of: a post by the agent (`threads/*/*-<id>.md`), a lock
it owns (`locks/*.json`, refresh rewrites the file), an event with
`agent == id` in `traces/events.jsonl` (covers `agent_start`, `inbox`,
`claim_file`, …), its `inbox/<id>/seen` cursor, and any file under
`.pi-sessions/<id>/` (SPECULATIVE: the last two mean "alive but only
chatting"). Baseline when nothing exists: `budget.json.started_at`.

Past `--timeout` (default 300 s) it:

1. writes `done/agents/<id>.dead` (frontmatter `by: reaper`, `reason: stall`, `last_activity`, `idle_seconds`, `timeout_seconds`, `locks_released`);
2. deletes that agent's lock files under the same `locks/.table.lock` protocol as `protocol.ts`;
3. appends to `traces/events.jsonl` in the harness schema:
   `{"ts","agent":"<id>","tool":"reap","args":{"timeout_seconds":300,"reason":"stall"},"result":{"reaped":true,"idle_seconds":…,"last_activity":"…","locks_released":n}}`;
4. with `--stop`, closes the agent's Herdr pane (`agent get` → `pane close`), tolerating failure.

Idempotent: the `.dead` marker makes later runs no-ops; a second reaper
racing on the same id re-checks under the table lock.

**Wire-in.**

- `scripts/await-done.sh` poll loop: `bash scripts/reap.sh --sandbox "$SANDBOX" --timeout "${REAP_TIMEOUT:-300}" --quiet --stop`. `scripts/swarm.sh status` runs the same script with `--timeout "${SWARM_STALL_SEC:-90}" --quiet` and no `--stop`: looking at a swarm should not close its panes.
- `scripts/watch.sh` and `extensions/observe.ts`: list `done/agents/*.dead` as "?" agents (`observe` now exposes `marker` / `stalled` / `dead`; the LAN list shows `?`).
- Optional rule: when every agent is `.done` or `.dead` and `SWARM_DONE` is absent, `swarm.sh` may record `cannot_complete` (product decision). Still open.

## 2. Network hardening — `scripts/netguard.sh`

```
scripts/netguard.sh [--allow h1,h2 | --only LIST | --allow-file F] [--port N]
                    [--mode auto|netns|proxy-only] [--log F] [--dry-run] -- CMD…
```

Default allowlist: `api.openai.com`, `api.deepseek.com`, `api.x.ai`,
`generativelanguage.googleapis.com` (+ `NETGUARD_ALLOW`). Grammar: exact host,
`.suffix` / `*.suffix`, `host:port`. IP literals must be listed explicitly.

Mechanism, chosen because it works **unprivileged** (veth + iptables needs
`CAP_NET_ADMIN` in the host namespace, which a rootless container lacks):

1. Host namespace: `netguard-proxy.mjs proxy` on a Unix socket; allowlists CONNECT and absolute-form HTTP; does all DNS.
2. `unshare -rn` → user + **empty network namespace** (only `lo`). `lo` is brought up with `ip`, or a python3 `SIOCSIFFLAGS` ioctl when iproute2 is missing.
3. Nested `unshare -U --map-user=<real uid>` so the command runs as its real uid, not mapped root.
4. Inside: `netguard-proxy.mjs bridge` forwards `127.0.0.1:PORT` → the Unix socket (Unix sockets are filesystem objects and cross network namespaces). Exports `HTTP(S)_PROXY`, `NO_PROXY=""`, `NODE_USE_ENV_PROXY=1`, `NETGUARD_MODE=netns`.

Clients that ignore the proxy get `ENETUNREACH` / "Could not resolve host":
fail-closed. `tests/netguard.test.sh` proves it against a loopback
`python3 -m http.server`: `localhost` allowed (HTTP and CONNECT), the same
server as `127.0.0.1` denied with 403, `curl --noproxy '*'` and Node's
proxy-unaware `fetch` both fail, the child's uid and exit code pass through.

**Wire-in (as shipped).** `herdr agent start --kind pi` cannot take a wrapper
argv, so `scripts/swarm.sh` `cmd_start` does two things instead (see
[README › Safety](safety.md)):

1. writes `<sandbox>/bin/pi`, a shim that execs
   `scripts/netguard.sh --allow <provider host> --log <sandbox>/traces/netguard.log -- <real pi> "$@"`,
   and prepends `<sandbox>/bin` to each pane's `PATH`;
2. starts a persistent `netguard.sh --mode proxy-only` sidecar on
   `127.0.0.1:${SWARM_NETGUARD_PORT:-43178}` and sets `HTTPS_PROXY` /
   `HTTP_PROXY` / `ALL_PROXY` / `NODE_USE_ENV_PROXY=1` on every pane, so the
   filter still applies if Herdr launches `pi` by absolute path.

`--no-netguard` (alias `--open-net`) skips both. Provider host per model
prefix: `openai/` → `api.openai.com`, `deepseek/` → `api.deepseek.com`,
`xai/` → `api.x.ai`, `google/` → `generativelanguage.googleapis.com`,
`anthropic/` → `api.anthropic.com`, `openrouter/` → `openrouter.ai`. The first
four are in `netguard.sh`'s default list; the last two are added by
`swarm.sh` via `--allow` only when that provider is selected.

**Fallback.** `--mode proxy-only` (auto-selected when `unshare -rn` fails) only
sets the env variables: advisory, prints a WARNING.

## 3. Real Playwright tool — `extensions/playwright-tool.ts`

The base registered a stub `playwright` tool (`available: false`). The stub is
replaced by `registerPlaywrightTool(pi, { getAgentId, logEvent })`; name,
label, `--playwright` gating (`PI_TOOLS+=",playwright"` in `swarm.sh`) and
event logging are unchanged.

```
playwright(target, actions?, screenshot?, text_selector?, note?)
  -> { ok, url, final_url, title, text, text_truncated, console_errors, page_errors, screenshot, actions_run,
       blocked_requests, blocked_downloads }
```

- `target`: sandbox-relative HTML file (`work/index.html` → `file://`) or a
  loopback URL. Remote http(s) is **refused** unless the spawner exports
  `SWARM_BROWSER_REMOTE=1` (under netguard the browser has no egress anyway).
- `actions`: ordered `click`, `fill`, `press`, `wait`, `goto`.
- `screenshot: true` → full-page PNG at `work/<agent>/.browser/<ts>-<agent>.png`,
  inside the agent's own writable directory, each directory opened without
  following a link.
- One request policy for navigation, redirects, subresources, fetch and
  WebSockets: what it refuses is listed whole in `blocked_requests`. Service
  workers are blocked, so none can route around it; downloads are cancelled
  and their suggested names listed in `blocked_downloads`. A sandbox file
  target is held inside the sandbox after `realpath`.
- Event line: `tool: "playwright"`, `args: {target, actions, screenshot, text_selector, note}`, `result: {ok, title, errors, screenshot, text_chars}` or `{ok:false, error}`.

**Install.** `npm install` + `npx playwright install chromium`. Hosts without
the download: `BROWSER_CHECK_EXECUTABLE=/path/to/chromium` or
`BROWSER_CHECK_CHANNEL=chrome` (installed Google Chrome). If `playwright` is
missing the tool throws an install hint; extension load still succeeds
(`tests/pi-load.test.ts`).

## Limitations and what is unverified

- **Pi through netguard with a real provider: verified once** on the live N=2
  run `s9091` (`ALLOW api.deepseek.com:443`, agent `curl https://example.com/`
  → `DENY` / CONNECT 403, swarm still reached `SWARM_DONE`; see
  [README › Verified results](verified-runs.md)). The client
  caveat stands: Pi's Node build uses global `fetch`, which honours
  `HTTP(S)_PROXY` only with `NODE_USE_ENV_PROXY=1` on Node 24+ / 22.21+
  (exported by netguard; on older Node it is ignored and the call fails
  closed). The `pi.dev/install.sh` binary is Bun-compiled; Bun's `fetch`
  honours the variables natively. Check a new host with
  `scripts/swarm.sh netcheck` or `scripts/netguard.sh --log /tmp/ng.log -- pi -p "hi"`.
- **macOS: UNKNOWN.** No `unshare`; only `proxy-only` runs there. A `pf`
  ruleset is the enforced equivalent and needs root.
- **Docker's default seccomp profile** blocks `unshare` for non-`CAP_SYS_ADMIN`
  containers; netguard falls back to proxy-only. This environment's kernel
  allowed it (`unshare -rn` worked as uid 1000).
- `herdr agent get` JSON shape is not pinned in the docs; `reap.sh --stop`
  takes the first `pane_id` found in the response. Exercised live since: see
  the `sd169` and `scff0` rows in [ui-coverage](ui-coverage.md#live-run), where
  the panes of the reaped agents were closed.
- `bash`-tool writes **no longer** bypass the guard silently: every shell call
  is bracketed by a hash of the watched paths, and a change that no recorded
  revision accounts for is snapshotted, logged as `claim_violation` with
  `via: "bash"`, and announced on the board by `system`. It is detection, not
  prevention — see
  [ADR 0001](adr/0001-detect-bash-writes-rather-than-block-them.md). The
  residual limit: two agents running shells at the same time can produce a
  duplicate report, since attribution is by "whose shell was running", not by
  the writing process.
- Reaper activity signals, `.dead` frontmatter, the `playwright` parameter
  shape and the screenshot directory are our reconstructions; Dan showed
  labels, not internals.
