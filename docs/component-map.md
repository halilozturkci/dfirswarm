# Component map

The files you would actually open, what they do, and when you would touch them. Moved out of the README for the release; the README keeps the architecture diagram.


The files you would actually open, what they do, and when you would touch them. Generated and incidental files (`package-lock.json`, `node_modules/`, the fixture runs directory) are left out.

### `scripts/`

| Path | What it does | Touch it when |
| --- | --- | --- |
| `scripts/swarm.sh` | The CLI: `start`, `list`, `status`, `stop`, `ui`, `reap`, `netcheck`. Allocates ids, validates the goal document, renders `SWARM.md`, writes the registry (`runs/registry.json`), lays out Herdr panes, starts/prompts Pi agents, starts the netguard sidecar and PATH shim. | Adding a kickoff flag, changing the pane grid, supporting a new provider prefix (key detection + allowlist host). |
| `scripts/spawn.sh` | Thin legacy wrapper around `swarm.sh start` (default cap $3). `--dry-run` runs the fixture test instead. | Rarely; kept for older scripts and env-var driven kickoff (`SWARM_N`, `SWARM_MODEL`, `SWARM_GOAL_FILE`, …). |
| `scripts/watch.sh` | Terminal observer: sentinel, `.done`/`.dead`, locks, `threads/main` list, `work/hello.txt`, budget totals, last 16 events humanised, compact Herdr agent table. `--once` or a 2 s loop. | Adding a panel to the terminal view. |
| `scripts/await-done.sh` | Blocks until `done/SWARM_DONE` exists **and** every `## Checks` line from the goal passes (exit 0), or times out (exit 1). Reads the goal from the registry, outside the sandbox, so a swarm cannot rewrite its own checks. Each check runs with stdin closed under `--check-timeout`. Polls `reap.sh --stop` each round. | Changing how a run is certified. |
| `scripts/reap.sh` | Stall reaper. For each team id without `.done`/`.dead`, computes last activity (post, lock refresh, event, inbox cursor, Pi session files) and past `--timeout` writes `done/agents/<id>.dead`, drops its locks, appends a `reap` event, optionally closes the Herdr pane. Idempotent. | Changing what counts as activity or the `.dead` frontmatter. |
| `scripts/fsguard.sh` | Runs a command with one or more directories read-only at the kernel: `sandbox-exec` deny profile on macOS, a bind-mount in a user + mount namespace on Linux, `none` with a WARNING elsewhere. `swarm.sh --inputs` puts the pane's shell under it through a hook: `ZDOTDIR` for a zsh, `HOME` for a bash login shell. | Changing how inputs are enforced on a platform. |
| `scripts/netguard.sh` | Runs a command with egress limited to an allowlist: user+net namespace via `unshare -rn` with only `lo`, plus a local allowlisting proxy reached through a Unix-socket bridge. Falls back to advisory `--mode proxy-only` when namespaces are unavailable. | Changing the default allowlist, the proxy port, or platform fallbacks. |
| `scripts/netguard-proxy.mjs` | Node, no deps. `proxy` mode: HTTP/1.1 forward proxy allowing CONNECT and absolute-form HTTP to allowlisted hosts only (exact, `.suffix`, `*.suffix`, `host:port`; a host with no port is 443 alone); `bridge` mode: TCP → Unix-socket forwarder run inside the empty netns; `self-test`. | Allowlist grammar, logging format. |
| `scripts/cloud-setup.sh` | Provisions an Anthropic-hosted Claude Code cloud environment (Node, Herdr, Pi, Chromium, `npm ci`, `ui:build`). Idempotent; pasted into the environment's setup-script field. See `docs/claude-cloud-env.md`. | Changing what a cloud session needs. |
| `scripts/dry-run.sh` | `node --test` over `tests/dry-run.test.ts` + `tests/ui-server.test.ts`. No model, no keys, no Herdr. | Adding a test file to the default suite (also update `package.json` `test`). |
| `scripts/test-bash.sh` | Runs every `tests/*.test.sh` and reports each one; `npm run test:bash` calls it. Takes suite stems to run a subset. | Rarely: a new suite is picked up by its name. |
| `scripts/test-slice2.sh` | The Playwright-tool node test plus the reaper and netguard shell suites; the Pi loader test is in `npm test` now. | Same. |
| `scripts/seed-fixture.ts` | Writes five fixture swarms (two running, two done, one stopped) into a runs dir using the real `protocol.ts` primitives: claim conflicts, a claim violation, a reaped agent, file history, artifacts. Used by `tests/ui-server.test.ts` and `npm run ui:fixture`. | Adding a UI state that needs fixture data. |
| `scripts/ui-server.ts` | Web app entry point: parses `--port/--host/--runs-dir`, builds the app, prints the URL. | Startup flags only. |
| `scripts/ui/app.ts` | `node:http` app: static `ui/dist` (503 page when the bundle is missing), JSON API, SSE, operator restore, artifact serving with a CSP sandbox, and the bearer token that gates the four mutating routes. | Adding or changing an endpoint. |
| `scripts/ui/model.ts` | Read models derived from sandbox files: swarm rows (phase, elapsed, violations), agent rows (callsign heuristic, per-agent spend, marker info), timed posts, work files, trace queries. | Adding a field the UI needs from disk. |
| `scripts/ui/actions.ts` | `ActionRunner`: spawns `bash scripts/swarm.sh start|stop|reap` as jobs with captured output; `validateStart`; model list from `pi --list-models` (table parser) or a static fallback. | Adding a UI action or a kickoff field. |
| `scripts/ui/watch.ts` | `ChangeBus`: recursive `fs.watch` on the runs dir, debounced into one `change` event naming the swarms touched and, per swarm, the kinds of thing that moved; session files, logs and the harness's bookkeeping are classified and dropped; the per-swarm change stamp the finish line's cache reads; polling fallback and re-attach. | Change-detection behaviour, a new file the console should or should not react to. |

### `extensions/`

| Path | What it does | Touch it when |
| --- | --- | --- |
| `extensions/protocol.ts` | The whole protocol as pure functions: sandbox init, posts, threads and membership, per-thread cursors, table lock, claims as reasoned leases, protected paths, write guard, done/sentinel, harness stop, event log, budget fold from Pi `Usage`, content-addressed history with diff and restore, bash-write detection, `wait`, stall markers, reaping. No Pi imports. | Any protocol change. Test it in `tests/dry-run.test.ts` first. |
| `extensions/agent-swarm.ts` | The Pi extension: registers the tools, hooks `session_start`, `before_agent_start` (injects id + sentinel line into the system prompt), `tool_call` (write guard, pre-write history, bash snapshot), `tool_result` (post-write history, bash-write report with a one-post-per-path-per-minute board notice, per-tool duration, built-in tool tracing with the whole result, `view` for a slice, and Pi's bash spill moved into `tool-output/` as `full_output`), `message_end` (the reasoning, whole), `inbox`/`wait` paging by whole posts (`SWARM_INBOX_PAGE_CHARS`), forged tools streamed whole to `tool-output/` past 64 KB, `turn_end` / `session_shutdown` (budget fold, cap and wall steer, harness stop, optional hard kill, claim release). Type-checked against Pi's own types. | Adding a tool, changing a hook. |
| `extensions/playwright-tool.ts` | `playwright` tool: headless Chromium against a `work/` HTML file or loopback URL, optional actions, text/console/page errors, screenshot to `work/<agent>/.browser/`; navigation, redirects, subresources and WebSockets held to one request policy, service workers off, downloads refused (`blocked_requests`, `blocked_downloads`). Lazy-imports the `playwright` package. | Browser verification behaviour. |
| `extensions/context-ceiling.ts` | Pure: the effective-ceiling table per model (272k GPT-5.4/5.5, 200k grok-4.6, 300k for a 1M model), the three threshold specs (tokens, `k`/`m`, `%`) parsed and resolved against a window with reserve and headroom kept, the level; a spec as a list with per-model overrides (`60%,openai/gpt-5.4-mini=55%`) parsed and resolved per seat, and the shape regex the shell and the console share. No Pi imports. | Changing a ceiling, a default line or the spec syntax. Test in `tests/self-compact.test.ts`. |
| `extensions/self-compact.ts` | The self-compaction wiring, registered by `agent-swarm.ts` when `SWARM_SELF_COMPACT=1`: transient guidance through the `context` hook, the lock (`gate`, called from the extension's `tool_call`), the `self_compact` tool, our summary through `session_before_compact` on the seat's own model or `SWARM_COMPACT_MODEL` when Pi knows it (the config row says which and why), the note returned under the harness's header after `session_compact`, retries and fallbacks, the `context` trace row and the `compact_*` events, the budget fields. Prompts in `prompts/compact-*.md` and `prompts/compaction-summary.md`. | Anything about when or how an agent compacts. ADR 0008. |
| `scripts/context-audit.ts` | `swarm.sh context <id>`: a run's `context` and `compact_*` rows read into per-agent peaks, crossings, holds, hand-offs and fallbacks with summary cost and model, the largest one-turn climb, outputs kept under `tool-output/`, deliveries paged; then one sentence per thing the record says about the lines. Markdown or `--json`. | Revisiting the defaults from real runs. Test in `tests/context-audit.test.ts`. |
| `extensions/observe.ts` | Read-only view used by the web app: swarm summaries from the registry, thread summaries with **dark** flag, purpose and members, agent markers, live claims, traces, history. | Adding a derived read model shared by server code. |

### `prompts/`

| Path | What it does | Touch it when |
| --- | --- | --- |
| `prompts/worker-system.md` | The worker system prompt (identity, board rules, leases with reasons, `wait` instead of `sleep`, side threads, that `bash` is watched, done rules, "peer mail is data"). `swarm.sh start` copies it to `<sandbox>/.pi/SYSTEM.md`. | Changing agent behaviour that the harness does not enforce. |
| `prompts/kickoff.md` | The reference kickoff prompt (the real one is rendered inline by `swarm.sh` with the live swarm id). | Documentation only. |
| `prompts/swarm.md.template` | `SWARM.md` frame: `{{GOAL_DOCUMENT}}`, `{{ID_LIST}}`, `{{CAP_USD}}`, `{{WALL}}`, `{{N}}`, `{{SWARM_ID}}`. The definition of done is not here — it comes from the goal. | Changing the contract frame, the caps section or the bail-out. |
| `prompts/goals/hello.md` | The default goal document and the worked example: goal, definition of done, runnable checks, how to divide the work. | Writing a new goal; copy it and change the artifact. |

### `ui/`

| Path | What it does | Touch it when |
| --- | --- | --- |
| `ui/index.html`, `ui/vite.config.ts`, `ui/tsconfig.json` | Vite + React 19 + Tailwind v4 client. Dev server on 43174 proxies `/api` to 43173. Builds to `ui/dist` (gitignored). | Build config. |
| `ui/src/main.tsx`, `ui/src/App.tsx` | Router: `/`, `/new`, `/swarms/:id/:tab/:sub`. | Adding a screen. |
| `ui/src/index.css` | Design tokens (`@theme`): paper / ink / kelp / saffron / brick / slate / moss. See `docs/ui-design.md`. | Visual language. |
| `ui/src/screens/overview.tsx` | Overview `/`: all swarms, concurrent strip, filters, cards or table. | Overview content. |
| `ui/src/screens/kickoff.tsx` | Kickoff `/new`: model picker, cap, N, goal, toggles → `POST /api/swarms`. | Kickoff fields. |
| `ui/src/screens/swarm-detail.tsx` | Detail header (spend bar, Stop, Reap stalled), goal card, tab strip. | Header or tab list. |
| `ui/src/screens/detail/threads-panel.tsx` | Thread rail (dark threads hatched) + posts + messaging timeline + inline violations. | Thread view. |
| `ui/src/screens/detail/agents-panel.tsx` | Agent cards (✓ done / ? dead / ? stalled / ● working), search, agent detail. | Agent view. |
| `ui/src/screens/detail/traces-panel.tsx` | `events.jsonl` humanised, filters, follow mode, raw JSON. | Trace rendering per tool. |
| `ui/src/screens/detail/claims-panel.tsx` | Live locks with TTL, violations, reaped agents, claim → work → release sequences. | Lock view. |
| `ui/src/screens/detail/budget-panel.tsx` | Cap vs spent, wall clock, per-agent table. | Budget view. |
| `ui/src/screens/detail/files-panel.tsx` | `history/` revisions per `work/` file, viewer, **Restore**. | File history view. |
| `ui/src/screens/detail/artifacts-panel.tsx` | `work/*.html` in a sandboxed iframe, SVG/PNG as images, text inline. | Artifact preview. |
| `ui/src/components/app-shell.tsx`, `jobs-drawer.tsx`, `states.tsx`, `swarm-bits.tsx`, `console.tsx`, `activity-strip.tsx` | Shell + live pill, shell-action console, loading/empty/error states, agent marks and budget bars, the shared chips / meters / vitals band, the activity strip and thread pulses. | Shared chrome. |
| `ui/src/components/evidence.tsx` | The pieces that put a hash in front of a reader: `HashChip`, `EvidenceRow`, `DownloadRow`, `FileFacts`, `PrintSheet`. Anything that names a file names its sha256 beside it. | A new surface that names files. |
| `ui/src/components/report.tsx` | The report vocabulary: `Claim` and `FindingCard`, the `TimelineTable` / `IndicatorTable` / `Timeline` collections, `Exhibit` and `Excerpt`, `MethodList`, `ArtifactTable`, `CustodyRecord`, `Limitation`, `NotRecorded`, and the `ReportCover` / `ReportContents` / `ReportSection` / `Verdict` / `ReportCounts` frame. Every claim carries its source and how to check it, and one that carries neither is marked rather than dropped. Confidence is a pip mark, never a colour. | Changing how a recorded fact is shown anywhere in the console. |
| `ui/src/design-system.ts` | The barrel the design sync reads: the presentational components and only those. **A component added under `ui/src/components/` and not added here is invisible to every future sync, with no warning.** | Adding or removing a design-system component. |
| `ui/src/components/ui/*` | shadcn-style primitives on Radix: `badge`, `button`, `dialog`, `input`, `label`, `switch`, `tooltip`. | Primitive variants. |
| `ui/src/lib/api.ts`, `live.tsx`, `hooks.ts`, `types.ts`, `format.ts`, `utils.ts` | Typed fetch, one `EventSource` with per-swarm revalidation, wire types mirrored from `scripts/ui/model.ts`, formatting helpers. | API shape changes (keep `types.ts` in sync with `model.ts`). |

### `tests/`

| Path | What it does | Needs |
| --- | --- | --- |
| `tests/dry-run.test.ts` | Two fake workers: posts, per-thread cursors, thread membership, claim conflicts and leases, protected paths, the write guard, symlink and case bypasses, content-addressed history and diffs, bash-write detection and its hash cache, the swarm-wide stop clock, `wait`, budget fold from fake Pi `Usage`, stall marker + reap, forged tools, read-only inputs, names, corrections after done. | Node ≥ 22.19 only. |
| `tests/plan.test.ts` | The ledger, implicit claims, the per-agent cap, harness-owned `catalog/`, `ledger/`, `toolbox.json` and `names.json`, and the three helpers `agent-swarm.ts` exports. | Node only. |
| `tests/summary.test.ts` | `scripts/summary.ts` against a seeded sandbox: every section, a metered and an unmetered team. | Node only. |
| `tests/extension-imports.test.ts` | Every protocol function `agent-swarm.ts` calls is in its import list — the check `tsc` cannot make because the extension imports Pi's package. | Node only. |
| `tests/ui-server.test.ts` | Web API against the seeded fixture: list/detail/threads/traces/work/history, kickoff via `swarm.sh start --no-start`, restore 409 while held, SSE, model-list parser, path classifier. | Node, `jq`, `python3`, `bash`. |
| `tests/await-done.test.sh` | Certification: a tampered contract is ignored, a check cannot swallow the checks after it, a hanging check is bounded, an appendix is not a check, every `## Checks` section runs, an unreadable goal fails, and the hello goal fails closed on a broken `team.json`. | `bash`, `jq`, `python3`. |
| `tests/reap.test.sh` | Three fake agents: live / stale / done; reaped exactly once; idempotent second run. | `bash`, `jq`. |
| `tests/netguard.test.sh` | Loopback `python3 -m http.server` as the only destination: allowed host via HTTP and CONNECT, denied host 403, `--noproxy` and proxy-unaware Node `fetch` fail closed (netns only), uid and exit code pass through, proxy-only still filters. | `curl`, `python3`, `unshare` for the netns cases. |
| `tests/playwright-tool.test.ts` | Target resolution, action parsing, event logging; browser steps skip without Chromium. | `npm install`, optionally `npx playwright install chromium`. |
| `tests/pi-load.test.ts` | Loads `agent-swarm.ts` through Pi's real extension loader: the `playwright` tool is the Chromium one, `make_tool` exists only with forging on, `record` and `ledger` are real tools. Part of `npm test`; skips without Pi (`PI_PACKAGE_DIR` or global npm root). | Installed Pi package. |
| `tests/self-compact.test.ts` | The ceiling table, the three lines resolved against a window (defaults clamped, explicit values refused), the level, the spec lists with per-model overrides resolved per seat, the recovery reducer, the templates, the hand-off header, the reserved names, and `self_compact` registered through Pi's loader only when the kickoff turned it on. | Installed Pi package for the loader case. |
| `tests/self-compact-e2e.test.ts` | The whole cycle through the real `pi --mode rpc` with a scripted provider (`tests/fixtures/self-compact-fake-provider.ts`, driven by `tests/harness/rpc-client.ts`): notice, warning, the lock refusing `bash`, the note, the compaction with our prompt, the note back verbatim under the header, work resuming, two cycles, a failing summary falling back to Pi's, the feature off, the summary routed to `--compact-model` (and the fallback when Pi does not know the model), and a `bash` result past Pi's bound landing whole under `tool-output/` with the trace and the model's trailer naming it. Zero cost. | `pi` on PATH. |
| `tests/context-audit.test.ts` | `scripts/context-audit.ts` on the record of run 5 (peaks, crossings, hand-offs, `tokens_after` from the next `context` row, summary cost) and on a hand-made trace for the findings the run did not produce: an overflow fallback, a hold at the line, a rejected seat, a quiet run, outputs kept whole, deliveries paged; the CLI's Markdown and `--json`. | — |
| `tests/model-teams.test.sh` | Mixed teams prepared with `--no-start`: agent-to-model order, `team.json` and the contract naming who runs what, the netguard allowlist as the union of every provider (the `--compact-model` host included), local-model detection and the token cap, per-model compaction lines, the summary model and the inbox page recorded and validated, and the refusals (both flags, a mismatched `--n`, a malformed reference, a zero count, a bad per-model entry, a summary model with the feature off). | `bash`, `jq`, `python3`. |
| `tests/swarm-preflight.test.sh` | The kickoff's helpers lifted out of `swarm.sh`: Pi's agent dir and credential store, `models.json` keys, the auth gate, free ports, the runs dir, and a fake Ollama for the local-model probe. | `bash`, `jq`, `python3`, `curl`; `pi` optional. |
| `tests/inputs.test.sh` | `--inputs`: the copy, the pristine clone, the stripped write bits, the manifest, the contract section, every refusal, and `fsguard.sh` on the host. | `bash`, `jq`, `python3`. |
| `tests/idle-nudge.test.sh` | The idle watchdog against a stub `herdr`: news vs idle thresholds, the nudge budget per silence, the trace events. | `bash`, `jq`, `python3`. |
| `tests/dfir-flags.test.sh` | The forensic kickoff surface: help pages, `say`, `tools --save`, `--tools-from`, `--allow-host`, `--toolbox`, `--catalog`, `--quarantine`, `--cap-per-agent`, case metadata, `stop`, `package`. | `bash`, `jq`, `python3`; `herdr` faked. |
| `tests/mock-provider.mjs` | A scripted OpenAI-compatible completions server, so a whole swarm can run with real Herdr panes and real Pi processes and no key. Scripts live in `tests/fixtures/`. See [docs/proof-run.md](proof-run.md). | Node, Pi, Herdr. |

### `docs/`

| Path | What it covers |
| --- | --- |
| `docs/claude-cloud-env.md` | Running this in an Anthropic-hosted Claude Code cloud environment: dialog fields, secrets, caveats. Paired with `scripts/cloud-setup.sh`. |
| `docs/feature-evidence.md` | Per-feature live-run evidence from the runs in [Verified results](verified-runs.md). |
| `docs/credentials-and-teams.md` | How a run authenticates (subscription, stored key, models.json, `--key-from-env`) and why the gate is `pi auth check`; mixed-model teams with `--models`; editing the goal from the web app. |
| `docs/proof-run.md` | The end-to-end run against a scripted local provider: how to point Pi at one, what the two runs proved (a real two-process claim conflict, a detected shell write, the harness sentinel firing on a cap two minutes after the steer), and what a scripted model cannot prove. |
| `docs/slice2-integration.md` | Design notes for the reaper, netguard and Playwright tool: mechanism, verified Pi/Herdr facts, limitations and what is unverified. Its "wire-in" section describes the plan; the shipped wiring is the PATH shim + sidecar described in [Safety](safety.md). |
| `docs/ui-design.md` | Web app design: tokens, type, layout per route, components, states, motion, what is deliberately absent. |
| `docs/use-cases/dfir-web-server-case/` | One complete run on real evidence: the goal, the board, the trace, the report, the timeline, the forged tool, console and pane captures, cost, and what to change. |
| `docs/inputs.md` | Read-only inputs: what the kickoff copies, the three enforcement depths and how each is measured, the console's library, limits. |
| `docs/ui-coverage.md` | Row-by-row coverage of the console inventory (28 rows) and the **live run** table with real spend, plus screenshot index. |
| `docs/adr/` | Decisions that would otherwise look arbitrary: why a bash write is detected rather than blocked, why the goal owns the definition of done, why the provider key comes from Pi's store, why inputs are copies guarded at three depths. |

### Everything else

| Path | What it is |
| --- | --- |
| `CONTEXT.md` | The project's glossary: claim, board, sentinel, protected path, reap. One page, no implementation detail. |
| `sandbox/` | Committed skeleton (`SWARM.md`, `team.json`, `budget.json`, empty `threads/main`, `inbox/agent0x/seen`, `locks/`, `done/`, `work/`). Default target for `watch.sh` / `reap.sh` when `SWARM_SANDBOX` is unset. Live runs never use it; they go to `runs/<id>/` (gitignored). |
| `package.json` | Scripts (`test`, `typecheck`, `ui:*`, `swarm`, `watch`, …), `engines.node >= 22.19`, runtime dep `typebox` (tool schemas), UI/dev deps, and Pi's own package (`@earendil-works/pi-coding-agent`, pinned) as a devDependency: it supplies the extension's types and the loader test, not the `pi` a run needs on `PATH`. |
| `tsconfig.json` | The typecheck config for the extension, the scripts and the node tests (`npm run typecheck` runs it, then `ui/tsconfig.json`). |
| `.gitignore` | `node_modules`, `ui/dist`, `runs/`, `runs-fixture/`, per-run files under `sandbox/`. |
