# Usage

Every command, flag, environment variable and API route, and how to write a goal. The README's quick start is the short version of this.


### `scripts/swarm.sh`

```
scripts/swarm.sh start --model <provider/id> --cap-usd <n> --n <N>
    [--models "<provider/id>=<k>[@USD],..."]
    [--compact-at SPEC] [--compact-warn-at SPEC] [--compact-notice-at SPEC]
    [--compact-model P/ID] [--inbox-page-chars N]
    [--goal-file FILE | --goal "<markdown>"]
    [--sandbox DIR] [--label NAME] [--wall-clock MIN] [--hard-kill] [--playwright]
    [--cap-per-agent USD] [--cap-tokens N] [--idle-nudge-sec N]
    [--allow-tool-forging] [--allow-install] [--no-pypi] [--tools-from DIR]
    [--no-read DIR]...
    [--inputs DIR] [--inputs-enforce auto|on|off] [--inputs-max-mb N]
    [--catalog] [--toolbox <sets>|auto|off] [--toolbox-required] [--quarantine]
    [--allow-host HOST]... [--case-id ID] [--examiner NAME]
    [--probe-violation] [--no-netguard] [--open-net] [--net-allow] [--local-only] [--no-start]
    [--key-from-env] [--env KEY=VALUE]...
scripts/swarm.sh list
scripts/swarm.sh status <id>
scripts/swarm.sh stop <id>
scripts/swarm.sh summary <id>
scripts/swarm.sh context <id> [--json]
scripts/swarm.sh package <id>
scripts/swarm.sh tools <id> [--save DIR]
scripts/swarm.sh say <id> "<message>"
scripts/swarm.sh ui [--port N] [--host H] [--no-build] [--inputs-root DIR]... [--allow-inputs-root-from-ui]
scripts/swarm.sh reap [id] [--stall-sec N] [--stop]
scripts/swarm.sh netcheck
scripts/swarm.sh help [command]
```

`swarm.sh --help` prints the commands and the options a run usually needs.
`swarm.sh help start` (or `start --help`) prints every `start` option with its
default; a test holds that page to the parser, so an option that exists is on
it. A wrong command line prints the mistake and where to read, not the manual.

#### `start`

| Flag | Required | Default | Effect |
| --- | --- | --- | --- |
| `--model provider/id` | yes, unless `--no-start` | — | Passed to `pi --model`. The prefix picks the provider key variable and the netguard allow host. |
| `--cap-usd N` | yes, unless nothing on the team bills | — | Swarm-wide spend cap written to `budget.json`. At `spent_usd >= cap_usd` the first agent over gets a steer to `done cannot_complete`. A team whose every model is unmetered (a local server, or a `models.json` provider with no `cost` block) reports an exact $0 whatever happens, so this cap cannot stop it; such a team needs `--cap-tokens` instead and may leave this out. |
| `--n N` | yes | — | 1–30 agents. Warns above 10. The harness assigns no roles and adds no artifacts of its own — if you want a critic, say so in the goal. |
| `--goal-file FILE` | no | `prompts/goals/hello.md` | The goal document. Must contain `## Definition of done`; its `## Checks` lines are what `await-done.sh` runs. Stored in the registry and shown in the UI. An investigation from the library (`library/<category>/<slug>.md`) launches as it is: the metadata block at its top is stripped, and the contract starts at `## Goal`. |
| `--goal "markdown"` | no | — | The same document inline. Same rule: no definition of done, no swarm. |
| `--key-from-env` | no | off | Read the provider key from the shell and pass it to each pane instead of letting Pi use its own store. For hosts with no persistent home; the key is briefly visible in `ps`. A subscription login needs neither a key nor this flag, and a local server has no key to forward: the kickoff refuses the combination rather than scanning the shell for someone else's. |
| `--models` | no | — | A mixed team: `provider/id=count`, comma-separated, e.g. `openai-codex/gpt-6-astra=3,deepseek/deepseek-v4-pro=2`. N is the sum of the counts. Every model is credential-checked and every provider's hosts reach the netguard allowlist. Mutually exclusive with `--model`. An entry may end in `@cap`, a USD ceiling on the combined spend of every agent running that model — `openai/gpt-5.4-mini=2@6,openai/gpt-5.4-nano=2@4` — for a team where the cost is in the model rather than the seat, which one `--cap-per-agent` number cannot fit. Over it, each agent on that model is steered to finish and stopped the way the per-agent cap does it, and the other models' agents go on. A per-model cap must fit under `--cap-usd`. Written to `budget.json` and the registry as `cap_per_model_usd`. See [docs/credentials-and-teams.md](credentials-and-teams.md). |
| `--env KEY=VALUE` | no | — | Extra environment for every agent pane; repeatable. `PI_CODING_AGENT_DIR` must be absolute. |
| `--sandbox DIR` | no | `runs/<id>` | Isolated cwd for this run. |
| `--label NAME` | no | `swarm-<id>` | Herdr workspace label and UI label. |
| `--wall-clock MIN` | no | 8 (N<10), 15 (N≥10), 20 (N≥20) | Written to `SWARM.md` and `budget.json`. **Enforced**, the same way the spend cap is: agents are steered to `done cannot_complete`, and if the swarm is still over one grace period later the harness writes the sentinel itself. |
| `--hard-kill` | no | off | After the cap steer, also call Pi `ctx.shutdown()` on that agent. |
| `--playwright` | no | off | Adds `playwright` and `browser_check` to the agents' `--tools`. |
| `--allow-tool-forging` | no | off | Agents may write tools with `make_tool` and share them: a script under `tools/<name>/` becomes a real tool for every agent on its next `inbox` / `wait`. Runs as a subprocess with the same limits as `bash`. Recorded as `tool_forging` in the registry. See [forged-tools.md](forged-tools.md). |
| `--no-self-compact` | no | on | Turn self-compaction off. On by default: each agent watches its own context against an effective ceiling the harness sets per model (272k for the GPT-5.4/5.5 family, 200k for grok-4.6, 300k for a million-token model, the declared window otherwise), receives a transient notice and warning as it climbs, and at the compact line every tool except `self_compact`, `budget` and `done` is refused until it hands off with `self_compact(note_to_self)`; the context is summarized with `prompts/compaction-summary.md` and the note comes back verbatim under the harness's own facts (live claims, unread posts, the ledger). Pi's own overflow compaction stays as the safety net and is recorded as such. Recorded as `self_compact` in the registry; a `context` row per turn and every `compact_*` event on the trace; `context_ceiling`, `context_level`, `compactions`, `compaction_usd` and `handoffs` per agent in `budget.json`. `--self-compact` says on explicitly. See [self-compaction-plan.md](self-compaction-plan.md). |
| `--compact-at SPEC` | no | `60%` | The compact line, as a token count (`150000`, `150k`, `0.5m`) or a percentage of the ceiling, optionally followed by per-model overrides, comma-separated: `60%,openai/gpt-5.4-mini=55%,grok-4.6=70%` (a key with a slash is a `provider/id`, one without matches the model id under any provider; the last match wins; a list with no seat value leaves the seats it does not name on the default). Never above what the window can hold once Pi's reserve and 32k of headroom are kept; an explicit value that does not fit is refused, a default that does not fit is clamped and noted on the trace (`compact_config`, which also records which per-model entry applied under `matched`). A line left unset is a default fitted to the lines you set, per seat and noted on the same row: it rises to a higher line set below it (the compact line no higher than the window holds) and drops below a lower line set above it in the defaults' 40 : 50 : 60 proportion, so `--compact-at 45%` alone runs at 30 / 37.5 / 45%. Two lines you set that are out of order are refused. The kickoff and the run's detail page mark an unset line `(default)` when another is set; `self_compact.set` in the registry says which lines were set. |
| `--compact-warn-at SPEC` | no | `50%` | The warning line: finish the current atomic step, write the note, hand off. Same shape as `--compact-at`. |
| `--compact-notice-at SPEC` | no | `40%` | The notice line: awareness only. Same shape. |
| `--compact-prompt-file FILE` | no | `prompts/compaction-summary.md` | Replace the system prompt of the summary call. |
| `--compact-model P/ID` | no | each agent's own | Send every summary call to this model: a cheap summarizer for expensive seats. It is credential-checked and its provider's hosts join the netguard allowlist like a seat's model, and it never counts as a seat (no cap, no share of `--models`). Recorded as `self_compact.model` in the registry; `compact_config` says which model the seat will use (`summary_model`, `summary_model_source`) and `compact_done` which one wrote each summary; a model Pi's registry does not know falls back to the agent's own and the config row says so (`summary_model_problem`). The summary's cost is the summarizer's, counted in `compaction_usd`. Refused with `--no-self-compact`. |
| `--inbox-page-chars N` | no | `40000` | How much post text one `inbox` or `wait` delivery carries. Whole posts only: a post is never cut, a delivery stops before the post that would break the bound, what stayed behind is still unread and the next call (or `wait`, at once) delivers it; the result says `remaining` and why. `0` removes the bound. Recorded as `inbox_page_chars` in the registry. |
| `--inputs DIR` | no | — | Hand the swarm a read-only copy of `DIR` as `inputs/`: the tools refuse to write it, a shell write is detected and healed from a pristine copy, and where the host can (macOS `sandbox-exec`, Linux mount namespace) the panes run with it read-only at the kernel. Recorded as `inputs` in the registry. See [inputs.md](inputs.md). |
| `--inputs-enforce M` | no | `auto` | `auto`: kernel guard when the host has one, otherwise a `WARN`; `on`: refuse to start without one (exit 3); `off`: detection and healing only. |
| `--inputs-max-mb N` | no | 512 | Refuse an inputs directory larger than N MB before copying. |
| `--catalog` | no | off | Before the agents start, run the standard first pass over the inputs once (`scripts/evidence-catalog.sh`): for a disk image the partition table, per partition a body file, a MAC timeline and a path list (a logical volume image with no partition table is catalogued from sector 0); for a memory image Volatility's info, pslist, psscan, cmdline, netscan, malfind and dlllist. Lands in `catalog/`, harness-owned and read-only, indexed in `catalog/README.md` and rendered into `SWARM.md`. Needs `--inputs`; implies `--quarantine` and `--toolbox dfir`. |
| `--toolbox M` | no | `off` | `dfir`: check the forensic toolbox on this host (`scripts/toolbox.sh`: Sleuth Kit, Volatility 3, regipy, python-evtx, yara, exiftool, sqlite3, strings, python3) into `toolbox.json` and a Toolbox section of `SWARM.md`, with install commands for what is missing; `auto`: `dfir` when `--catalog` is set; `off`. |
| `--toolbox-required` | no | off | A missing tool is a `BLOCKER` (exit 3) instead of a `WARN`. |
| `--quarantine` | no | off | `work/extracted/` and `work/quarantine/` cannot execute: no-exec at the kernel where the host can (`fsguard.sh --noexec`), and the harness strips execute bits from anything written there. Evidence pulled out of an image is for reading, never for running. |
| `--tools-from DIR` | no | — | Seed `tools/` from a library of tools forged in earlier runs: one directory per tool, each with its `manifest.json` and script. They are in every agent's list from the first turn, author and version kept, so a swarm does not rewrite what the last one wrote. `swarm.sh tools <id> --save DIR` puts a finished run's tools into such a library. |
| `--allow-install` | no | off | Agents may install the Python packages a case needs: `pypi.org` and `files.pythonhosted.org` join netguard's allowlist, `PYTHONUSERBASE` points at `work/.toolchain/` inside the sandbox, and the contract tells the agents the rule and asks them to record what they installed. There is still no root, nothing mounts, and Homebrew and the system package managers stay out — they write outside the sandbox. Recorded as `allow_install` in the registry. See [safety.md](safety.md) and [credentials-and-teams.md](credentials-and-teams.md#what-a-run-may-install). |
| `--no-pypi` | no | off | With `--allow-install`: `pypi.org` and `files.pythonhosted.org` stay off netguard's allowlist. pip is still pointed into `work/.toolchain/` and what comes through is still inventoried, but the network refuses the index, and the contract tells the agents that instead of inviting them to try; on one published run the invitation was what an agent walked around. Recorded as `install_hosts: false`. |
| `--no-read DIR` | no | none | A directory the panes may not read, denied at the kernel; repeatable. Reads are open by design, so this is narrow on purpose: a previous run's findings on the same evidence, above all, so a re-run cannot read the back of the book. Recorded as `no_read` and `no_read_applied` (whether the host could apply it). |
| `--cap-per-agent USD` | no | — | A cap per seat on top of `--cap-usd`: an agent over its own cap is steered to post what it has and call `done(reason=agent_cap)`, and a grace period later its own harness stops it. The swarm goes on. Written to `budget.json` as `cap_per_agent_usd`. |
| `--cap-tokens N` | required when nothing on the team bills | — | A swarm-wide cap in tokens: Pi's own totals (`input + output + cacheRead + cacheWrite`) summed over every turn of every agent. The brake for a team of local models, which bill nothing and so cannot be stopped by `--cap-usd`; an optional second brake for any other team. Over it, the same steer and grace period as the USD cap. The context is re-sent every turn, so a small goal on two agents is a few million and a seven-agent case runs to tens of millions. Written to `budget.json` as `cap_tokens`, next to `metered`. See [credentials-and-teams.md](credentials-and-teams.md#local-models-ollama-lm-studio-vllm-llamacpp). |
| `--allow-host HOST` | no | — | Add a host to the netguard allowlist for this run (repeatable): the provider hosts plus, say, a symbol server. A bare host means port 443 and nothing else, so anything on another port is named as `host:port` — a bare `127.0.0.1` would open every port on the machine, the console's included. Recorded as `allow_hosts` in the registry. |
| `--case-id ID`, `--examiner NAME` | no | — | Chain of custody: both go into the registry, the contract's title block and the run summary. |
| `--idle-nudge-sec N` | no | 180 | The idle watchdog (`scripts/idle-nudge.sh`, started next to netguard): an agent with no tool call for N seconds and no marker is prompted through Herdr to continue its seat or call done, at most three times, each an `idle_nudge` event on the trace. `0` turns it off. |
| `--probe-violation` | no | off | Dev only. Starts one extra agent `<id>pv` (not in `team.json`) without `claim_file`, told to do both: a `write` (which the guard must block) and a shell write (which the harness must detect and announce). |
| `--no-netguard` / `--open-net` | no | netguard on | Skip the netguard sidecar and PATH shim: open egress. |
| `--local-only` | no | off | Every model on the team must be served from this machine or this network — a `models.json` `baseUrl` on loopback, a private range, link-local or `.local`, or Pi's built-in `llama.cpp` provider — and the netguard allowlist becomes those endpoints and nothing else (`netguard --only`): the eight cloud hosts of the default list drop out. Panes also get `PI_OFFLINE=1`, so Pi makes no catalog-refresh calls at startup. Refused with a cloud model on the team, and refused with `--no-netguard`. Recorded as `net: "local"` in the registry. |
| `--net-allow` | no | — | Alias of the default (kept for older scripts). |
| `--no-start` | no | — | Prepare the sandbox, `SWARM.md`, `team.json`, `budget.json` and the registry entry, but start no Herdr/Pi. Used by the web API test and the UI's "Prepare only". |

What `start` does, in order: read and validate the goal document (no definition of done, no swarm) → allocate id → resolve the sandbox path and reset per-run files, including `work/` → render `SWARM.md` → write `team.json` + `budget.json` → copy `prompts/worker-system.md` to `<sandbox>/.pi/SYSTEM.md` → registry `prepared` → check `herdr`, `pi`, `jq` → check the credential store → start netguard sidecar + shim → `herdr workspace create --cwd <sandbox>` → pane grid (`√N` columns, max 5; new tab at `SWARM_PANES_PER_TAB`, default 30; new workspace if tab create fails) → `herdr agent start <id> --kind pi --pane <p> -- --approve --name <id> --session-dir <sandbox>/.pi-sessions/<id> -e extensions/agent-swarm.ts --tools read,bash,edit,write,post,inbox,wait,claim_file,release_file,claims,list_team,budget,file_history,file_restore,file_diff,thread_open,thread_join,inputs,name,record,ledger,done --model <model>` for each agent (with `--allow-tool-forging` the list travels in `SWARM_TOOLS` instead, so `make_tool`, `tools` and every forged tool can join it) → `herdr agent prompt <id> "Join swarm <id>. …"` → write `layout.json` → registry `running`.

Per-pane environment: `AGENT_ID`, `SWARM_ID`, `SWARM_HARD_KILL`, `PATH=<sandbox>/bin:$PATH`, `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY=http://127.0.0.1:<port>` (the swarm's own sidecar port, recorded in `<sandbox>/netguard.port`), `NODE_USE_ENV_PROXY=1`, empty `NO_PROXY`, and `BROWSER_CHECK_EXECUTABLE` if Google Chrome is found at `/usr/local/bin` or `/usr/bin`. No provider key, unless `--key-from-env` was passed.

#### `list`, `status`, `stop`

- `list` prints `ID STATE LABEL WS N MODEL SANDBOX` from `runs/registry.json`.
- `status <id>` prints the registry record, then `watch.sh --once`. Looking at a swarm does not reap anyone.
- `stop <id>` closes every Herdr workspace recorded for the swarm, kills the netguard sidecar (`<sandbox>/netguard.pid`) and the idle watchdog (`<sandbox>/idle-nudge.pid`), and sets state `done` when `done/SWARM_DONE` exists, `stopped` otherwise. It does **not** write `SWARM_DONE` and does not delete the sandbox.

#### `summary`, `package`

- `say <id> "<message>"` posts to a running swarm's board as the examiner: what an operator notices, or a tool that has just appeared on the host. Agents see it on their next `inbox` or `wait`.
- `tools <id>` lists the tools a run forged, with author, version and runtime; `tools <id> --save DIR` copies them into a library for `--tools-from`.
- `summary <id>` prints a Markdown run summary from the sandbox's files (`scripts/summary.ts`): outcome and markers, the team with what each agent called itself and its spend, by agent and by model, activity counts from the trace (tool calls, implicit claims, violations, forge hints, nudges, per-agent cap events, forged tools, the commands typed most), the ledger, the work files, and the chain of custody (case id, examiner, input hashes, the inputs checks, the toolbox, the catalog).
- `context <id>` prints the context history of every agent from the trace (`scripts/context-audit.ts`; `--json` for the same as data): per agent the model, the ceiling and the three lines it ran under, the turns, the peak, the lines it crossed, the holds, the hand-offs and Pi's own fallbacks with what each summary cost and which model wrote it, the largest climb in one turn, how many tool calls had more output than the model received (whole under `tool-output/`) and how many `inbox`/`wait` deliveries held posts back; then one sentence per thing the record says about the lines (a provider refusal, a hold at the compact line, a seat that handed off early, a run that never reached a line). A run with no `context` rows says it is not measured rather than guessing. The same record the console's Context chart draws.
- `report <id>` writes `<sandbox>/package/report.html`: one self-contained document — cover, summary of findings, scope and evidence with a sha256 per file, the timeline, indicators and findings as numbered exhibits taken from the ledger's own `seq`, the method, the artifacts with their hashes, the limitations, the chain of custody, and the swarm's own `work/report.md` reproduced verbatim. It fetches no stylesheet, script, font or image, so it reads the same on a machine with no network. `--pdf` prints it through Chrome, Chromium or Edge if one is installed (`SWARM_CHROME` names another); the browser numbers the pages, because `@page` margin boxes are unimplemented there and a number this document computed itself would be wrong in every other engine. `--lint` warns when a numbered section cites nothing checkable — a code span, an exhibit number, an inode, a record id or a registry key — and never fails. `--out PATH` writes somewhere else.
- `package <id>` writes `<sandbox>/package/`: `report.html`, `summary.md`, `artifacts.json` (every file under `work/` with its sha256, including the extracted material the package deliberately leaves behind), everything the run wrote under `work/` whatever its extension, the run's `tools/` with their manifests, the ledger (`ledger.md`, `ledger.jsonl`), `inputs.json`, `toolbox.json`, `team.json`, `budget.json`, `layout.json`, `netguard.allow`, `SWARM.md`, the catalog index, the trace, one file per board thread, and `MANIFEST.txt` with a sha256 per file. One walk of `work/` produces the report, the summary and `artifacts.json` together, so the hashes on the report's artifact table are the hashes in `artifacts.json`. What you hand over, with the hashes to prove it is what the swarm produced. `work/extracted/` and `work/quarantine/` stay in the sandbox — they came out of the evidence and may be live — and the command says how many files it left behind.

#### `ui`

`ui [--port N] [--host H] [--no-build] [--inputs-root DIR]... [--allow-inputs-root-from-ui]`. `--inputs-root` names where the evidence sets live (or `SWARM_INPUTS_ROOT`, `:`-separated); `--allow-inputs-root-from-ui` lets the token holder add one from the kickoff form, off by default (see docs/inputs.md). Defaults `SWARM_UI_PORT=43173`, `SWARM_UI_HOST=0.0.0.0`, runs dir `SWARM_RUNS_DIR` (default `runs/`). Builds `ui/dist` when missing and `node_modules/vite` exists; `--no-build` skips that. Then `exec node --experimental-strip-types scripts/ui-server.ts`.

#### `reap`

`reap [id] [--stall-sec N] [--stop]`. Without `id`, every `running` swarm in the registry. Default stall `REAP_TIMEOUT` or 960 s (above the catalog's 900 s step, so a long `vol`/`fls` is not a stall). A pane Herdr reports as `working` is never reaped. `--stop` also closes the reaped agent's pane. Delegates to `scripts/reap.sh`.

#### `netcheck`

Runs `netguard.sh --only api.deepseek.com` around two curls: `https://api.deepseek.com/` must not return a proxy 403 or fail to connect (origin 401/404 is fine); `https://example.com/` must be 403 or unreachable. Prints the last 20 netguard log lines. Exit non-zero on failure.

### `scripts/spawn.sh`

```
scripts/spawn.sh [--dry-run] [--no-start] [--sandbox DIR] [--n 1-30] [--model provider/id] [--label NAME]
```

`--dry-run` runs `tests/dry-run.test.ts`. Otherwise forwards to `swarm.sh start` with `--cap-usd ${SWARM_CAP_USD:-3}` and, when set, `--goal-file "$SWARM_GOAL_FILE"` or `--goal "$SWARM_GOAL"`; with neither, `swarm.sh` uses its default goal file. Env: `SWARM_N` (2), `SWARM_MODEL`, `SWARM_SANDBOX`, `SWARM_LABEL`, `SWARM_CAP_USD`, `SWARM_GOAL_FILE`, `SWARM_GOAL`.

### `scripts/watch.sh`

```
scripts/watch.sh [--once] [--sandbox DIR]
```

Sandbox from `--sandbox`, else `SWARM_SANDBOX`, else the repo `sandbox/`. Interval `WATCH_INTERVAL` (2 s). Uses `watch(1)` when present, otherwise a loop. Sections: `DONE`, `AGENT DONE`, `STALL / REAP` (`? <id>.dead`), `LOCKS`, `MAIN` (post count + last 40 filenames), `WORK` (`hello.txt`), `BUDGET`, `EVENTS` (last 16, humanised), `HERDR` (agent count by status + first 40 agents).

### `scripts/await-done.sh`

```
scripts/await-done.sh [--sandbox DIR] [--timeout SEC] [--interval SEC]
                      [--check-timeout SEC] [--quiet]
```

Defaults: `SWARM_SANDBOX` or `sandbox/`, `SWARM_TIMEOUT` 480 s, `WATCH_INTERVAL`
8 s, `SWARM_CHECK_TIMEOUT` 30 s. Each round runs `reap.sh --timeout
${REAP_TIMEOUT:-960} --quiet --stop` and `watch.sh --once`.

Exit 0 when `done/SWARM_DONE` exists **and** every check passes. The checks are
the backticked spans on bullet lines under `## Checks`, read from the goal as
the registry recorded it — not from `<sandbox>/SWARM.md`, which the agents can
reach. (If the sandbox has no registry entry — a hand-made directory, or a
custom `--sandbox` without the matching `SWARM_RUNS_DIR` — it falls back to
`SWARM.md` and says so on stderr.) Each check runs in the sandbox with stdin
closed and a time limit, so one that reads a FIFO an agent left behind cannot
hang the wait.

A failing check is not fatal: the swarm may still be working, so it keeps
polling until `--timeout`. Exit 1 on that timeout, or immediately when the
goal's checks cannot be read at all. A goal with no checks exits 0 on the
sentinel alone and says so.

### `scripts/reap.sh`

```
scripts/reap.sh [--sandbox DIR] [--timeout SECONDS] [--stop] [--dry-run] [--quiet]
```

Default timeout `REAP_TIMEOUT` 960 s. A pane Herdr reports as `working` is skipped. Exit 0 always (housekeeping), 2 on usage or missing `jq`/`team.json`. See [Observability › Reaping](observability.md#reaping-and-the--mark).

### `scripts/netguard.sh`

```
scripts/netguard.sh [--allow h1,h2] [--only LIST] [--allow-file F] [--port N]
                    [--mode auto|netns|proxy-only] [--log FILE] [--dry-run] -- CMD [ARGS...]
```

Default allowlist `api.openai.com,api.deepseek.com,api.x.ai,generativelanguage.googleapis.com` (+ `NETGUARD_ALLOW`). `swarm.sh start` adds the model's host (`anthropic/` → `api.anthropic.com`, `openrouter/` → `openrouter.ai`, others already listed). `--only` replaces the list. Port `NETGUARD_PORT` (3128; `swarm.sh` gives each swarm's sidecar the first free port at or above `SWARM_NETGUARD_PORT`, default 43178, so concurrent swarms never share a proxy). Mode `auto` picks `netns` when `unshare -rn` works and `lo` can be brought up, else `proxy-only` with a WARNING. `--dry-run` prints mode, allowlist, proxy and command. Exit 3 if the proxy fails to start or `--mode netns` was forced where unavailable.

### `npm` scripts

| Script | Runs |
| --- | --- |
| `npm test` | the protocol, plan, summary, web API and extension-import suites, plus the Pi loader suite, which skips where Pi is not installed |
| `npm run test:bash` | every shell suite through `scripts/test-bash.sh`, one verdict per suite (`scripts/test-bash.sh reap inputs` runs a subset) |
| `npm run test:server` | web API tests only |
| `npm run typecheck` | `tsc -p tsconfig.json` (the extension against Pi's own types, the scripts, every node test) then `tsc -p ui/tsconfig.json` (the React client) |
| `npm run ui:build` / `ui:dev` / `ui:preview` | Vite build to `ui/dist` / dev server on 43174 with `/api` proxied / preview |
| `npm run ui:server` | `scripts/ui-server.ts` on 43173 without the build step — it still serves `ui/dist` if one is there |
| `npm run ui:fixture` | Seed five fixture swarms into `runs-fixture/` |
| `npm run swarm` / `watch` / `spawn` / `ui` / `dry-run` | Wrappers around the scripts above |

### The web app

The kickoff form's goal picker offers two shelves: the investigation library
([library/](../library/README.md), one goal document per kind of case, grouped
by category and read from the repo on every request, so an edit to a file is
what the picker offers next) and the operator's own goals (the files in
`prompts/goals/`, loadable, savable and deletable from the browser). Loading
replaces the editor, and edits you have not saved are asked about first; a
library entry may suggest a team size, a cap and a wall clock, which the form
applies only when asked. The model control switches between one model and a
mixed team. Each swarm has a **Goal** tab showing the goal document
and the rendered `SWARM.md` the agents read; the live contract is read-only, and
the way to change it is "edit a copy and relaunch". See
[docs/credentials-and-teams.md](credentials-and-teams.md).

Hierarchy is **swarms → threads → agents → traces**; kickoff, stop, reap and restore are our additions and labelled as such in the UI. Design language and states: `docs/ui-design.md`. Coverage against the console inventory and a live-run screenshot index: `docs/ui-coverage.md`.

| Screen | Route | What you see and can do |
| --- | --- | --- |
| Overview | `/` | Every swarm: model, N, spend/cap bar, tokens, calls, phase (running · done · stopped · prepared), elapsed; a strip totalling spend, tokens and calls across every swarm (with the running ones counted separately); status filters; card grid or table. |
| Kickoff | `/new` | Model picker (from `pi --list-models` when `pi` is on the server's `PATH`, else a static list, plus a custom field), USD cap, N slider, goal, **Playwright** and **Netguard** toggles, advanced label / wall clock / hard-kill / **Prepare only** (`--no-start`), and **Read-only inputs**: a set from `SWARM_INPUTS_ROOT` plus the kernel-guard choice (`--inputs`, `--inputs-enforce`). Shows the exact `swarm.sh start …` argv, then the job output, then navigates to the swarm. Also on the form: how the evidence is attached (copy with a size ceiling, bind in place, or a disk image), a clean room over earlier runs (`--no-read`), the tools of an earlier run (`--tools-from`), a required toolbox, and, with installs allowed, keeping the package index off the allowlist (`--no-pypi`). |
| Swarm detail | `/swarms/:id` | Header with live spend bar, remaining, tokens, calls, elapsed vs wall clock, badges (cap hit, violations, sentinel); **Stop** (confirm dialog → `swarm.sh stop`) and **Reap stalled** (`swarm.sh reap <id> --stall-sec N [--stop]`); full `SWARM.md`. |
| · Threads | `…/threads/:thread` | `main` plus agent-opened threads with creator; a thread is **dark** (hatched, moon mark) when idle longer than `SWARM_THREAD_DIM_MS` (default 2 min) or its last tag is `hold`/`veto`/`stop`; posts with tag, callsign, time (file mtime); a 48-bucket messaging-density timeline with violation ticks; claim violations inline. Under the list, **what the board adds up to**: posts and characters, who spoke and who never did, the span, the median gap and the longest silence; the tag mix for the team and per speaker; the matrix of who named whom; every hold / veto / stop including the harness's own; the paths the posts cited; and the three longest silences with the post that broke each. All of it counted from `threads/` — `GET …/posts` returns every post across every thread. |
| · Agents | `…/agents/:agent` | Callsign (heuristic from the first `intro` post), id, role, mark (● working · ✓ done · ? stalled · ? dead), the paths it holds (from the lock directory, so a just-expired one can linger a moment — the Claims tab filters by expiry), per-agent spend/tokens/calls and context-window occupancy, last activity text; search; agent detail = that agent's trace under ALL / MESSAGES / TOOLS / **THINKING** / FAILURES / SESSION ENDS. THINKING is set as prose — one wrapped block per turn — and when it is empty it says why: this model returned no reasoning anywhere in the run (naming the models that did), this agent alone was quiet, or nobody reasoned at all. |
| · Traces | `…/traces` | `events.jsonl` humanised, up to 1000 matching lines; filters by agent, tool, text; oldest-first by default, newest-first on request; **Show all** reveals the `inbox`/`budget`/`read`/`bash`/`wait`/`thinking` chatter; follow mode. A row opens **in place** — its arguments and result as fields underneath it, one row at a time, no dialog, with RAW and COPY for the exact record — and says so when the harness kept an opening rather than the whole argument. Long lists are paged (25 / 50 / 100 / 250). Each row carries its duration. A line written by the trace collector carries `prev`, the sha256 of the line before it; the report's custody section says whether that chain is intact. |
| · Claims | `…/claims` | Live locks with TTL, `claim_violation` list (who, which file, whose lock), reaped agents, claim → work → release sequences per agent and path. |
| · Budget | `…/budget` | Cap vs spent, wall clock, per-agent usage table from `budget.json`. |
| · Files | `…/files/:path` | Opens with the read-only inputs when the swarm has them: source, every file, the guard measured per pane, healed writes, the final check. Then `history/` revisions per `work/` file with a viewer and **Restore** (operator claim → guarded restore → release → `file_restore` event; HTTP 409 while an agent holds the lock). |
| · Artifacts | `…/artifacts/:path` | `work/*.html` in an iframe served with `Content-Security-Policy: sandbox allow-scripts`, SVG/PNG as images, text inline; `done.output_file` highlighted. |
| Jobs drawer | header **Actions** | Every start/stop/reap job with argv, exit code, captured output, link to the swarm. |

Live updates: the server watches the runs dir recursively and pushes `change` events over `GET /api/events` naming the swarms touched and, in `by_swarm`, what kind of thing moved under each (`threads`, `events`, `locks`, `budget`, `history`, `work`, `tools`, `ledger`, `names`, `inputs`, `contract`, `done`, `team`, `registry`); open views revalidate what they read. Writes the console cannot show, Pi's session files, the proxy and watchdog logs, the inbox cursors and the lock-table mutex, are dropped at the server. Header pill: `live`, `live · polling` (watcher unavailable), or `offline`.

API (JSON, same-origin — the `access-control-allow-origin: *` these routes used to carry let any page the operator had open read a run's board, trace, goal and spend): `GET /api/health`, `/api/inputs` (the sets under `SWARM_INPUTS_ROOT`), `/api/library` and `/api/library/<category>/<slug>` (the investigation library, read-only: metadata for the picker, and the document with its metadata block removed), `/api/goals` and `/api/goals/<name>` (the operator's own goals; `PUT` and `DELETE` need the token), `/api/models` (`pi --list-models` plus every local provider in Pi's `models.json`, keyless or not, under `local`), `/api/models/readiness` (one `pi auth check` per provider, cached 60 s; the kickoff form defaults to a model whose provider is ready; a local server Pi will not list until it has a placeholder `apiKey` is reported as `status: "local"` with the fix, and a ready one carries `local: true`), `/api/jobs`, `/api/jobs/:id`, `/api/swarms`, `/api/swarms/:id?traces=N`, `/api/swarms/:id/threads/:thread`, `/api/swarms/:id/traces?agent&tool&q&limit&order=asc|desc`, `/api/swarms/:id/work`, `/api/swarms/:id/work/<path>` (raw bytes), `/api/swarms/:id/tool-output/<path>` (the whole output of a tool call whose result reached the model as a prefix, as a trace row's `full_output` names it; plain text, same symlink checks as an artifact), `/api/swarms/:id/history`, `/api/swarms/:id/history/rev?path&rev`; `POST /api/swarms` (`{model, cap_usd, n, goal?, label?, wall_clock?, playwright?, net?, allow_hosts?, netguard?, hard_kill?, tool_forging?, self_compact?, compact_notice_at?, compact_warn_at?, compact_at?, compact_model?, inbox_page_chars?, inputs?, inputs_enforce?, no_start?, cap_tokens?, cap_per_agent?, catalog?, toolbox?, quarantine?, case_id?, examiner?, allow_install?}` → 202 job; `self_compact` is on unless `false`, the three lines are token counts or percentages of the ceiling with optional per-model overrides (`60%,openai/gpt-5.4-mini=55%`), sent only when set, `compact_model` is a `provider/id` for every summary call (refused with the feature off) and `inbox_page_chars` a whole number of characters of post text per `inbox`/`wait` delivery (0 for no bound); `net` is `guarded`, `hosts`, `open` or `local` (`--local-only`); `cap_usd` may be 0 only with `cap_tokens`, which is how a team that bills nothing is started; `inputs` is a set name, resolved under `SWARM_INPUTS_ROOT` on the server; the case settings map to `--cap-per-agent`, `--catalog`, `--toolbox`, `--quarantine`, `--case-id`, `--examiner` and `--allow-install`, `catalog` needs `inputs`, `toolbox` is `dfir`, `crypto`, `linux` comma-separated or `auto` or `off`, and a `cap_per_agent` above `cap_usd` is refused), `POST /api/swarms/:id/stop`, `POST /api/swarms/:id/reap` (`{stall_sec?, stop?}`), `POST /api/swarms/:id/history/restore` (`{path, rev}`); SSE `GET /api/events` (`hello`, `change`, `job`).

### Writing a goal

The goal is a markdown document. It says what to build, how the team should
split it, when the work is finished, and how to check that. `swarm.sh start`
frames it as `SWARM.md` — adding only the team, the caps and the bail-out — and
refuses to start without a `## Definition of done`. For an investigation, start
from the library: [library/README.md](../library/README.md) is the contract the
published cases converged on (the questions, the seven ground rules, the
division of work, the definition of done, the standard checks) and every entry
there keeps it.

```markdown
## Goal

Draw a pelican riding a bicycle as `work/pelican.svg`: one self-contained SVG,
no external assets.

## Definition of done

`work/pelican.svg` is valid XML, renders with no console errors, and two
different agents have signed it off on the board by its content hash.

## Checks

- `test -s work/pelican.svg`
- `python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse('work/pelican.svg')"`
- `grep -c '^approved ' threads/main/*.md | awk -F: '{n+=$2} END {exit !(n>=2)}'`

## How to divide the work

Slices that divide cleanly: bicycle geometry, pelican anatomy, palette and
scene, render-and-measure tooling, adversarial verification. Check `claims`
and take an unclaimed one.
```

Rules that make goals work with this harness:

1. **Name the artifact and make the checks runnable.** Each backticked span
   under `## Checks` is run in the sandbox by `await-done.sh`; every one has to
   exit 0 before a run counts as finished. Prose bullets are for the agents and
   are skipped. Write the checks so they fail closed, and test them by hand
   before you trust them: `ids=$(jq -e …) && …` rather than
   `for id in $(jq …)`, which passes when `jq` fails, and
   `grep -l … *.md | wc -l` rather than `grep -rlc …`, which on BSD grep
   prints both a count line and a filename line for the same file and so
   counts one sign-off as two.
2. **Say how to split the work.** Peers coordinate on the board, not through a
   planner. A list of slices that divide cleanly gives them a first move and
   avoids the pile-up on one file at boot.
3. **Ask for review explicitly if you want it.** The harness assigns no roles.
   "One of you verifies and signs off by content hash before anyone calls done"
   is a sentence in the goal, not a flag.
4. **Keep the bail-out.** It is in the frame for a reason: the agents in the
   Hugging Face incident write-up had no safe exit from impossible tasks and
   "rarely gave up". If your goal contradicts it, the frame still wins.
5. **Keep the cap tight.** Start at `--cap-usd 1` for N ≤ 3. The 10- and
   30-agent runs in [verified-runs.md](verified-runs.md) spent $0.19 and $0.73
   under a $3 cap; spend scales with N, so raise the cap with the team, not
   before.
6. **Use the verification tools you enable.** With `--playwright`: "render
   `work/index.html` and post `console_errors` before calling done."
7. Under 256 KiB (`SWARM_GOAL_MAX_BYTES`); label `[A-Za-z0-9_-]{1,40}`.
