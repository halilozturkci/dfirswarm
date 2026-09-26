# Web app coverage vs. the UI inventory

Acceptance source: the console inventory (28 rows). Priority mapping: rows the inventory requires = `must`; rows it leaves open = `should`; operator controls (kickoff, stop, reap, restore) = `addition` — built because the task asked for them, labelled “our additions” in the UI.

Status: **done** = present and exercised against the fixture (`scripts/seed-fixture.ts`) by `tests/ui-server.test.ts` and the screenshot pass; **partial** = present with a stated limit.

| # | Inventory row (short) | Priority | Status | Where in our app |
| --- | --- | --- | --- | --- |
| 1 | Swarm list; ≥3 running + finished visible together | must | done | Overview `/` — card grid / table; fixture shows 3 running + 2 done + 1 stopped. `SwarmCard`, `SwarmTable` |
| 2 | Active / done status per swarm | must | done | `StatusDot` + a status chip on every row (running · finishing · done · stopped · prepared · finish failed · stop incomplete · failed), the phase on the detail header's vitals band. `finishing` is a VM run whose hub is putting the VMs away; `finish_failed` and `stop_incomplete` are their own phases, sentinel or not |
| 3 | Swarm-level live spend $, tokens, provider calls | must | done | Card stats + `ConcurrentStrip`; detail header stats. Data: `budget.json` via `SwarmRow` |
| 4 | Remaining budget (cap − spent) | must | done | `BudgetBar` ($ and %), header “Remaining” stat, Budget tab |
| 5 | Elapsed time | should | done | Card “elapsed / took”, header ticking counter (`useNow`), wall-clock bar in Budget tab. Done swarms freeze at `SWARM_DONE` mtime |
| 6 | Goal / kickoff prompt full text | must | done | `GoalCard` on detail (full `SWARM.md`, clamp + **Show all**) |
| 7 | Thread list: `main` + agent-created threads, with creator | must | done | Threads tab rail; creator from `threads/<name>/meta.json`, falling back to the first post's author for a thread opened before meta existed |
| 8 | Idle thread goes dark | must | done | `.thread-dark` hatch + moon mark; rule = idle > `SWARM_THREAD_DIM_MS` (2 min) **or** last tag hold / veto / stop (`observe.ts`) |
| 8b | Thread purpose and member list | must | done | From `threads/<name>/meta.json`. Membership decides whose inbox a thread reaches, so an abandoned side thread is visible as one. Rail shows the member count; the header shows the purpose and the names. |
| 9 | Thread view: author + body + time, scrollable, message count | must | done | Posts column; time = post file mtime (`TimedPost.at`); “N messages” in thread header |
| 10 | Messaging timeline (gaps / busy phases) | must | done | `ActivityStrip` at the foot of a swarm's page: 96 buckets of messages against tool calls over the run's lifetime; `ThreadPulse` per thread with a dot per post |
| 11 | “Show all” equivalent | must | done | Goal + post bodies clamp with **Show all**; agents collapse past 12 with **Show all N agents**; Traces hides inbox/budget/read/bash/list_team chatter until **Show all (+n)** |
| 12b | Context-window occupancy per agent | must | done | Bar on the agent card from Pi's own `getContextUsage()`, plus a Context column in the budget table. Shown as `55.3k of 1.0M | 5%`. |
| 12 | Agent list: self-chosen name, ✓ done, ? dead/reaped | must | done | `AgentMark` (✓ moss, ? brick dead, ? saffron stalled, ● working). Callsign = heuristic on the first `intro` post (“Call me Scout”, “I'm Quill”); falls back to the id — the protocol has no name field |
| 13 | Per-agent last status text (done / session end / working) | must | done | `lastActivity()` in Agents tab: “done · reason”, “reaped · stall after Ns”, “posting”, “claiming work/x”, … |
| 14 | Agent search by name → detail | must | done | Search box (callsign, id, role) → `AgentDetail` |
| 15 | Agent detail: that agent's calls + current activity | must | done | `AgentDetail` = header + `/traces?agent=` list; Traces tab also deep-links via `/traces/:agent` |
| 16 | Raw traces, swarm-wide, tool + args + result readable | must | done | Traces tab `TraceRow`: humanised args/result per tool, raw JSON on click, a duration on every row, and what the call returned, whole (it was the first 2,000 characters; the harness keeps everything now) — `ok: true` is not correctness. A result the model saw only a prefix of carries `full_output` (path, bytes, sha256), and the detail links it to `/api/swarms/:id/tool-output/<path>`. **Corrected:** this row used to claim Pi does not expose model reasoning. It does — `message_end` — and the trace shows those rows, whole. The harness traces the built-in tools (`read`, `bash`, `edit`, `write`, `grep`, …) that previously left no line at all. |
| 17 | `inbox` result with sender; `post` content in trace | must | done | `post` shows `#thread [tag] “body”` (harness `summarizeArgs`, the body whole). `inbox` and `wait` event results are `{ n, from, ids, remaining }` (every delivered post's sender and id, whole — the lists once stopped at 20 — and what the page bound held back). TraceRow renders “n new from A, B” and links each sender to `/swarms/:id/agents/:agent`. |
| 18 | `done` with reason + output_file, then session end | must | done | `done` row shows `reason= output_file=`; `agent_stop` renders as **session end** (moss) |
| 19 | Claim violation human-visible: file, whose lock, who tried | must | done | Both places: inline brick row in `#main` thread view and Claims tab list (+ trace row, + header badge, + timeline tick). A row now says whether it was **blocked** (`edit`/`write`) or **detected after the fact** (`bash`), and the bash case explains that the change was snapshotted and can be restored. |
| 20 | Claim → work → release sequence per agent | must | done | Claims tab right column groups `claim_file → write/edit/file_history/file_restore → release_file` per (agent, path); open ones marked “still held”. Live claims now show the **reason** the owner gave and the remaining lease, and come from the live-claims list rather than the raw lock directory. |
| 21 | Reaped agent = `?`, reason in trace | should | done | `?` mark; `reap` / `reaped` rows show idle seconds + locks released; `marker_info` from `.dead` frontmatter in agent detail |
| 22 | Artifact preview: `done.output_file` + `work/` HTML/SVG/PNG in browser | must | done | Artifacts tab: sandboxed `iframe` (scripts off, origin off: an agent's page could otherwise send what it holds to any host from the examiner's browser), `<img>` for svg/png, text inline; `output` badge from `SWARM_DONE` frontmatter; header badge links to it; “Open in new tab” |
| 23 | file history / restore agent tools visible in trace; human restore optional | should | done | Trace rows (slate); Files tab lists `history/` revisions with viewer. **Restore** is our addition: operator claim → guarded restore → release → `file_restore` event; refused with 409 when an agent holds the lock |
| 24 | LAN access: second machine | must | done | `ui-server.ts` binds `127.0.0.1` by default; `--host 0.0.0.0` opens it to the LAN (an explicit choice), `--port`, default 43173. Watching is open to whoever can reach it; the four actions that spend money or change a run need a token. |
| 25 | Multi-window consistency | must | done | Each tab holds one `EventSource`; `fs.watch` → `change` → per-swarm revalidation. Verified: post written to disk appeared in an open tab without reload |
| 26 | Hierarchical navigation and back | must | done | Breadcrumb Swarms › swarm › tab › selection; header nav; routes `/swarms/:id/:tab/:sub` |
| 27 | Hello-world path (N=1) | must | done | Fixture `s1e77`: goal + “Hello from Scout” + trace ending `done → session end`; screenshot `11-done-hello.png` |
| 28 | CLI-started swarm appears instantly | must | done | Watcher on `registry.json`; kickoff test proves a `swarm.sh start` run shows up in `/api/swarms` and the list refreshes over SSE |
| — | Kickoff form | addition | done | `/new` → `POST /api/swarms` → `swarm.sh start` job; model list from `pi --list-models` or static fallback; “Prepare only” = `--no-start`. The goal field is a 32k markdown document and the form refuses one with no `## Definition of done`, the same rule the CLI enforces. Before Start, and on demand, the form runs `swarm.sh start --check` with its options (the start's own checks, nothing written) and shows its BLOCKER and WARN lines in its words; Start stays off while the check of that very form says 2. Extra environment (`--env KEY=VALUE`, one a line): the form checks the shape only, and swarm.sh's refusal comes back through the check; no value, and not the notify command, is shown in the check, the command preview, the job list or the operator's record. A “Where the agents run” card chooses microVM (the default) or host (unisolated) and holds the VM image, size, disk, snapshot and where the disks are kept, OAuth in a VM, and the model gateway when `swarm.sh help start` lists it; allow-root is host only. The rest of the form carries packs (with consent when a pack declares secrets), inputs (attach mode, a file cap, no verify copy), custody timeout, idle nudge, notify, a prior run's ledger, allow a synced folder, self-compaction and the team mode. Before Start, `GET /api/vm/readiness` asks `vm.ts probe` and `vm.ts capacity` (read-only, cached 60 s) and Start is disabled with the reason when a VM run would be refused. |
| — | Token on the mutating routes | addition | done | Start / stop / reap / restore need the bearer token the server prints in its URL fragment; reads and SSE stay open. |
| — | Stop | addition | done | Header **Stop** → `swarm.sh stop <id>` with confirm dialog, which carries stop's custody options (`--no-custody`, or `--custody-timeout SEC`). A stop that could not put every VM away exits 3 and the run shows as `stop_incomplete`, with each kept VM's reason in the VM panel |
| — | Reap | addition | done | Header **Reap stalled** → `swarm.sh reap <id> --stall-sec N [--stop]`, offered only while the run is running; for a VM run the dialog says a reaped seat has its VM stopped and its disk kept |
| — | Shell action console | addition | done | `JobsDrawer`: every start/stop/reap/hold/release/export/package/verify/purge/review with argv, exit code, captured output, link to the swarm |
| — | The record's actions | addition | done | Header **Record**: legal hold and release, export the ledger (CSV or a Timesketch import, downloaded from the finished job), package (`--sign` with the operator's SSH key), verify a package, and purge behind the run id typed out. Each is a `swarm.sh` command run with `SWARM_OPERATOR_VIA=console`, so it lands in `runs/operator-audit.jsonl` as the console's |

## Not covered / limits

- Inventory §2 mentions “thinking” and “batch calls” as trace labels. **Thinking
  is covered now** (`message_end` → a 240-character preview). Batch calls are
  still not exposed as an event; the harness logs each tool call with its own
  duration instead. “Calls” everywhere in this app means provider rounds —
  assistant messages that carried usage — not tool invocations.
- Post timestamps are file mtimes; posts have no `ts` in frontmatter. A `touch` on a thread file would move it on the timeline.
- Stopped swarms have no `stopped_at` in the registry, so “elapsed” keeps counting from `started_at` unless `SWARM_DONE` exists.
- Live provider run of the UI (real Herdr/Pi agents feeding it) is recorded below. Fixture + `--no-start` coverage stays in the table above; the live pass is the same screens with real spend, traces, and Herdr panes.

## Console parity pass (second look)

A second pass over the console inventory, against the re-skin. Each row is a console detail that was still missing, and where it now lives. All exercised on a real run (`s0010`, openai-codex subscription, N=3) and on the fixture (`s7a1c`, three threads) with zero console errors, desktop and phone width.

| Console detail | Where in our app |
| --- | --- |
| Every agent has its own colour, everywhere | `ui/src/lib/agent-colour.ts`: one ink per seat in team.json, used on post cards, joining chips, thread pulses, trace rows, agent cards, the Team panel |
| Per-thread activity line with a dot per post | `ThreadPulse` (`components/activity-strip.tsx`) in the thread list, in the story's *Side threads* cards; data is `ThreadRow.activity` |
| Bottom strip: “N messages \| N tool calls” histogram with the clock at both ends | `ActivityStrip`, sticky at the foot of a swarm's page; data is `SwarmView.activity` (`activitySeries()` in `scripts/ui/model.ts`, 96 buckets, lifecycle lines excluded) |
| Thread header: MEMBERS chips with post counts and ✓ / ? / ● | Threads tab header (`roster`), marks from the agent's marker |
| SHOW ALL / PREVIEW / RAW and “▲ LATEST” | Threads tab: view-mode segmented control, floating ▲ Latest that re-enables follow |
| Trace filter chips per agent with line count and spend | Traces tab chips from `TracePage.by_agent` (lines over the whole trace, spend from budget.json); dashed chip for an id outside the team |
| “RAW EVENT TRACE · N EVENTS”, session-end rows showing `tok \| $` | Traces header; `Tail` renders tokens and spend for `agent_stop`, duration for everything else |
| Click a trace row → its fields open underneath it | `TraceDetail` (one row at a time; fields, with RAW and COPY for the exact record) |
| Overview row: start time · threads · msgs · calls · tok | Second line of `SwarmLine`; `SwarmRow.threads_total`, `posts_total` |
| “N swarms \| N live” and `find a signal… ( / )` | Overview header line; `/` focuses the first `[data-find]` box on any screen (overview, threads, traces, agents) |
| Side threads in the story | `SideThreads` block after the phases, with purpose, pulse and members |
| Agent card context-window bar | `ContextBar` on every agent card and in the agent detail |
| Kickoff: the default model is one that will actually start | `/api/models/readiness` → `ReadyDot`, option labels “ready (subscription)”, a Credentials row per provider, a warning when the chosen provider is not logged in; blank wall clock explains swarm.sh's default for the team size |

Threads are now listed main first, then by most recent post (was alphabetical).

### Second look: every widget, four readers

The console inventory was split across four readers, and every widget they catalogued was checked against the app. Proven live on `sb36c` (openai-codex subscription, N=4, two side threads, 4/4 checks) at desktop and phone width with zero console errors.

| Console detail | Where in our app |
| --- | --- |
| Threads: `ORDER ACTIVITY / CREATED / VOLUME / MEMBERS` and `SHOW ALL / ACTIVE / DORMANT` | `SegBar` in the Threads tab; the primary thread stays on top whatever the order |
| `◆ PRIMARY THREAD` with a `RUNNING` / `DONE` badge; side threads plain | `ThreadLine` |
| A lane per agent on the pulse line (dots on the author's lane), ticks past 12 agents, the newest post ringed, the message count at the end | `ThreadPulse` `lanes` prop |
| `Agents:` chips under each thread — `●` / `✓` / `?` (dashed when dormant), name in colour, tool calls — ordered by who moved last | `ThreadLine` roster |
| Two-line preview of the latest post under the thread | `ThreadLine` |
| The thread as an overlay: red top rule, `public · created by X \| HH:MM:SS \| N messages`, `COMPUTE BUDGET` bar with `$left of $cap \| $spent \| N tokens`, `MEMBERS +name…`, `SHOW ALL` ⇄ `COLLAPSE ALL` / `PREVIEW` / `RAW`, oldest/newest toggle, `▲ LATEST`, footer caption | `ThreadOverlay` (a `Dialog`) |
| `▸ 1,931 chars` / `▾ collapse` on every post; `GOAL / STARTING PROMPT` badge on the mission post (the goal document, oldest on the primary thread); `HARNESS` badge on system posts | `PostBody`, `ThreadOverlay` rows |
| A freshly landed post washes green | `.post-fresh` |
| Agents: the last five trace lines on top; `ORDER ACTIVE / MESSAGES / THREADS / CALLS / COST / NAME` | `AgentsPanel` |
| Agent row: role glyph (◇ worker · △ critic · ○ other), `N threads / N messages / N calls`, an activity span from first to last call with a brick tick per failed call, `calls \| tokens \| $ \| failures`, token chips `read / write / cache r / cache w / total`, `CONTEXT WINDOW n of N \| p%` | `AgentLine`, `ActivitySpan`, `TokenChips`, `ContextBar`; data from `AgentRow.first_event_at / last_event_at / failures / failure_at / thread_posts` and `budget.agents[id]` |
| Agent detail: `glyph id \| role \| active from — to \| model`, `THREADS` (# name N), `AGENT STATS`, lenses `ALL / MESSAGES / TOOLS / THINKING / FAILURES / SESSION ENDS` over its own trace | `AgentDetail` |
| Trace rows: `→ #thread` in brick on post rows, thinking in purple italic | `TraceRow` |
| Model chip carries a provider glyph; the empty list reads `Quiet field`; the spend vital says `$x left of $cap` | `overview.tsx`, `swarm-detail.tsx`, `providerGlyph()` |

A failed call is one whose result says `ok:false`, carries an `error`, timed out, or was a blocked write (`claim_violation`) — `isFailureEvent()` in `scripts/ui/model.ts`.

Not built, on purpose: a blue "viewport" marker on the activity strip (a brush with nothing to brush), and a per-swarm selection tint on the list (the list navigates instead of selecting).

## microVM runs and the examiner's record

The fixture has a microVM run, `svm1d` (`web-server-vm`, three VMs, done): VM records with the whole probe, kept disks, msb's database state and logs; hub events with a refusal, a hub and a collector restart and a cap stop; a post a seat's harness code sent from its VM; inputs with md5/sha1; `custody.json`; chained operator-audit lines; ledger entries with a correction and a searched-not-found; one review line; a job store (a command that ran, a tool that failed and was sealed all the same, one cancelled before it ran, and an examiner's note added after custody). `tests/ui-server.test.ts` and the screenshot pass exercise every row below against it, plus synthetic records for the variants (a keeper that gave up, a hub that finished and exited, a FIFO spill).

| Surface | Where in our app |
| --- | --- |
| Isolation on every row | Overview chip (microVM, or “host · unisolated”, the latter for a record from before isolation) and a band chip on the detail; the fleet band says how many runs are in VMs and how many hubs are down. `net` for a VM run is `vm` or `vm-open`, never the host guard's word |
| VM lifecycle | One timeline across the run above the VM cards, built on the server over the whole trace (`ui/src/lib/vm-timeline.ts`): a lane for the run (kickoff, the keeper's hub and collector restarts, the finish, custody, the clear-up, the operator) and one per seat (created and probed, every link up and down, a cap steer or stop, the session's end, put away with the disk and msb's database), each mark in words in a list below it |
| VM panel (Agents tab) | One card per VM: size, uptime and longest run, a lifecycle line (created, probe, cap stop, put away, disk kept, msb's database), the probe's checks (`vm.ts` `probeChecks` itself, the rows `probeVerdict` refuses on, each with what it means), what the hub refused per seat, the kept disk's path, size and sha256 or why it was not kept with the remedy, msb's database in words, logs kept or not. The network policy and the placeholders are said once per run, with per-VM differences |
| Hub and keeper | Hub up only while its pid is this run's `vm-hub.ts`; a hub that finished the run and exited is said as that, never as “HUB DOWN”; restart counts for the hub and the collector; a danger note when the keeper gave up |
| Hub-sourced states | One source for a seat's state (`ui/src/lib/seat-state.ts`): while the hub hears from a VM, its word is the state in the band's counts, the Team list, the team strip and the Agents list, with the host's quiet as a note; without a live hub the host's markers decide. The hub's `status.json` lives outside the runs directory and is watched on its own (a real directory of this user's, never a link), so a seat's change reaches the console as it happens |
| Story and traces | A seat's harness post (`system via <seat>`) is the seat's post, never the harness's. Trace lanes: agent, infrastructure (hub, VM finish, restarts, custody, cap steers and stops) and operator (operator actions, opened with scripts), each line described in words; a seat's filter includes the hub's lines about it; spilled lines only when asked, marked as not on the chain |
| Jobs tab (Evidence group) | The run's tool jobs from `store/journal.jsonl` (`GET /api/swarms/:id/jobs`, `scripts/ui/store-jobs.ts`): totals over every job, the journal's chain and anchor, the service's degraded and recovered notices, examiner notes, custody's `store:` line and when it was verified; a table where the outcome (status, exit) and the record (queued … committed) are two columns, and committed is never drawn as success. A job: what it ran whole, its times, worker, requester and who was told, its manifest's files with sha256 (held to the journal, paged), the links it left named, stdout and stderr paged by bytes on a character boundary and whole on `?raw=1`, its journal lines and `job.json`. A run with no store says it had no job service |
| Custody tab (Output group) | The verdict, evidence digests compared (sha256, md5, sha1), the artifact index, each VM's finding joined to its record, the source check of the copy, provenance and host clock, the custody timeout, and who did what from the operator's record, its chain checked |
| Inputs per VM | How the evidence is held (in place or copied, read-only and no-exec in every VM), how the copy was checked against its source, each file's md5/sha1, links and special files marked, a name that is not UTF-8 shown as escaped bytes |
| Goal: how this run was started | Provenance (commit, Pi, Node, msb, image digest, OS), host clock, disks kept at, OAuth allowed, pack-secret consent, custody deadline, idle nudge, disk size and encryption, notify, a prior run's ledger, synced folder allowed |
| Budget | For a VM run the spend is what each VM reported through the hub, not metered by the host; seats stopped at their own cap are named |
| Report and dossier | The dossier adds the court set: `custody.json`, the custody anchor, `inputs.json`, each `vm/<id>.json` and this run's operator-audit lines, each with sha256 and a download. Each row is two-level: the description full width, the meta and the download below |
| Ledger | Examiner review: accept, reject or amend an entry with a note, and sign the ledger as it stands, through `swarm.sh review` (token required); the review file is read by `scripts/review.ts`'s own reader and its chain is checked and shown; a link or a FIFO in its place is an error on screen, never "not reviewed". Corrections (`supersedes`) are marked both ways; searched-not-found entries are their own list; the inputs no command named are listed as that and never as “covered”; the time as written shows when it was not UTC |
| Open with scripts | An HTML artifact is framed with no scripts; **Open with scripts** runs that one file once, after a warning, and the grant is recorded on the run's trace as an operator action, shown in the Artifacts tab |
| Packs | Each pack's declared secrets, by name and title, so the kickoff asks for consent before `--allow-pack-secrets`; the kickoff shows the image the chosen packs boot as `swarm.sh image-for` names it (reference, profile, digest, why), and checks that image in the readiness |
| Package | The Record dialog says what `swarm.sh package` left (when, how many files, the manifest's sha256, signed by whom) and offers the directory as one zip, made on download, which `swarm.sh verify` takes as it takes the directory; a link or a FIFO in the package is left out and counted |
| Layout | `tests/ui-server.test.ts` builds the UI from the source, serves it over the fixture and opens the key screens in Chromium at 390 px: none may scroll sideways, and each must have rendered. It skips with the reason when Playwright or its browser is missing; CI installs the headless shell before `npm test` |

No live VM pass is recorded in this document yet: the VM screens are proven against the fixture and synthetic records, not against a real microVM run.

## Live run

2026-09-16 on this VM. Kickoff was **only** `POST /api/swarms` from `/new` (the form), not `swarm.sh start` in a terminal. UI process inherited `DEEPSEEK_API_KEY` and nvm `pi` on `PATH`. Server: `scripts/swarm.sh ui --port 43173` bound `0.0.0.0`. `GET /api/models` → `{source:"pi", models: 46}` including `deepseek/deepseek-v4-pro` (official `pi --list-models` table: `provider` + `model` columns). Screenshots: store `media/webapp-live/`.

| Swarm | Label | N | Model | Cap | Spent | Tokens | Calls | How it ended |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `sc60f` | web-n6 | 6 | `deepseek/deepseek-v4-pro` | $1 | **$0.171158** | 429472 | 59 | `done/SWARM_DONE`. `work/index.html` (title `swarm-ok`, bouncing circle) + `work/summary.md` (six ids). 2× `playwright` ok. 5× `claim_file` `conflict:true`. Operator **Restore** `work/hello.txt` rev 1 (`file_restore` via `web`). |
| `s4081` | web-n2 | 2 | same | $1 | **$0.020167** | 49262 | 13 | Started from the form while `sc60f` was running. **Stop** in the UI (`swarm.sh stop s4081`, exit 0). Herdr workspace `wN` closed. |
| `scff0` | web-reap | 2 | same | $1 | **$0.015239** | 35111 | 10 | Extra live reap: `SIGSTOP` `scff000` (held `work/hello.txt`), then UI **Reap stalled** `--stall-sec 12 --stop`. Both `.dead`; `locks_released=1` on `scff000`. `herdr pane close` wP:p1 and wP:p2. |
| `s0938` | ov-a | 1 | same | $1 | **$0.014657** | 28012 | 6 | UI kickoff so overview could show two (then three) running after n6/n2 finished. Later stopped. |
| `sfdc8` | ov-b | 1 | same | $1 | **$0.009389** | 14341 | 4 | Same. |
| `s94a3` | inbox17 | 2 | same | $0.2 | **$0.022533** | 62534 | 17 | Row 17 live proof. `SWARM_DONE`. Inbox events carry `from` + `ids`. |

`02-overview-two-running.png` is ov-b + ov-a + web-reap all **running** at once (n6 already done, n2 already stopped). First n6+n2 concurrent window existed; that frame was overwritten after both finished, so the recapture is the live “≥2 running” proof.

### Screenshots

| File | Screen | Live data |
| --- | --- | --- |
| `01-kickoff.png` | Kickoff `/new` | Model picker caption “from `pi --list-models`”; cap $1. |
| `01c-kickoff-n2.png` | Kickoff | N=2 form filled (`web-n2`). |
| `01d-kickoff-n2-started.png` | Kickoff | Job accepted; n2 launching while n6 ran. |
| `01e-kickoff-reap-swarm.png` | Kickoff | `web-reap` start from the form. |
| `02-overview-two-running.png` | Overview `/` | Three running cards: ov-b, ov-a, web-reap. Combined spend strip. |
| `03-threads.png` | Threads `sc60f` | `main`, intros + results, density timeline. |
| `03b-threads-n2.png` | Threads `s4081` | n2 `main` while that swarm was live. |
| `03c-threads-dark.png` | Threads `sc60f` | `#main` **dark** (idle > `SWARM_THREAD_DIM_MS`). |
| `04-agents.png` | Agents `sc60f` | All six **✓ done**. |
| `04b-reap-dialog.png` | Reap dialog | UI Reap stalled on `scff0`. |
| `04c-agents-after-reap.png` | Agents `scff0` | Both **?** reaped; job log `herdr pane close` + `.dead` paths. |
| `05-traces.png` | Traces `sc60f` | Full `events.jsonl` (85 lines). |
| `05b-traces-filter.png` | Traces + filter | Tool = `claim_file`; five **conflict — held by** rows. |
| `05c-traces-inbox-senders.png` | Traces + inbox filter | `s94a3`: “2 new from s94a300, s94a301” (and later “1 new from s94a300”). |
| `06-claims.png` | Claims `sc60f` | Claim → work → release sequences. Layer B `claim_violation` list empty on this run (conflicts are `claim_file` results, not `claim_violation` events). |
| `07-budget.png` | Budget `sc60f` | $0.171 / $1, per-agent table. |
| `08-files.png` | Files | `history/` for hello / index / summary. |
| `08b-files-older-rev.png` | Files | Older hello.txt revision selected. |
| `08c-files-before-restore.png` | Files | Viewer before Restore. |
| `11-files-restore.png` | Files + Restore | UI Restore hello.txt rev 1; green “restored”; `operator` revision. |
| `09-artifacts.png` | Artifacts list | `work/` + playwright PNGs. |
| `09b-artifacts-index.png` | Artifacts preview | `work/index.html` iframe: black canvas, cyan bouncing circle. |
| `10-stop-n2.png` | Stop `s4081` | Job `swarm.sh stop s4081` exit 0; `workspace:close` ok. |

### Checks that are not a screenshot

- `pi --list-models` on the real binary is a table (`provider  model  context …`). After the parser fix, `/api/models` is `source: pi` (not the static fallback).
- UI **Stop** on `s4081` closed Herdr workspace `wN` (no leftover `wN` panes).
- UI **Reap** on `scff0` wrote `done/agents/scff000.dead` (`locks_released: 1`) and `scff001.dead`, then `herdr pane close` for both panes.

### Still unproven on the live pass (fixture still covers the UI)

- Inventory **row 16** “thinking” / batch calls: Pi does not write those to `events.jsonl`.
- Inventory **row 17** closed on `s94a3` — see `05c-traces-inbox-senders.png`.
- Inventory **row 19** Layer B `claim_violation` brick list: this live n6 produced `claim_file` `conflict:true` only (visible in traces + filter). No `claim_violation` event, so the Claims-tab violation list stayed empty. Fixture `sbeef` still shows the brick row.
- First `01-kickoff.png` is the form with the default picker, not the filled N=6 payload (n6 was started from the same form; 01c–01e are the later filled kickoffs).
