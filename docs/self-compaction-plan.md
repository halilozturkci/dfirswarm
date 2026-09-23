# Self-compaction: agents that compact their own context

Status: approved and implemented on 2026-09-22 on the branch that carries
this document, with three changes Halil asked for over the proposal below:
the default lines are **40 / 50 / 60%** of the ceiling (not 50 / 65 / 75),
the trace keeps every argument, result and reasoning whole (no clip of any
size), and the console's agent page shows the agent's context over time with
every crossing and compaction. Later the same day phases 3 and 4 of section
8 shipped under a fourth rule, **nothing is cut anywhere and nothing is
unrecorded**: section 5.7 is rewritten to what that meant (whole tool
outputs under `tool-output/`, `inbox`/`wait` paging by whole posts, the
board flood quieted at its source, no silent cut left), and section 8
records the per-model lines, `--compact-model` and `swarm.sh context`.
Sections 5.2, 5.5, 5.7 and 8 are updated to what shipped; the rest is the
analysis as written. The decision record is
[ADR 0008](adr/0008-agents-compact-their-own-context.md). The pin moved to
Pi **0.87.0** (npm `latest` that day, and what the Linux host already ran) on
the same branch; the e2e suite passes on both versions. Written 2026-09-22
against this repository at `5d20590`, the then-pinned `@earendil-works/pi-coding-agent`
**0.85.1**, the reference build in
[disler/self-compact-pi-agent](https://github.com/disler/self-compact-pi-agent)
(a Pi 0.85.1 extension, MIT) and its video
([Self Compact](https://youtu.be/3b0U4_02bAE)), and the run data this
repository and the Linux droplet hold. Every number below was measured with the
scripts described in section 4; where something is inferred it says so.

## 1. The verdict

- **No agent in the swarm compacts on purpose today.** The harness sets no
  compaction option, so every agent runs Pi's default: summarize when the
  context passes `window - 16,384` tokens, with Pi's generic summary prompt,
  no warning to the agent and nothing of the agent's own intent carried across.
  On the 500k and 1M models that trigger has never fired (the largest context
  ever recorded is 262k). On `openai/gpt-5.4` (272k) agents have ended runs at
  94%, 81% and 80% of the window.
- **Pi's declared window is not the real one.** On the Linux run `s3096`
  agent `s309602` was refused by the provider ("Your input exceeds the context
  window of this model") at about 215k tokens on `gpt-5.4-mini`, which Pi
  declares as 400k. The threshold path never fired; the overflow path did,
  summarizing a single "split turn" of 196k tokens for 54k tokens ($0.04)
  and dropping the context to 85k. That is exactly the reactive, bystander
  compaction the video argues against, and it happened here.
- **Context grows fast on a forensics case.** 11k to 21k tokens per minute
  per agent; 200k is crossed in 11 to 13 minutes. Bash output is 73% of the
  growth; one `wait` call returned 240k characters of board posts (64k
  tokens) in a single tool result.
- **Context is the bill.** Re-sending the context is 86% to 100% of spend on
  `grok-4.6`, `DeepSeek-V4-Pro` on Azure and `gpt-5.4`; the average prompt
  per call across the archive is 68k to 109k tokens. Replaying the real
  `s3096` curves under a compaction policy: a hard line at 120k to 150k saves
  25% to 31% with OpenAI-style caching and 44% to 56% without it; a line at
  200k to 250k saves 6% on a 14-minute run. `grok-4.6` on Azure doubles its
  price above 200k input tokens, `gpt-5.4` and `gpt-5.5` above 272k.
  `deepseek-v4-pro` reads cache at 1/120 of the input price, so there
  compaction saves nothing; the reason to compact on it is rot and the wall.
- **Decision proposed:** adopt the video's design (three thresholds, a
  `self_compact(note_to_self)` tool, a forced lock, a compaction prompt we
  own) as a kickoff option that is **on by default**, implemented inside the
  swarm extension rather than as a second extension, with thresholds resolved
  per model against an *effective* ceiling the harness owns, a hand-off that
  carries swarm state (name, claims, ledger, board cursor, next action), and
  Pi's overflow compaction kept as the safety net. Two context-hygiene
  changes were proposed here as clips (post bodies capped in `wait`/`inbox`,
  oversized tool results clipped); they shipped without any clip, as §5.7
  now says: whole posts paged, whole outputs kept under `tool-output/`.

## 2. What the video and the reference extension do

The video is a walkthrough of the reference repository, so the repository is
the primary source. The mechanism, as built:

| Phase | Trigger | What the agent gets | Tools |
| --- | --- | --- | --- |
| notice | usage crosses `--compact-soft-at` (default 10% of the window) | one transient message with live numbers; nothing required | all |
| warning | usage crosses `--compact-at` (default 20%) | "finish the current atomic step, write your note, call `self_compact`", refreshed on every call | all |
| forced | usage crosses warning + `--compact-buffer` (default 10%, capped at 90%) | every tool call is blocked with a reason naming `self_compact` | only `self_compact` and `view_context` |
| handoff | agent calls `self_compact({ note_to_self })` | the note is saved, the run ends, compaction runs once idle with a prompt the operator owns, the note comes back verbatim as the next message | restored |

How it is wired to Pi 0.85.1 (`apps/self-compact/extensions/self-compact/self-compact.ts`):

- `pi.on("context")` appends one transient `custom` message with the guidance
  for the current level on every model call; it is never persisted, so the
  prompt-cache prefix stays stable and the transcript stays clean.
- `pi.on("tool_call")` returns `{ block: true, reason }` for every tool except
  the two of its own while locked, and `{ block, terminate }` for siblings in a
  batch that contains `self_compact`.
- `self_compact` validates the note (1 to 24,000 chars), saves it with
  `pi.appendEntry`, sets the lock, and returns `{ terminate: true }` so the run
  ends; `agent_settled` then calls `ctx.compact()`.
- `pi.on("session_before_compact")` cancels every non-manual compaction (Pi's
  own threshold and overflow paths) and, for the manual one it triggers,
  generates the summary through Pi's `compact()` with the replacement system
  prompt (`--compact-prompt` > `.pi/self-compact/USER_PROMPT_COMPACTION_MESSAGE.md`
  > built-in) and `cacheRetention: "none"`.
- `pi.on("session_compact")` bumps the cycle counter, unlocks, and
  `pi.sendMessage({ customType, content: note }, { triggerTurn: true })`
  returns the note byte for byte.
- `view_context()` returns the gauge as JSON; `/self-compact-info` and
  `/self-compact-now` are the human-in-the-loop commands; a one-line footer
  draws a 20-cell bar with the three markers.
- State is a snapshot entry per change plus a pure recovery reducer, so a
  reload, a resume and a `/tree` switch rebuild the pending hand-off.

Two points the video makes that matter for us: keep a wide gap before the
warning so the agent can find a natural stopping point and a short gap to the
hard cutoff; and set the defaults around the price cliff of the model (the
video's example: 225k / 250k / 270k for a GPT model whose price doubles at
270k).

## 3. What the harness does today

Facts, with the places to change.

| Fact | Where |
| --- | --- |
| Each agent is one `pi` process started by Herdr: `--approve --name <id> --session-dir <sandbox>/.pi-sessions/<id> -e extensions/agent-swarm.ts --tools <list> --model <provider/id>` | `scripts/swarm.sh:2779-2794`, `:1035-1057` |
| One Pi extension, `extensions/agent-swarm.ts`; `protocol.ts`, `toolchain.ts`, `playwright-tool.ts` are modules it imports | `extensions/agent-swarm.ts:281` |
| Hooks in use: `session_start`, `before_agent_start`, `turn_end` (twice), `tool_call`, `tool_result`, `message_end`, `session_shutdown`. Not used: `context`, `agent_end`, `agent_settled`, `session_before_compact`, `session_compact`, `session_compact_failed` | `extensions/agent-swarm.ts:604-1392` |
| Options reach the pane as environment (`SWARM_TOOL_FORGING=1`, `SWARM_TOOLS`, `SWARM_HARD_KILL`, ...) on `herdr workspace create` / `pane split`; the extension reads `process.env` | `scripts/swarm.sh:2508-2543`, `extensions/agent-swarm.ts:291` |
| The tool allowlist is a fixed string `PI_TOOLS`; with forging on it goes through `SWARM_TOOLS` and `pi.setActiveTools` | `scripts/swarm.sh:2505`, `extensions/agent-swarm.ts:1926-1931` |
| No compaction setting anywhere: no `.pi/settings.json` in the sandbox, none on the operator machines. Pi defaults apply: `reserveTokens` 16,384, `keepRecentTokens` 20,000 | `scripts/swarm.sh:2284-2285`; `~/.pi/agent/settings.json` on the Mac and the droplet |
| Context occupancy is read once per turn (`ctx.getContextUsage()`) into `budget.json` as `context_tokens` / `context_window`, and shown as a bar in the console. Nothing acts on it | `extensions/agent-swarm.ts:339-360`, `ui/src/screens/detail/agents-panel.tsx:212-227` |
| Compaction entries already count toward spend and caps | `extensions/protocol.ts:1855` |
| The trace has no per-turn context row; `budget.json` is overwritten every turn. The only per-turn record is Pi's own session file, which is never copied out of the sandbox | `docs/use-cases/*` hold 21 `budget.json` snapshots; the droplet holds `.pi-sessions` for six runs |
| A swarm agent's whole life is **one turn**: the kickoff user message, then a chain of tool calls that the worker prompt tells it never to leave (`wait` must stay open). Every Pi compaction is therefore a split-turn compaction: Pi summarizes the turn prefix and keeps the last `keepRecentTokens` | `prompts/worker-system.md` ("Waiting"); the `s309602` compaction summary begins "No prior history. Turn Context (split turn)" |
| The harness steers with `pi.sendUserMessage(msg, { deliverAs: "steer" })`; `done` ends the session with `{ terminate: true }`; the sentinel check runs first in `tool_call` | `extensions/agent-swarm.ts:319-330`, `:2247`, `:958-975` |
| `idle-nudge.sh` and `reap.sh` decide "idle" from `.pi-sessions/<id>/*.jsonl` mtimes and nudge through `herdr agent prompt` | `scripts/idle-nudge.sh:92,249`, `scripts/reap.sh:130-132` |
| Model windows and prices come from Pi's registry (`pi-ai/dist/providers/data/*.json`) and the operator's `~/.pi/agent/models.json`; the harness has no table of its own | `scripts/swarm.sh:3251-3257` reads `contextWindow` only for local models |
| Pi drift: the droplet's global `pi` reports changelog 0.87.0 in its settings while the repo pins 0.85.1 | `/home/swarm/.pi/agent/settings.json` |

## 4. What the data says

Sources: the 21 archived `budget.json` files under `docs/use-cases/` (final
state of 147 agent seats), the six run directories on the droplet
(`/home/swarm/swarm-runs`, fetched on 2026-09-22: `budget.json`,
`traces/events.jsonl` and the Pi session files of 14 agents), and Pi's model
registry. Scripts: `analyze.py` (per-turn curves from session files, the
final-state census, the trace proxy) and `simulate.py` (policy replay); both
live in the session scratchpad and are small enough to move into `scripts/`
when the feature lands. The trace-based proxy turned out useless (the trace
stores a 2,000-character preview of each result, so it undercounts by 20x);
the session files are the only per-turn source.

### 4.1 Per-turn curves (the only long run with session files: `s3096`, 4 x `gpt-5.4-mini`, 14 minutes)

| Agent | Calls | Peak prompt | Growth | 100k at | 200k at | Largest single jump |
| --- | --- | --- | --- | --- | --- | --- |
| s309600 | 122 | 268,899 | 20,800 tok/min | 5.7 min | 11.6 min | +64,731 (`wait`, 239,986 chars of posts) |
| s309601 | 104 | 217,704 | 15,300 tok/min | 4.7 min | 10.9 min | +22,980 (`bash`) |
| s309602 | 97 | 214,738 then overflow | 15,900 tok/min | 6.5 min | 13.1 min | +30,124 (`bash`) |
| s309603 | 90 | 163,106 | 11,300 tok/min | 5.5 min | (not reached) | +64,484 (`wait`, 239,841 chars) |

Cache-read share of the prompt on these OpenAI sessions: 96% to 98%, so each
call pays 2k to 4k new tokens at the input price and the rest at the cache
price.

Which tool result precedes the growth (sum of prompt deltas by the preceding
tool, all droplet sessions): `bash` 73.0%, `wait` 14.5% (8 calls, 16k tokens
each on average), `read` 3.6%, `inbox` 2.2%, `record` 2.1%. Tool results in
`s3096` by total size: `bash` 1.49M chars over 288 calls, `wait` 483k over 5,
`inbox` 341k over 11.

The overflow, verbatim from the session file of `s309602`: the last
successful call carried 214,950 tokens (210 new, 214,528 cached); the next
call errored with "Your input exceeds the context window of this model"; Pi
wrote a `context_edit`, then a `compaction` entry with `tokensBefore`
196,180, `usage.totalTokens` 54,350, cost $0.0436, a 2,779-character summary;
the next call carried 85,270 tokens.

### 4.2 Final state across the archive (164 seats, 27 runs, droplet included)

| Statistic | Value |
| --- | --- |
| Final context tokens: p50 / p75 / p90 / max | 143k / 170k / 199k / 262k |
| Seats ending above 100k / 150k / 200k / 250k | 78% / 43% / 10% / 2% |
| Final ratio to Pi's declared window: p50 / p90 / max | 0.21 / 0.54 / 0.94 |

By model (final context, cache-read share of all input, new input per call):

| Model | Seats | Declared window | Final ctx p50 / max | Cache share | New input per call |
| --- | --- | --- | --- | --- | --- |
| `azure-foundry/grok-4.6` | 44 | 500,000 | 142k / 183k | 0.25 | 67,581 |
| `azure-foundry/DeepSeek-V4-Pro` | 38 | 1,000,000 | 151k / 262k | 0.41 | 42,492 |
| `openai/gpt-5.4` | 36 | 272,000 | 134k / 255k (94%) | 0.93 | 5,920 |
| `deepseek/deepseek-v4-pro` | 26 | 1,000,000 | 158k / 231k | 0.94 | 5,037 |
| `openai/gpt-5.4-mini` | 18 | 400,000 | 191k / 254k (long run) | 0.65 | 1,420 |

The three highest ratios are all `gpt-5.4`: `sbe1801` in c04 at 254,959 /
272,000, `s9f2000` in c03 at 81%, `s881003` in c06 at 80%. One more large
tool result and each of those would have hit the overflow path.

### 4.3 The re-send tax (archive totals, priced from Pi's registry and `models.json`)

| Model | Calls | Avg prompt per call | Input $ | Cache $ | Spent $ | Context share of spend |
| --- | --- | --- | --- | --- | --- | --- |
| `azure-foundry/grok-4.6` | 1,723 | 94,767 | 239.55 | 21.75 | 266.07 | 98% |
| `azure-foundry/DeepSeek-V4-Pro` | 3,713 | 68,370 | 257.14 | 15.38 | 264.68 | ~100% |
| `openai/gpt-5.4` | 2,936 | 108,562 | 37.36 | 75.95 | 125.22 | 90% |
| `deepseek/deepseek-v4-pro` | 1,379 | 84,039 | 3.03 | 0.39 | 19.33 | 18% |
| `openai/gpt-5.4-mini` | 507 | 85,510 | 1.15 | 3.14 | 4.96 | 86% |

Price cliffs in the registry: `grok-4.6` (Azure entry in `models.json`) has a
tier above 200,000 input tokens that doubles input, output and cache-read
prices; `gpt-5.4` and `gpt-5.5` have a tier above 272,000 that doubles them,
and Pi declares 272,000 as their window, so in practice the cliff is the wall.

### 4.4 Policy replay on the real curves (`simulate.py`)

Policy: when the prompt before a call is at or above `T`, pay one
summarization call (the whole prompt at the input price plus 1,500 output
tokens), collapse the context to `keepRecentTokens` 20,000 plus a 3,000-token
summary and note, and shrink every later prompt by the same amount; the call
right after a compaction has no cache. Four agents, 14 minutes.

| Priced as | Cache | none | T=250k | T=200k | T=150k | T=120k | T=100k |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `gpt-5.4-mini` | observed (96%) | $4.76 | -5.5% | -5.8% | -25.4% | -31.1% | -34.8% |
| `gpt-5.4` | observed | $15.88 | -5.5% | -5.8% | -25.4% | -31.1% | -34.8% |
| `gpt-5.4` | none | $108.73 | -7.7% | -15.1% | -43.8% | -47.6% | -56.2% |
| `grok-4.6` (tier > 200k) | none (Azure measured 25%) | $101.29 | -14.4% | -27.9% | -52.6% | -55.9% | -63.3% |
| `deepseek-v4-pro` | observed (94%) | $0.88 | -2.5% | +12.2% | +6.8% | -4.9% | +0.5% |

Compactions in the replay: 1 at 250k, 3 at 200k, 4 at 150k, 5 at 120k, 8 at
100k, across the four agents. At the observed growth rates a 60-minute run
needs, per agent and hour, 3 to 7 compactions with the hard line at 200k and
5 to 10 with it at 150k. Each summarization call costs the context at the
input price: about $0.12 on `gpt-5.4-mini`, $0.40 on `gpt-5.4`, $0.80 on
`gpt-5.5` at 160k.

Reading: the savings come from keeping the *average* prompt small, not from
avoiding the wall; a line at 200k or above barely changes the average on runs
of 15 to 60 minutes. Between 120k and 150k the savings flatten and the
compaction count is still low. Below 100k the summaries start to cost what
they save. Where the provider caches well and prices the cache near zero
(DeepSeek direct), compaction is not a cost measure at all.

## 5. Design

### 5.1 The option

One switch, on by default, plus three advanced knobs, following the forging
pattern hop for hop (`scripts/swarm.sh` default, `case` arm, `usage_start`,
registry `jq`; `scripts/ui/actions.ts` `StartParams`, `validateStart`,
`startArgv`; `ui/src/screens/kickoff.tsx` `FormState`, default, `<Switch>`,
submit body, preview string; `docs/usage.md`).

| Surface | Name | Default | Note |
| --- | --- | --- | --- |
| CLI | `--no-self-compact` (and `--self-compact` to force on) | on | a default-on boolean needs the negative flag; `validateStart` must read `body.self_compact !== false`, not `=== true` |
| CLI | `--compact-soft-at <spec>`, `--compact-at <spec>`, `--compact-buffer <spec>` | see 5.2 | `spec` is tokens, `k`/`m`, or `%` of the effective ceiling, parsed by the vendored `thresholds.ts` |
| CLI | `--compact-prompt-file <path>` | `prompts/compaction-summary.md` | replaces the summary system prompt |
| Console | switch "Self compaction · agents compact their own context at a threshold they can see" | on | advanced group with the three specs |
| Registry | `self_compact: { enabled, soft_at, at, buffer, prompt }` | | mirrored in `scripts/run-record.ts`, `scripts/ui/model.ts`, `ui/src/lib/types.ts`, `scripts/seed-fixture.ts` |
| Pane env | `SWARM_SELF_COMPACT=1`, `SWARM_COMPACT_SOFT_AT`, `SWARM_COMPACT_AT`, `SWARM_COMPACT_BUFFER`, `SWARM_COMPACT_PROMPT` | | read at extension load like `SWARM_TOOL_FORGING`; the probe agent gets the same |
| Tool list | `self_compact` appended to `PI_TOOLS` when on (and to `SWARM_TOOLS` with forging) | | `tests/pi-load.test.ts` asserts registration with and without the env |

Environment rather than Pi flags because that is how every other option
reaches the pane, because `tests/pi-load.test.ts` already tests that path,
and because the extension is loaded before Pi parses `registerFlag` values.

### 5.2 The effective ceiling and the thresholds

The harness owns a small table, `extensions/context-ceiling.ts`, consulted at
`session_start` and `model_select`:

| Model | Declared by Pi | Effective ceiling | Why |
| --- | --- | --- | --- |
| `openai/gpt-5.4`, `openai/gpt-5.5` | 272,000 | 272,000 | price doubles above it |
| `openai/gpt-5.4-mini` | 400,000 | 272,000 | measured overflow at ~215k plus one result |
| `grok-4.6` (any provider) | 500,000 | 200,000 | price doubles above it |
| DeepSeek V4 family | 1,000,000 | 300,000 | rot ceiling; the video's 30% of 1M; observed max 262k |
| anything else | declared | `min(declared, 300,000)` | rot ceiling |

Thresholds default to fractions of the effective ceiling: **notice 40%,
warning 50%, compact line 60%** (Halil's decision over the proposal's
50 / 65 / 75; the compaction runs at the compact line). The reference caps
its hard line at 90% of the window; here the compact line never sits above
`declared - reserveTokens - 32,000`, so a result that lands after it still
fits, and never inside Pi's retained `keepRecentTokens`, where a compaction
would have nothing to cut. An explicit value that does not fit is refused at
kickoff; a default that does not fit a small window is clamped and noted on
the trace (`compact_config`). A line the operator leaves unset is a default
fitted to the lines they set: it rises to a higher operator line below it,
drops below a lower one above it in the 40 : 50 : 60 proportion, and is
noted the same way; only two operator lines out of order are refused.

| Model | notice | warning | compact | room to the real wall |
| --- | --- | --- | --- | --- |
| `gpt-5.4` / `gpt-5.5` / `gpt-5.4-mini` | 109k | 136k | 163k | 93k below `272k - 16k` |
| `grok-4.6` | 80k | 100k | 120k | every call stays in the cheap tier |
| DeepSeek V4 (1M) | 120k | 150k | 180k | wall is far; ceiling is about rot |

Why these and not the video's 10 / 20 / 30% of the declared window: on a 1M
model those are 105k / 210k / 315k, close to this table's 1M row; on a 272k
model they would be 27k / 54k / 82k, which on a forensics run means a
compaction every four minutes and summaries that cost more than they save
(section 4.4). Why not the video's token defaults (225k / 250k / 270k): they
sit above the measured overflow for `gpt-5.4-mini` and inside the zone where
one `wait` result (64k) reaches the wall. The replay puts the sweet spot
between 120k and 180k for the compact line on 272k models; 163k sits inside
it, keeps the compaction count near 5 to 9 per hour at the observed growth,
and leaves a margin larger than the largest jump ever measured.

The operator can override per run with the three specs. A later slice adds
per-model specs in the `--models` syntax; the table is the default, not the
only path.

### 5.3 The agent-facing surface

- **`self_compact(note_to_self)`**: as in the reference (1 to 24,000 chars,
  saved, run ends with `terminate: true`, compaction once idle, note returned
  verbatim), plus swarm rules: refused while `done/SWARM_DONE` exists (call
  `done` instead), refused when Pi would find nothing to compact.
- **Context numbers in `budget`**, not a separate `view_context`: the tool
  agents already call gets a `context` object (`tokens`, `ceiling`, `window`,
  `percent`, `level`, `thresholds`, `tokens_until_hard_cutoff`, `cycle`,
  `tools_locked`). One tool fewer in the list, one prompt paragraph fewer.
- **Guidance** through the `context` hook, transient, never persisted, rebuilt
  from live numbers on every call while a level is active (notice, warning,
  forced). Text lives in `prompts/compact-notice.md`,
  `prompts/compact-warning.md`, `prompts/compact-forced.md` with the
  reference's `{{placeholders}}`.
- **The lock** at the hard line: `tool_call` blocks every tool except
  `self_compact`, `budget` and `done`, with a reason that names
  `self_compact` and the live numbers. The sentinel check keeps running first.
  `wait` is blocked too, which is the point: an agent parked in `wait` at the
  hard line compacts before it waits again.
- **One system-prompt line** in `buildSystemPrompt` (static, so the cache
  prefix stays stable): what the thresholds are for, that the note comes back
  verbatim, that finished work in the note is finished.
- **`agent_end` nudge**: if the run ends (for any reason) while at warning or
  forced, send one follow-up asking for the note, as the reference does.

### 5.4 The hand-off, swarm edition

The reference returns the note alone. A swarm agent needs more, and the
harness knows most of it from files, which is more reliable than the model's
memory. After a successful compaction the extension sends one custom message:

```
[self-compact · handoff] cycle 2 · you are s309602 "disk-triage" (disk triage; attacker-added files)
Live claims: work/report.md (renew by 22:04:10), work/extracted/s309602/ (yours, no claim needed)
Unread posts: 7 in main, 2 in memory. Call inbox before acting.
Ledger: 41 entries, 12 yours (last seq 39). Sentinel: absent. Spend: $1.04 of your $6 cap.
Your note follows verbatim:
---
<note_to_self>
```

The `note_to_self` contract the tool description asks for: name and slice,
DONE with exact paths and commands, IN PROGRESS, evidence already recorded
(ledger seq ids), what peers own and what you are waiting on, verified
results, and the NEXT ACTION last. Never list finished work as pending.

The compaction summary prompt (`prompts/compaction-summary.md`) is ours and
DFIR-specific: preserve exact paths under `inputs/`, `catalog/`, `work/`,
offsets, hashes, commands that worked and their outputs, forged tool names,
peer ownership, holds and vetoes; never state that a finding was recorded
unless a `record` tool result confirms it; mark everything unverified that no
tool result verified. The summary and the note are two things: the summary
is Pi's structured history, the note is the agent's intent.

### 5.5 Interplay with Pi's own compaction

Unlike the reference, do **not** cancel Pi's `overflow` compaction. The
reference cancels every non-manual compaction and relies on its lock; in a
swarm the model call that would carry `self_compact` can itself be the one
the provider refuses (a 64k `wait` result on top of a context near the wall),
and cancelling the overflow path then leaves the agent with no working call.
Rules:

- `reason === "threshold"` and `reason === "overflow"` (Pi's own paths): let
  them run, with our summary prompt. The proposal cancelled the threshold
  path; as shipped neither is cancelled, because cancelling one leaves the
  agent at the wall where its next call overflows anyway, and a compaction
  that lands is better than one that is refused. Both are recorded as
  `compact_done` with `via: pi` and the reason, so the report shows the
  fallback was needed; a note saved before one is still delivered after it.
- `reason === "manual"` (our `ctx.compact()` after a note): our prompt, our
  details (`handoffId`, cycle, prompt source), the note returned afterwards
  under the header; `compact_done` with `via: self`.
- Our summary failing twice returns nothing, so Pi's own summarizer runs
  (`compact_failed` with `fallback: pi-summary`); a compaction that fails
  past three retries releases the lock and keeps the note
  (`lock_released: true`), because a locked agent nobody can unlock is a
  dead agent.

Keep `keepRecentTokens` at Pi's 20,000 and `reserveTokens` at 16,384; write
them into `<sandbox>/.pi/settings.json` at kickoff so a run no longer depends
on whatever the operator's global settings say.

### 5.6 What the harness records and shows

- **Trace**: a `context` row at every `turn_end` (`tokens`, `window`,
  `ceiling`, `percent`, `level`, `cycle`) so the time series exists in every
  archive from now on; `compact_notice`, `compact_warning`, `compact_forced`
  on each crossing; `compact_note` (chars) when a note is saved;
  `compact_done` (`reason`, `tokens_before`, `tokens_after`, `usage`, `cost`,
  `cycle`) and `compact_failed`. All names go into `TOOL_RESERVED_NAMES` and
  `RESERVED_NAME_REASON` in `extensions/protocol.ts`.
- **`budget.json`** per agent: `context_ceiling`, `context_level`,
  `compactions`, `compaction_tokens`, `compaction_usd`, `last_compaction_at`.
- **Console**: the agent card's context bar gets the three markers and the
  cycle count; a `COMPACTING` state on the card; a "Compactions" column in the
  budget panel; the trace filter chip `compact`; the kickoff switch and the
  three specs; the run detail shows the resolved ceiling per model.
- **Summary and report**: compactions per agent, summary cost, peak context,
  the ceiling table, and how many compactions were overflow fallbacks.
- **Docs**: `docs/usage.md` (flags, API body), `docs/protocol.md` (events,
  budget fields), `docs/component-map.md`, a new ADR
  `0008-agents-compact-their-own-context.md`, and the worker prompt paragraph.

### 5.7 Context hygiene (the other half of the problem)

Compaction treats the symptom. This section first proposed two clips (post
bodies cut at 4,000 characters with a pointer, tool results cut at 60,000),
and Halil's rule for the platform overrode them: **nothing is cut, anywhere,
and nothing is unrecorded.** A forensic platform cannot hold an output the
agent never saw and the record does not have. What shipped instead keeps
every byte and bounds only how much of it enters one model call:

- **`wait` and `inbox` page by whole posts.** One delivery carries at most
  `--inbox-page-chars` characters of post text (40,000 by default; `0`
  removes the bound), never cutting a post: the delivery stops before the
  post that would break the bound, only the delivered posts move the cursors,
  the result says `remaining` and why, and `wait` returns at once while
  anything is unread. The two 240k-character `wait` results on `s3096` were
  578 posts each; under the bound they are fifteen deliveries of the same
  posts, whole.
- **The flood at its source.** Those 578 posts were the harness's own: 566
  `CLAIM VIOLATION` posts from a shell loop appending to a peer's file, one
  per write, read by every peer. The board post now comes once per path per
  minute and says how many repeats the minute held; every write is still a
  `claim_violation` row on the trace.
- **Tool output is kept whole, and the model receives a prefix only where
  it always did.** Pi's `bash` shows the last 50 KB and spills the rest to
  the host's temp directory; the harness moves that file into the sandbox
  under `tool-output/`, names it on the trace row (`full_output`: path,
  bytes, lines, sha256) and rewrites the model's trailer to the sandbox
  path. A forged tool used to be killed at 64 KB with the rest dropped; now
  its whole stdout and stderr stream to `tool-output/` and the model gets the
  first 64 KB with the same trailer. `browser_check` keeps the whole page
  text the same way. `read`, `grep`, `find` and `ls` show slices of files
  that exist, and the row records the slice (`view`). The console links each
  file from the row; `swarm.sh context` counts them.
- **No silent cut remains in the harness.** The trace's arguments, results
  and reasoning are whole; the `inbox` and `wait` rows list every delivered
  post; a provider's error text, a forged tool's error, an agent's `doing`
  are whole; the ledger's source and evidence, a forged tool's parameter
  descriptions and example are refused over their limits rather than cut.

Measured once, on run 6 (Linux, the same case and team as run 5, summaries
by `gpt-5.4-nano`): four hand-offs in 34 minutes, every one between the
warning and the compact line, none held, none of Pi's; eleven tool outputs
kept whole under `tool-output/` (21 MB, the largest a 12.7 MB `grep` the
model saw 35 KB of); no delivery ever reached the page bound, because the
board's flood on `s3096` had been the harness's own violation posts and on
run 6 the board held 58 posts of at most 887 characters. What the run found
instead was the next flood: one agent's venv under `work/.toolchain/` was
642 implicit claims and seven violation posts, and the panes' temp files
under `work/.tmp/` (Pi's own spills) were more; both directories are out of
the watch now. The compaction count itself did not move (three on run 5,
four on run 6) and will not until something shrinks the growth, which on
this case is `bash` output the agents asked for.

### 5.8 Code shape

- Vendor the reference's pure modules with attribution in `NOTICE` (MIT):
  `thresholds.ts` (parse and resolve), the prompt templating from
  `prompts.ts`, the state reducer from `state.ts`, and the summary generation
  from `summary.ts`; every export it needs (`compact`, `findCutPoint`,
  `sessionEntryToContextMessages`, `SettingsManager`, `serializeConversation`,
  `convertToLlm`) exists in the pinned 0.85.1 `dist/index.d.ts`.
- One new module `extensions/self-compact.ts` exporting
  `registerSelfCompact(pi, deps)`; `agent-swarm.ts` calls it after its own
  hooks so the sentinel check stays first. No second `-e`.
- The TUI footer and the two slash commands are not needed: the console is
  the operator's view, and `budget` is the agent's.
- Typecheck against the pinned package; the runtime `pi` on every host must
  be 0.85.1 (the droplet's global install reports 0.87.0 and needs pinning or
  the sandbox `bin/pi` shim must point at the repo's `node_modules` binary).

## 6. Threading the option, hop by hop

| Hop | File and place | Change |
| --- | --- | --- |
| 1 | `ui/src/screens/kickoff.tsx` `FormState` (113-162), defaults (315-346), the "Run" switch group (951-966), `submit()` (445-486), preview (492) | `self_compact: true`, `compact_soft_at`, `compact_at`, `compact_buffer` |
| 2 | `scripts/ui/actions.ts` `StartParams` (27-105), `validateStart` (289-473), `startArgv` (476-517) | `self_compact: body.self_compact !== false`; push `--no-self-compact` when false and the three specs when set |
| 3 | `scripts/swarm.sh` defaults (1658-1681), `case` (1682-1747), `usage_start` (155-320), registry `jq` (2290-2371), `provider_env` (2508-2543), `PI_TOOLS` (2505), `.pi/settings.json` next to `SYSTEM.md` (2284) | `self_compact=1`; `--no-self-compact`; the specs; `self_compact` object in the record; env into every pane; tool list |
| 4 | `extensions/agent-swarm.ts` load (291), `buildSystemPrompt` (800-854), `tool_call` (942), `turn_end` (856), `session_start` (604) | read env, register the module, the system-prompt line, the `context` trace row |
| 5 | `extensions/self-compact.ts` (new), `extensions/context-ceiling.ts` (new), `prompts/compact-*.md`, `prompts/compaction-summary.md` | the feature |
| 6 | `extensions/protocol.ts` `AgentBudget` (153-167), `TOOL_RESERVED_NAMES` (3204-3217), `RESERVED_NAME_REASON` (3266-3288) | fields and names |
| 7 | `scripts/run-record.ts`, `scripts/ui/model.ts`, `ui/src/lib/types.ts`, `scripts/seed-fixture.ts` | registry mirrors |
| 8 | `scripts/summary.ts`, `scripts/report.ts`, `ui/src/screens/detail/agents-panel.tsx`, `budget-panel.tsx`, `goal-panel.tsx` | readers |
| 9 | `docs/usage.md`, `docs/protocol.md`, `docs/component-map.md`, `docs/adr/0008-*.md`, `prompts/worker-system.md` | docs |

## 7. Tests

Following the repository's conventions (`node:test` under
`--experimental-strip-types`, shell suites with `--no-start`, no mocks beyond
`tests/mock-provider.mjs`):

- `tests/self-compact-thresholds.test.ts`: spec parsing, ceiling table,
  resolution per model, the cap below `window - reserve - 32k`, rejection of
  bad specs.
- `tests/self-compact-state.test.ts`: the recovery reducer (pending, failed,
  ready, done, journaled-unanswered).
- `tests/pi-load.test.ts`: `self_compact` registered iff `SWARM_SELF_COMPACT=1`;
  `budget` result carries `context`.
- `tests/self-compact-e2e.test.ts` with `mock-provider.mjs` reporting growing
  usage: notice, warning, forced (a blocked `wait` with the reason), the note,
  the compaction, the handoff message byte for byte, the next tool call
  succeeding; a steer landing during the handoff; the sentinel appearing
  during the handoff (`done` still allowed); an overflow error from the
  provider (Pi's path runs with our prompt); a note over 24,000 chars refused.
- `tests/ui-server.test.ts`: `validateStart` off and on, `startArgv` carries
  `--no-self-compact` and the specs; a 202 end to end into `registry.json`.
- `tests/dfir-flags.test.sh`: the help gate picks up the new flags.
- `tests/model-teams.test.sh`: registry `self_compact.enabled` true by
  default and false with `--no-self-compact`.
- `tests/summary.test.ts`, `tests/report.test.ts`: the compaction fields reach
  the outputs.
- A trace-schema test that the new event names are reserved.

## 8. Rollout, as tracer bullets

0. **Measure first (half a day).** The `context` trace row and the
   `budget.json` fields, nothing else. Also, today, in `~/.pi/agent/models.json`
   on the droplet and the Mac, a `modelOverrides` entry that sets
   `openai/gpt-5.4-mini` `contextWindow` to 272,000: Pi's own threshold then
   fires before the provider refuses, which removes the overflow path from the
   next run even before this feature exists.
1. **The core, behind the env, on by default (2 to 3 days).** The module, the
   ceiling table, the prompts, the tool, the lock, the handoff, the trace
   events, the CLI flags and the registry field, the e2e test, `docs/usage.md`.
   Proven on the droplet with the web-server case at a 60-minute wall clock on
   `gpt-5.4-mini`, compared with `s3096`: peak context, compactions, cost,
   and whether the report answers the same questions.
2. **The console and the outputs (1 to 2 days).** The switch and the specs,
   the bar markers, the compaction column, summary and report, the ADR.
3. **Hygiene, without a clip (shipped 2026-09-22).** What §5.7 now says:
   `wait`/`inbox` page by whole posts (`--inbox-page-chars`), the claim
   violation post comes once per path per minute, every tool output is kept
   whole under `tool-output/` and named on the trace, no silent cut remains.
   The re-measure of the compaction count waits for the next real runs;
   `swarm.sh context <id>` is what reads them.
4. **Tuning (shipped 2026-09-22, ongoing by nature).** Per-model lines on
   the three flags (`--compact-at "60%,openai/gpt-5.4-mini=55%,grok-4.6=70%"`,
   resolved per seat and recorded under `matched` on `compact_config`); a
   summarizer model for the expensive seats (`--compact-model`, credential-
   checked and allowlisted like a seat's model, never a seat, recorded on
   `compact_config` and `compact_done`, falling back to the agent's own with
   the reason on the trace when Pi does not know it); and `swarm.sh context`
   (`scripts/context-audit.ts`), which reads a run's `context` and `compact_*`
   rows into per-agent peaks, crossings, hand-offs, summary cost and one
   sentence per thing the record says about the lines, so the defaults are
   revisited from measurements rather than memory.

## 9. Open questions

1. Defaults: 50 / 65 / 75% of the effective ceiling (this plan) or the
   video's 10 / 20 / 30% of the declared window?
2. At the hard line, allow `done` and `budget` beside `self_compact` (this
   plan) or nothing else, as the reference does?
3. Keep Pi's overflow compaction as the fallback (this plan) or cancel it as
   the reference does and accept the stall risk?
4. Should the DeepSeek seats compact at all, given that it costs them money
   and saves none? The plan says yes, for rot and for the wall, at 225k.
5. Should a hand-off be visible on the board (a `system` post naming the
   cycle) or only in the trace and the console? The plan says trace and
   console; the board is for the case.
6. ~~The tool-result clip: ship it, and at what size?~~ Answered by the
   platform's rule: never. Every output is kept whole under `tool-output/`;
   what the model receives in one call is bounded only where Pi's own tools
   already bound it (§5.7).

## 10. Risks

- **Version drift.** The reference and this plan lean on internal exports of
  Pi (`findCutPoint`, `sessionEntryToContextMessages`, `SettingsManager`,
  `convertToLlm`, `serializeConversation`). Resolved for now by pinning the
  repository to 0.87.0, the version the Linux host runs; the e2e suite is the
  check that a future bump keeps the cycle working (it passes on 0.85.1 and
  0.87.0, whose provider contracts differ, which the scripted provider
  absorbs).
- **Split-turn summaries.** Because a swarm agent never ends its turn, every
  compaction summarizes a turn prefix. Pi handles this, and the `s309602`
  summary was usable, but the note carries the intent; the e2e must assert the
  note survives byte for byte.
- **A result larger than the buffer.** The hard line leaves 52k on 272k
  models; a 64k `wait` result still exists until 5.7 lands. Pi's overflow
  path covers the gap, at the cost of a bystander summary.
- **Races with nudges and steers.** `idle-nudge.sh` and the cap steer can
  inject a user message between "run ended" and "compaction started"; Pi
  queues, the lock holds, and `self_compact` is idempotent on a saved note.
  The e2e covers both.
- **Summary cost on expensive models.** $0.40 to $0.80 per compaction on
  `gpt-5.4` / `gpt-5.5`; `--compact-model` (phase 4, shipped) is the answer:
  the summary call goes to a cheap model and the trace says which.
- **Cache warm-up after each compaction.** The first call after a compaction
  is uncached; the replay includes that and the savings hold.
