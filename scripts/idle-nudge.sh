#!/usr/bin/env bash
# idle-nudge: the watchdog for agents that stop calling tools.
#
# A Pi session that ends its turn sits at the prompt until something prompts
# it again. Nothing in the swarm does, so an agent that posted its intro and
# stopped, or finished a slice and waited for nothing, stays idle until the
# wall clock runs out. This sidecar prompts such an agent through Herdr
# ("you are idle, pick up what you said you would do or call done"), a bounded number of
# times, and writes an `idle_nudge` event to the trace each time.
#
# Activity is measured from the agent's Pi session files (Pi appends to them
# on every message) and from the agent's last trace event, whichever is
# newer; an agent past the limit is then asked of Herdr, which reports a pane
# in a long tool call as `working`, and only an `idle` one is prompted. An
# agent with a done or dead marker is left alone; the loop ends when
# done/SWARM_DONE appears or the sandbox goes away. Plain bash 3.2: macOS
# ships that, so no associative arrays here.
#
# Measured over seven forensic runs: 34 agents had to be woken this way, and
# in 32 of those 34 a peer's post had landed while they slept — a median of 26
# seconds into the silence, then unread until the 180-second timer fired. So
# there are two thresholds. An agent with unread posts is woken after
# --news-sec (45 by default), because there is something to read; an agent that
# is quiet with an empty inbox waits the full --idle-sec, because waking it
# buys nothing. The nudge budget is per silence, not per run: an agent that
# comes back and works starts again with a full budget, since the measurement
# shows every agent that spent its three nudges did come back and keep working.
#
# An agent that only waits is idle too, after longer. `wait` holds a call open
# and returns with each post, so an agent in a wait loop writes a trace row a
# minute and Herdr and the hub see it working: on run s6895a8, s6895a806
# called nothing but wait (and inbox) for 33 minutes and was never nudged.
# So a second clock runs from the agent's last call that was neither a wait
# nor an inbox read nor a row its harness writes for it, and an agent still
# waiting past --wait-idle-sec (600 by default) is nudged, as a steer, since
# its turn does not end. Over the 30 VM runs of 2026-09-24 to 26, 2,489
# stretches of only waiting ended in a call of the agent's own; 98% of them
# within 494 seconds, 34 after 600. Waiting on a job of its own that is still
# running is never counted, and a peer's answer has the whole ten minutes
# from the ask to come in.
#
# A model provider's usage limit refuses every seat at once, and an
# until-solved run used to prompt each seat again, half an hour apart, for
# days, with every VM up and the operator never told. When every live seat's
# last turn ended in a provider error and each seat's limit is plainly not a
# passing one (a stated wait of half an hour or more, or refused again after
# a retry), the run pauses for the provider's limit, under any stop policy
# (scripts/provider-limit.ts); the harness tries again at the end the
# provider named, or every half hour, and the operator is told once.
#
# A seat whose compaction is running takes no prompt at all (Pi refuses it),
# so it is not nudged; one open past --compact-stall-sec (1200 by default,
# past the fifteen minutes after which the seat's own harness stops one) has
# lost its seat, and that is said once on the board and the trace.
#
# Usage:
#   idle-nudge.sh --sandbox DIR [--idle-sec 180] [--news-sec 45] [--interval 30]
#                 [--max-nudges 3] [--local-first-turn-sec 600]
#                 [--wait-idle-sec 600] [--compact-stall-sec 1200] [--once]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/trace.sh
. "$ROOT/scripts/lib/trace.sh"
SANDBOX=""
IDLE_SEC="${SWARM_IDLE_SEC:-180}"
NEWS_SEC="${SWARM_NEWS_SEC:-45}"
WAIT_IDLE_SEC="${SWARM_WAIT_IDLE_SEC:-600}"
COMPACT_STALL_SEC="${SWARM_COMPACT_STALL_SEC:-1200}"
# How recent an agent's last wait must be for it to be waiting still: the
# wait tool's longest call (WAIT_MAX_SECONDS, 300) and two minutes for the
# model's turn around it.
WAIT_LOOP_SEC=420
INTERVAL=30
MAX_NUDGES=3
# How long a seat on a locally served model may take over its first turn
# before the watchdog treats the silence as a stall.
LOCAL_FIRST_TURN_SEC="${SWARM_LOCAL_FIRST_TURN_SEC:-600}"
ONCE=0
HERDR="${HERDR_BIN:-herdr}"
# Agents in microVMs (--isolation microvm): the pane runs `msb exec`, so
# Herdr can neither see Pi's state on the screen nor type a prompt Pi will
# take. The hub has both — each agent's extension reports working/idle up its
# link, and a prompt goes down it as a user message.
HUB_ADMIN="${SWARM_HUB_ADMIN:-}"
HUB_STATUS="${SWARM_HUB_STATUS:-}"
HUB_DIR="${SWARM_HUB_DIR:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sandbox) SANDBOX="$2"; shift 2 ;;
    --idle-sec) IDLE_SEC="$2"; shift 2 ;;
    --news-sec) NEWS_SEC="$2"; shift 2 ;;
    --wait-idle-sec) WAIT_IDLE_SEC="$2"; shift 2 ;;
    --compact-stall-sec) COMPACT_STALL_SEC="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --max-nudges) MAX_NUDGES="$2"; shift 2 ;;
    --local-first-turn-sec) LOCAL_FIRST_TURN_SEC="$2"; shift 2 ;;
    --once) ONCE=1; shift ;;
    *) echo "idle-nudge: unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$SANDBOX" && -d "$SANDBOX" ]] || { echo "idle-nudge: --sandbox DIR is required" >&2; exit 2; }
SANDBOX="$(cd "$SANDBOX" && pwd -P)"

# A seat on a model served from this machine or this network. team.json
# carries the model per agent, and models.json says where a provider lives.
is_local_model() { # <agent id>
  local id="$1" model host
  model="$(jq -r --arg id "$id" '.agents[] | select(.id == $id) | .model // empty' "$SANDBOX/team.json" 2>/dev/null || true)"
  [[ -n "$model" ]] || return 1
  case "${model%%/*}" in
    lmstudio|ollama|vllm|llamacpp|llama.cpp|local) return 0 ;;
  esac
  host="$(jq -r --arg p "${model%%/*}" '.providers[$p].baseUrl // empty' "${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}/models.json" 2>/dev/null || true)"
  # The host part of the base URL, not any "10." in it: a public name such
  # as api10.example.com is not local.
  host="$(printf '%s' "$host" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#^[^@/]*@##; s#[/?].*$##')"
  if [[ "$host" == \[* ]]; then
    host="${host#[}"
    host="${host%%]*}"
  else
    host="${host%:*}"
  fi
  case "$host" in
    127.*|localhost|::1|0.0.0.0|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|169.254.*|fc*|fd*|fe80:*|*.local|*.localhost|host.microsandbox.internal) return 0 ;;
  esac
  return 1
}

# Has this agent completed anything at all? A first turn that has not landed
# yet is not a silence to interrupt.
has_worked() { # <agent id>
  grep -q "\"agent\":\"$1\",\"tool\":\"\(bash\|read\|post\|name\|inbox\|wait\|thinking\)\"" \
    "$SANDBOX/traces/events.jsonl" 2>/dev/null
}

# Rows a seat's harness writes under the seat's id without its model having
# answered (scripts/provider-limit.ts SEAT_HARNESS_ROWS; a test holds the two
# lists the same). A seat's last turn is its last row that is none of these.
SEAT_HARNESS_ROWS='agent_start agent_stop hub_prompt hub_lost hub_lost_stop context thinking tool_loaded toolchain inputs_guard budget_precall_stop pause_hold run_paused harness_stop extension_error watch_truncated agent_cap_steer agent_cap_stop sentinel_nudge repeat_hint job_hint evidence_code forge_hint publish_needed skills_index skills_compacted self_compact compact_config compact_notice compact_warning compact_forced compact_hold compact_note compact_start compact_done compact_failed compact_stalled compact_held harness_record model_reported'

# The tool of the agent's own last turn on the trace: its own rows only (a
# watchdog's row about it is the system's), the harness's rows passed over.
last_turn() { # <agent id>
  grep "\"agent\":\"$1\",\"tool\":" "$SANDBOX/traces/events.jsonl" 2>/dev/null \
    | sed -n 's/.*"agent":"'"$1"'","tool":"\([A-Za-z0-9_.-]*\)".*/\1/p' \
    | awk -v skip="$SEAT_HARNESS_ROWS" 'BEGIN { n = split(skip, s, " "); for (i = 1; i <= n; i++) h[s[i]] = 1 } !($0 in h) { last = $0 } END { print last }'
}

# Each agent's clocks, one line each, from one read of the trace:
#   <id> <idle> <busy> <waiting> <compacting since>
# idle: seconds since it last did anything (its Pi session files, which Pi
# appends to on every message, or its last trace row, whichever is newer), -1
# when nothing is known. A prompt arriving is not the agent doing anything:
# the `hub_prompt` row its extension writes is the echo of this watchdog's own
# nudge, and counting it gave s6895a803, whose prompts Pi refused, a fresh
# nudge budget each time.
# busy: seconds since its last call that was neither a wait nor an inbox read
# nor a row its harness writes for it (or since its first row, when it has
# made none), -1 when nothing is known.
# waiting: 1 when it has waited since that call and its last wait is recent.
# compacting since: when its last hand-off compaction started, in epoch
# seconds, while no end of it is on the trace; -1 otherwise.
agent_clocks() { # <agent id>...
  python3 - "$SANDBOX" "$WAIT_LOOP_SEC" "$@" <<'PY'
import glob, json, os, sys, time
from datetime import datetime
sandbox, loop_sec, ids = sys.argv[1], float(sys.argv[2]), sys.argv[3:]
# Rows an agent's harness writes for it without the agent doing anything: a
# prompt arriving, its context gauge, its thinking, forged tools loading, and
# the self-compaction's own bookkeeping. They say the seat is alive, not that
# it works.
BOOKKEEPING = {
    "hub_prompt", "context", "thinking", "tool_loaded", "agent_start", "inputs_guard", "budget_precall_stop",
    "self_compact", "compact_config", "compact_notice", "compact_warning", "compact_forced", "compact_hold",
    "compact_note", "compact_start", "compact_done", "compact_failed", "compact_stalled",
}
WAITING = {"wait", "inbox"}
now = time.time()
seen = {a: {"last": 0.0, "first": 0.0, "work": 0.0, "wait": 0.0, "compact": 0.0} for a in ids}
try:
    with open(os.path.join(sandbox, "traces", "events.jsonl"), "rb") as fh:
        for raw in fh:
            try:
                event = json.loads(raw)
                agent = event.get("agent")
                if agent not in seen:
                    continue
                # The collector's clock, the host's: a VM's own `ts` is the
                # guest's, and a guest whose clock runs ahead would never
                # look idle.
                at = datetime.fromisoformat((event.get("recv_ts") or event["ts"]).replace("Z", "+00:00")).timestamp()
            except Exception:
                continue
            tool = event.get("tool")
            s = seen[agent]
            s["first"] = s["first"] or at
            if tool != "hub_prompt":
                s["last"] = max(s["last"], at)
            # A compaction ends with compact_done or a failure of the whole
            # of it; a failed summary attempt inside it is not its end.
            stage = (event.get("args") or {}).get("stage")
            if tool == "compact_start":
                s["compact"] = at
            elif tool == "compact_done" or (tool == "compact_failed" and stage in ("compaction", "pi")):
                s["compact"] = 0.0
            if tool in WAITING:
                s["wait"] = max(s["wait"], at)
            elif tool not in BOOKKEEPING:
                s["work"] = max(s["work"], at)
except OSError:
    pass
for agent in ids:
    s = seen[agent]
    last = s["last"]
    for f in glob.glob(os.path.join(sandbox, ".pi-sessions", agent, "*.jsonl")):
        try:
            last = max(last, os.path.getmtime(f))
        except OSError:
            pass
    idle = int(now - last) if last else -1
    base = s["work"] or s["first"]
    busy = int(now - base) if base else -1
    waiting = 1 if s["wait"] > s["work"] and now - s["wait"] <= loop_sec else 0
    since = int(s["compact"]) if s["compact"] else -1
    print(agent, idle, busy, waiting, since)
PY
}

# Whether the agent has a job of its own still to finish: then its waiting is
# what the job asked of it, and the job's post wakes it.
has_open_job() { # <agent id>
  local f
  for f in "$SANDBOX"/store/jobs/*/job.json; do
    [[ -f "$f" ]] || continue
    jq -e --arg id "$1" '.requester.agent == $id and (.state | IN("accepted", "running", "finished", "fenced"))' "$f" >/dev/null 2>&1 && return 0
  done
  return 1
}

# What an agent still holds, for the words in front of it and on the board.
# The ninth case ended with two agents holding work/report.md and
# work/crypto.md after half an hour of silence, and nobody — including them —
# was told.
held_by() { # <agent id>
  [[ -d "$SANDBOX/locks" ]] || return 0
  jq -r --arg id "$1" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    'select(.owner == $id and .expires_at > $now) | .path' "$SANDBOX/locks"/*.json 2>/dev/null \
    | paste -sd ', ' - || true
}

# How many posts this agent has not read, across the primary thread and any
# thread it joined. The cursor file is what `inbox` advances; the highest post
# id in a thread is the last line of its directory listing.
unread_for() {
  local id="$1" total=0 thread cursor highest
  for thread in "$SANDBOX"/threads/*/; do
    [[ -d "$thread" ]] || continue
    local name
    name="$(basename "$thread")"
    if [[ "$name" != "main" ]]; then
      jq -e --arg id "$id" '.members // [] | index($id)' "$thread/meta.json" >/dev/null 2>&1 || continue
    fi
    highest="$(ls "$thread" 2>/dev/null | sed -n 's/^\([0-9]\{6\}\)-.*/\1/p' | sort -n | tail -1)"
    [[ -n "$highest" ]] || continue
    cursor="$(jq -r --arg t "$name" '.[$t] // 0' "$SANDBOX/inbox/$id/cursors.json" 2>/dev/null || echo 0)"
    [[ "$cursor" =~ ^[0-9]+$ ]] || cursor=0
    total=$(( total + 10#$highest - cursor ))
  done
  [[ "$total" -lt 0 ]] && total=0
  printf '%s\n' "$total"
}

log_event() { # log_event <agent> <idle> <ok> <count> [why]
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  local line
  line="$(jq -cn --arg ts "$ts" --arg agent "$1" --argjson idle "$2" --argjson ok "$3" --argjson n "$4" --arg why "${5:-idle}" \
    '{ts: $ts, agent: "system", tool: "idle_nudge", args: {agent: $agent, idle_seconds: $idle, why: $why}, result: {ok: $ok, nudges: $n}}')"
  # Through the collector, so this line is chained like every other. Appending
  # here directly used to break the chain for the *next* line the collector
  # wrote, which with this watchdog on by default meant a run reporting its
  # own record as edited every three minutes.
  trace_emit "$ROOT" "$SANDBOX" "$line"
}

# The stop from outside the panes, for a host run. Each pane's extension
# steers its agent and writes the sentinel itself past a cap or the wall
# clock plus the grace period — from inside the pane, where an agent that
# never ends a turn, or a pane whose extension is wedged, never gets there.
# This watchdog runs for the length of the run outside every pane: past a
# limit it claims the stop clock (and says so on the board) when no pane
# has, and past the grace period it writes the sentinel as the harness. A VM
# run's hub does the same from its own process; this is the host's.
host_backstop() {
  [[ -z "$HUB_DIR" ]] || return 0
  local said
  said="$(node --experimental-strip-types --no-warnings -e '
    const [protocol, S] = process.argv.slice(1);
    import(protocol).then(async (P) => {
      if (await P.swarmDoneExists(S)) return;
      const budget = await P.readBudget(S).catch(() => null);
      if (!budget) return;
      const pressure = P.budgetPressure(budget);
      if (!pressure.reason || P.isPaused(budget)) return;
      const mark = await P.markStopSteer(S, pressure.reason);
      if (mark.claimed) {
        // The words follow the stop policy: a pause is announced as a pause, a stop as a stop.
        await P.systemPost(S, { tag: "stop", body: P.capSteerText(budget, pressure) }).catch(() => undefined);
        console.log(`steered ${pressure.reason}`);
      }
      if (Date.now() - Date.parse(mark.at) < P.STOP_GRACE_MS) return;
      const acted = await P.capAct(S, pressure.reason, `The harness watchdog ${P.stopPolicyOf(budget) === "cap-pause" ? "paused" : "stopped"} the swarm: ${pressure.reason} passed and the grace period ended.`);
      if (acted.kind === "paused" && acted.created) {
        await P.systemPost(S, { tag: "stop", body: `The run is paused (${pressure.reason === "cap" ? "its cap" : "its wall clock"}): no model call goes out until the operator extends it (swarm.sh extend) or stops it (swarm.sh stop). What the run holds stays as it is.` }).catch(() => undefined);
        console.log(`paused ${pressure.reason}`);
      }
      // The operator is told of it by pause_notify, whoever wrote it.
      if (acted.kind === "stopped" && acted.created) console.log(`stopped ${pressure.reason}`);
    }).catch(() => undefined);
  ' "$ROOT/extensions/protocol.ts" "$SANDBOX" 2>/dev/null || true)"
  local what reason ts line
  while read -r what reason; do
    [[ -n "$what" ]] || continue
    ts="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
    line="$(jq -cn --arg ts "$ts" --arg t "$(if [[ "$what" == stopped ]]; then echo harness_stop; elif [[ "$what" == paused ]]; then echo run_paused; elif [[ "$reason" == cap ]]; then echo cap_steer; else echo wall_steer; fi)" --arg r "$reason" \
      '{ts: $ts, agent: "system", tool: $t, args: {via: "idle-nudge", reason: $r}, result: {ok: true}}')"
    trace_emit "$ROOT" "$SANDBOX" "$line"
    echo "idle-nudge: $what the swarm ($reason)" >&2
    # The operator's notify command, once, when the swarm's cap is reached.
    if [[ "$what" == steered && "$reason" == cap ]]; then
      bash "$ROOT/scripts/notify.sh" "$SANDBOX" budget_cap "$(jq -c '{spent_usd: (.spent_usd // null), cap_usd: (.cap_usd // null)}' "$SANDBOX/budget.json" 2>/dev/null || echo '{}')" >/dev/null 2>&1 </dev/null || true
    fi
  done <<< "$said"
}

# The operator's token marks (--token-alert) in a host run: each told once
# (claimTokenAlerts claims it on disk and says it on the board), on the trace
# and to the notify hook. A VM run's hub tells them; this is the host's.
# Advisory: nothing pauses or stops for one.
host_token_alerts() {
  [[ -z "$HUB_DIR" ]] || return 0
  # No marks, no node: this runs every interval.
  jq -e '(.token_alerts // []) | length > 0' "$SANDBOX/budget.json" >/dev/null 2>&1 || return 0
  local told mark tokens ts line
  told="$(node --experimental-strip-types --no-warnings -e '
    const [protocol, S] = process.argv.slice(1);
    import(protocol).then(async (P) => {
      const budget = await P.readBudget(S).catch(() => null);
      if (!budget || !(budget.token_alerts ?? []).length) return;
      for (const t of await P.claimTokenAlerts(S, budget)) console.log(`${t.mark} ${t.tokens}`);
    }).catch(() => undefined);
  ' "$ROOT/extensions/protocol.ts" "$SANDBOX" 2>/dev/null || true)"
  while read -r mark tokens; do
    [[ -n "$mark" ]] || continue
    ts="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
    line="$(jq -cn --arg ts "$ts" --argjson mark "$mark" --argjson tokens "$tokens" \
      '{ts: $ts, agent: "system", tool: "token_alert", args: {via: "idle-nudge", mark: $mark}, result: {ok: true, tokens: $tokens}}')"
    trace_emit "$ROOT" "$SANDBOX" "$line"
    bash "$ROOT/scripts/notify.sh" "$SANDBOX" token_alert "$(jq -nc --argjson mark "$mark" --argjson tokens "$tokens" '{mark: $mark, tokens: $tokens}')" >/dev/null 2>&1 </dev/null || true
    echo "idle-nudge: the run crossed the operator's token mark $mark ($tokens tokens)" >&2
  done <<< "$told"
}

# The operator is told of a pause once, whichever process wrote it: this
# watchdog, the hub, or a pane's own extension. The claim is a mark on disk
# (traces/pause-notices/), so a pause whose writer never said so, or a
# watchdog that restarts, still tells it, and no two processes tell it twice.
# A spell of the provider's limit is told once, whatever the harness's tries
# within it (pauseNoticeKey); the operator's own hold is not told back.
pause_notify() {
  local notice
  paused_now || return 0
  notice="$(node --experimental-strip-types --no-warnings -e '
    const [protocol, S] = process.argv.slice(1);
    import(protocol).then(async (P) => {
      const paused = (await P.readBudget(S)).paused;
      if (!paused || !(await P.claimPauseNotice(S, P.pauseNoticeKey(paused)))) process.exit(1);
      const notice = P.pauseNotice(paused);
      if (!notice) process.exit(1);
      process.stdout.write(JSON.stringify(notice));
    }).catch(() => process.exit(1));
  ' "$ROOT/extensions/protocol.ts" "$SANDBOX" 2>/dev/null)" || return 0
  bash "$ROOT/scripts/notify.sh" "$SANDBOX" paused "$notice" >/dev/null 2>&1 </dev/null || true
  echo "idle-nudge: the operator was told the run is paused ($(jq -r '.reason // "?"' <<<"$notice" 2>/dev/null), since $(jq -r '.paused.since // .paused.at // "?"' <<<"$notice" 2>/dev/null))" >&2
}

# The provider's limit (scripts/provider-limit.ts): under a pause for it, the
# harness's try once it is due (the pause lifted, by the harness, and the
# seats woken below as after any lift); otherwise the rule, read off the
# trace, and the pause when it holds. Both under the table lock, so a second
# watchdog cannot act twice. Nothing is read until some seat has ended a turn
# in a provider error, or while the run is paused for anything else.
provider_limit_check() {
  local reason out action ts line
  reason="$(jq -r 'if (.paused | type) == "object" then (.paused.reason // "") else "-" end' "$SANDBOX/budget.json" 2>/dev/null || true)"
  if [[ "$reason" == "-" ]]; then
    grep -q '"tool":"agent_error"' "$SANDBOX/traces/events.jsonl" 2>/dev/null || return 0
  elif [[ "$reason" != provider_limit ]]; then
    return 0
  fi
  out="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/provider-limit.ts" tick "$SANDBOX" 2>/dev/null || true)"
  action="$(jq -r '.action // empty' <<<"$out" 2>/dev/null || true)"
  ts="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  case "$action" in
    paused)
      line="$(jq -cn --arg ts "$ts" --argjson r "$out" '{ts: $ts, agent: "system", tool: "run_paused", args: {via: "idle-nudge", reason: "provider_limit", until: ($r.pause.until // null), retry_at: $r.retry_at, models: ($r.pause.models // []), spell: $r.spell, since: ($r.pause.since // $r.pause.at)}, result: {ok: true, why: $r.why, seats: $r.seats}}')"
      trace_emit "$ROOT" "$SANDBOX" "$line"
      echo "idle-nudge: paused the run for the model provider's limit ($(jq -r '.why' <<<"$out")); the harness tries again at $(jq -r '.retry_at' <<<"$out")" >&2
      ;;
    lifted)
      line="$(jq -cn --arg ts "$ts" --argjson r "$out" '{ts: $ts, agent: "system", tool: "run_unpaused", args: {via: "idle-nudge", reason: "provider_limit", by: "harness", paused_at: $r.pause.at, until: ($r.pause.until // null)}, result: {ok: true, resumed_at: $r.pause.resumed_at}}')"
      trace_emit "$ROOT" "$SANDBOX" "$line"
      echo "idle-nudge: lifted the pause for the model provider's limit (since $(jq -r '.pause.at' <<<"$out")) to try again; every seat is woken" >&2
      ;;
  esac
  return 0
}

# Where nobody has looked, three times a run: at a quarter, a half and three
# quarters of the wall clock, one harness post lists the inputs no command
# has named yet (scripts/coverage.ts, read off the trace). A named input is
# not an examined one, and an unnamed one is only unnamed: the post says
# which, and assigns nothing. Skipped when every input has been named, or
# when this checkout has no coverage.ts.
coverage_hint() {
  local cov="$ROOT/scripts/coverage.ts" mark="$SANDBOX/traces/idle-nudge.coverage" pct at due="" list body
  [[ -f "$cov" && -f "$SANDBOX/inputs.json" && -f "$SANDBOX/budget.json" ]] || return 0
  pct="$(jq -r 'if (.started_at // "") == "" or ((.wall_clock_minutes // 0) | tonumber) <= 0 then empty
    else (((now - (.started_at | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601)) / 60) / (.wall_clock_minutes | tonumber) * 100 | floor) end' "$SANDBOX/budget.json" 2>/dev/null || true)"
  [[ "$pct" =~ ^-?[0-9]+$ ]] || return 0
  for at in 25 50 75; do
    [[ "$pct" -ge "$at" ]] && ! grep -qx "$at" "$mark" 2>/dev/null && due="$at"
  done
  [[ -n "$due" ]] || return 0
  # Every mark passed is spent by this one post: a watchdog that started
  # late does not post three times in a row.
  for at in 25 50 75; do
    [[ "$at" -le "$due" ]] && ! grep -qx "$at" "$mark" 2>/dev/null && echo "$at" >> "$mark"
  done
  list="$(node --experimental-strip-types --no-warnings "$cov" "$SANDBOX" --json 2>/dev/null | jq -r '.untouched[]? // empty' 2>/dev/null || true)"
  [[ -n "$list" ]] || return 0
  body="$(printf 'At %s%% of the wall clock, no command has named these inputs yet (read off the trace; a named input is not always an examined one):\n\n%s\n\nNobody is assigned to them. If one matters to the goal and nobody has it, say on the board that you are taking it.' \
    "$due" "$(printf '%s\n' "$list" | sed 's/^/- `/; s/$/`/')")"
  node --experimental-strip-types --no-warnings -e '
    const [protocol, S, body] = process.argv.slice(1);
    import(protocol).then((P) => P.systemPost(S, { tag: "ask", body })).catch(() => process.exit(1));
  ' "$ROOT/extensions/protocol.ts" "$SANDBOX" "$body" >/dev/null 2>&1 || return 0
  echo "idle-nudge: posted the inputs no command has named yet ($(printf '%s\n' "$list" | wc -l | tr -d ' ') at ${due}%)" >&2
}

# An until-solved run (budget.json until_solved) never ends on a clock, a cap
# or an abandon, so a swarm that stops moving would wait forever. When
# nothing has moved for the run's stall_minutes (no new standing entry, no
# lead closed, no job committed), one post to everyone lists the questions
# not answered, the leads open and blocked, what waits on the operator and
# the evidence no entry cites, and asks for another route; again, with
# backoff, while nothing moves (scripts/leads-cli.ts regroup). Never stops.
until_solved() {
  [[ "$(jq -r '.until_solved // false' "$SANDBOX/budget.json" 2>/dev/null)" == true ]]
}
regroup_check() {
  until_solved || return 0
  local out ts line
  out="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/leads-cli.ts" regroup "$SANDBOX" 2>/dev/null || true)"
  [[ "$(jq -r '.posted // false' <<<"$out" 2>/dev/null)" == true ]] || return 0
  ts="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  line="$(jq -cn --arg ts "$ts" --argjson r "$out" '{ts: $ts, agent: "system", tool: "regroup", args: {since: $r.since}, result: {ok: true, kind: ($r.kind // "all_hands"), count: $r.count, post: $r.post, next_minutes: $r.next_minutes, to: ($r.to // null)}}')"
  trace_emit "$ROOT" "$SANDBOX" "$line"
  if [[ "$(jq -r '.kind // "all_hands"' <<<"$out")" == nudge ]]; then
    echo "idle-nudge: nothing had moved since $(jq -r '.since' <<<"$out"), but jobs run under leads: their holders are nudged ($(jq -r '.to | join(", ")' <<<"$out"), #$(jq -r '.post' <<<"$out"))" >&2
  else
    echo "idle-nudge: regroup $(jq -r '.count' <<<"$out") posted (#$(jq -r '.post' <<<"$out")); nothing had moved since $(jq -r '.since' <<<"$out")" >&2
  fi
}

# The seats' subscription tokens in a microVM run, renewed on the host at
# half their validity (scripts/vm.ts renew-secrets: msb rotates a VM's
# secret live, and the guest keeps its placeholder). Checked every ten
# minutes; a run with no VM spec, or none of whose seats holds a token, does
# nothing. Never a value on the trace or in the log.
secret_renewal_check() {
  local spec="$HUB_DIR/vm-spec.json" mark="$SANDBOX/traces/idle-nudge.secrets" now last out ts line
  [[ -n "$HUB_DIR" && -f "$spec" ]] || return 0
  now="$(date +%s)"
  last="$(cat "$mark" 2>/dev/null || echo 0)"
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  [[ $((now - last)) -ge 600 ]] || return 0
  echo "$now" > "$mark"
  out="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" renew-secrets --spec "$spec" --state "$HUB_DIR/secret-renewal.json" 2>/dev/null || true)"
  [[ "$(jq -r '.due // false' <<<"$out" 2>/dev/null)" == true ]] || return 0
  ts="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  line="$(jq -cn --arg ts "$ts" --argjson r "$out" '{ts: $ts, agent: "system", tool: "secrets_renewed", args: {next_at: $r.next_at}, result: {ok: $r.ok, seats: [$r.seats[] | {agent, outcome, rotated, why}]}}')"
  trace_emit "$ROOT" "$SANDBOX" "$line"
  echo "idle-nudge: the seats' tokens renewed on the host: $(jq -r '[.seats[] | "\(.agent) \(.outcome)"] | join(", ")' <<<"$out"); next at $(jq -r '.next_at' <<<"$out")" >&2
}

# The stop policy (docs/adr/0013). A paused run's seats are held, whatever
# paused it (a cap, the provider's limit, the operator): none is nudged,
# since a nudge would start a turn whose model call the pause refuses. When
# the pause is lifted (the operator's extension or unpause, the harness's
# try under the provider's limit), every live seat is woken once, with the
# words that say so.
paused_now() {
  [[ "$(jq -r 'if (.paused | type) == "object" then "yes" else "no" end' "$SANDBOX/budget.json" 2>/dev/null)" == yes ]]
}
# Each seat is woken once per lifted pause, and only a delivery that went
# through counts: traces/idle-nudge.resumed holds "<resumed_at> <seat>" for
# each one reached, and a seat not reached is tried again on the next pass
# (its first failure is on the trace, not every retry). A lift that a new
# pause has already followed wakes nobody, and neither does a pause a resume
# folded into the history. The words say who lifted it and
# why (pauseLiftedText): the operator's extension, the operator's unpause, or
# the harness's try under the provider's limit.
resume_wake() {
  local mark="$SANDBOX/traces/idle-nudge.resumed" tried="$SANDBOX/traces/idle-nudge.resume-tried" last id text ts line ok woken=0 pending=0 due=""
  paused_now && return 0
  last="$(jq -r '(.pauses // []) | last | .resumed_at // empty' "$SANDBOX/budget.json" 2>/dev/null || true)"
  [[ -n "$last" ]] || return 0
  # A pause swarm.sh resume folded into the history ("<by> (resume)") was
  # ended by a stop and a resume: the resume's kickoff starts every seat from
  # its hand-off, and a wake here would tell them a pause was lifted.
  [[ "$(jq -r '(.pauses // []) | last | (.resumed_by // "") | endswith("(resume)")' "$SANDBOX/budget.json" 2>/dev/null)" == true ]] && return 0
  for id in $(jq -r '.agents[].id' "$SANDBOX/team.json" 2>/dev/null); do
    [[ -e "$SANDBOX/done/agents/$id.done" || -e "$SANDBOX/done/agents/$id.dead" ]] && continue
    grep -qxF "$last $id" "$mark" 2>/dev/null && continue
    due="$due $id"
  done
  [[ -n "$due" ]] || return 0
  text="$(node --experimental-strip-types --no-warnings -e '
    const [protocol, S] = process.argv.slice(1);
    import(protocol).then(async (P) => {
      const p = (await P.readBudget(S)).pauses?.at(-1);
      if (!p) process.exit(1);
      process.stdout.write(P.pauseLiftedText(p));
    }).catch(() => process.exit(1));
  ' "$ROOT/extensions/protocol.ts" "$SANDBOX" 2>/dev/null)" || text="The pause is lifted. Pick up where you were: read inbox, go on with what you hold, and record what you find."
  for id in $due; do
    ok=false
    if [[ -n "$HUB_ADMIN" ]]; then
      node "$ROOT/scripts/vm-hub-send.mjs" "$HUB_ADMIN" "$(jq -nc --arg a "$id" --arg t "$text" '{op: "prompt", agent: $a, text: $t, kind: "resume", deliver: "followUp"}')" >/dev/null 2>&1 && ok=true
    else
      "$HERDR" agent prompt "$id" "$text" >/dev/null 2>&1 && ok=true
    fi
    if [[ "$ok" == true ]]; then
      printf '%s %s\n' "$last" "$id" >> "$mark"
      woken=$((woken + 1))
      # The wake is the retry of a seat whose last turn failed: the next
      # provider-error prompt waits its backoff from here, not in this pass.
      set_err "$id" "$(awk -v id="$id" '$1 == id { print $2; found = 1 } END { if (!found) print 0 }' "$ERRSTATE")" "$(date +%s)"
    else
      pending=$((pending + 1))
      grep -qxF "$last $id" "$tried" 2>/dev/null && continue
      printf '%s %s\n' "$last" "$id" >> "$tried"
    fi
    ts="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
    line="$(jq -cn --arg ts "$ts" --arg a "$id" --argjson ok "$ok" --arg at "$last" '{ts: $ts, agent: "system", tool: "resume_wake", args: {agent: $a, resumed_at: $at}, result: {ok: $ok}}')"
    trace_emit "$ROOT" "$SANDBOX" "$line"
  done
  [[ "$woken" -gt 0 ]] && echo "idle-nudge: the pause was lifted at $last; $woken seat(s) woken" >&2
  [[ "$pending" -gt 0 ]] && echo "idle-nudge: the pause was lifted at $last; $pending seat(s) not reached, tried again on the next pass" >&2
  return 0
}
# Diminishing returns: when nothing has yielded (no new finding, question
# disposition or coverage record) for a window of minutes (and of jobs, when
# SWARM_YIELD_JOBS sets one), the
# operator is asked, once per window, whether to stop (an operator request of
# kind decision). Never an agent's vote; nothing is stopped here.
yield_check() {
  local mark="$SANDBOX/traces/idle-nudge.yield" last now out ts line
  now="$(date +%s)"
  last="$(cat "$mark" 2>/dev/null || echo 0)"
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  [[ $((now - last)) -ge 120 ]] || return 0
  echo "$now" > "$mark"
  out="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/stop-policy.ts" yield "$SANDBOX" 2>/dev/null || true)"
  [[ "$(jq -r '.proposed // false' <<<"$out" 2>/dev/null)" == true ]] || return 0
  ts="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  line="$(jq -cn --arg ts "$ts" --argjson r "$out" '{ts: $ts, agent: "system", tool: "stop_proposed", args: {since: $r.since, jobs: $r.jobs, minutes: $r.minutes}, result: {ok: true, request: $r.id}}')"
  trace_emit "$ROOT" "$SANDBOX" "$line"
  echo "idle-nudge: nothing has yielded since $(jq -r '.since' <<<"$out") ($(jq -r '.jobs' <<<"$out") jobs, $(jq -r '.minutes' <<<"$out") minutes): a stop is proposed to the operator ($(jq -r '.id' <<<"$out"))" >&2
}

# What the run asked of the operator (the operator requests' outbox,
# extensions/requests.ts, docs/adr/0014): the hub writes and delivers each
# request itself, as it is committed and on every round. This is the
# fallback: in a host run (no hub) it is the delivery, every round; with a
# hub, once every five minutes, and it delivers only what the hub has not (a
# request is notified once, by its `notified` event on the chain).
operator_requests_check() {
  local mark="$SANDBOX/traces/idle-nudge.requests" now last out
  if [[ -n "$HUB_ADMIN" && -S "$HUB_ADMIN" ]]; then
    now="$(date +%s)"
    last="$(cat "$mark" 2>/dev/null || echo 0)"
    [[ "$last" =~ ^[0-9]+$ ]] || last=0
    [[ $((now - last)) -ge 300 ]] || return 0
    echo "$now" > "$mark"
  fi
  out="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/requests-cli.ts" fire "$SANDBOX" ${SWARM_RUNS_DIR:+--runs "$SWARM_RUNS_DIR"} 2>/dev/null || true)"
  [[ -n "$out" ]] || return 0
  local opened notified
  opened="$(jq -r '(.opened // []) | join(", ")' <<<"$out" 2>/dev/null)"
  notified="$(jq -r '(.notified // []) | join(", ")' <<<"$out" 2>/dev/null)"
  [[ -n "$opened" ]] && echo "idle-nudge: operator request(s) written from what was committed: $opened (swarm.sh requests <run> list)" >&2
  [[ -n "$notified" ]] && echo "idle-nudge: the operator's notify targets were handed $notified, by id" >&2
  return 0
}

# A compaction open this long is past the bound the seat's own harness holds
# it to (it stops one at fifteen minutes and retries it or releases the
# lock), so the seat's process is stuck or Pi did not let go when it was
# stopped. Either way the seat takes no prompt, and on run s6895a8 its peers
# were never told. Said once per compaction, on the board and the trace.
report_stalled_compaction() { # <agent id> <started, epoch seconds> <open seconds>
  local id="$1" since="$2" open="$3" mark="$SANDBOX/traces/idle-nudge.compact" held body posted=false line
  grep -qx "$id $since" "$mark" 2>/dev/null && return 0
  echo "$id $since" >> "$mark"
  held="$(held_by "$id")"
  body="COMPACTION STALLED: ${id}'s context compaction started $((open / 60)) minutes ago and has not ended. Until it does, Pi takes no prompt from anyone, this watchdog's and the stop's included, so ${id} may be lost for the rest of the run.${held:+ It still holds: ${held}; the leases lapse on their own.} If its slice matters to the goal, say on the board that you are taking it over. The operator can look at its pane."
  node --experimental-strip-types --no-warnings -e '
    const [protocol, S, body] = process.argv.slice(1);
    import(protocol).then((P) => P.systemPost(S, { tag: "hold", body })).catch(() => process.exit(1));
  ' "$ROOT/extensions/protocol.ts" "$SANDBOX" "$body" >/dev/null 2>&1 && posted=true
  line="$(jq -cn --arg ts "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" --arg agent "$id" --argjson open "$open" --argjson limit "$((COMPACT_STALL_SEC * 1000))" --argjson posted "$posted" \
    '{ts: $ts, agent: "system", tool: "compact_stalled", args: {agent: $agent, by: "watchdog", limit_ms: $limit}, result: {ok: true, open_seconds: $open, posted: $posted}}')"
  trace_emit "$ROOT" "$SANDBOX" "$line"
  echo "idle-nudge: ${id}'s compaction has been open ${open}s; said on the board (posted=$posted)" >&2
}

# "id n idle_at_last_nudge" lines. The count is per silence: if the agent has
# done anything since we last nudged it — its idle clock is shorter than it was
# then — this is a new silence and the budget starts again.
# Words in front of an agent: through the hub for a VM, through Herdr otherwise.
# An agent in a turn (one that is waiting) is steered: a follow-up would wait
# for a turn end that does not come. Herdr's typed words steer a working pane.
prompt_agent() { # <agent id> <text> [followUp|steer]
  if [[ -n "$HUB_ADMIN" ]]; then
    node "$ROOT/scripts/vm-hub-send.mjs" "$HUB_ADMIN" \
      "$(jq -nc --arg a "$1" --arg t "$2" --arg d "${3:-followUp}" '{op: "prompt", agent: $a, text: $t, kind: "idle_nudge", deliver: $d}')" >/dev/null 2>&1
  else
    "$HERDR" agent prompt "$1" "$2" >/dev/null 2>&1
  fi
}

STATE="$SANDBOX/traces/idle-nudge.state"
[[ -f "$STATE" ]] || : > "$STATE"
# Until solved: per agent, how many times in a row it was prompted after a
# provider error, and when last; the wait doubles each time, up to half an hour.
ERRSTATE="$SANDBOX/traces/idle-nudge.errors"
[[ -f "$ERRSTATE" ]] || : > "$ERRSTATE"
set_err() { # <id> <count> <epoch>
  local tmp="$ERRSTATE.tmp.$$"
  awk -v id="$1" -v n="$2" -v t="$3" 'NF && $1 == id { $2 = n; $3 = t; found = 1 } NF { print } END { if (!found) print id, n, t }' "$ERRSTATE" > "$tmp"
  mv "$tmp" "$ERRSTATE"
}
count_of() { awk -v id="$1" '$1 == id { print $2; found = 1 } END { if (!found) print 0 }' "$STATE"; }
mark_of() { awk -v id="$1" '$1 == id { print ($3 == "" ? 0 : $3); found = 1 } END { if (!found) print 0 }' "$STATE"; }
set_count() {
  local tmp="$STATE.tmp.$$"
  awk -v id="$1" -v n="$2" -v m="$3" 'NF && $1 == id { $2 = n; $3 = m; found = 1 } NF { print } END { if (!found) print id, n, m }' "$STATE" > "$tmp"
  mv "$tmp" "$STATE"
}

# The hub is the VMs' board, trace door and stop: a run whose hub died has
# none of the three until it is back. The hub kept what the kickoff gave it
# in its own directory, so it resumes with the same tokens and the same
# clock; this watchdog, which already runs for the length of the run, is
# what notices.
ensure_hub() {
  [[ -n "$HUB_DIR" && -d "$HUB_DIR" && ! -e "$HUB_DIR/.stop" ]] || return 0
  # A keeper that gave up on a hub dying in a row has said why in the hub's
  # log; restarting it here every pass would only repeat the crash.
  [[ -e "$HUB_DIR/.keeper-gave-up" ]] && return 0
  local pid keeper script
  pid="$(cat "$SANDBOX/hub.pid" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then return 0; fi
  # The hub's own keeper (hub-supervise.sh) brings it back; two restarting
  # it at once would start two hubs.
  keeper="$(cat "$HUB_DIR/supervisor.pid" 2>/dev/null || true)"
  if [[ -n "$keeper" ]] && ps -o command= -p "$keeper" 2>/dev/null | grep -q "hub-supervise.sh"; then return 0; fi
  [[ -f "$HUB_DIR/hub-input.json" ]] || return 0
  script="$ROOT/scripts/vm-hub.ts"
  [[ -f "$HUB_DIR/host/scripts/vm-hub.ts" ]] && script="$HUB_DIR/host/scripts/vm-hub.ts"
  nohup node --experimental-strip-types --no-warnings "$script" --resume "$HUB_DIR" >>"$SANDBOX/traces/vm-hub.log" 2>&1 </dev/null &
  echo $! > "$SANDBOX/hub.pid"
  local i
  for ((i = 0; i < 50; i++)); do
    [[ -S "$HUB_DIR/admin.sock" ]] && break
    sleep 0.1
  done
  local ok=false line
  [[ -S "$HUB_DIR/admin.sock" ]] && ok=true
  line="$(jq -nc --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg d "$HUB_DIR" --argjson ok "$ok" \
    '{ts: $ts, agent: "system", tool: "hub_restarted", args: {dir: $d}, result: {ok: $ok}}')"
  printf '%s' "$line" | node "$ROOT/scripts/trace-emit.mjs" "$SANDBOX" >/dev/null 2>&1 || printf '%s\n' "$line" >> "$HUB_DIR/hub-spill.jsonl"
  echo "idle-nudge: the hub was down; restarted (ok=$ok)" >&2
}

while :; do
  [[ -d "$SANDBOX" ]] || exit 0
  [[ -f "$SANDBOX/done/SWARM_DONE" || -f "$SANDBOX/done/ALL_AGENTS_DEAD" ]] && exit 0
  ensure_hub
  host_backstop
  host_token_alerts
  provider_limit_check
  pause_notify
  resume_wake
  if paused_now; then
    # Paused: the seats are held, nobody is nudged; the operator's requests are still said, and the tokens kept valid.
    operator_requests_check
    secret_renewal_check
    [[ "$ONCE" -eq 1 ]] && exit 0
    sleep "$INTERVAL"
    continue
  fi
  coverage_hint
  regroup_check
  secret_renewal_check
  yield_check
  operator_requests_check
  # --idle-sec 0: nobody is nudged; the stop policy above (the backstop, the
  # pause's notice, the wake after an extension, the proposal of a stop) and
  # the operator's requests are this watchdog's all the same.
  if [[ "$IDLE_SEC" -eq 0 ]]; then
    [[ "$ONCE" -eq 1 ]] && exit 0
    sleep "$INTERVAL"
    continue
  fi
  US=0
  until_solved && US=1
  ids="$(jq -r '.agents[].id' "$SANDBOX/team.json" 2>/dev/null | tr '\n' ' ')"
  # shellcheck disable=SC2086
  clocks="$([[ -n "${ids// /}" ]] && agent_clocks $ids)"
  for id in $ids; do
    [[ -e "$SANDBOX/done/agents/$id.done" || -e "$SANDBOX/done/agents/$id.dead" ]] && continue
    read -r idle busy waiting since <<<"$(awk -v id="$id" '$1 == id { print $2, $3, $4, $5 }' <<<"$clocks")"
    [[ -n "$idle" ]] || continue
    # A seat whose compaction runs refuses every prompt; a nudge would be
    # dropped and counted. Past the bound it is reported instead.
    if [[ "$since" -ge 0 ]]; then
      open=$(( $(date +%s) - since ))
      [[ "$open" -ge "$COMPACT_STALL_SEC" ]] && report_stalled_compaction "$id" "$since" "$open"
      continue
    fi
    # Something to read makes a short silence worth interrupting; an empty
    # inbox does not. 32 of the 34 stalls measured had a peer's post waiting.
    unread="$(unread_for "$id")"
    why="idle"
    clock="$idle"
    deliver="followUp"
    if [[ "$waiting" -eq 1 && "$busy" -ge "$WAIT_IDLE_SEC" ]] && ! has_open_job "$id"; then
      # Waiting since its last call: the hub and Herdr both see it working,
      # and it is, only at nothing. Its turn does not end, so it is steered.
      why="waiting"
      clock="$busy"
      deliver="steer"
    else
      [[ "$idle" -ge 0 ]] || continue
      if [[ "$unread" -gt 0 ]]; then
        [[ "$idle" -ge "$NEWS_SEC" ]] || continue
      else
        [[ "$idle" -ge "$IDLE_SEC" ]] || continue
      fi
      # A long tool call writes nothing to the session or the trace until it
      # ends; Herdr knows the pane is still working, so ask it before nudging.
      if [[ -n "$HUB_STATUS" ]]; then
        status="$(jq -r --arg id "$id" '.agents[$id].state // empty' "$HUB_STATUS" 2>/dev/null || true)"
      else
        status="$("$HERDR" agent get "$id" 2>/dev/null | jq -r '.result.agent.agent_status // empty' 2>/dev/null || true)"
      fi
      [[ "$status" == "working" ]] && continue
    fi
    # An agent whose last turn ended in a provider error is not idle in the
    # usual sense: a nudge buys another identical failure while the error
    # holds (both DeepSeek agents on the BelkaCTF #6 run spent all three
    # nudges against a 402). So it is tried again with backoff, each wait
    # twice the last, up to half an hour: under a cap policy MAX_NUDGES
    # times per run of errors, within the wall clock; until solved, for as
    # long as the run goes, and a rate limit that lifts finds it working. A
    # retry refused again is also what tells a limit on every seat from a
    # passing error (provider_limit_check), and a paused run's seats are not
    # nudged.
    provider_error=0
    if grep -q "\"agent\":\"$id\",\"tool\":\"agent_error\"" "$SANDBOX/traces/events.jsonl" 2>/dev/null; then
      [[ "$(last_turn "$id")" == "agent_error" ]] && provider_error=1
    fi
    if [[ "$provider_error" -eq 1 ]]; then
      read -r ek elast <<<"$(awk -v id="$id" '$1 == id { print $2, $3 }' "$ERRSTATE")"
      ek="${ek:-0}"
      elast="${elast:-0}"
      [[ "$US" -eq 1 || "$ek" -lt "$MAX_NUDGES" ]] || continue
      eback=$(( IDLE_SEC * (1 << (ek > 4 ? 4 : ek)) ))
      [[ "$eback" -gt 1800 ]] && eback=1800
      [[ $(( $(date +%s) - elast )) -ge "$eback" ]] || continue
      set_err "$id" $((ek + 1)) "$(date +%s)"
      etry=$((ek + 1))
    elif grep -q "^$id " "$ERRSTATE" 2>/dev/null; then
      # It worked since: the next error starts the backoff again.
      set_err "$id" 0 0
    fi
    # A model served from this machine can take minutes to answer its first
    # turn on a long contract — the LM Studio seat on BelkaCTF #6 took four,
    # and was nudged twice before it had emitted a token. Nothing it has done
    # yet means it is still loading, not stalling.
    if [[ "$idle" -lt "$LOCAL_FIRST_TURN_SEC" ]] && is_local_model "$id" && ! has_worked "$id"; then
      continue
    fi
    held="$(held_by "$id")"
    # A shorter clock than when we last nudged means the agent worked in
    # between: this is a new silence, and it gets a fresh budget.
    n="$(count_of "$id")"
    mark="$(mark_of "$id")"
    if [[ "$mark" -gt 0 && "$clock" -lt "$mark" ]]; then
      n=0
    fi
    if [[ "$n" -ge "$MAX_NUDGES" && "$provider_error" -eq 0 ]]; then
      # Past the budget an until-solved run keeps nudging, each wait twice
      # the last, up to half an hour: it never gives an agent up.
      [[ "$US" -eq 1 ]] || continue
      backoff=$(( IDLE_SEC * (1 << (n - MAX_NUDGES + 1)) ))
      [[ "$backoff" -gt 1800 ]] && backoff=1800
      [[ $(( clock - mark )) -ge "$backoff" ]] || continue
    fi
    n=$((n + 1))
    set_count "$id" "$n" "$clock"
    minutes=$((clock / 60))
    # "0 posts you have not read" is worse than saying nothing.
    news_line=""
    [[ "$unread" -gt 0 ]] 2>/dev/null && news_line="You have ${unread} post(s) you have not read. "
    # What the lead register would have this agent take: the top question
    # nobody covers or the ready lead it ranks first, what it holds, and its
    # jobs awaiting interpretation (scripts/leads-cli.ts nudge-line).
    leads_line="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/leads-cli.ts" nudge-line "$SANDBOX" "$id" 2>/dev/null || true)"
    [[ -n "$leads_line" ]] && leads_line=" ${leads_line}"
    budget_words="Nudge ${n} of ${MAX_NUDGES}."
    if [[ "$US" -eq 1 && "$n" -gt "$MAX_NUDGES" ]]; then budget_words="Nudge ${n}: this run is until solved, and the nudges go on."; fi
    if [[ "$provider_error" -eq 1 && "$US" -eq 1 ]]; then
      why="provider_error"
      text="Your last turn ended in a provider error, and this run is until solved: an error or a rate limit is waited out and retried, and never ends the run. Pick up where you left off: read inbox, go on with what you hold, or take the next thing nobody holds.${held:+ You still hold: ${held}.}${leads_line} ${budget_words}"
    elif [[ "$provider_error" -eq 1 ]]; then
      why="provider_error"
      text="Your last turn ended in a provider error. The harness tries you again up to ${MAX_NUDGES} times, each wait longer than the last, in case it has passed; if the provider refuses every seat, the run pauses instead. Pick up where you left off: read inbox, go on with what you hold, or take the next thing nobody holds.${held:+ You still hold: ${held}.}${leads_line} Try ${etry} of ${MAX_NUDGES}."
    elif [[ "$why" == waiting ]]; then
      text="For ${minutes} minutes you have called only wait and inbox: no post, no record, no command. Waiting is right while an answer you asked for is coming; past that it is idle. ${news_line}If a peer owes you an answer, ask them again by name. Otherwise read inbox, see what your peers have taken, take the next piece of the goal nobody holds and say so on the board; when nothing is left for you, keep waiting. Only done ends your part.${held:+ You still hold: ${held} — release_file what you are not working on, or a peer will take it when the lease runs out.}${leads_line} Nudge ${n} of ${MAX_NUDGES}."
    else
      text="You ended your turn ${minutes} minutes ago and the swarm is not done. Ending a turn is not waiting: nothing prompts you again. ${news_line}Read inbox, see what your peers have taken, and get on with what you said you were doing (name() if that has changed); when there is nothing left to take, call the wait tool and keep it open, and call it again each time it returns. Only done ends your part.${held:+ You still hold: ${held} — release_file what you are not working on, or a peer will take it when the lease runs out.}${leads_line} Nudge ${n} of ${MAX_NUDGES}."
    fi
    text="${text//Nudge ${n} of ${MAX_NUDGES}./$budget_words}"
    if prompt_agent "$id" "$text" "$deliver" >/dev/null 2>&1; then
      log_event "$id" "$clock" true "$n" "$why"
      echo "idle-nudge: prompted $id after ${clock}s ${why} (nudge $n/$MAX_NUDGES)"
    else
      log_event "$id" "$clock" false "$n" "$why"
      echo "idle-nudge: could not prompt $id (pane gone?)" >&2
    fi
  done
  [[ "$ONCE" -eq 1 ]] && exit 0
  sleep "$INTERVAL"
done
