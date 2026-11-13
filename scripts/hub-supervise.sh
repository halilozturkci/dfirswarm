#!/usr/bin/env bash
# The VM hub's keeper, for the length of a microVM run.
#
# The hub is the VMs' board, their trace door and the stop that does not
# depend on them. It used to come back after a crash only when the idle
# watchdog noticed, and a run started with --idle-nudge-sec 0, or one past
# its sentinel, has no watchdog: a dead hub then left the VMs with no board
# and no stop but msb's own time limit. This process waits on the hub and
# brings it back with `--resume` (same tokens, same stop clock; the hub keeps
# them in its own directory) until the run's stop says it is over (a `.stop`
# file in the hub directory) or the run is gone.
#
# The trace collector too: in a VM run it is the trace's only door (the hub
# sends every seat's line through it), and one that died left the rest of
# the run in spill files outside the chain. It is brought back with the same
# tokens (the hub keeps them) and the same anchor, and resumes the chain from
# the file's last line.
#
#   hub-supervise.sh <sandbox> <hub dir> <hub script> <first hub pid>
set -u

SANDBOX="$1"
HUB_DIR="$2"
HUB_SCRIPT="$3"
PID="$4"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# A hub that dies this often in a row is not going to stay up: say so and stop trying.
MAX_RESTARTS="${SWARM_HUB_MAX_RESTARTS:-20}"
# In a row: a hub that stayed up this long before it died starts the count
# again, or a run of days with a crash now and then lost its keeper for good.
STABLE_SEC="${SWARM_HUB_STABLE_SEC:-600}"

over() { [[ -e "$HUB_DIR/.stop" || ! -d "$SANDBOX" || ! -f "$HUB_DIR/hub-input.json" ]]; }

# The harness's own token, from what the hub keeps: this keeper's lines are
# the harness's, attributed as such.
SYSTEM_TOKEN="$(jq -r '.tokens.system // empty' "$HUB_DIR/hub-input.json" 2>/dev/null || true)"

emit() { # <json line>
  printf '%s' "$1" | SWARM_TRACE_TOKEN="$SYSTEM_TOKEN" node "$ROOT/scripts/trace-emit.mjs" "$SANDBOX" >/dev/null 2>&1 \
    || printf '%s\n' "$1" >> "$HUB_DIR/hub-spill.jsonl"
}

collector_alive() {
  local pid cmd
  pid="$(cat "$SANDBOX/collector.pid" 2>/dev/null || true)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null || return 1
  cmd="$(ps -ww -o command= -p "$pid" 2>/dev/null)" || return 1
  [[ "$cmd" == *trace-collector.mjs* && "$cmd" == *"$SANDBOX"* ]]
}

# Only a run whose kickoff started a collector has one to keep.
KEEP_COLLECTOR=0
collector_alive && KEEP_COLLECTOR=1
collector_restarts=0
collector_since=$SECONDS
COLLECTOR_SCRIPT="$ROOT/scripts/trace-collector.mjs"
[[ -f "$HUB_DIR/host/scripts/trace-collector.mjs" ]] && COLLECTOR_SCRIPT="$HUB_DIR/host/scripts/trace-collector.mjs"

keep_collector() {
  [[ "$KEEP_COLLECTOR" -eq 1 ]] || return 0
  collector_alive && return 0
  over && return 0
  (( SECONDS - collector_since >= STABLE_SEC )) && collector_restarts=0
  collector_restarts=$((collector_restarts + 1))
  if (( collector_restarts > MAX_RESTARTS )); then
    echo "hub-supervise: the collector died ${MAX_RESTARTS} times in a row; not restarting it again" >> "$SANDBOX/traces/vm-hub.log"
    KEEP_COLLECTOR=0
    return 0
  fi
  local anchor tokens pid ok=false i
  anchor="$(cd "$(dirname "$SANDBOX")" && pwd -P)/$(basename "$SANDBOX").trace-anchor.json"
  # The collector's own shape: token -> agent, and no gate in a VM run.
  tokens="$(jq -c '{tokens: ((.tokens // {}) | to_entries | map({key: .value, value: .key}) | from_entries), gate: ""}' "$HUB_DIR/hub-input.json" 2>/dev/null)" || return 0
  rm -f "$SANDBOX/traces/.collector.sock"
  printf '%s' "$tokens" | node "$COLLECTOR_SCRIPT" "$SANDBOX" --tokens --anchor "$anchor" --quiet >>"$SANDBOX/traces/collector.log" 2>&1 &
  pid=$!
  echo "$pid" > "$SANDBOX/collector.pid"
  collector_since=$SECONDS
  for ((i = 0; i < 50; i++)); do
    [[ -S "$SANDBOX/traces/.collector.sock" ]] && kill -0 "$pid" 2>/dev/null && { ok=true; break; }
    sleep 0.1
  done
  emit "$(jq -nc --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson ok "$ok" --argjson n "$collector_restarts" \
    '{ts: $ts, agent: "system", tool: "collector_restarted", args: {by: "hub-supervise", restart: $n}, result: {ok: $ok}}')"
}

# The model gateway (--model-gateway), when the kickoff started one: brought
# back on the port the VMs were given, with the same config.
gateway_alive() {
  local pid cmd
  pid="$(cat "$HUB_DIR/model-gateway.pid" 2>/dev/null || true)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null || return 1
  cmd="$(ps -ww -o command= -p "$pid" 2>/dev/null)" || return 1
  [[ "$cmd" == *model-gateway.ts* && "$cmd" == *"$HUB_DIR"* ]]
}
gateway_restarts=0
gateway_since=$SECONDS
GATEWAY_GAVE_UP=0
GATEWAY_SCRIPT="$ROOT/scripts/model-gateway.ts"
[[ -f "$HUB_DIR/host/scripts/model-gateway.ts" ]] && GATEWAY_SCRIPT="$HUB_DIR/host/scripts/model-gateway.ts"

keep_gateway() {
  [[ "$GATEWAY_GAVE_UP" -eq 0 && -f "$HUB_DIR/model-gateway.json" && -s "$HUB_DIR/model-gateway.port" ]] || return 0
  gateway_alive && return 0
  over && return 0
  (( SECONDS - gateway_since >= STABLE_SEC )) && gateway_restarts=0
  gateway_restarts=$((gateway_restarts + 1))
  if (( gateway_restarts > MAX_RESTARTS )); then
    echo "hub-supervise: the model gateway died ${MAX_RESTARTS} times in a row; not restarting it again" >> "$SANDBOX/traces/model-gateway.log"
    GATEWAY_GAVE_UP=1
    return 0
  fi
  local port pid ok=false i
  port="$(cat "$HUB_DIR/model-gateway.port")"
  rm -f "$HUB_DIR/model-gateway.ready"
  SWARM_TRACE_TOKEN="$SYSTEM_TOKEN" node --experimental-strip-types --no-warnings "$GATEWAY_SCRIPT" --config "$HUB_DIR/model-gateway.json" \
    --port "$port" --ready "$HUB_DIR/model-gateway.ready" --quiet >>"$SANDBOX/traces/model-gateway.log" 2>&1 </dev/null &
  pid=$!
  echo "$pid" > "$HUB_DIR/model-gateway.pid"
  gateway_since=$SECONDS
  for ((i = 0; i < 100; i++)); do
    [[ -s "$HUB_DIR/model-gateway.ready" ]] && kill -0 "$pid" 2>/dev/null && { ok=true; break; }
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  emit "$(jq -nc --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson ok "$ok" --argjson n "$gateway_restarts" --argjson port "$port" \
    '{ts: $ts, agent: "system", tool: "model_gateway_restarted", args: {by: "hub-supervise", restart: $n, port: $port}, result: {ok: $ok}}')"
}

# The fetch service (--network dynamic or open), when the kickoff started
# one: brought back on the port the hub and the job workers were given, with
# the same config (the same secret, so every principal's token still holds).
netfetch_alive() {
  local pid cmd
  pid="$(cat "$HUB_DIR/net-fetch.pid" 2>/dev/null || true)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null || return 1
  cmd="$(ps -ww -o command= -p "$pid" 2>/dev/null)" || return 1
  [[ "$cmd" == *net-fetch.ts* && "$cmd" == *"$HUB_DIR"* ]]
}
netfetch_restarts=0
netfetch_since=$SECONDS
NETFETCH_GAVE_UP=0
NETFETCH_SCRIPT="$ROOT/scripts/net-fetch.ts"
[[ -f "$HUB_DIR/host/scripts/net-fetch.ts" ]] && NETFETCH_SCRIPT="$HUB_DIR/host/scripts/net-fetch.ts"

keep_netfetch() {
  [[ "$NETFETCH_GAVE_UP" -eq 0 && -f "$HUB_DIR/net-fetch.json" && -s "$HUB_DIR/net-fetch.port" ]] || return 0
  netfetch_alive && return 0
  over && return 0
  (( SECONDS - netfetch_since >= STABLE_SEC )) && netfetch_restarts=0
  netfetch_restarts=$((netfetch_restarts + 1))
  if (( netfetch_restarts > MAX_RESTARTS )); then
    echo "hub-supervise: the fetch service died ${MAX_RESTARTS} times in a row; not restarting it again" >> "$SANDBOX/traces/net-fetch.log"
    NETFETCH_GAVE_UP=1
    return 0
  fi
  local port pid ok=false i
  port="$(cat "$HUB_DIR/net-fetch.port")"
  rm -f "$HUB_DIR/net-fetch.ready"
  SWARM_TRACE_TOKEN="$SYSTEM_TOKEN" node --experimental-strip-types --no-warnings "$NETFETCH_SCRIPT" --config "$HUB_DIR/net-fetch.json" \
    --port "$port" --ready "$HUB_DIR/net-fetch.ready" --quiet >>"$SANDBOX/traces/net-fetch.log" 2>&1 </dev/null &
  pid=$!
  echo "$pid" > "$HUB_DIR/net-fetch.pid"
  netfetch_since=$SECONDS
  for ((i = 0; i < 100; i++)); do
    [[ -s "$HUB_DIR/net-fetch.ready" ]] && kill -0 "$pid" 2>/dev/null && { ok=true; break; }
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  emit "$(jq -nc --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson ok "$ok" --argjson n "$netfetch_restarts" --argjson port "$port" \
    '{ts: $ts, agent: "system", tool: "net_fetch_restarted", args: {by: "hub-supervise", restart: $n, port: $port}, result: {ok: $ok}}')"
}

restarts=0
up_since=$SECONDS
while :; do
  while kill -0 "$PID" 2>/dev/null; do
    keep_collector
    keep_gateway
    keep_netfetch
    sleep 2
  done
  over && exit 0
  (( SECONDS - up_since >= STABLE_SEC )) && restarts=0
  restarts=$((restarts + 1))
  if (( restarts > MAX_RESTARTS )); then
    echo "hub-supervise: the hub died ${MAX_RESTARTS} times in a row; not restarting it again" >> "$SANDBOX/traces/vm-hub.log"
    # The idle watchdog restarts a hub whose keeper is gone; one that gave
    # up is not second-guessed every half minute.
    date -u +%Y-%m-%dT%H:%M:%SZ > "$HUB_DIR/.keeper-gave-up"
    # A run whose hub is down for good has no board, trace door or stop:
    # the operator's notify command hears it.
    bash "$ROOT/scripts/notify.sh" "$SANDBOX" hub_down "$(jq -nc --argjson n "$MAX_RESTARTS" '{restarts_in_a_row: $n}')" >/dev/null 2>&1 </dev/null || true
    exit 1
  fi
  sleep 2
  over && exit 0
  # A hub that runs out of heap leaves a snapshot in its own directory (operator-only), never in the run's.
  SWARM_HUB_SUPERVISED=1 node --experimental-strip-types --no-warnings --max-old-space-size="${SWARM_HUB_HEAP_MB:-8192}" --heapsnapshot-near-heap-limit=1 --diagnostic-dir="$HUB_DIR" "$HUB_SCRIPT" --resume "$HUB_DIR" >>"$SANDBOX/traces/vm-hub.log" 2>&1 </dev/null &
  PID=$!
  up_since=$SECONDS
  echo "$PID" > "$SANDBOX/hub.pid"
  ok=false
  for ((i = 0; i < 100; i++)); do
    [[ -S "$HUB_DIR/admin.sock" ]] && kill -0 "$PID" 2>/dev/null && { ok=true; break; }
    sleep 0.1
  done
  emit "$(jq -nc --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg d "$HUB_DIR" --argjson ok "$ok" --argjson n "$restarts" \
    '{ts: $ts, agent: "system", tool: "hub_restarted", args: {dir: $d, by: "hub-supervise", restart: $n}, result: {ok: $ok}}')"
done
