#!/usr/bin/env bash
# Stall / timeout reaper. An agent the harness timed out is shown as "?" —
# not `done`, just dead. What counts as a stall is a local choice
# (SPECULATIVE choices are marked below).
#
# For every id in team.json that has neither done/agents/<id>.done nor
# done/agents/<id>.dead, compute last activity as the newest of:
#   - a post by the agent           threads/*/*-<id>.md         (mtime)
#   - a lock refresh by the agent   locks/*.json owner==<id>    (mtime)
#   - an event by the agent         traces/events.jsonl agent==<id> (ts)
#   - inbox cursor advance          inbox/<id>/cursors.json     (mtime)   SPECULATIVE
#   - Pi session activity           .pi-sessions/<id>/**        (mtime)   SPECULATIVE
#   - fallback: budget.json started_at (swarm start) when none of the above exist
# If now - last_activity > timeout: write done/agents/<id>.dead, release the
# agent's locks, append a `reap` line to traces/events.jsonl (same schema as
# the harness: ts, agent, tool, args, result), and with --stop close the
# agent's Herdr pane. The official CLI reference (herdr.dev/docs/cli-reference)
# has no `herdr agent stop`; the documented path is `herdr agent get <id>` ->
# pane id -> `herdr pane close <pane_id>`. Failure is tolerated.
#
# Idempotent: a reaped agent has a .dead marker and is skipped on later runs.
# Requires: bash 4+, jq, GNU or BSD stat/date (both handled).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/trace.sh
. "$ROOT/scripts/lib/trace.sh"
SANDBOX="${SWARM_SANDBOX:-$ROOT/sandbox}"
TIMEOUT="${REAP_TIMEOUT:-960}"
STOP=0
DRY_RUN=0
QUIET=0
HERDR="${HERDR_BIN:-herdr}"

usage() {
  cat <<EOF
Usage: scripts/reap.sh [--sandbox DIR] [--timeout SECONDS] [--stop] [--dry-run] [--quiet]

  --sandbox   Isolated cwd (default: repo sandbox/ or \$SWARM_SANDBOX)
  --timeout   Seconds of silence before an agent is declared dead (default 960, \$REAP_TIMEOUT).
              A pane Herdr reports as working is never reaped: a long bash call
              writes nothing until it ends.
  --stop      Also close the reaped agent's Herdr pane (agent get -> pane close; best effort)
  --dry-run   Report stalls, change nothing
  --quiet     Only print reaped/skipped lines, no per-agent status

Exit code: 0 always (idempotent housekeeping), 2 on usage / missing deps.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sandbox) SANDBOX="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --stop) STOP=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --quiet) QUIET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

command -v jq >/dev/null 2>&1 || { echo "reap.sh needs jq" >&2; exit 2; }
[[ -f "$SANDBOX/team.json" ]] || { echo "No team.json in $SANDBOX" >&2; exit 2; }
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { echo "--timeout must be an integer" >&2; exit 2; }

log() { [[ "$QUIET" -eq 1 ]] || echo "$@"; }

# Portable mtime (epoch seconds): GNU stat first, BSD/macOS second.
mtime() {
  stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0
}

# ISO-8601 (with or without fractional seconds) -> epoch seconds via jq.
iso_to_epoch() {
  printf '%s' "$1" | jq -Rr 'sub("\\.[0-9]+Z$"; "Z") | try fromdateiso8601 catch 0'
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
NOW="$(date +%s)"

max() { if [[ "$1" -ge "$2" ]]; then echo "$1"; else echo "$2"; fi; }

# Same table lock as protocol.ts: exclusive mkdir locks/.table.lock, 10s wait,
# break stale (>15s) locks whose pid is gone.
TABLE_LOCK="$SANDBOX/locks/.table.lock"
table_lock() {
  mkdir -p "$SANDBOX/locks"
  local deadline=$((SECONDS + 10))
  while ! mkdir "$TABLE_LOCK" 2>/dev/null; do
    if [[ -d "$TABLE_LOCK" ]]; then
      local age=$(( $(date +%s) - $(mtime "$TABLE_LOCK") ))
      local pid; pid="$(cat "$TABLE_LOCK/pid" 2>/dev/null || true)"
      if [[ "$age" -ge 15 ]] && { [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; }; then
        rm -rf "$TABLE_LOCK"
        continue
      fi
    fi
    if (( SECONDS >= deadline )); then echo "Timed out waiting for locks/.table.lock" >&2; return 1; fi
    sleep 0.05
  done
  echo $$ > "$TABLE_LOCK/pid"
}
table_unlock() { rm -rf "$TABLE_LOCK"; }

# A long `vol` / `fls` writes nothing to the session or the trace until it
# returns. Herdr already knows the pane is working; idle-nudge.sh asks it
# before nudging, and the reaper must ask before declaring the seat dead.
agent_working() {
  local id="$1" status
  status="$("$HERDR" agent get "$id" 2>/dev/null | jq -r '.result.agent.agent_status // empty' 2>/dev/null || true)"
  [[ "$status" == "working" ]]
}

last_activity() {
  local id="$1" last=0 f ts
  shopt -s nullglob
  for f in "$SANDBOX"/threads/*/*-"$id".md; do last="$(max "$last" "$(mtime "$f")")"; done
  for f in "$SANDBOX"/locks/*.json; do
    if [[ "$(jq -r '.owner // empty' "$f" 2>/dev/null)" == "$id" ]]; then
      last="$(max "$last" "$(mtime "$f")")"
    fi
  done
  if [[ -f "$SANDBOX/traces/events.jsonl" ]]; then
    ts="$(jq -r --arg id "$id" 'select(.agent == $id) | .ts' "$SANDBOX/traces/events.jsonl" 2>/dev/null | tail -n 1 || true)"
    [[ -n "$ts" ]] && last="$(max "$last" "$(iso_to_epoch "$ts")")"
  fi
  for f in "$SANDBOX/inbox/$id/cursors.json" "$SANDBOX/inbox/$id/seen"; do
    [[ -f "$f" ]] && last="$(max "$last" "$(mtime "$f")")"
  done
  if [[ -d "$SANDBOX/.pi-sessions/$id" ]]; then
    while IFS= read -r f; do last="$(max "$last" "$(mtime "$f")")"; done \
      < <(find "$SANDBOX/.pi-sessions/$id" -type f 2>/dev/null)
  fi
  shopt -u nullglob
  if [[ "$last" -eq 0 && -f "$SANDBOX/budget.json" ]]; then
    ts="$(jq -r '.started_at // empty' "$SANDBOX/budget.json")"
    [[ -n "$ts" ]] && last="$(iso_to_epoch "$ts")"
  fi
  echo "$last"
}

reap_agent() {
  local id="$1" last="$2" idle="$3" released=0 f lock_path
  local dead="$SANDBOX/done/agents/$id.dead"
  local last_iso; last_iso="$(date -u -d "@$last" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$last" +%Y-%m-%dT%H:%M:%SZ)"

  table_lock
  # Re-check under the lock: another reaper may have won the race.
  if [[ -e "$dead" || -e "$SANDBOX/done/agents/$id.done" ]]; then
    table_unlock
    echo "skip $id: already marked while waiting for the table lock"
    return 0
  fi
  mkdir -p "$SANDBOX/done/agents"
  shopt -s nullglob
  for f in "$SANDBOX"/locks/*.json; do
    if [[ "$(jq -r '.owner // empty' "$f" 2>/dev/null)" == "$id" ]]; then
      lock_path="$(jq -r '.path // "?"' "$f")"
      rm -f "$f"
      released=$((released + 1))
      log "  released lock $lock_path"
    fi
  done
  shopt -u nullglob
  cat > "$dead" <<EOF
---
by: reaper
agent: $id
reason: stall
last_activity: $last_iso
idle_seconds: $idle
timeout_seconds: $TIMEOUT
locks_released: $released
at: $(now_iso)
---

Worker $id showed no post, lock refresh, event, or session activity for ${idle}s (> ${TIMEOUT}s). Marked dead by scripts/reap.sh.
EOF
  mkdir -p "$SANDBOX/traces"
  local reap_line
  reap_line="$(jq -cn --arg ts "$(now_iso)" --arg agent "$id" --arg last "$last_iso" \
    --argjson idle "$idle" --argjson timeout "$TIMEOUT" --argjson released "$released" \
    '{ts: $ts, agent: $agent, tool: "reap",
      args: {timeout_seconds: $timeout, reason: "stall"},
      result: {reaped: true, idle_seconds: $idle, last_activity: $last, locks_released: $released}}')"
  # Through the collector when there is one, so the chain stays unbroken.
  trace_emit "$ROOT" "$SANDBOX" "$reap_line"
  table_unlock

  if [[ "$STOP" -eq 1 ]]; then
    if command -v herdr >/dev/null 2>&1; then
      # Official CLI has no `agent stop`; close the pane that hosts the agent.
      # `agent get` JSON shape is not pinned in the docs, so take the first
      # pane_id anywhere in the result.
      local pane
      pane="$(herdr agent get "$id" 2>/dev/null | jq -r '[.. | objects | .pane_id? // empty] | first // empty' 2>/dev/null || true)"
      if [[ -n "$pane" ]] && herdr pane close "$pane" >/dev/null 2>&1; then
        log "  herdr pane close $pane ($id): ok"
      else
        log "  herdr pane close for $id: agent not found or close failed (ignored)"
      fi
    else
      log "  herdr not installed; skipping pane close"
    fi
  fi
  echo "reaped $id (idle ${idle}s, released ${released} lock(s)) -> done/agents/$id.dead"
}

reaped=0
while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  if [[ -e "$SANDBOX/done/agents/$id.done" ]]; then
    log "ok   $id: done"
    continue
  fi
  if [[ -e "$SANDBOX/done/agents/$id.dead" ]]; then
    log "dead $id: already reaped"
    continue
  fi
  last="$(last_activity "$id")"
  idle=$((NOW - last))
  if [[ "$last" -eq 0 ]]; then
    log "??   $id: no activity signal and no budget.json baseline; leaving alone"
    continue
  fi
  if (( idle > TIMEOUT )); then
    if agent_working "$id"; then
      log "work $id: idle ${idle}s but herdr says working; leaving alone"
      continue
    fi
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "would reap $id (idle ${idle}s > ${TIMEOUT}s)"
    else
      reap_agent "$id" "$last" "$idle"
      reaped=$((reaped + 1))
    fi
  else
    log "live $id: idle ${idle}s"
  fi
done < <(jq -r '.agents[].id' "$SANDBOX/team.json")

log "reaped $reaped agent(s)"
exit 0
