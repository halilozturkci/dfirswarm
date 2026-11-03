#!/usr/bin/env bash
# The stop policy from the command line (docs/adr/0013): the kickoff's --stop
# (cap-pause by default, cap-stop, operator; --until-solved is operator; the
# goal's metadata; a conflict refused), the default token cap, the contract's
# words; swarm.sh extend (refused while still over, the pause lifted with
# room, on the board and the operator's record); swarm.sh stop (stopped,
# never completed); and the watchdog: a paused run's seats are not nudged,
# the pause is enforced from outside the panes, the seats are woken once
# when an extension lifts it, and a stop is proposed when nothing yields.
# No model, no VM; Herdr is a stand-in that records what it is told.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stop-policy.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
HELLO="$ROOT/prompts/goals/hello.md"
export SWARM_RUNS_DIR="$TMP/runs"
kick() { bash "$ROOT/scripts/swarm.sh" start --model solo/model --n 2 --no-start --goal-file "$HELLO" --toolbox off "$@" 2>&1; }
sandbox_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .sandbox' "$TMP/runs/registry.json"; }
id_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .id' "$TMP/runs/registry.json"; }
# A harness line is on the run's trace in one of two files (scripts/lib/trace.sh):
# the kickoff's line, taken by its collector, chains the record, and --no-start
# then stops the collector, so the watchdog's lines are kept in
# traces/system-spill.jsonl rather than put unchained into a chained record.
# Where the collector's socket could not be reached (a path past the 104 bytes
# macOS allows) the record stays unchained and the line is appended. Each file
# on its own: BSD grep exits 2 when one of several files is missing, whatever
# it matched in the others.
trace_has() { # <sandbox> <pattern>
  local f
  for f in "$1/traces/events.jsonl" "$1/traces/system-spill.jsonl"; do
    [[ -f "$f" ]] && grep -q -- "$2" "$f" && return 0
  done
  return 1
}

echo "# the kickoff"
out="$(kick --cap-usd 5 --label p1)" || fail "a default kickoff was refused: $out"
sb="$(sandbox_of p1)"
[[ "$(jq -r '.stop_policy' "$sb/budget.json")" == cap-pause ]] || fail "the default policy is not cap-pause: $(jq -c . "$sb/budget.json")"
[[ "$(jq -r '.cap_tokens' "$sb/budget.json")" == 100000000 ]] || fail "a metered team did not get the default token cap"
[[ "$(jq -r '.runs[] | select(.label == "p1") | .stop_policy' "$TMP/runs/registry.json")" == cap-pause ]] || fail "the registry does not say the policy"
grep -q 'Stop policy:  cap-pause' <<<"$out" || fail "the kickoff does not say the policy: $out"
grep -q '(the default token cap)' <<<"$out" || fail "the kickoff does not say the token cap is the default: $out"
grep -q '^## At a cap$' "$sb/SWARM.md" || fail "the contract does not say what a cap does"
grep -q 'two minutes later the run pauses: no model call goes out' "$sb/SWARM.md" || fail "the contract does not say the pause"
grep -q -- '- Tokens: 100000000 across the swarm' "$sb/SWARM.md" || fail "the contract does not name the token cap"
# One rule for the end of a run, whatever the policy: the dispositions under the bar, and the way to not_determinable.
grep -q 'The run ends, whatever its stop policy, when every question in scope has a' "$sb/SWARM.md" || fail "the contract does not say how a cap-pause run ends"
grep -q '"looked, not found" is not an end' "$sb/SWARM.md" || fail "the contract does not refuse a limitation as an end"
grep -q 'then answer not_determinable (or bounded_negative' "$sb/SWARM.md" || fail "the contract does not say the not_determinable path"
out="$(kick --cap-usd 5 --cap-tokens 7000 --stop cap-stop --label p2)" || fail "--stop cap-stop was refused: $out"
sb2="$(sandbox_of p2)"
[[ "$(jq -r '.stop_policy' "$sb2/budget.json")" == cap-stop && "$(jq -r '.cap_tokens' "$sb2/budget.json")" == 7000 ]] || fail "--stop cap-stop or --cap-tokens not kept"
grep -q "This run's stop policy is cap-stop" "$sb2/SWARM.md" || fail "the contract does not say cap-stop"
out="$(kick --stop operator --label p3)" || fail "--stop operator was refused: $out"
sb3="$(sandbox_of p3)"
jq -e '.stop_policy == "operator" and .until_solved == true and .wall_clock_minutes == 0 and (has("cap_tokens") | not)' "$sb3/budget.json" >/dev/null || fail "--stop operator is not --until-solved: $(jq -c . "$sb3/budget.json")"
out="$(kick --until-solved --label p4)" || fail "--until-solved was refused: $out"
[[ "$(jq -r '.stop_policy' "$(sandbox_of p4)/budget.json")" == operator ]] || fail "--until-solved is not --stop operator"
set +e
out="$(kick --until-solved --stop cap-stop --label p5)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q -- '--until-solved is --stop operator' <<<"$out" || fail "a conflicting policy was not refused (rc $rc): $out"
set +e
out="$(kick --cap-usd 1 --stop sometimes --label p6)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q -- '--stop takes cap-pause' <<<"$out" || fail "an unknown policy was not refused (rc $rc): $out"
{ printf -- '---\ntitle: t\nstop: cap-stop\n---\n'; cat "$HELLO"; } > "$TMP/goal-stop.md"
out="$(bash "$ROOT/scripts/swarm.sh" start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/goal-stop.md" --toolbox off --label p7 2>&1)" || fail "a goal naming its policy was refused: $out"
[[ "$(jq -r '.stop_policy' "$(sandbox_of p7)/budget.json")" == cap-stop ]] || fail "the goal's stop: was not taken"
pass "the kickoff: cap-pause by default with a default token cap, --stop cap-stop and operator, --until-solved as operator, the goal's stop:, conflicts refused"

echo "# swarm.sh extend and stop"
id="$(id_of p1)"
set +e
out="$(bash "$ROOT/scripts/swarm.sh" extend "$id" --minutes 5 2>&1)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'an extension is for a run that is going' <<<"$out" || fail "extending a prepared run was not refused (rc $rc): $out"
# The run going, and paused at its token cap.
tmp="$(mktemp)"; jq --arg id "$id" '(.runs[] | select(.id == $id) | .state) = "running"' "$TMP/runs/registry.json" > "$tmp" && mv "$tmp" "$TMP/runs/registry.json"
jq --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.tokens = 100000500 | .paused = {at: $at, reason: "cap", detail: "the token cap passed"}' "$sb/budget.json" > "$tmp" && mv "$tmp" "$sb/budget.json"
set +e
out="$(bash "$ROOT/scripts/swarm.sh" extend "$id" --minutes 30 2>&1)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'would still be over the token cap' <<<"$out" || fail "an extension that leaves the run over a cap was not refused (rc $rc): $out"
[[ "$(jq -r '.paused.reason' "$sb/budget.json")" == cap ]] || fail "a refused extension changed the pause"
out="$(bash "$ROOT/scripts/swarm.sh" extend "$id" --tokens 1000000 2>&1)" || fail "the extension was refused: $out"
grep -q 'the pause is lifted, and every seat is woken where it was' <<<"$out" || fail "the extension does not say the pause lifted: $out"
jq -e '(has("paused") | not) and (.pauses | length) == 1 and .pauses[0].resumed_by == "operator" and .cap_tokens == 101000500' "$sb/budget.json" >/dev/null || fail "the pause was not lifted as said: $(jq -c '{paused, pauses, cap_tokens}' "$sb/budget.json")"
grep -q '"command":"extend"' "$TMP/runs/operator-audit.jsonl" || fail "the extension is not on the operator's record"
grep -rq 'The operator extended the run' "$sb/threads/main/" || fail "the extension is not on the board"
set +e
out="$(bash "$ROOT/scripts/swarm.sh" extend "$id" --tokens nope 2>&1)"; rc=$?
set -e
[[ $rc -eq 2 ]] || fail "a bad number was not refused: $out"
out="$(bash "$ROOT/scripts/swarm.sh" stop "$id" --no-custody 2>&1)" || fail "stop failed: $out"
[[ "$(jq -r '.outcome' "$sb/done/STOPPED")" == stopped ]] || fail "the operator's stop did not record stopped"
[[ "$(node --experimental-strip-types --no-warnings "$ROOT/scripts/stop-policy.ts" outcome "$sb" | jq -r '.outcome')" == stopped ]] || fail "the outcome is not stopped"
[[ "$(jq -r --arg id "$id" '.runs[] | select(.id == $id) | .state' "$TMP/runs/registry.json")" == ended ]] || fail "the registry does not say ended (a run with nothing alive is ended, cause unknown, not stopped)"
pass "extend: refused while still over, the pause lifted with room, on the record and the board; stop: stopped, never completed"

echo "# the watchdog"
SB="$(sandbox_of p2)"
mkdir -p "$TMP/bin" "$SB/.pi-sessions/sp00" "$SB/.pi-sessions/sp01"
cat > "$TMP/bin/herdr" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
  "agent get") printf '{"result":{"agent":{"agent_status":"idle"}}}\n' ;;
  "agent prompt") printf '%s\t%s\n' "$3" "$4" >> "$PROMPT_LOG" ;;
  *) : ;;
esac
SH
chmod +x "$TMP/bin/herdr"
export PROMPT_LOG="$TMP/prompts.txt"
: > "$PROMPT_LOG"
ids="$(jq -r '.agents[].id' "$SB/team.json" | tr '\n' ' ')"
old="$(date -v-600S +%Y%m%d%H%M.%S 2>/dev/null || date -d '600 seconds ago' +%Y%m%d%H%M.%S)"
for a in $ids; do
  mkdir -p "$SB/.pi-sessions/$a"
  : > "$SB/.pi-sessions/$a/s.jsonl"
  touch -t "$old" "$SB/.pi-sessions/$a/s.jsonl"
done
watch_once() { HERDR_BIN="$TMP/bin/herdr" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$SB" --once --idle-sec 60 >/dev/null 2>&1 || true; }
# Paused: nobody is nudged.
tmp="$(mktemp)"; jq --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.stop_policy = "cap-pause" | .tokens = 9000 | .paused = {at: $at, reason: "cap", detail: "d"}' "$SB/budget.json" > "$tmp" && mv "$tmp" "$SB/budget.json"
watch_once
[[ ! -s "$PROMPT_LOG" ]] || fail "a paused run's seats were nudged: $(cat "$PROMPT_LOG")"
# Extended: every seat is woken once, with the words that say so, and then nudged as usual.
node --experimental-strip-types --no-warnings "$ROOT/scripts/stop-policy.ts" extend "$SB" --tokens 50000 --by operator >/dev/null || fail "the extension failed"
watch_once
for a in $ids; do
  grep -q "^$a	The operator extended the run at .*: the pause for cap is lifted" "$PROMPT_LOG" || fail "$a was not woken after the extension: $(cat "$PROMPT_LOG")"
done
woken="$(grep -c 'The operator extended the run' "$PROMPT_LOG")"
watch_once
[[ "$(grep -c 'The operator extended the run' "$PROMPT_LOG")" -eq "$woken" ]] || fail "the seats were woken twice for one extension"
trace_has "$SB" '"tool":"resume_wake"' || fail "the wake is not on the trace"
# The pause, enforced from outside the panes: over the cap under cap-pause, the watchdog steers, and past the grace pauses.
tmp="$(mktemp)"; jq --arg t "$(date -u -v-5M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)" '.tokens = 90000 | .stop_steer_at = $t | .stop_reason = "cap"' "$SB/budget.json" > "$tmp" && mv "$tmp" "$SB/budget.json"
watch_once
[[ "$(jq -r '.paused.reason' "$SB/budget.json")" == cap ]] || fail "the watchdog did not pause the run past the grace: $(jq -c '{paused, stop_steer_at}' "$SB/budget.json")"
[[ ! -f "$SB/done/SWARM_DONE" ]] || fail "a paused run got a sentinel"
trace_has "$SB" '"tool":"run_paused"' || fail "the pause is not on the trace"
pass "the watchdog: a paused run's seats are held, woken once when an extension lifts the pause, and a cap past its grace pauses the run"

echo "# diminishing returns"
tmp="$(mktemp)"; jq 'del(.paused) | .tokens = 0 | .started_at = "2026-01-01T00:00:00Z" | del(.wall_base_at) | del(.wall_used_ms) | .wall_clock_minutes = 10000000 | del(.stop_steer_at) | del(.stop_reason)' "$SB/budget.json" > "$tmp" && mv "$tmp" "$SB/budget.json"
rm -f "$SB/traces/idle-nudge.yield"
watch_once
grep -q '"kind":"decision"' "$SB/operator-requests.jsonl" || fail "no stop was proposed after a window with nothing yielded"
trace_has "$SB" '"tool":"stop_proposed"' || fail "the proposal is not on the trace"
[[ ! -f "$SB/done/SWARM_DONE" && ! -f "$SB/done/STOPPED" ]] || fail "a proposal stopped the run"
pass "diminishing returns: a stop is proposed to the operator (a request of kind decision), and nothing is stopped"

echo "# the watchdog under review: a pause told once whoever wrote it, a wake retried until it lands, the stop policy at --idle-sec 0"
id2="$(id_of p2)"
mkdir -p "$TMP/runs/notify"
printf 'cat >> %q\n' "$TMP/notified.jsonl" > "$TMP/runs/notify/$id2.cmd"
chmod 600 "$TMP/runs/notify/$id2.cmd"
: > "$TMP/notified.jsonl"
# A pause a pane's own extension wrote: the watchdog did not make it, and tells it all the same, once.
paused_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
tmp="$(mktemp)"; jq --arg at "$paused_at" '.tokens = 9000 | .paused = {at: $at, reason: "cap", detail: "a pane paused it"}' "$SB/budget.json" > "$tmp" && mv "$tmp" "$SB/budget.json"
watch_life() { HERDR_BIN="$TMP/bin/herdr" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$SB" --once --idle-sec 0 >/dev/null 2>&1 || true; }
watch_life
for _ in $(seq 1 40); do grep -q '"event":"paused"' "$TMP/notified.jsonl" && break; sleep 0.25; done
grep -q '"event":"paused"' "$TMP/notified.jsonl" || fail "a pause the watchdog did not write was never told: $(cat "$TMP/notified.jsonl")"
watch_life
sleep 1
[[ "$(grep -c '"event":"paused"' "$TMP/notified.jsonl")" -eq 1 ]] || fail "the pause was told more than once: $(cat "$TMP/notified.jsonl")"
# The extension lifts it; one seat cannot be reached the first time: it is tried again, and the other is not woken twice.
cat > "$TMP/bin/herdr" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
  "agent get") printf '{"result":{"agent":{"agent_status":"idle"}}}\n' ;;
  "agent prompt")
    if [[ -f "$UNREACHABLE" && "$3" == "$(cat "$UNREACHABLE")" ]]; then exit 1; fi
    printf '%s\t%s\n' "$3" "$4" >> "$PROMPT_LOG" ;;
  *) : ;;
esac
SH
chmod +x "$TMP/bin/herdr"
export UNREACHABLE="$TMP/unreachable"
set -- $ids
first="$1"; second="$2"
printf '%s' "$first" > "$UNREACHABLE"
: > "$PROMPT_LOG"
node --experimental-strip-types --no-warnings "$ROOT/scripts/stop-policy.ts" extend "$SB" --tokens 50000 --by operator >/dev/null || fail "the extension failed"
watch_life
grep -q "^$second	The operator extended the run" "$PROMPT_LOG" || fail "$second was not woken: $(cat "$PROMPT_LOG")"
if grep -q "^$first	" "$PROMPT_LOG"; then fail "$first was reached although it could not be"; fi
rm -f "$UNREACHABLE"
watch_life
grep -q "^$first	The operator extended the run" "$PROMPT_LOG" || fail "$first was not woken when it could be reached again: $(cat "$PROMPT_LOG")"
[[ "$(grep -c "^$second	" "$PROMPT_LOG")" -eq 1 ]] || fail "$second was woken twice: $(cat "$PROMPT_LOG")"
# --idle-sec 0 prompts nobody for being idle, though every seat has been silent for ten minutes.
if grep -v 'The operator extended the run' "$PROMPT_LOG" | grep -q .; then fail "a seat was nudged at --idle-sec 0: $(cat "$PROMPT_LOG")"; fi
out="$(kick --cap-usd 5 --idle-nudge-sec 0 --label p8)" || fail "a kickoff with --idle-nudge-sec 0 was refused: $out"
grep -q '^Idle nudge:   off (--idle-nudge-sec 0): no agent is prompted; the watchdog still runs the stop policy' <<<"$out" || fail "the kickoff does not say the watchdog still runs at --idle-nudge-sec 0: $out"
pass "the watchdog: a pause is told once whoever wrote it, a wake that did not land is tried again, and --idle-sec 0 keeps the stop policy without nudging"
