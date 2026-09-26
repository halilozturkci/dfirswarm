#!/usr/bin/env bash
# A team on a subscription is braked by tokens, and every cap can be changed
# while the run goes on (swarm.sh cap).
set -uo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/subscription-caps.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
swarm() { SWARM_RUNS_DIR="$TMP/runs" PI_CODING_AGENT_DIR="$TMP/pi" bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
start() { swarm start --n 2 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off "$@"; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }
reg() { jq -r --arg l "$1" ".runs[] | select(.[\"label\"] == \$l) | $2" "$TMP/runs/registry.json"; }
mkdir -p "$TMP/pi"
printf '{"openai-codex": {"type": "oauth", "access": "not-real", "refresh": "not-real", "expires": 4102444800000}}\n' > "$TMP/pi/auth.json"

# --- a subscription is braked by tokens --------------------------------------------------
out="$(start --model openai-codex/gpt-6-luna --cap-usd 50 --label sub-no-tokens)"; rc=$?
[[ $rc -eq 2 ]] || fail "a subscription team with only --cap-usd exited $rc, wanted 2: $out"
grep -q 'run on a subscription (OAuth)' <<<"$out" || fail "the refusal does not say the team is on a subscription: $out"
grep -q -- '--cap-tokens N' <<<"$out" || fail "the refusal does not name the token cap: $out"

out="$(start --model openai-codex/gpt-6-luna --cap-usd 50 --cap-tokens 5000000 --cap-per-agent 10 --cap-per-agent-tokens 800000 --label sub-ok)"; rc=$?
[[ $rc -eq 0 ]] || fail "a subscription team with --cap-tokens did not prepare: $out"
sb="$(sandbox_of "$out")"
jq -e '.metered == false and .cap_tokens == 5000000 and .cap_per_agent_tokens == 800000' "$sb/budget.json" >/dev/null \
  || fail "the budget does not brake the subscription by tokens: $(jq -c 'del(.agents)' "$sb/budget.json")"
grep -q "^Cap: *5000000 tokens / .*on a subscription" <<<"$out" || fail "the kickoff does not say the cap is tokens on a subscription: $out"
grep -q 'WARN: --cap-per-agent \$10 brakes nothing' <<<"$out" || fail "a per-agent dollar cap on a subscription was not said to brake nothing: $out"
grep -q '^Per-agent cap: 800000 tokens' <<<"$out" || fail "the per-agent token cap is not said: $out"
[[ "$(reg sub-ok '.cap_per_agent_tokens')" == 800000 ]] || fail "the run record lacks the per-agent token cap"
pass "a subscription team needs --cap-tokens, its dollars brake nothing, and a per-agent token cap is kept"

# --- swarm.sh cap -----------------------------------------------------------------------
id="$(reg sub-ok '.id')"
out="$(swarm cap "$id" --tokens 9000000 --wall-clock 120)"; rc=$?
[[ $rc -eq 0 ]] || fail "cap on a prepared run exited $rc: $out"
grep -q 'changed the token cap from 5,000,000 tokens to 9,000,000 tokens, the wall clock from' <<<"$out" || fail "cap does not say what it changed: $out"
jq -e '.cap_tokens == 9000000 and .wall_clock_minutes == 120 and (.cap_changes | length) == 1 and .cap_changes[0].by == "operator"' "$sb/budget.json" >/dev/null \
  || fail "the budget does not hold the new caps and their record: $(jq -c 'del(.agents)' "$sb/budget.json")"
grep -rq 'changed the token cap' "$sb/threads/main/" || fail "the board was not told"
[[ "$(reg sub-ok '.cap_tokens')" == 9000000 && "$(reg sub-ok '.wall_clock_minutes')" == 120 ]] || fail "the run record does not follow the new caps"
grep -q '"tool":"operator_action".*"command":"cap"' "$sb/traces/events.jsonl" 2>/dev/null || grep -rq '"command":"cap"' "$sb/traces/" 2>/dev/null \
  || fail "the change is not on the trace as the operator's"
out="$(swarm cap "$id" --tokens 0)"; rc=$?
[[ $rc -eq 2 ]] || fail "a token cap of 0 on a subscription team exited $rc, wanted 2: $out"
grep -q 'token cap stays above zero' <<<"$out" || fail "the refusal does not say why: $out"
out="$(swarm cap "$id")"; rc=$?
[[ $rc -eq 2 ]] || fail "cap with nothing to set exited $rc, wanted 2: $out"
out="$(swarm cap nosuchrun --tokens 5)"; rc=$?
[[ $rc -ne 0 ]] || fail "cap on an unknown run succeeded: $out"
pass "swarm.sh cap changes a run's caps under the lock, records it, tells the board and the run record, and keeps the brake"
