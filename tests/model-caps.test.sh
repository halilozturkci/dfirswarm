#!/usr/bin/env bash
# Fixture for the per-model cap. No Herdr, no Pi, no panes: `--no-start`
# prepares the sandbox and we read what it wrote.
#
# A mixed team's cost is in the model, not the seat, so a `--models` entry may
# end in "@cap": a USD ceiling on the combined spend of every agent running that
# model. What must not go wrong: the spec has to parse with and without the
# suffix, the caps have to land in budget.json and the registry with each
# seat's model beside its spend, and every refusal (a cap that is not a
# number, a cap above the swarm's own) has to be a refusal.
set -uo pipefail
# This suite tests host runs, and a run is in microVMs unless it says
# otherwise: it names host. An image, a lock file or another pack home
# exported in the shell would point its kickoffs somewhere else.
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/model-caps.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

start() { # start <args...> -> prints stdout+stderr, never fails the suite
  SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" start "$@" 2>&1
}
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }
reg() { # reg <label> <jq expression>
  jq -r --arg l "$1" ".runs[] | select(.[\"label\"] == \$l) | $2" "$TMP/runs/registry.json"
}
HELLO="$ROOT/prompts/goals/hello.md"

# --- the spec parses, and the caps land where the harness reads them --------
out="$(start --models "openai/gpt-5.4-mini=2@6,openai/gpt-5.4-nano=2@4" --cap-usd 20 --no-start \
  --goal-file "$HELLO" --label capped)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -d "$sb" ]] || fail "no sandbox from a capped mixed start: $out"

got="$(jq -r '[.agents[].model] | join(",")' "$sb/team.json")"
[[ "$got" == "openai/gpt-5.4-mini,openai/gpt-5.4-mini,openai/gpt-5.4-nano,openai/gpt-5.4-nano" ]] \
  || fail "the counts still decide the team: $got"
pass "an entry with @cap still expands to its count of agents"

got="$(jq -c '.cap_per_model_usd' "$sb/budget.json")"
[[ "$got" == '{"openai/gpt-5.4-mini":6,"openai/gpt-5.4-nano":4}' ]] || fail "budget.json cap_per_model_usd: $got"
pass "the per-model caps reach budget.json as cap_per_model_usd"

got="$(jq -r '[.agents | to_entries[] | .value.model] | join(",")' "$sb/budget.json")"
[[ "$got" == "openai/gpt-5.4-mini,openai/gpt-5.4-mini,openai/gpt-5.4-nano,openai/gpt-5.4-nano" ]] \
  || fail "each seat's model should sit beside its spend in budget.json: $got"
pass "each seat's model is on its own budget row, so the cap can be summed from budget.json alone"

got="$(reg capped '.cap_per_model_usd | tojson')"
[[ "$got" == '{"openai/gpt-5.4-mini":6,"openai/gpt-5.4-nano":4}' ]] || fail "registry cap_per_model_usd: $got"
pass "the per-model caps reach the run record"

grep -q '^Per-model cap: \$6 on openai/gpt-5.4-mini' <<<"$out" || fail "no Per-model cap line for mini in the kickoff output: $out"
grep -q '^Per-model cap: \$4 on openai/gpt-5.4-nano' <<<"$out" || fail "no Per-model cap line for nano in the kickoff output: $out"
pass "the kickoff summary prints one line per model cap"

# --- the suffix is optional, per entry ---------------------------------------
out="$(start --models "alpha/one=2,beta/two=1@2.5" --cap-usd 5 --no-start --goal-file "$HELLO" --label partial)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "a spec with one capped entry should start: $out"
got="$(jq -c '.cap_per_model_usd' "$sb/budget.json")"
[[ "$got" == '{"beta/two":2.5}' ]] || fail "only the capped model should carry a cap: $got"
[[ "$(jq -r '.agents | length' "$sb/team.json")" == "3" ]] || fail "the counts should be unchanged by a cap on one entry"
pass "an entry without @ has no cap; a decimal cap is kept as written"

out="$(start --models "alpha/one=2,beta/two=1" --cap-usd 5 --no-start --goal-file "$HELLO" --label nocaps)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "provider/id=2 should still start: $out"
[[ "$(jq -r 'has("cap_per_model_usd")' "$sb/budget.json")" == "false" ]] || fail "budget.json should carry no per-model caps unless asked"
[[ "$(reg nocaps '.cap_per_model_usd')" == "null" ]] || fail "registry cap_per_model_usd should be null without any @cap"
[[ "$(jq -r '[.agents[].model] | join(",")' "$sb/team.json")" == "alpha/one,alpha/one,beta/two" ]] || fail "the plain spec changed shape"
grep -q '^Per-model cap' <<<"$out" && fail "no cap was asked for, so no Per-model cap line: $out"
pass "provider/id=count still works exactly as before, with no per-model cap anywhere"

# A count of one may be implied, and a model id may carry ':' and '.': the
# split is the last '@'.
out="$(start --models "ollama/qwen3:8b@1.5,vendor/model.v2=1@2" --cap-usd 5 --no-start --goal-file "$HELLO" --label ids)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "model ids with ':' and '.' should take a cap: $out"
got="$(jq -c '.cap_per_model_usd' "$sb/budget.json")"
[[ "$got" == '{"ollama/qwen3:8b":1.5,"vendor/model.v2":2}' ]] || fail "caps on ids with ':' and '.': $got"
[[ "$(jq -r '.agents | length' "$sb/team.json")" == "2" ]] || fail "@cap without =count should mean one agent"
pass "@cap works without a count, and on model ids that carry ':' and '.'"

# A uniform swarm has no spec and so no per-model caps.
out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$HELLO" --label uniform)"
sb="$(sandbox_of "$out")"
[[ "$(jq -r 'has("cap_per_model_usd")' "$sb/budget.json")" == "false" ]] || fail "--model should write no per-model caps"
[[ "$(jq -r '[.agents[].model] | unique | join(",")' "$sb/budget.json")" == "solo/model" ]] || fail "a uniform swarm's seats still record their model"
pass "--model writes no per-model cap, and its seats still carry their model"

# --- refusals ----------------------------------------------------------------
refuses() { # refuses <label> <expected-substring> <args...>
  local label="$1" want="$2"; shift 2
  local out rc
  out="$(start "$@")"
  rc=$?
  [[ "$rc" -ne 0 ]] || fail "$label: expected a non-zero exit"
  case "$out" in
    *"$want"*) pass "$label" ;;
    *) fail "$label: wanted [$want], got: $out" ;;
  esac
  [[ -z "$(sandbox_of "$out")" ]] || fail "$label: a refusal should prepare nothing"
}

refuses "a cap that is not a number is refused" "needs a positive number of USD after '@'" \
  --models "alpha/one=2@six" --cap-usd 20 --no-start
refuses "a cap of zero is refused" "needs a positive number of USD after '@'" \
  --models "alpha/one=2@0" --cap-usd 20 --no-start
refuses "an empty cap is refused" "needs a positive number of USD after '@'" \
  --models "alpha/one=2@" --cap-usd 20 --no-start
refuses "a cap above --cap-usd is refused" "above the swarm's own cap" \
  --models "alpha/one=2@6,beta/two=1" --cap-usd 5 --no-start
refuses "a cap above --cap-usd is refused when only the cents put it over" "above the swarm's own cap" \
  --models "alpha/one=1@5.01" --cap-usd 5 --no-start
refuses "the same model with two different caps is refused" "two caps" \
  --models "alpha/one=1@3,alpha/one=1@4" --cap-usd 20 --no-start
refuses "a malformed reference keeps its refusal, cap or not" "does not look like provider/id" \
  --models "not-a-model=2@3" --cap-usd 20 --no-start

# The same model twice with one cap is one ceiling over both entries.
out="$(start --models "alpha/one=1@3,alpha/one=2" --cap-usd 20 --no-start --goal-file "$HELLO" --label twice)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "the same model twice, capped once, should start: $out"
[[ "$(jq -c '.cap_per_model_usd' "$sb/budget.json")" == '{"alpha/one":3}' ]] || fail "one cap for a model named twice: $(jq -c '.cap_per_model_usd' "$sb/budget.json")"
[[ "$(jq -r '.agents | length' "$sb/team.json")" == "3" ]] || fail "both entries should still add their agents"
pass "a model named twice with one cap gets one ceiling over all its agents"

# A cap equal to --cap-usd fits: the refusal is for larger, not for equal.
out="$(start --models "alpha/one=2@5" --cap-usd 5 --no-start --goal-file "$HELLO" --label equal)"
[[ -n "$(sandbox_of "$out")" ]] || fail "a per-model cap equal to --cap-usd should be accepted: $out"
pass "a per-model cap equal to --cap-usd is accepted"

echo "all per-model cap cases passed"
