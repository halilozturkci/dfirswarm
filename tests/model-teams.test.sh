#!/usr/bin/env bash
# Fixture for mixed-model swarms. No Herdr, no Pi, no panes: `--no-start`
# prepares the sandbox and we read what it wrote.
#
# A swarm does not have to be one model, and the thing that must not go wrong is
# the *mapping*: agent 00 has to get the model the operator named first, every
# distinct model has to reach the netguard allowlist, and the team has to be able
# to see who is running what.
set -uo pipefail
# This suite tests host runs, and a run is in microVMs unless it says
# otherwise: it names host. An image, a lock file or another pack home
# exported in the shell would point its kickoffs somewhere else.
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/model-teams.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

start() { # start <args...> -> prints stdout+stderr, never fails the suite
  SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" start "$@" 2>&1
}

sandbox_of() { # sandbox_of <output>
  printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1
}

# --- the mapping -------------------------------------------------------------
out="$(start --models "alpha/one=2,beta/two=1,gamma/three=1" --cap-usd 1 --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label teams)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -d "$sb" ]] || fail "no sandbox from a mixed start: $out"

case "$out" in
  *"N:            4"*) pass "N is the sum of the counts" ;;
  *) fail "N was not derived from --models: $out" ;;
esac

got="$(jq -r '[.agents[].model] | join(",")' "$sb/team.json")"
[[ "$got" == "alpha/one,alpha/one,beta/two,gamma/three" ]] \
  || fail "agent order does not follow the spec: $got"
pass "agents get their models in the order the spec names them"

got="$(jq -r '.models | join(",")' "$sb/team.json")"
[[ "$got" == "alpha/one,beta/two,gamma/three" ]] || fail "team.json models: $got"
pass "team.json lists the distinct models"

grep -q 'Assigned ids: `s[a-z0-9]*00` (alpha/one)' "$sb/SWARM.md" \
  || fail "the contract does not name each agent's model"
pass "the contract tells the team who is running what"

# --- a uniform swarm is still uniform ----------------------------------------
out="$(start --model solo/model --n 3 --cap-usd 1 --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label uniform)"
sb="$(sandbox_of "$out")"
got="$(jq -r '[.agents[].model] | unique | join(",")' "$sb/team.json")"
[[ "$got" == "solo/model" ]] || fail "uniform swarm models: $got"
pass "--model still puts every agent on the same model"
# With one model there is nothing to disambiguate, so the contract stays terse.
grep -q 'Assigned ids: `s[a-z0-9]*00`,' "$sb/SWARM.md" \
  || fail "a uniform contract should not repeat the model after every id"
pass "a uniform contract does not repeat the model after every id"

# --- the allowlist is the union ----------------------------------------------
# Read the helper out of the script: starting for real would need Herdr.
HELPERS="$TMP/helpers.sh"
{
  # Pi's store is read where the kickoff reads it (an --env value wins).
  sed -n '/^pane_home() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^pi_agent_dir() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^valid_model_ref() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^parse_model_teams() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^distinct_models() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^credential_models() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^provider_hosts_for_model() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^provider_known_hosts() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^models_json_base_url() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^provider_base_url() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^host_of_url() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^allow_entry_of_url() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^host_is_local() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^provider_is_local() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^model_is_metered() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^provider_hosts_for_models() {/,/^}/p' "$ROOT/scripts/swarm.sh"
} > "$HELPERS"

hosts_for() { # hosts_for <spec>
  local script="$TMP/hosts.sh"
  {
    echo 'set -u'
    echo "ROOT=\"$ROOT\""
    echo "source \"$HELPERS\""
    echo "parse_model_teams \"\$1\""
    echo 'provider_hosts_for_models'
  } > "$script"
  bash "$script" "$1"
}

got="$(hosts_for "anthropic/claude-sonnet-5=1,openai-codex/gpt-6-astra=1")"
[[ "$got" == "api.anthropic.com,platform.claude.com,chatgpt.com,auth.openai.com" ]] \
  || fail "mixed allowlist: $got"
pass "every provider in the team reaches the allowlist"

# A subscription needs its token endpoint too, or a refresh mid-run fails closed.
got="$(hosts_for "anthropic/claude-sonnet-5=2")"
[[ "$got" == "api.anthropic.com,platform.claude.com" ]] || fail "anthropic hosts: $got"
pass "a subscription provider brings its OAuth token endpoint"

got="$(hosts_for "openai/gpt-5.4=1,openai/gpt-5.5=1")"
[[ "$got" == "api.openai.com" ]] || fail "duplicate hosts should collapse: $got"
pass "two models from one provider do not duplicate the host"

got="$(hosts_for "mockswarm/scripted-1=2")"
[[ -z "$got" ]] || fail "an unknown provider should contribute nothing, got: $got"
pass "an unknown provider contributes no hosts"

# Azure's host is the customer's resource: from the shell, or from Pi's store.
got="$(AZURE_OPENAI_BASE_URL="https://MyRes.openai.azure.com/openai/v1" hosts_for "azure-openai-responses/gpt-5.4=2,deepseek/deepseek-v4-pro=1")"
[[ "$got" == "myres.openai.azure.com,api.deepseek.com" ]] || fail "azure host from the base url: $got"
got="$(AZURE_OPENAI_BASE_URL="" AZURE_OPENAI_RESOURCE_NAME="other-res" hosts_for "azure-openai-responses/gpt-5.4=1")"
[[ "$got" == "other-res.openai.azure.com" ]] || fail "azure host from the resource name: $got"
mkdir -p "$TMP/pi-agent"
printf '{"azure-openai-responses":{"type":"api_key","key":"x","env":{"AZURE_OPENAI_BASE_URL":"https://stored.cognitiveservices.azure.com"}}}\n' > "$TMP/pi-agent/auth.json"
got="$(AZURE_OPENAI_BASE_URL="" AZURE_OPENAI_RESOURCE_NAME="" PI_CODING_AGENT_DIR="$TMP/pi-agent" hosts_for "azure-openai-responses/gpt-5.4=1")"
[[ "$got" == "stored.cognitiveservices.azure.com" ]] || fail "azure host from Pi's store: $got"
got="$(AZURE_OPENAI_BASE_URL="" AZURE_OPENAI_RESOURCE_NAME="" PI_CODING_AGENT_DIR="$TMP/nowhere" hosts_for "azure-openai-responses/gpt-5.4=1")"
[[ -z "$got" ]] || fail "azure with nothing configured should contribute nothing, got: $got"
pass "the Azure OpenAI host comes from the shell or Pi's store, and is empty when neither has it"

# A provider Pi knows only from models.json (a gateway, a local server, an
# Azure AI Foundry resource) brings the host of its own baseUrl.
mkdir -p "$TMP/pi-models"
cat > "$TMP/pi-models/models.json" <<'JSON'
{
  "providers": {
    "azure-foundry": {
      "baseUrl": "https://Some-Resource.services.ai.azure.com/openai/v1",
      "api": "openai-completions",
      "models": [{ "id": "grok-4.6" }, { "id": "DeepSeek-V4-Pro" }]
    }
  }
}
JSON
got="$(PI_CODING_AGENT_DIR="$TMP/pi-models" hosts_for "azure-foundry/grok-4.6=2,azure-foundry/DeepSeek-V4-Pro=1")"
[[ "$got" == "some-resource.services.ai.azure.com" ]] || fail "models.json host: $got"
got="$(PI_CODING_AGENT_DIR="$TMP/pi-models" hosts_for "azure-foundry/grok-4.6=1,deepseek/deepseek-v4-pro=1")"
[[ "$got" == "some-resource.services.ai.azure.com,api.deepseek.com" ]] || fail "mixed models.json host: $got"
got="$(PI_CODING_AGENT_DIR="$TMP/pi-models" hosts_for "not-configured/some-model=1")"
[[ -z "$got" ]] || fail "a provider absent from models.json should contribute nothing: $got"
pass "a provider defined in Pi's models.json contributes the host of its baseUrl"

# Model ids as vendors write them: dots, dashes and capitals.
ref_ok() { bash -c 'source "$1"; valid_model_ref "$2"' _ "$HELPERS" "$1"; }
ref_ok "azure-foundry/DeepSeek-V4-Pro" || fail "a capitalised deployment id should be a valid model ref"
ref_ok "azure-foundry/grok-4.6" || fail "a dotted model id should be a valid model ref"
ref_ok "azure-foundry/" && fail "a model ref with no model should be refused"
pass "a deployment id with capitals and dots is a valid model reference"

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
}

refuses "--model and --models together are refused" "not both" \
  --model a/b --models "a/b=2" --cap-usd 1 --no-start
refuses "--n that disagrees with --models is refused" "disagrees with --models" \
  --models "a/b=2" --n 3 --cap-usd 1 --no-start
refuses "a malformed model reference is refused" "does not look like provider/id" \
  --models "not-a-model=2" --cap-usd 1 --no-start
refuses "a zero count is refused" "needs a count of at least 1" \
  --models "a/b=0" --cap-usd 1 --no-start
refuses "an empty spec is refused" "--models is empty" \
  --models "  ,  " --cap-usd 1 --no-start
refuses "a team larger than the cap on N is refused" "more than 30 agents" \
  --models "a/b=31" --cap-usd 1 --no-start
# Counts are decimal. "010" is eight in shell arithmetic and "08" is an error,
# so a count that looks octal must not quietly become a different team size.
out="$(start --models "alpha/one=010" --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md")"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "a leading-zero count should still start: $out"
got="$(jq -r '.agents | length' "$sb/team.json")"
[[ "$got" == "10" ]] || fail "010 should mean ten agents, got $got"
pass "a leading-zero count is read as decimal, not octal"
refuses "a count with a non-digit is refused" "needs a count of at least 1" \
  --models "a/b=1x" --cap-usd 1 --no-start
refuses "an absurd count is refused before it is expanded" "more than 30 agents" \
  --models "a/b=999" --cap-usd 1 --no-start

# --- tool forging is a kickoff flag, recorded where the console can see it ---
out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --allow-tool-forging \
  --goal-file "$ROOT/prompts/goals/hello.md" --label forge)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -d "$sb/tools" ]] || fail "a forging swarm should have a tools/ directory: $out"
grep -q "Tools:        forging on" <<<"$out" || fail "kickoff should say forging is on"
got="$(jq -r '.. | objects | select(.["label"]? == "forge") | .tool_forging' "$TMP/runs/registry.json")"
[[ "$got" == "true" ]] || fail "registry tool_forging should be true, got $got"
got="$(jq -r '.. | objects | select(.["label"]? == "uniform") | .tool_forging' "$TMP/runs/registry.json")"
[[ "$got" == "false" ]] || fail "registry tool_forging should default to false, got $got"
pass "--allow-tool-forging is recorded in the registry and prepares tools/"

# --- self-compaction is on by default, recorded, and switchable ------------
got="$(jq -r '.. | objects | select(.["label"]? == "uniform") | .self_compact | "\(.enabled) \(.notice_at) \(.warn_at) \(.compact_at)"' "$TMP/runs/registry.json")"
[[ "$got" == "true 40% 50% 60%" ]] || fail "registry self_compact should default to on at 40/50/60, got $got"
grep -q "Compaction:   self" <<<"$out" || fail "kickoff should say self-compaction is on"
sb_uniform="$(jq -r '.. | objects | select(.["label"]? == "uniform") | .sandbox' "$TMP/runs/registry.json")"
[[ -f "$sb_uniform/.pi/settings.json" ]] || fail "the sandbox should carry Pi's compaction settings"
jq -e '.compaction.reserveTokens == 16384 and .compaction.keepRecentTokens == 20000' "$sb_uniform/.pi/settings.json" >/dev/null \
  || fail "the sandbox's .pi/settings.json should pin reserveTokens and keepRecentTokens"
out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --no-self-compact \
  --goal-file "$ROOT/prompts/goals/hello.md" --label nocompact)"
grep -q "Compaction:   Pi's own only" <<<"$out" || fail "kickoff should say self-compaction is off: $out"
got="$(jq -r '.. | objects | select(.["label"]? == "nocompact") | .self_compact.enabled' "$TMP/runs/registry.json")"
[[ "$got" == "false" ]] || fail "registry self_compact.enabled should be false with --no-self-compact, got $got"
out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --compact-at 150k --compact-warn-at 45% \
  --goal-file "$ROOT/prompts/goals/hello.md" --label tuned)"
got="$(jq -r '.. | objects | select(.["label"]? == "tuned") | .self_compact | "\(.notice_at) \(.warn_at) \(.compact_at)"' "$TMP/runs/registry.json")"
[[ "$got" == "40% 45% 150k" ]] || fail "registry should record the tuned lines with the default filled in, got $got"
got="$(jq -r '.. | objects | select(.["label"]? == "tuned") | .self_compact.set | "\(.notice_at) \(.warn_at) \(.compact_at)"' "$TMP/runs/registry.json")"
[[ "$got" == "false true true" ]] || fail "registry should record which lines the operator set, got $got"
grep -q "notice 40% (default) · warning 45% · compact 150k" <<<"$out" \
  || fail "kickoff should mark a default next to a set line as a default, not as a line the operator set: $out"
got="$(jq -r '.. | objects | select(.["label"]? == "uniform") | .self_compact.set | "\(.notice_at) \(.warn_at) \(.compact_at)"' "$TMP/runs/registry.json")"
[[ "$got" == "false false false" ]] || fail "registry should record that no line was set on a default run, got $got"
refuses "a compact line that is neither tokens nor a percentage is refused" "a compact threshold is a token count" \
  --model solo/model --n 2 --cap-usd 1 --no-start --compact-at lots --goal-file "$ROOT/prompts/goals/hello.md"
pass "self-compaction is on by default, recorded with its lines, and switchable"

# --- per-model lines, the summary model, the inbox page ---------------------
out="$(start --models "alpha/one=2,beta/two=1" --cap-usd 1 --no-start \
  --compact-at "60%,alpha/one=55%,two=70%" --compact-model beta/two --inbox-page-chars 12000 \
  --goal-file "$ROOT/prompts/goals/hello.md" --label permodel)"
got="$(jq -r '.. | objects | select(.["label"]? == "permodel") | "\(.self_compact.compact_at)|\(.self_compact.model)|\(.inbox_page_chars)"' "$TMP/runs/registry.json")"
[[ "$got" == "60%,alpha/one=55%,two=70%|beta/two|12000" ]] || fail "registry should record the per-model line, the summary model and the inbox page, got $got"
grep -q "summaries by beta/two" <<<"$out" || fail "kickoff should say which model writes the summaries: $out"
got="$(jq -r '.. | objects | select(.["label"]? == "uniform") | .inbox_page_chars' "$TMP/runs/registry.json")"
[[ "$got" == "40000" ]] || fail "registry should record the default inbox page, got $got"
got="$(compact_model="deepseek/deepseek-v4-pro" hosts_for "openai/gpt-5.4=1")"
[[ "$got" == "api.openai.com,api.deepseek.com" ]] || fail "the summary model's host should join the allowlist: $got"
got="$(compact_model="openai/gpt-5.4-nano" hosts_for "openai/gpt-5.4=1")"
[[ "$got" == "api.openai.com" ]] || fail "a summary model on a seat's provider adds no host: $got"
refuses "a per-model entry with a bad value is refused" "a compact threshold is a token count" \
  --model solo/model --n 2 --cap-usd 1 --no-start --compact-at "60%,solo/model=lots" --goal-file "$ROOT/prompts/goals/hello.md"
refuses "a per-model entry with a bad key is refused" "a per-model compact entry is model=value" \
  --model solo/model --n 2 --cap-usd 1 --no-start --compact-at "60%,bad!key=55%" --goal-file "$ROOT/prompts/goals/hello.md"
refuses "a summary model that is not provider/id is refused" "does not look like provider/id" \
  --model solo/model --n 2 --cap-usd 1 --no-start --compact-model nano --goal-file "$ROOT/prompts/goals/hello.md"
refuses "a summary model with self-compaction off is refused" "drop --no-self-compact" \
  --model solo/model --n 2 --cap-usd 1 --no-start --no-self-compact --compact-model solo/model --goal-file "$ROOT/prompts/goals/hello.md"
refuses "an inbox page that is not a number is refused" "whole number of characters" \
  --model solo/model --n 2 --cap-usd 1 --no-start --inbox-page-chars lots --goal-file "$ROOT/prompts/goals/hello.md"
pass "per-model lines, the summary model and the inbox page are validated, recorded and allowlisted"

# --- a local server: its host, its twin, and what it means for the caps -----
# Nothing on the way resolves names: not Pi's own proxy matcher, not the
# proxy's allowlist. So a loopback host reaches the allowlist with its other
# spelling, an IPv6 literal is written [v6]:port, and Pi's llama.cpp provider,
# which has no models.json entry, brings the host of LLAMA_BASE_URL.
mkdir -p "$TMP/pi-local"
cat > "$TMP/pi-local/models.json" <<'JSON'
{
  "providers": {
    "ollama":   { "baseUrl": "http://127.0.0.1:11434/v1", "api": "openai-completions", "apiKey": "ollama",
                  "models": [{ "id": "qwen3:8b" },
                             { "id": "paid", "cost": { "input": 1, "output": 2, "cacheRead": 0, "cacheWrite": 0 } }] },
    "lmstudio": { "baseUrl": "http://localhost:1234/v1", "api": "openai-completions", "apiKey": "x", "models": [{ "id": "m" }] },
    "six":      { "baseUrl": "http://[::1]:8000/v1", "api": "openai-completions", "apiKey": "x", "models": [{ "id": "m" }] },
    "lan":      { "baseUrl": "http://192.168.1.20:8000/v1", "api": "openai-completions", "apiKey": "x",
                  "models": [{ "id": "m", "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 } }] },
    "gateway":  { "baseUrl": "https://gateway.example.com/v1", "api": "openai-completions", "apiKey": "x", "models": [{ "id": "m" }] }
  }
}
JSON
got="$(PI_CODING_AGENT_DIR="$TMP/pi-local" hosts_for "ollama/qwen3:8b=2")"
[[ "$got" == "127.0.0.1:11434,localhost:11434" ]] || fail "a loopback address brings its name: $got"
got="$(PI_CODING_AGENT_DIR="$TMP/pi-local" hosts_for "lmstudio/m=1")"
[[ "$got" == "localhost:1234,127.0.0.1:1234" ]] || fail "localhost brings its address: $got"
got="$(PI_CODING_AGENT_DIR="$TMP/pi-local" hosts_for "six/m=1")"
[[ "$got" == "[::1]:8000" ]] || fail "an IPv6 literal with a port is bracketed, the form netguard and a VM both read: $got"
got="$(LLAMA_BASE_URL="" PI_CODING_AGENT_DIR="$TMP/pi-local" hosts_for "llama.cpp/qwen=1")"
[[ "$got" == "127.0.0.1:8080,localhost:8080" ]] || fail "llama.cpp defaults to Pi's own base URL: $got"
got="$(LLAMA_BASE_URL="http://gpu-box.local:8080" PI_CODING_AGENT_DIR="$TMP/pi-local" hosts_for "llama.cpp/qwen=1")"
[[ "$got" == "gpu-box.local:8080" ]] || fail "llama.cpp takes LLAMA_BASE_URL: $got"
got="$(PI_CODING_AGENT_DIR="$TMP/pi-local" hosts_for "ollama/qwen3:8b=1,deepseek/deepseek-v4-pro=1")"
[[ "$got" == "127.0.0.1:11434,localhost:11434,api.deepseek.com" ]] || fail "a mixed team keeps every host: $got"
pass "a local server's host reaches the allowlist with its other spelling; IPv6 and llama.cpp included"

# "Local" is the endpoint's address; "metered" is whether anyone bills. They
# are decided once, from models.json, and everything else reads the answer.
classify() { # classify <fn> <model> -> yes|no
  PI_CODING_AGENT_DIR="$TMP/pi-local" bash -c 'source "$1"; if "$2" "$3"; then echo yes; else echo no; fi' _ "$HELPERS" "$1" "$2"
}
[[ "$(classify provider_is_local ollama/qwen3:8b)" == yes ]] || fail "loopback is local"
[[ "$(classify provider_is_local lmstudio/m)" == yes ]] || fail "localhost is local"
[[ "$(classify provider_is_local six/m)" == yes ]] || fail "::1 is local"
[[ "$(classify provider_is_local lan/m)" == yes ]] || fail "a private range is local"
[[ "$(classify provider_is_local llama.cpp/x)" == yes ]] || fail "Pi's llama.cpp provider is local"
[[ "$(classify provider_is_local gateway/m)" == no ]] || fail "a gateway on the internet is not local"
[[ "$(classify provider_is_local deepseek/deepseek-v4-pro)" == no ]] || fail "a cloud provider is not local"
[[ "$(classify provider_is_local nowhere/m)" == no ]] || fail "an unknown provider is not local"
[[ "$(classify model_is_metered ollama/qwen3:8b)" == no ]] || fail "no cost block: nothing to cap in dollars"
[[ "$(classify model_is_metered lan/m)" == no ]] || fail "an all-zero cost block: nothing to cap in dollars"
[[ "$(classify model_is_metered ollama/paid)" == yes ]] || fail "a cost block with a rate is metered"
[[ "$(classify model_is_metered gateway/m)" == no ]] || fail "a models.json provider without a cost block reports \$0, whatever it charges"
[[ "$(classify model_is_metered llama.cpp/x)" == no ]] || fail "llama.cpp is free"
[[ "$(classify model_is_metered deepseek/deepseek-v4-pro)" == yes ]] || fail "a cloud provider is metered"
[[ "$(classify model_is_metered nowhere/m)" == yes ]] || fail "an unknown provider is assumed to bill: the safe mistake"
pass "local and metered are decided from the endpoint and the cost block"

# A team that bills nothing cannot be stopped by a USD cap, so it is not
# allowed to start without a token cap; a team with one paid model keeps the
# USD cap mandatory and takes the token cap as a second brake.
out="$(PI_CODING_AGENT_DIR="$TMP/pi-local" start --model ollama/qwen3:8b --n 2 --cap-usd 1 --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label freenocap)"
grep -q -- '--cap-tokens' <<<"$out" || fail "a free team without --cap-tokens should be refused and told why: $out"
[[ -z "$(sandbox_of "$out")" ]] || fail "a refused free team should prepare nothing: $out"
out="$(PI_CODING_AGENT_DIR="$TMP/pi-local" start --model ollama/qwen3:8b --n 2 --cap-tokens 5000000 --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label free)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -d "$sb" ]] || fail "a free team with a token cap should start: $out"
[[ "$(jq -r '.metered' "$sb/budget.json")" == "false" ]] || fail "budget.json should say the team is not metered"
[[ "$(jq -r '.cap_tokens' "$sb/budget.json")" == "5000000" ]] || fail "budget.json should carry the token cap"
[[ "$(jq -r '.cap_usd == 0' "$sb/budget.json")" == "true" ]] || fail "no USD cap was asked for, so none is recorded: $(jq -c '.cap_usd' "$sb/budget.json")"
grep -q 'Cap:          5000000 tokens' <<<"$out" || fail "the kickoff should say the brake is tokens: $out"
grep -q 'Local:        ollama/qwen3:8b' <<<"$out" || fail "the kickoff should name the local model: $out"
reg="$(jq -c '.. | objects | select(.["label"]? == "free") | {metered, cap_tokens, local_models, net}' "$TMP/runs/registry.json")"
[[ "$reg" == '{"metered":false,"cap_tokens":5000000,"local_models":["ollama/qwen3:8b"],"net":"guarded"}' ]] \
  || fail "the registry should record metered, the token cap and the local models: $reg"
pass "a team that bills nothing is braked by a mandatory token cap, recorded in budget.json and the registry"

out="$(PI_CODING_AGENT_DIR="$TMP/pi-local" start --models "ollama/qwen3:8b=1,deepseek/deepseek-v4-pro=1" --cap-tokens 100 --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label mixednousd)"
grep -q 'start requires --cap-usd' <<<"$out" || fail "one paid model keeps --cap-usd mandatory: $out"
out="$(PI_CODING_AGENT_DIR="$TMP/pi-local" start --models "ollama/qwen3:8b=1,deepseek/deepseek-v4-pro=1" --cap-usd 2 --cap-tokens 100 --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label mixed)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "a mixed team with both caps should start: $out"
[[ "$(jq -r '.metered == true and .cap_usd == 2 and .cap_tokens == 100' "$sb/budget.json")" == "true" ]] || fail "a mixed team is metered and keeps both caps: $(jq -c '{metered, cap_usd, cap_tokens}' "$sb/budget.json")"
grep -q 'Cap:          \$2 / .*m / 100 tokens' <<<"$out" || fail "the kickoff should show both brakes: $out"
reg="$(jq -c '.. | objects | select(.["label"]? == "mixed") | {metered, local_models}' "$TMP/runs/registry.json")"
[[ "$reg" == '{"metered":true,"local_models":["ollama/qwen3:8b"]}' ]] || fail "registry for a mixed team: $reg"
pass "a team with one paid model is metered, and the token cap rides along as a second brake"

refuses "a --cap-usd that is not a number is refused" "must be a number of USD" \
  --model solo/model --n 1 --cap-usd abc --no-start
refuses "a --cap-usd of zero is refused for a team that bills" "--cap-usd must be above zero" \
  --model solo/model --n 1 --cap-usd 0 --no-start
refuses "a --cap-usd of 0.00 is refused for a team that bills" "--cap-usd must be above zero" \
  --model solo/model --n 1 --cap-usd 0.00 --no-start
refuses "a --cap-tokens of zero is refused" "above zero" \
  --model solo/model --n 1 --cap-usd 1 --cap-tokens 0 --no-start
refuses "a --cap-tokens that is not a number is refused" "above zero" \
  --model solo/model --n 1 --cap-usd 1 --cap-tokens 5m --no-start

# --local-only: the allowlist is the local endpoints and nothing else. It is
# refused with a cloud model on the team, and it is a netguard mode.
out="$(PI_CODING_AGENT_DIR="$TMP/pi-local" start --model ollama/qwen3:8b --n 1 --cap-tokens 1000 --local-only --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label lonly)"
[[ -n "$(sandbox_of "$out")" ]] || fail "--local-only on an all-local team should start: $out"
reg="$(jq -r '.. | objects | select(.["label"]? == "lonly") | .net' "$TMP/runs/registry.json")"
[[ "$reg" == "local" ]] || fail "the registry should record net=local, got $reg"
out="$(PI_CODING_AGENT_DIR="$TMP/pi-local" start --models "ollama/qwen3:8b=1,deepseek/deepseek-v4-pro=1" --cap-usd 1 --local-only --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label lonlymixed)"
grep -q -- '--local-only, but deepseek/deepseek-v4-pro' <<<"$out" || fail "--local-only with a cloud model should name it: $out"
out="$(PI_CODING_AGENT_DIR="$TMP/pi-local" start --model ollama/qwen3:8b --n 1 --cap-tokens 1000 --local-only --no-netguard --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label lonlyopen)"
grep -q 'drop --no-netguard' <<<"$out" || fail "--local-only without netguard should be refused: $out"
out="$(PI_CODING_AGENT_DIR="$TMP/pi-local" start --model ollama/qwen3:8b --n 1 --cap-tokens 1000 --local-only --compact-model deepseek/deepseek-v4-pro --no-start \
  --goal-file "$ROOT/prompts/goals/hello.md" --label local-cloud-summary)" && fail "--local-only with a cloud summary model should be refused: $out"
grep -q -- '--compact-model deepseek/deepseek-v4-pro is not served from this machine' <<<"$out" || fail "the refusal should name the summary model: $out"
pass "--local-only is recorded as a network mode, refused with a cloud model or a cloud summary model, and needs netguard"

echo "all model-team cases passed"
