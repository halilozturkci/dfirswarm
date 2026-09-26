#!/usr/bin/env bash
# Fixture for the credential preflight in scripts/swarm.sh. No model, no Herdr,
# no panes: the helpers are sourced out of the script and exercised directly.
#
# What this pins down:
#   * which directory the preflight reads, given --env, an inherited variable,
#     an explicitly empty value, and a tilde — Pi's own precedence, because a
#     preflight that reads a different auth.json than Pi is worse than none.
#   * that a relative PI_CODING_AGENT_DIR is refused rather than guessed at
#     (agents run with the sandbox as cwd, the launcher does not).
#   * that `pi auth check` is what actually decides whether a run can
#     authenticate — subscriptions, stored keys and models.json providers alike.
#   * that the models.json helper behind the *diagnostic* still reads an apiKey
#     the way Pi resolves one, since it is what explains a refusal.
set -uo pipefail
# This suite tests host runs, and a run is in microVMs unless it says
# otherwise: it names host. An image, a lock file or another pack home
# exported in the shell would point its kickoffs somewhere else.
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/swarm-preflight.XXXXXX")"
# A kickoff that stops at a BLOCKER after its daemons are up (the collector,
# the gate, the nudge broker) leaves them running; stop them with the
# script's own helper before the directory goes.
eval "$(sed -n '/^stop_sandbox_daemons()/,/^}/p' "$ROOT/scripts/swarm.sh")"
cleanup() {
  local d
  for d in "$TMP"/runs/*/; do [[ -d "$d" ]] && stop_sandbox_daemons "${d%/}" 2>/dev/null; done
  chmod -R u+w "$TMP" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# Values reach the generated script through a file, one per line, instead of
# being quoted into it. `printf %q` left `PI_CODING_AGENT_DIR=~/x` bare and bash
# tilde-expanded it while building the array, so the tilde case was testing bash
# rather than pi_agent_dir; hand-rolled single-quoting then broke on an
# apostrophe. A file needs no quoting at all.
write_env() {
  : > "$TMP/env.lines"
  [[ $# -gt 0 ]] || return 0
  printf '%s\n' "$@" > "$TMP/env.lines"
}

emit_env_array() {
  echo 'extra_env=()'
  echo "while IFS= read -r __line; do extra_env+=(\"\$__line\"); done < \"$TMP/env.lines\""
}

# Lift the helpers out of swarm.sh rather than re-implementing them here.
HELPERS="$TMP/helpers.sh"
{
  sed -n '/^pane_home() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^pi_agent_dir() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^pi_auth_file() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^models_json_has_key() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^provider_key_var() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^models_json_declares_key() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^with_timeout() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^pi_auth_report() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^port_in_use() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^pick_free_port() {/,/^}/p' "$ROOT/scripts/swarm.sh"
} > "$HELPERS"
grep -q "^pi_agent_dir()" "$HELPERS" || fail "could not lift pi_agent_dir out of swarm.sh"
grep -q "^models_json_has_key()" "$HELPERS" || fail "could not lift models_json_has_key out of swarm.sh"

# Each case runs in its own shell with set -u, the way swarm.sh runs.
agent_dir() { # agent_dir <inherited-or-empty> [extra_env entries...]
  local inherited="$1"; shift
  write_env "$@"
  local script="$TMP/case.sh"
  {
    echo 'set -u'
    echo "source \"$HELPERS\""
    emit_env_array
    echo 'pi_agent_dir'
  } > "$script"
  if [[ -n "$inherited" ]]; then
    PI_CODING_AGENT_DIR="$inherited" bash "$script"
  else
    env -u PI_CODING_AGENT_DIR bash "$script"
  fi
}

expect() { # expect <label> <want> <got>
  [[ "$2" == "$3" ]] || fail "$1: want [$2] got [$3]"
  pass "$1"
}

expect "no flag, nothing inherited -> Pi's home default" \
  "$HOME/.pi/agent" "$(agent_dir "")"

expect "inherited value is used when no flag overrides it" \
  "/custom/agent" "$(agent_dir "/custom/agent")"

expect "--env wins over the inherited value" \
  "/flag/agent" "$(agent_dir "/custom/agent" --env "PI_CODING_AGENT_DIR=/flag/agent")"

# Pi treats an empty string as unset, so the preflight must too — otherwise it
# reads /custom/auth.json while Pi opens ~/.pi/agent/auth.json.
expect "an explicitly empty --env value falls back to the home default" \
  "$HOME/.pi/agent" "$(agent_dir "/custom/agent" --env "PI_CODING_AGENT_DIR=")"

expect "the last --env entry wins" \
  "/second" "$(agent_dir "" --env "PI_CODING_AGENT_DIR=/first" --env "PI_CODING_AGENT_DIR=/second")"

expect "a tilde is expanded the way Pi expands it" \
  "$HOME/pidir" "$(agent_dir "" --env "PI_CODING_AGENT_DIR=~/pidir")"

expect "unrelated --env entries are ignored" \
  "$HOME/.pi/agent" "$(agent_dir "" --env "FOO=bar" --env "PI_CODING_AGENT_DIR_X=/nope")"

expect "a value containing spaces and = survives" \
  "/a b=c" "$(agent_dir "" --env "PI_CODING_AGENT_DIR=/a b=c")"

# Quoting a value into the generated script used to break on these.
expect "an apostrophe in the value survives" \
  "/it's/there" "$(agent_dir "" --env "PI_CODING_AGENT_DIR=/it's/there")"

expect "shell metacharacters are not interpreted" \
  '/a$b`c;d*e' "$(agent_dir "" --env 'PI_CODING_AGENT_DIR=/a$b`c;d*e')"

# The panes' HOME is what Pi expands against, and --env can move it.
expect "a tilde expands against a HOME handed to the panes" \
  "/other/pidir" "$(agent_dir "" --env "HOME=/other" --env "PI_CODING_AGENT_DIR=~/pidir")"

expect "the default follows a HOME handed to the panes" \
  "/other/.pi/agent" "$(agent_dir "" --env "HOME=/other")"

# Pi's expandTildePath only understands "~" and "~/", so "~someone" stays
# literal and therefore relative — which the absolute-path gate must catch.
expect "~someone is left alone rather than guessed at" \
  "~someone/agent" "$(agent_dir "" --env "PI_CODING_AGENT_DIR=~someone/agent")"

# --- models.json as a credential source ------------------------------------
mkdir -p "$TMP/agent"
cat > "$TMP/agent/models.json" <<'JSON'
{
  "providers": {
    "withkey":  { "api": "openai-completions", "baseUrl": "http://127.0.0.1:1/v1", "apiKey": "k" },
    "blankkey": { "api": "openai-completions", "baseUrl": "http://127.0.0.1:1/v1", "apiKey": "   " },
    "nokey":    { "api": "openai-completions", "baseUrl": "http://127.0.0.1:1/v1" },
    "envkey":   { "api": "openai-completions", "baseUrl": "http://127.0.0.1:1/v1", "apiKey": "$SWARM_TEST_KEY" },
    "bracekey": { "api": "openai-completions", "baseUrl": "http://127.0.0.1:1/v1", "apiKey": "pre-${SWARM_TEST_KEY}-post" },
    "cmdkey":   { "api": "openai-completions", "baseUrl": "http://127.0.0.1:1/v1", "apiKey": "!echo hunter2" }
  }
}
JSON

has_key() { # has_key <provider> [extra_env entries...] -> prints yes|no
  local provider="$1"; shift
  write_env "$@"
  local script="$TMP/key.sh"
  {
    echo 'set -u'
    echo "source \"$HELPERS\""
    emit_env_array
    echo "if models_json_has_key \"$TMP/agent/models.json\" \"$provider\"; then echo yes; else echo no; fi"
  } > "$script"
  env -u SWARM_TEST_KEY bash "$script"
}

expect "a provider with an apiKey counts as a credential" "yes" "$(has_key withkey)"
expect "a whitespace-only apiKey does not" "no" "$(has_key blankkey)"
expect "a provider without an apiKey does not" "no" "$(has_key nokey)"
expect "an unknown provider does not" "no" "$(has_key deepseek)"

# Pi interpolates $VAR / ${VAR} in an apiKey, so a missing variable is not a
# credential however non-blank the string looks.
expect "an apiKey naming an unset variable is not a credential" \
  "no" "$(has_key envkey)"
expect "the same apiKey counts once the variable is forwarded" \
  "yes" "$(has_key envkey --env "SWARM_TEST_KEY=abc")"
expect "an unset variable inside \${...} is caught too" \
  "no" "$(has_key bracekey)"
expect "a forwarded variable inside \${...} counts" \
  "yes" "$(has_key bracekey --env "SWARM_TEST_KEY=abc")"
expect "a forwarded but empty variable does not count" \
  "no" "$(has_key envkey --env "SWARM_TEST_KEY=")"
# Only running it would tell us, so a command value is taken on trust.
expect "a !command apiKey is trusted" "yes" "$(has_key cmdkey)"

# --- what Pi itself says about a model ---------------------------------------
# The preflight no longer guesses at credentials; it asks `pi auth check`, which
# knows about OAuth subscriptions, stored keys and models.json providers alike.
# These cases need Pi installed, and only assert the *shape* of the answer, so
# they hold whatever the developer happens to be logged in to.
auth_report() { # auth_report <model> [extra_env entries...]
  local model="$1"; shift
  write_env "$@"
  local script="$TMP/auth.sh"
  {
    echo 'set -u'
    echo "source \"$HELPERS\""
    emit_env_array
    echo "pi_auth_report \"$model\""
  } > "$script"
  bash "$script"
}

if command -v pi >/dev/null 2>&1; then
  # A provider nobody could be logged in to must never come back ready.
  report="$(auth_report "nosuchprovider/nosuchmodel")"
  status="$(printf '%s' "$report" | cut -f1)"
  [[ "$status" != "ready" ]] || fail "an unknown model reported ready: $report"
  pass "an unknown model is never ready"

  # Four tab-separated fields, always, even when Pi says nothing useful.
  fields="$(printf '%s' "$report" | awk -F'\t' '{print NF}')"
  expect "the report always has four fields" "4" "$fields"

  # The mock provider in the throwaway dir is configured entirely by models.json,
  # so a ready answer here is the models.json path working end to end.
  mock_dir="$TMP/mockagent"
  mkdir -p "$mock_dir"
  cat > "$mock_dir/models.json" <<'JSON'
{
  "providers": {
    "preflightmock": {
      "api": "openai-completions",
      "baseUrl": "http://127.0.0.1:1/v1",
      "apiKey": "$SWARM_PREFLIGHT_KEY",
      "models": [{ "id": "m1" }]
    }
  }
}
JSON
  printf '{}\n' > "$mock_dir/auth.json"

  report="$(auth_report "preflightmock/m1" --env "PI_CODING_AGENT_DIR=$mock_dir")"
  expect "a models.json apiKey naming an unset variable is not ready" \
    "not_ready" "$(printf '%s' "$report" | cut -f1)"

  report="$(auth_report "preflightmock/m1" --env "PI_CODING_AGENT_DIR=$mock_dir" --env "SWARM_PREFLIGHT_KEY=abc")"
  expect "the same provider is ready once --env supplies the variable" \
    "ready" "$(printf '%s' "$report" | cut -f1)"
  expect "and Pi reports how it authenticated" \
    "api_key" "$(printf '%s' "$report" | cut -f2)"
else
  echo "skip - pi auth check cases (pi is not installed)"
fi


printf 'not json at all' > "$TMP/agent/broken.json"
broken="$TMP/broken.sh"
{
  echo 'set -u'
  echo "source \"$HELPERS\""
  echo "if models_json_has_key \"$TMP/agent/broken.json\" withkey; then echo yes; else echo no; fi"
  echo "if models_json_has_key \"$TMP/agent/absent.json\" withkey; then echo yes; else echo no; fi"
} > "$broken"
got="$(bash "$broken" | tr '\n' ' ')"
expect "unparseable and missing models.json both fail closed" "no no " "$got"

# --- argument validation ----------------------------------------------------
out="$(bash "$ROOT/scripts/swarm.sh" start --model a/b --n 1 --cap-usd 1 --env 2>&1)"
rc=$?
[[ "$rc" -ne 0 ]] || fail "a trailing --env should not be accepted"
case "$out" in
  *"--env expects KEY=VALUE"*) pass "a trailing --env reports the problem instead of an unbound variable" ;;
  *) fail "a trailing --env printed: $out" ;;
esac

for value in "./rel" "~someone/agent"; do
  out="$(bash "$ROOT/scripts/swarm.sh" start --model a/b --n 1 --cap-usd 1 --env "PI_CODING_AGENT_DIR=$value" 2>&1)"
  rc=$?
  [[ "$rc" -ne 0 ]] || fail "PI_CODING_AGENT_DIR=$value should be refused"
  case "$out" in
    *"must be an absolute path"*) pass "PI_CODING_AGENT_DIR=$value is refused, not guessed at" ;;
    *) fail "PI_CODING_AGENT_DIR=$value printed: $out" ;;
  esac
done

# An inherited relative value is just as ambiguous as a flagged one.
out="$(PI_CODING_AGENT_DIR=./inherited bash "$ROOT/scripts/swarm.sh" start --model a/b --n 1 --cap-usd 1 2>&1)"
rc=$?
[[ "$rc" -ne 0 ]] || fail "an inherited relative PI_CODING_AGENT_DIR should be refused"
case "$out" in
  *"must be an absolute path"*) pass "an inherited relative PI_CODING_AGENT_DIR is refused too" ;;
  *) fail "an inherited relative PI_CODING_AGENT_DIR printed: $out" ;;
esac

out="$(bash "$ROOT/scripts/swarm.sh" start --model a/b --n 1 --cap-usd 1 --env NOPE 2>&1)"
rc=$?
[[ "$rc" -ne 0 ]] || fail "--env without = should be refused"
case "$out" in
  *"--env expects KEY=VALUE, got: NOPE"*) pass "--env without = is refused" ;;
  *) fail "--env NOPE printed: $out" ;;
esac

# --- one netguard sidecar port per swarm ------------------------------------
# Two swarms at once must not share a proxy: the second would inherit the
# first's allowlist and lose its egress the moment the first was stopped.
grep -q "^pick_free_port()" "$HELPERS" || fail "could not lift pick_free_port out of swarm.sh"
busy_port=45711
python3 -c 'import socket,sys,time
s=socket.socket(); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(1)
sys.stdout.write("listening\n"); sys.stdout.flush(); time.sleep(20)' "$busy_port" > "$TMP/busy.out" &
busy_pid=$!
for _ in $(seq 1 50); do grep -q listening "$TMP/busy.out" 2>/dev/null && break; sleep 0.1; done
picked="$(bash -c "source \"$HELPERS\"; pick_free_port $busy_port")"
kill "$busy_pid" 2>/dev/null || true
wait "$busy_pid" 2>/dev/null || true
[[ "$picked" == "$((busy_port + 1))" ]] && pass "pick_free_port skips a port something answers on ($busy_port -> $picked)" || fail "pick_free_port returned '$picked', expected $((busy_port + 1))"
picked2="$(bash -c "source \"$HELPERS\"; pick_free_port $busy_port")"
[[ "$picked2" == "$busy_port" ]] && pass "pick_free_port takes the first port once it is free again" || fail "pick_free_port returned '$picked2' after the listener died"
if bash -c "source \"$HELPERS\"; pick_free_port $busy_port 0" >/dev/null 2>&1; then
  fail "pick_free_port with an empty span should fail"
else
  pass "pick_free_port reports when no port in its span is free"
fi

# --- which directory the runs go in -------------------------------------------
# Runs used to live in sandbox-runs/, one hyphen from the committed sandbox/
# skeleton. They live in runs/ now, and a checkout that still has the old
# directory has to keep reading it: a rename must not hide anyone's runs.
runs_root="$TMP/runs-root"
mkdir -p "$runs_root/scripts" "$runs_root/sandbox-runs"
cp "$ROOT/scripts/swarm.sh" "$runs_root/scripts/"
printf '{"runs":[{"id":"sold1","state":"done","label":"before the rename","workspaces":[],"n":2,"model":"solo/model","sandbox":"%s/sandbox-runs/sold1"}]}\n' \
  "$runs_root" > "$runs_root/sandbox-runs/registry.json"
out="$(bash "$runs_root/scripts/swarm.sh" list 2>&1)"
grep -q 'sold1' <<<"$out" || fail "a checkout with only sandbox-runs/ lost its runs: $out"
pass "with only sandbox-runs/ present, the runs there are still listed"

mkdir -p "$runs_root/runs"
printf '{"runs":[{"id":"snew1","state":"running","label":"after the rename","workspaces":[],"n":1,"model":"solo/model","sandbox":"%s/runs/snew1"}]}\n' \
  "$runs_root" > "$runs_root/runs/registry.json"
out="$(bash "$runs_root/scripts/swarm.sh" list 2>&1)"
grep -q 'snew1' <<<"$out" || fail "runs/ is present but was not read: $out"
grep -q 'sold1' <<<"$out" && fail "both directories were read at once: $out"
pass "once runs/ exists it is the one used"

mkdir -p "$runs_root/elsewhere"
printf '{"runs":[{"id":"selse","state":"done","label":"somewhere else","workspaces":[],"n":1,"model":"solo/model","sandbox":"%s/elsewhere/selse"}]}\n' \
  "$runs_root" > "$runs_root/elsewhere/registry.json"
out="$(SWARM_RUNS_DIR="$runs_root/elsewhere" bash "$runs_root/scripts/swarm.sh" list 2>&1)"
grep -q 'selse' <<<"$out" || fail "SWARM_RUNS_DIR was not honoured: $out"
pass "SWARM_RUNS_DIR still overrides both"

# --- a local model server is probed before Pi is asked -----------------------
# A credential check cannot see whether the server answers, whether it has the
# model, or how much context Ollama will really give; a pane would find out by
# dying. The probe runs first. A fake server on loopback stands in for Ollama:
# OpenAI-style /v1/models, plus Ollama's /api/version and /api/show.
LOCAL_HELPERS="$TMP/local-helpers.sh"
{
  # Pi's store is read where the kickoff reads it (an --env value wins).
  sed -n '/^pane_home() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^pi_agent_dir() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^provider_base_url() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^host_of_url() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^host_is_local() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^provider_is_local() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^model_is_metered() {/,/^}/p' "$ROOT/scripts/swarm.sh"
  sed -n '/^preflight_local_model() {/,/^}/p' "$ROOT/scripts/swarm.sh"
} > "$LOCAL_HELPERS"
grep -q "^preflight_local_model()" "$LOCAL_HELPERS" || fail "could not lift preflight_local_model out of swarm.sh"

cat > "$TMP/fake-ollama.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])

class H(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/v1/models":
            return self._json({"data": [{"id": "qwen3:8b"}, {"id": "gpt-oss:20b"}]})
        if self.path == "/api/version":
            return self._json({"version": "0.0.0-fake"})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/api/show":
            if body.get("name") == "qwen3:8b":
                return self._json({"parameters": "num_ctx 8192\nstop \"<|im_end|>\""})
            return self._json({"parameters": "stop \"<|im_end|>\""})
        return self._json({"error": "not found"}, 404)

    def log_message(self, *_):
        pass

HTTPServer(("127.0.0.1", PORT), H).serve_forever()
PY
FAKE_PORT="$(bash -c 'source "$1"; pick_free_port 27000' _ "$HELPERS")"
python3 "$TMP/fake-ollama.py" "$FAKE_PORT" &
FAKE_PID=$!
trap 'kill "$FAKE_PID" 2>/dev/null; wait "$FAKE_PID" 2>/dev/null; cleanup' EXIT
for _ in $(seq 1 50); do
  if curl -sf -m 1 "http://127.0.0.1:$FAKE_PORT/v1/models" >/dev/null 2>&1; then break; fi
  sleep 0.1
done
curl -sf -m 1 "http://127.0.0.1:$FAKE_PORT/v1/models" >/dev/null 2>&1 || fail "the fake local server did not come up on $FAKE_PORT"

local_dir="$TMP/localagent"
mkdir -p "$local_dir"
cat > "$local_dir/models.json" <<JSON
{
  "providers": {
    "localmock": { "baseUrl": "http://127.0.0.1:$FAKE_PORT/v1", "api": "openai-completions",
                   "models": [{ "id": "qwen3:8b", "contextWindow": 131072 }, { "id": "gpt-oss:20b", "contextWindow": 131072 }] },
    "tuned":     { "baseUrl": "http://127.0.0.1:$FAKE_PORT/v1", "api": "openai-completions", "apiKey": "x",
                   "compat": { "supportsDeveloperRole": false },
                   "models": [{ "id": "qwen3:8b", "contextWindow": 8192 }] },
    "dead":      { "baseUrl": "http://127.0.0.1:1/v1", "api": "openai-completions", "apiKey": "x", "models": [{ "id": "m" }] }
  }
}
JSON
printf '{}\n' > "$local_dir/auth.json"

probe() { # probe <model> -> prints stderr, exit code on the last line
  PI_CODING_AGENT_DIR="$local_dir" SWARM_LOCAL_PROBE_TIMEOUT=2 \
    bash -c 'source "$1"; preflight_local_model "$2" "$3" 2>&1; echo "exit=$?"' _ "$LOCAL_HELPERS" "$1" "$local_dir/models.json"
}

out="$(probe dead/m)"
grep -q 'BLOCKER: the local model server for dead/m does not answer' <<<"$out" || fail "a dead endpoint should be a BLOCKER: $out"
grep -q 'exit=1' <<<"$out" || fail "a dead endpoint should exit 1: $out"
pass "a local server that does not answer is a BLOCKER before any pane opens"

out="$(probe localmock/nothere)"
grep -q "has no model 'nothere'" <<<"$out" || fail "a missing model should be a BLOCKER: $out"
grep -q 'It serves: qwen3:8b, gpt-oss:20b' <<<"$out" || fail "the BLOCKER should list what the server has: $out"
grep -q 'exit=1' <<<"$out" || fail "a missing model should exit 1: $out"
pass "a model the server does not have is a BLOCKER that names what it does have"

out="$(probe localmock/qwen3:8b)"
grep -q 'exit=0' <<<"$out" || fail "a present model should pass the probe: $out"
grep -q 'WARN: Ollama gives qwen3:8b a context of 8192 tokens; models.json declares 131072' <<<"$out" \
  || fail "a smaller server-side context than declared should be a WARN: $out"
grep -q "WARN: models.json gives 'localmock' no compat block" <<<"$out" || fail "a missing compat block should be a WARN: $out"
pass "a present model passes, with warnings for the context Ollama really gives and the missing compat block"

out="$(probe localmock/gpt-oss:20b)"
grep -q 'WARN: Ollama has no num_ctx for gpt-oss:20b' <<<"$out" || fail "no num_ctx at all should warn about the 4096 default: $out"
pass "a model Ollama has no num_ctx for is warned about the default"

out="$(probe tuned/qwen3:8b)"
grep -q 'exit=0' <<<"$out" || fail "a tuned provider should pass: $out"
grep -qv 'WARN' <<<"$out" || true
[[ "$(printf '%s\n' "$out" | grep -c 'WARN')" -eq 0 ]] || fail "a provider with compat and a matching context should get no warning: $out"
pass "a provider with a compat block and a matching context window passes silently"

# --- what Pi says about a keyless local provider, and what the kickoff says ---
if command -v pi >/dev/null 2>&1; then
  # Measured against Pi 0.85.1: a models.json provider with no apiKey is
  # "not_ready / credentials_not_configured" and absent from --list-models; a
  # placeholder value makes it ready. The kickoff's BLOCKER has to say that,
  # not "pi /login".
  report="$(auth_report "localmock/qwen3:8b" --env "PI_CODING_AGENT_DIR=$local_dir")"
  expect "a keyless local provider is not ready for Pi" "not_ready" "$(printf '%s' "$report" | cut -f1)"
  expect "and the reason is the missing credential" "credentials_not_configured" "$(printf '%s' "$report" | cut -f4)"
  report="$(auth_report "tuned/qwen3:8b" --env "PI_CODING_AGENT_DIR=$local_dir")"
  expect "a placeholder apiKey makes the same server ready" "ready" "$(printf '%s' "$report" | cut -f1)"

  if command -v herdr >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    out="$(PI_CODING_AGENT_DIR="$local_dir" SWARM_RUNS_DIR="$TMP/runs" SWARM_LOCAL_PROBE_TIMEOUT=2 \
      bash "$ROOT/scripts/swarm.sh" start --model localmock/qwen3:8b --n 1 --cap-tokens 1000 --no-write-guard \
      --goal-file "$ROOT/prompts/goals/hello.md" --label keyless --env "PI_CODING_AGENT_DIR=$local_dir" 2>&1)"
    grep -q 'BLOCKER: Pi will not use localmock/qwen3:8b without a credential, and a local server has none' <<<"$out" \
      || fail "a keyless local provider should get the local BLOCKER: $out"
    grep -q '"apiKey": "local"' <<<"$out" || fail "the BLOCKER should show the placeholder to add: $out"
    grep -q 'pi auth check --model localmock/qwen3:8b --json' <<<"$out" || fail "the BLOCKER should say how to confirm: $out"
    grep -q 'pi /login' <<<"$out" && fail "a local server must not be sent to pi /login: $out"
    pass "the kickoff tells a keyless local provider to add a placeholder apiKey, not to log in"
  else
    echo "skip - the keyless kickoff BLOCKER (herdr or jq is not installed)"
  fi
else
  echo "skip - keyless local provider cases (pi is not installed)"
fi

# --- the write guard's login-shell check: zsh and bash carry a hook, others do not ---
# getent is stubbed so the account database says what the case needs, and so
# are pi (whose auth check always says invalid) and herdr (a no-op): a case
# that passes the shell check stops at the next BLOCKER, the credential one,
# before any pane could open.
mkdir -p "$TMP/getent-bin" "$TMP/shell-inputs"
printf 'evidence\n' > "$TMP/shell-inputs/a.txt"
cat > "$TMP/getent-bin/pi" <<'SH'
#!/bin/sh
echo '{"status":"invalid","reason":"stub"}'
exit 1
SH
printf '#!/bin/sh\nexit 0\n' > "$TMP/getent-bin/herdr"
chmod +x "$TMP/getent-bin/pi" "$TMP/getent-bin/herdr"
login_shell_out() { # login_shell_out <shell> [start args...] -> the kickoff's output with that login shell
  local shell="$1"; shift
  printf '#!/bin/sh\necho "u:x:1000:1000::/home/u:%s"\n' "$shell" > "$TMP/getent-bin/getent"
  chmod +x "$TMP/getent-bin/getent"
  PATH="$TMP/getent-bin:$PATH" SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" start --model solo/model \
    --n 1 --cap-usd 1 --goal-file "$ROOT/prompts/goals/hello.md" --label "shell-$(basename "$shell")" "$@" 2>&1 || true
}
past_shell_check='BLOCKER: Pi cannot authenticate solo/model'
out="$(login_shell_out /usr/bin/fish)"
grep -q "BLOCKER: this account's login shell is /usr/bin/fish, and the kernel guard is a hook that only a zsh or a bash reads" <<<"$out" \
  || fail "a login shell that is neither zsh nor bash should be refused: $out"
pass "a login shell with no pane hook (fish) is refused while the write guard is on"
out="$(login_shell_out /bin/bash)"
grep -q "BLOCKER: this account's login shell" <<<"$out" \
  && fail "a bash login shell should pass the write guard's shell check: $out"
grep -q "$past_shell_check" <<<"$out" || fail "a bash login shell should get past the shell check to the credential one: $out"
pass "a bash login shell passes the write guard's shell check and the kickoff goes on"
# An account database that does not answer is not taken for zsh: the kickoff
# says so and leaves the panes' HOME alone.
printf '#!/bin/sh\nexit 2\n' > "$TMP/getent-bin/getent"
chmod +x "$TMP/getent-bin/getent"
out="$(PATH="$TMP/getent-bin:$PATH" SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" start --model solo/model \
  --n 1 --cap-usd 1 --goal-file "$ROOT/prompts/goals/hello.md" --label shell-unknown 2>&1 || true)"
grep -q "WARN: this account's login shell could not be read" <<<"$out" \
  || fail "a login shell nobody can read should be warned about, not assumed to be zsh: $out"
pass "a login shell the account database does not give is warned about, not assumed"
if command -v zsh >/dev/null 2>&1; then
  echo "skip - a zsh login shell with no zsh installed (zsh is on PATH here)"
else
  out="$(login_shell_out /usr/bin/zsh)"
  grep -q "BLOCKER: missing .*zsh (the pane hook runs in it)" <<<"$out" \
    || fail "a zsh login shell on a host with no zsh should be refused as missing zsh: $out"
  pass "a zsh login shell with no zsh installed is refused as a missing tool"
fi
# --no-write-guard still writes a hook for --inputs. The shell check has to run
# then too: the bash hook moves the panes' HOME, and a fish pane would keep it.
guard_here="$(bash "$ROOT/scripts/fsguard.sh" --ro "$TMP/shell-inputs" --dry-run -- true 2>/dev/null | sed -n 's/^mode: //p')"
if [[ -z "$guard_here" || "$guard_here" == "none" ]]; then
  echo "skip - the login-shell check with --no-write-guard --inputs (no kernel guard on this host, so no hook)"
else
  out="$(login_shell_out /usr/bin/fish --no-write-guard --inputs "$TMP/shell-inputs")"
  grep -q "WARN: this account's login shell is /usr/bin/fish, which reads neither pane hook" <<<"$out" \
    || fail "--no-write-guard --inputs with a fish login shell should warn that the hook will not be read: $out"
  grep -q "$past_shell_check" <<<"$out" || fail "--no-write-guard --inputs with fish should still start, as on main: $out"
  pass "--no-write-guard --inputs with a fish login shell warns and goes on ($guard_here)"
  out="$(login_shell_out /usr/bin/fish --no-write-guard --inputs "$TMP/shell-inputs" --inputs-enforce on)"
  grep -q "BLOCKER: this account's login shell is /usr/bin/fish" <<<"$out" \
    || fail "--inputs-enforce on with a fish login shell should be refused before any pane opens: $out"
  pass "--inputs-enforce on with a fish login shell is refused at the shell check"
fi

# --- what Herdr is handed: HOME=<sandbox>/.bash for a bash login shell only ---
# Here pi's auth check says ready, so the kickoff builds the panes' env and
# hands it to `herdr workspace create`; the stub herdr writes that argv to a
# file and returns nothing, which stops the kickoff before any pane.
mkdir -p "$TMP/pane-env-bin"
cat > "$TMP/pane-env-bin/pi" <<'SH'
#!/bin/sh
echo '{"status":"ready","authType":"api_key","provider":"solo"}'
SH
cat > "$TMP/pane-env-bin/herdr" <<'SH'
#!/bin/sh
if [ "$1" = workspace ] && [ "$2" = create ]; then printf '%s\n' "$@" > "$HERDR_ARGV"; fi
exit 0
SH
chmod +x "$TMP/pane-env-bin/pi" "$TMP/pane-env-bin/herdr"
pane_env_argv() { # pane_env_argv <getent body> [start args...] -> the argv Herdr got, one per line
  local body="$1"; shift
  printf '#!/bin/sh\n%s\n' "$body" > "$TMP/pane-env-bin/getent"
  chmod +x "$TMP/pane-env-bin/getent"
  rm -f "$TMP/herdr-argv"
  HERDR_ARGV="$TMP/herdr-argv" PATH="$TMP/pane-env-bin:$PATH" SWARM_RUNS_DIR="$TMP/runs" \
    bash "$ROOT/scripts/swarm.sh" start --model solo/model --n 1 --cap-usd 1 --no-netguard \
    --goal-file "$ROOT/prompts/goals/hello.md" --label pane-env "$@" > "$TMP/pane-env.out" 2>&1 || true
  [[ -f "$TMP/herdr-argv" ]] || fail "the kickoff never reached herdr workspace create: $(cat "$TMP/pane-env.out")"
  cat "$TMP/herdr-argv"
}
env_values() { # env_values <argv> <KEY> -> each value passed as --env KEY=..., one per line
  awk -v key="$2=" 'prev == "--env" && index($0, key) == 1 { print substr($0, length(key) + 1) } { prev = $0 }' <<<"$1"
}
# --allow-install on the host: pip installs into the run, past Debian's
# externally-managed guard, and the panes are told so.
argv="$(pane_env_argv 'echo "u:x:1000:1000::/home/u:/bin/bash"' --allow-install)"
expect "an --allow-install pane lets pip install into the run (PEP 668)" "1" "$(env_values "$argv" PIP_BREAK_SYSTEM_PACKAGES)"
argv="$(pane_env_argv 'echo "u:x:1000:1000::/home/u:/bin/bash"' --env HOME=/x)"
sandbox_dir="$(awk 'prev == "--cwd" { print; exit } { prev = $0 }' <<<"$argv")"
[[ -n "$sandbox_dir" ]] || fail "herdr workspace create got no --cwd: $argv"
expect "a bash login shell's panes get HOME=<sandbox>/.bash, once, in place of an operator's --env HOME" \
  "$sandbox_dir/.bash" "$(env_values "$argv" HOME)"
# This kickoff then stops: the stand-in Herdr returns no pane. What it
# started is put away and the run is recorded as failed, not left running.
grep -q 'Kickoff did not finish' "$TMP/pane-env.out" || fail "a kickoff that stopped after registering did not say it was putting things away: $(cat "$TMP/pane-env.out")"
[[ "$(jq -r '[.runs[] | select(.label == "pane-env")] | last | .state' "$TMP/runs/registry.json")" == failed ]] \
  || fail "a kickoff that stopped after registering left the run as $(jq -r '[.runs[] | select(.label == "pane-env")] | last | .state' "$TMP/runs/registry.json")"
[[ ! -f "$sandbox_dir/collector.pid" ]] || fail "a kickoff that stopped left its collector running"
[[ ! -d "$TMP/runs/registry.json.lock" ]] || fail "the registry lock was left behind"
pass "a kickoff that stops after registering puts away its daemons and records the run as failed"
if [[ -z "$guard_here" || "$guard_here" == "none" ]]; then
  echo "skip - Herdr's env with --no-write-guard --inputs (no kernel guard on this host, so no hook)"
else
  argv="$(pane_env_argv 'echo "u:x:1000:1000::/home/u:/usr/bin/fish"' --no-write-guard --inputs "$TMP/shell-inputs")"
  [[ -n "$(env_values "$argv" ZDOTDIR)" ]] || fail "--inputs should still write the pane hook: $argv"
  expect "a fish login shell's panes keep their HOME (--no-write-guard --inputs)" "" "$(env_values "$argv" HOME)"
  argv="$(pane_env_argv 'exit 2' --no-write-guard --inputs "$TMP/shell-inputs")"
  expect "panes keep their HOME when the account database does not answer (getent exits 2)" "" "$(env_values "$argv" HOME)"
fi

# --- the panes' HOME: moved for a bash hook only, and never passed twice ---
BASH_ENV_HELPERS="$TMP/bash-hook-env.sh"
sed -n '/^bash_hook_env() {/,/^}/p' "$ROOT/scripts/swarm.sh" > "$BASH_ENV_HELPERS"
grep -q "^bash_hook_env()" "$BASH_ENV_HELPERS" || fail "could not lift bash_hook_env out of swarm.sh"
hook_env() { # hook_env <provider_env...> -> provider_env after bash_hook_env, one per line
  bash -c 'set -u; source "$1"; shift; provider_env=("$@"); bash_hook_env /sb; printf "%s\n" "${provider_env[@]}"' _ "$BASH_ENV_HELPERS" "$@"
}
got="$(hook_env --env "TMPDIR=/t" | tr '\n' ' ')"
expect "the bash hook's HOME is added to the panes' env" "--env TMPDIR=/t --env HOME=/sb/.bash " "$got"
got="$(hook_env --env "HOME=/x" --env "TMPDIR=/t" --env "HOME=/y" | tr '\n' ' ')"
expect "an operator's --env HOME is taken out, so Herdr gets HOME once" "--env TMPDIR=/t --env HOME=/sb/.bash " "$got"
got="$(hook_env | tr '\n' ' ')"
expect "an empty env still gets the hook's HOME" "--env HOME=/sb/.bash " "$got"

echo "all swarm preflight cases passed"
