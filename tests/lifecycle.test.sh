#!/usr/bin/env bash
# The kickoff's and stop's housekeeping, taken from the script itself: the
# registry written by several writers at once, the host kept awake for a run
# and let go at stop.
#
# What must not go wrong: two writers of the registry must never lose each
# other's change (the hub and a stop, two kickoffs); a stale lock left by a
# writer that died must not block the next one for ever; the process that
# keeps the host awake must stop with the run, and a pid file that names
# something else must not stop that.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/lifecycle.XXXXXX")"
# The VM hubs' directory is the test's own: never the operator's.
HUBS_TMP="$(mktemp -d /tmp/dfh.XXXXXX)"
export SWARM_HUBS_DIR="$HUBS_TMP/dfirswarm-hubs"
PIDS=()
cleanup() { local p; for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null; done; rm -rf "$TMP" "$HUBS_TMP"; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

fn() { sed -n "/^$1() {/,/^}/p" "$ROOT/scripts/swarm.sh"; }
for f in ensure_registry registry_lock registry_unlock registry_upsert registry_update_state detach_exec keep_host_awake stop_sandbox_daemons hub_dir_of hubs_parent hub_pid_ours; do
  eval "$(fn "$f")"
  type "$f" >/dev/null 2>&1 || fail "$f was not found in swarm.sh"
done

# --- the registry, written by many at once ------------------------------------
RUNS_DIR="$TMP/runs"
REGISTRY="$RUNS_DIR/registry.json"
ensure_registry
for i in $(seq 1 12); do
  ( registry_upsert "{\"id\":\"s$i\",\"state\":\"running\"}" ) &
done
wait
[[ "$(jq '.runs | length' "$REGISTRY")" == 12 ]] || fail "concurrent upserts lost a run: $(jq -c '[.runs[].id]' "$REGISTRY")"
for i in $(seq 1 12); do
  ( registry_update_state "s$i" stopped ) &
done
wait
[[ "$(jq '[.runs[] | select(.state == "stopped")] | length' "$REGISTRY")" == 12 ]] || fail "concurrent state changes lost one: $(jq -c '[.runs[].state]' "$REGISTRY")"
[[ ! -d "$REGISTRY.lock" ]] || fail "the lock was left behind"
ls "$RUNS_DIR" | grep -q 'registry.json.tmp' && fail "a temporary registry was left behind"
pass "twelve writers at once lose nothing, and leave no lock or temporary file"

# A lock a writer left when it died goes stale after a minute.
mkdir "$REGISTRY.lock"
touch -t "$(date -v-5M +%Y%m%d%H%M 2>/dev/null || date -d '5 minutes ago' +%Y%m%d%H%M)" "$REGISTRY.lock"
registry_update_state s1 done || fail "a stale lock blocked the writer"
[[ "$(jq -r '.runs[] | select(.id == "s1") | .state' "$REGISTRY")" == done ]] || fail "the write after a stale lock did not land"
pass "a lock left by a writer that died does not block the next"

# --- the host kept awake, for the run and no longer -----------------------------
if command -v caffeinate >/dev/null 2>&1 || command -v systemd-inhibit >/dev/null 2>&1; then
  mkdir -p "$TMP/sb"
  out="$(keep_host_awake "$TMP/sb" 1 2>&1)"
  pid="$(cat "$TMP/sb/inhibit.pid" 2>/dev/null)"
  if [[ -z "$pid" ]]; then
    # The system refused the inhibitor (systemd-inhibit with no login
    # session): said as such, never claimed.
    grep -q "could not be kept from sleeping" <<<"$out" || fail "an inhibitor that died was not said: $out"
    grep -q "kept from sleeping for the run" <<<"$out" && fail "a refused inhibitor was claimed: $out"
  else
    kill -0 "$pid" 2>/dev/null || fail "nothing keeps the host awake: $out"
    PIDS+=("$pid")
    stop_sandbox_daemons "$TMP/sb"
    sleep 0.3
    kill -0 "$pid" 2>/dev/null && fail "the host is still kept awake after stop"
    [[ ! -f "$TMP/sb/inhibit.pid" ]] || fail "the pid file stayed"
  fi
  # A pid file naming something else is not obeyed.
  sleep 60 & other=$!
  disown "$other" 2>/dev/null || true
  PIDS+=("$other")
  echo "$other" > "$TMP/sb/inhibit.pid"
  stop_sandbox_daemons "$TMP/sb"
  kill -0 "$other" 2>/dev/null || fail "stop killed a process the pid file named that is not the run's"
  pass "the host is kept awake for a run (or the refusal is said), let go at stop, and a pid file that names something else is left alone"
else
  echo "skip - neither caffeinate nor systemd-inhibit on this host"
fi

# --- the harness a VM run started with ---------------------------------------------
for f in freeze_harness vm_build_spec vm_providers_json pi_agent_dir pi_auth_file credential_models distinct_models; do
  eval "$(fn "$f")"
done
mkdir -p "$TMP/hub/runs" "$TMP/sandbox/.pi-sessions"
freeze_harness "$TMP/hub"
for rel in extensions/agent-swarm.ts scripts/vm.ts prompts node_modules/typebox; do
  [[ -e "$TMP/hub/harness/$rel" ]] || fail "the frozen harness lacks $rel"
done
[[ -s "$TMP/hub/harness/COMMIT" ]] || fail "the frozen harness does not say which commit it is"
# The spec mounts the copy where the checkout is.
sandbox="$TMP/sandbox" swarm_id=s1 hard=0 wall=10 n=0 vm_image=img vm_cpus=1 vm_memory=1024 vm_disk=8192 \
  playwright=0 pack_dirs="" compact_prompt="" self_compact=0 forging=0 inbox_page_chars="" quarantine=0 local_only=0 \
  allow_install=0 install_hosts=0 allow_hosts="" use_netguard=1 PACK_SECRETS_VM='[]' PACK_SECRETS_ENV='{}' REGISTRY="$TMP/runs/registry.json" \
  vm_image_digest="" extra_env=() agent_ids=() AGENT_MODELS=() PI_TOOLS="" \
  vm_build_spec "$TMP/hub" "$TMP/spec.json" 2>/dev/null || true
[[ -f "$TMP/spec.json" ]] || fail "vm_build_spec wrote no spec"
jq -e --arg h "$TMP/hub/harness/extensions" --arg g "$ROOT/extensions" '.mounts[] | select(.host == $h and .guest == $g and .readonly)' "$TMP/spec.json" >/dev/null \
  || fail "the VMs do not get the frozen extensions at the checkout's path: $(jq -c .mounts "$TMP/spec.json")"
jq -e --arg h "$ROOT/extensions" '.mounts[] | select(.host == $h)' "$TMP/spec.json" >/dev/null && fail "the live checkout is still mounted"
pass "a VM run's harness is a copy taken at kickoff, mounted read-only where the checkout is"

# Pi's built-in llama.cpp provider has no models.json entry: the VMs are
# given its server as the guest reaches it, through the host gateway, and a
# stand-in key the server ignores.
eval "$(fn provider_base_url)"
# Arrays cannot ride on a command's prefix: set them for the call.
extra_env=() agent_ids=() AGENT_MODELS=("llama.cpp/qwen")
sandbox="$TMP/sandbox" swarm_id=s1 hard=0 wall=10 n=0 vm_image=img vm_cpus=1 vm_memory=1024 vm_disk=8192 \
  playwright=0 pack_dirs="" compact_prompt="" self_compact=0 forging=0 inbox_page_chars="" quarantine=0 local_only=0 \
  allow_install=0 install_hosts=0 allow_hosts="" use_netguard=1 PACK_SECRETS_VM='[]' PACK_SECRETS_ENV='{}' REGISTRY="$TMP/runs/registry.json" \
  vm_image_digest="" PI_TOOLS="" LLAMA_BASE_URL="http://127.0.0.1:8080" \
  vm_build_spec "$TMP/hub" "$TMP/spec-llama.json" 2>/dev/null || true
[[ "$(jq -r '.env.LLAMA_BASE_URL // empty' "$TMP/spec-llama.json" 2>/dev/null)" == "http://host.microsandbox.internal:8080" ]] \
  || fail "llama.cpp in a VM is not pointed at the host gateway: $(jq -c '.env' "$TMP/spec-llama.json" 2>&1)"
[[ "$(jq -r '.env.LLAMA_API_KEY // empty' "$TMP/spec-llama.json")" == "local" ]] || fail "llama.cpp in a VM has no stand-in key"
pass "Pi's built-in llama.cpp provider reaches the host's server from a VM through the gateway"

# --- the hub's keeper, its stop and the seats' tokens, from the frozen copy --------
for f in run_script write_seat_tokens start_vm_hub hub_send; do
  eval "$(fn "$f")"
  type "$f" >/dev/null 2>&1 || fail "$f was not found in swarm.sh"
done
HD="$(hubs_parent --create)/dfs-sfz1.test"
mkdir -p "$HD/host/scripts" "$TMP/fsb/traces"
[[ "$(run_script "" scripts/idle-nudge.sh)" == "$ROOT/scripts/idle-nudge.sh" ]] || fail "a run with no frozen copy does not use the checkout"
[[ "$(run_script "$HD" scripts/idle-nudge.sh)" == "$ROOT/scripts/idle-nudge.sh" ]] || fail "a script the copy lacks is not taken from the checkout"
: > "$HD/host/scripts/idle-nudge.sh"
[[ "$(run_script "$HD" scripts/idle-nudge.sh)" == "$HD/host/scripts/idle-nudge.sh" ]] || fail "the frozen copy's watchdog is not the one run"
# Tokens: one per seat, 32 hex, 0600, in the hub's directory.
tokens_file="$(write_seat_tokens "$HD" sfz100 sfz101)" || fail "write_seat_tokens failed"
[[ "$tokens_file" == "$HD/seat-tokens.json" ]] || fail "the tokens are not in the hub's directory: $tokens_file"
jq -e '(keys == ["sfz100", "sfz101"]) and ([.[] | test("^[0-9a-f]{32}$")] | all) and (.sfz100 != .sfz101)' "$tokens_file" >/dev/null || fail "the tokens are not one 32-hex token per seat: $(cat "$tokens_file")"
mode="$(stat -c %a "$tokens_file" 2>/dev/null || stat -f %Lp "$tokens_file")"
[[ "$mode" == 600 ]] || fail "the tokens file is mode $mode"
# A stand-in hub in the frozen copy: it keeps its argv and its stdin, and
# answers on admin.sock; a stand-in keeper says which copy was started.
cat > "$HD/host/scripts/vm-hub.ts" <<'EOF'
import { writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
const dir = process.argv[process.argv.indexOf("--dir") + 1];
let input = "";
process.stdin.on("data", (d) => (input += d));
process.stdin.on("end", () => {
  writeFileSync(join(dir, "stand-in.json"), JSON.stringify({ argv: process.argv.slice(2), input: JSON.parse(input) }));
  createServer().listen(join(dir, "admin.sock"));
  setTimeout(() => process.exit(0), 20000);
});
EOF
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$0" "$SWARM_RUNS_DIR" > "%s/keeper-ran"\n' "$HD" > "$HD/host/scripts/hub-supervise.sh"
printf '#!/usr/bin/env bash\n' > "$HD/host/scripts/swarm.sh"
TRACE_TOKENS_JSON='{"sfz100":"t0","sfz101":"t1"}' SEAT_TOKENS_FILE="$tokens_file" RUNS_DIR="$TMP/runs" REGISTRY="$TMP/runs/registry.json" \
  start_vm_hub "$TMP/fsb" "$HD" sfz1 "$TMP/collector.sock" sfz100 sfz101 || fail "start_vm_hub failed: $(cat "$TMP/fsb/traces/vm-hub.log" 2>/dev/null)"
PIDS+=("$(cat "$TMP/fsb/hub.pid")")
for i in $(seq 1 50); do [[ -f "$HD/keeper-ran" ]] && break; sleep 0.1; done
[[ "$(head -1 "$HD/keeper-ran" 2>/dev/null)" == "$HD/host/scripts/hub-supervise.sh" ]] || fail "the keeper was not started from the frozen copy: $(cat "$HD/keeper-ran" 2>/dev/null)"
[[ "$(sed -n 2p "$HD/keeper-ran")" == "$TMP/runs" ]] || fail "the keeper does not know the runs directory"
jq -e --arg s "$HD/host/scripts/swarm.sh" '.argv | index("--stop-cmd") as $i | .[$i + 1] == $s' "$HD/stand-in.json" >/dev/null || fail "the hub's stop is not the frozen copy's: $(jq -c .argv "$HD/stand-in.json")"
jq -e --slurpfile t "$tokens_file" '.input.seat_tokens == $t[0] and .input.tokens == {"t0": "sfz100", "t1": "sfz101"}' "$HD/stand-in.json" >/dev/null \
  || fail "the hub was not given the seats' tokens beside the collector's: $(jq -c .input "$HD/stand-in.json")"
pass "the keeper, the hub's stop and the watchdog run from the frozen copy; the hub gets one 32-hex token per seat (0600, in its own directory) beside the collector's"

# The spec names the tokens file and never holds a token.
for f in vm_build_spec vm_providers_json pi_agent_dir pi_auth_file credential_models distinct_models; do eval "$(fn "$f")"; done
extra_env=() agent_ids=() AGENT_MODELS=()
sandbox="$TMP/sandbox" swarm_id=s1 hard=0 wall=10 n=0 vm_image=img vm_cpus=1 vm_memory=1024 vm_disk=8192 \
  playwright=0 pack_dirs="" compact_prompt="" self_compact=0 forging=0 inbox_page_chars="" quarantine=0 local_only=0 \
  allow_install=0 install_hosts=0 allow_hosts="" use_netguard=1 PACK_SECRETS_VM='[]' PACK_SECRETS_ENV='{}' REGISTRY="$TMP/runs/registry.json" \
  vm_image_digest="" PI_TOOLS="" SEAT_TOKENS_FILE="$tokens_file" \
  vm_build_spec "$TMP/hub" "$TMP/spec-tokens.json" 2>/dev/null || true
[[ "$(jq -r '.seat_tokens_file // empty' "$TMP/spec-tokens.json")" == "$tokens_file" ]] || fail "the spec does not name the tokens file"
for tok in $(jq -r '.[]' "$tokens_file"); do
  grep -q "$tok" "$TMP/spec-tokens.json" && fail "a seat's token is in the spec"
done
pass "the VM spec names the seats' tokens file and holds no token"

# An unpacked `git archive` (how the Linux host is synced) knows its commit
# from scripts/HARNESS_COMMIT, which the archive fills in; git itself is
# asked first, and without git local changes are "unknown", not "changed".
eval "$(fn harness_commit)"; eval "$(fn harness_dirty)"
G="$TMP/arch-src"; mkdir -p "$G/scripts"
cp "$ROOT/.gitattributes" "$G/.gitattributes"; cp "$ROOT/scripts/HARNESS_COMMIT" "$G/scripts/HARNESS_COMMIT"
git -C "$G" init -q && git -C "$G" -c user.name=t -c user.email=t@t add -A && git -C "$G" -c user.name=t -c user.email=t@t commit -qm t
want="$(git -C "$G" rev-parse HEAD)"
mkdir -p "$TMP/arch-out" && git -C "$G" archive HEAD | tar -x -C "$TMP/arch-out"
[[ "$(tr -d '[:space:]' < "$TMP/arch-out/scripts/HARNESS_COMMIT")" == "$want" ]] || fail "git archive did not write the commit: $(cat "$TMP/arch-out/scripts/HARNESS_COMMIT")"
[[ "$(ROOT="$TMP/arch-out" harness_commit)" == "$want" ]] || fail "an unpacked archive does not know its commit"
[[ "$(ROOT="$TMP/arch-out" harness_dirty)" == unknown ]] || fail "an unpacked archive claims to know its local changes"
[[ "$(ROOT="$G" harness_commit)" == "$want" ]] || fail "a git checkout's own commit is not used"
mkdir -p "$TMP/no-commit/scripts" && printf '$Format:%%H$\n' > "$TMP/no-commit/scripts/HARNESS_COMMIT"
[[ -z "$(ROOT="$TMP/no-commit" harness_commit)" ]] || fail "an unfilled placeholder was taken for a commit"
pass "an unpacked archive knows its commit, and says it cannot tell local changes"

echo "lifecycle: all checks passed"
