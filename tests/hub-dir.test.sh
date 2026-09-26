#!/usr/bin/env bash
# The files a sandbox keeps about its VM hub (hub.dir, hub.pid) are only
# tool-protected: a host pane's shell can write them. What the harness does
# with them — send the hub words, read its status, kill it at stop — must
# only ever reach the hub made for that sandbox, never another run's.
#
# The functions are taken from the scripts themselves, so this tests the
# code that runs and not a copy of it.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/hub-dir.XXXXXX")"
# The hubs' directory is the test's own, and short (a hub socket path must
# fit in 104 bytes): never the operator's ~/.dfirswarm/hubs.
HUBS_TMP="$(mktemp -d /tmp/dfh.XXXXXX)"
export SWARM_HUBS_DIR="$HUBS_TMP/dfirswarm-hubs"
PIDS=()
cleanup() { local p; for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null; done; rm -rf "$TMP" "$HUBS_TMP"; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
export TMPDIR="$TMP/tmp"
mkdir -p "$TMPDIR"

fn() { sed -n "/^$2() {/,/^}/p" "$ROOT/scripts/$1"; }
eval "$(fn swarm.sh hubs_parent)"
eval "$(fn swarm.sh hubs_parent_path)"
eval "$(fn swarm.sh vm_hub_dir)"
eval "$(fn swarm.sh hub_dir_of)"
eval "$(fn swarm.sh hub_pid_ours)"
eval "reap_$(fn reap.sh hub_dir_of)"
type hub_pid_ours >/dev/null 2>&1 || fail "hub_pid_ours was not found in swarm.sh"
type reap_hub_dir_of >/dev/null 2>&1 || fail "hub_dir_of was not found in reap.sh"

mkdir -p "$TMP/runs/a" "$TMP/runs/b"
A="$TMP/runs/a" B="$TMP/runs/b"
hub_a="$(vm_hub_dir sa "$A")"
hub_b="$(vm_hub_dir sb "$B")"
printf '%s\n' "$hub_a" > "$A/hub.dir"
[[ "$(hub_dir_of "$A")" == "$hub_a" ]] || fail "a sandbox's own hub directory is not accepted"
[[ "$(reap_hub_dir_of "$A")" == "$hub_a" ]] || fail "reap does not accept a sandbox's own hub directory"
pass "a sandbox's own hub directory is its hub"

# A pane in run b names run a's hub.
printf '%s\n' "$hub_a" > "$B/hub.dir"
hub_dir_of "$B" >/dev/null && fail "a sandbox that names another run's hub directory was given it"
reap_hub_dir_of "$B" >/dev/null && fail "reap accepted another run's hub directory"
printf '%s\n' "$TMP/elsewhere" > "$B/hub.dir"
mkdir -p "$TMP/elsewhere"
hub_dir_of "$B" >/dev/null && fail "a hub directory outside the hubs' parent was accepted"
printf '%s\n' "$(hubs_parent)/dfs-sb.x/../$(basename "$hub_a")" > "$B/hub.dir"
hub_dir_of "$B" >/dev/null && fail "a path that climbs out of a hub directory was accepted"
pass "another run's hub, a directory elsewhere, and a path with .. are refused"

# await-done's inline check agrees.
grep -q '"$(cat "$hd/sandbox" 2>/dev/null)" == "$(cd "$sandbox" 2>/dev/null && pwd -P)"' "$ROOT/scripts/await-done.sh" \
  || fail "await-done.sh does not check which sandbox a hub directory serves"

# hub.pid: only this sandbox's hub is killed at stop. A stand-in hub whose
# command line names its directory, the way the kickoff starts one.
printf '%s\n' "$hub_b" > "$B/hub.dir"
mkdir -p "$TMP/bin"
printf '#!/usr/bin/env bash\nfor _ in $(seq 60); do sleep 1; done\n' > "$TMP/bin/vm-hub.ts"
bash "$TMP/bin/vm-hub.ts" "$A" --dir "$hub_a" >/dev/null 2>&1 &
pid_a=$!
PIDS+=("$pid_a")
disown "$pid_a" 2>/dev/null || true
sleep 0.3
hub_pid_ours "$A" "$pid_a" || fail "a sandbox's own hub pid is not recognised"
hub_pid_ours "$B" "$pid_a" && fail "run b's stop would kill run a's hub, named in b's hub.pid"
hub_pid_ours "$A" "$$" && fail "a process that is not a hub was taken for one"
hub_pid_ours "$A" "" && fail "an empty hub.pid was taken for a hub"
pass "hub.pid names this sandbox's hub or nothing: another run's hub and a stranger are refused"
# watch.sh lists a VM run's agents from the hub, and only from the hub made
# for that sandbox.
printf '{"agents":{"a0":{"state":"working","connected":true,"since":"t1"},"a1":{"state":"idle","connected":false,"since":"t2"}}}\n' > "$hub_a/status.json"
printf '%s\n' "$hub_a" > "$A/hub.dir"
out="$(SWARM_SANDBOX="$A" bash "$ROOT/scripts/watch.sh" --once 2>&1)"
grep -q '^VM AGENTS' <<<"$out" || fail "watch.sh shows no VM agents: $out"
grep -q $'^a1\tidle\tnot linked' <<<"$out" || fail "watch.sh does not show an agent's state and link: $out"
printf '%s\n' "$hub_a" > "$B/hub.dir"
SWARM_SANDBOX="$B" bash "$ROOT/scripts/watch.sh" --once 2>&1 | grep -q '^VM AGENTS' && fail "watch.sh read another run's hub for sandbox b"
pass "watch.sh lists a VM run's agents from its own hub and no other"

# Every pane of a VM run gets the quiet shell and nothing of the host run's
# environment; a host pane gets its identity, token and provider settings.
eval "$(fn swarm.sh pane_env_for)"
type pane_env_for >/dev/null 2>&1 || fail "pane_env_for was not found in swarm.sh"
trace_token_for() { echo "tok-$1"; }
swarm_id=s1 hard=0 provider_env=(--env HTTPS_PROXY=http://127.0.0.1:3128)
VM_PANE_ZDOTDIR="" pane_env_for a0
host_env="${PANE_ENV_ARGS[*]}"
[[ "$host_env" == *"SWARM_TRACE_TOKEN=tok-a0"* && "$host_env" == *"HTTPS_PROXY="* && "$host_env" == *"AGENT_ID=a0"* ]] || fail "a host pane lost its environment: $host_env"
VM_PANE_ZDOTDIR=/h/zdot pane_env_for a1
[[ "${PANE_ENV_ARGS[*]}" == "--env ZDOTDIR=/h/zdot" ]] || fail "a VM run's pane got more than the quiet shell: ${PANE_ENV_ARGS[*]}"
pass "every pane of a VM run gets the quiet shell and none of the host run's tokens or keys"
echo "hub-dir: all checks passed"
