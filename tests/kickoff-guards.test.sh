#!/usr/bin/env bash
# Small guards of scripts/swarm.sh, taken from the script itself. No model,
# no Herdr, no VM.
#
# - the VM hubs' directory is one per user, not a link, not someone else's,
#   and a run whose hub sockets would not fit a Unix socket path is refused;
# - stop ends a daemon only when the pid names that daemon for that sandbox;
# - a run id is not allocated past a failed `msb list`.
set -euo pipefail
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/kguard.XXXXXX)"
PIDS=()
cleanup() { local p; for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

fn() { sed -n "/^$1() {/,/^}/p" "$ROOT/scripts/swarm.sh"; }
for f in hubs_parent hubs_parent_path hub_socket_path_max vm_hub_dir hub_dir_of daemon_pid_ours stop_sandbox_daemons hub_pid_ours alloc_prefix; do
  eval "$(fn "$f")"
  type "$f" >/dev/null 2>&1 || fail "$f was not found in swarm.sh"
done

echo "# the hubs' directory"
export SWARM_HUBS_DIR="$TMP/hubs"
p="$(hubs_parent --create)" || fail "the hubs' directory was not made"
[[ "$(stat -c %a "$SWARM_HUBS_DIR" 2>/dev/null || stat -f %Lp "$SWARM_HUBS_DIR")" == "700" ]] || fail "the hubs' directory is not 0700"
[[ "$p" == "$(cd "$SWARM_HUBS_DIR" && pwd -P)" ]] || fail "hubs_parent did not resolve the directory"
unset SWARM_HUBS_DIR
[[ "$(HOME="$TMP/home" hubs_parent_path)" == "$TMP/home/.dfirswarm/hubs" ]] || fail "the default is not under the user's home"
[[ "$(HOME="$TMP/home" TMPDIR="$TMP/elsewhere" hubs_parent_path)" == "$TMP/home/.dfirswarm/hubs" ]] || fail "the hubs' directory follows TMPDIR"
export SWARM_HUBS_DIR="$TMP/hubs"
mkdir -p "$TMP/real"
ln -s "$TMP/real" "$TMP/linked"
out="$(SWARM_HUBS_DIR="$TMP/linked" hubs_parent --create 2>&1)" && fail "a hubs' directory that is a link was used: $out"
grep -q 'is a link' <<<"$out" || fail "the refusal does not say it is a link: $out"
if [[ "$(id -u)" -ne 0 && -d /private/var/root ]] && [[ ! -O /private/var/root ]]; then
  out="$(SWARM_HUBS_DIR=/private/var/root hubs_parent 2>&1)" && fail "another user's directory was taken for the hubs' directory"
  grep -q 'is not yours' <<<"$out" || fail "the refusal does not say it is not the user's: $out"
elif [[ "$(id -u)" -ne 0 && -d /root ]]; then
  out="$(SWARM_HUBS_DIR=/root hubs_parent 2>&1)" && fail "another user's directory was taken for the hubs' directory"
fi
pass "the hubs' directory is the user's own (0700), the same whatever TMPDIR, and a link or another user's directory is refused"

echo "# a hub socket past the Unix limit is refused at kickoff"
n="$(hub_socket_path_max s1a2b3c s1a2b3c09)" || fail "hub_socket_path_max failed"
(( n < 104 )) || fail "a short hubs' directory gave a socket path of $n bytes"
long="$TMP/$(printf 'x%.0s' $(seq 1 60))"
mkdir -p "$long"
n="$(SWARM_HUBS_DIR="$long/hubs" hub_socket_path_max s1a2b3c s1a2b3c09)"
(( n > 103 )) || fail "a long hubs' directory was not measured as too long ($n)"
# The kickoff checks it before anything is written.
grep -q 'this run.s hub sockets would be' "$ROOT/scripts/swarm.sh" || fail "the kickoff does not refuse a socket path that is too long"
pass "the longest hub socket path is measured in bytes, and one past 103 is caught"

echo "# stop ends only this sandbox's own daemons"
SB="$TMP/sb"
mkdir -p "$SB/traces"
SB="$(cd "$SB" && pwd -P)"
bash -c "exec -a 'node trace-collector.mjs $SB --tokens' sleep 300" >/dev/null 2>&1 &
ours=$!
disown "$ours" 2>/dev/null || true
PIDS+=("$ours")
sleep 300 >/dev/null 2>&1 &
stranger=$!
disown "$stranger" 2>/dev/null || true
PIDS+=("$stranger")
bash -c "exec -a 'node nudge-broker.mjs $TMP/other-sandbox --roster' sleep 300" >/dev/null 2>&1 &
other=$!
disown "$other" 2>/dev/null || true
PIDS+=("$other")
sleep 0.3
echo "$ours" > "$SB/collector.pid"
echo "$stranger" > "$SB/idle-nudge.pid"
echo "$other" > "$SB/nudge.pid"
stop_sandbox_daemons "$SB" keep-record
kill -0 "$ours" 2>/dev/null && fail "this sandbox's collector was not stopped"
kill -0 "$stranger" 2>/dev/null || fail "a process a pid file named, but not a daemon of this run, was killed"
kill -0 "$other" 2>/dev/null || fail "another sandbox's daemon, named in this sandbox's pid file, was killed"
pass "stop ends a daemon its pid file names only when the process is that daemon for this sandbox"

echo "# a run id is not allocated past a failed msb list"
herdr_agent_names() { :; }
json_get() { :; }
vm_cli() { printf '{"ok":false,"error":"msb list failed: the runtime is not running"}\n'; return 1; }
set +e
out="$(isolation=microvm alloc_prefix 2>&1)"
rc=$?
set -e
[[ $rc -eq 3 ]] || fail "a failed msb list exited $rc, wanted 3: $out"
grep -q 'msb could not list its VMs.*the runtime is not running' <<<"$out" || fail "the refusal does not say msb's list failed: $out"
grep -q 'Could not allocate' <<<"$out" && fail "a failed list was reported as ids that could not be had: $out"
vm_cli() { printf '{"ok":true,"vms":[]}\n'; }
id="$(isolation=microvm alloc_prefix)" || fail "an id was not allocated with msb answering"
[[ "$id" =~ ^s[0-9a-f]{6}$ ]] || fail "the id is not s and three bytes: $id"
pass "a failed msb list is said as that; with msb answering an id of three bytes is allocated"

echo "kickoff-guards.test.sh: all checks passed"
