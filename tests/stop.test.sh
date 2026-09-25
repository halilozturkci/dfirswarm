#!/usr/bin/env bash
# `swarm.sh stop` of a microVM run, against a stand-in msb (SWARM_MSB_BIN).
# No model, no Herdr, no VM.
#
# What a stop must not do is say "Stopped" while a VM of the run is still up:
# a run whose VMs are up is not stopped, whatever the record says. And the
# hub's own clear-up after it finished a run keeps the state it recorded.
set -euo pipefail
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stop-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# Nothing here reaches the operator's own msb database or VM hubs: a finish
# that removes a stand-in VM scrubs msb's database, and the hubs live in a
# directory of the user's own.
export MSB_HOME="$TMP/msb-home"
export SWARM_HUBS_DIR="$TMP/dfirswarm-hubs"
mkdir -p "$MSB_HOME"

RUNS="$TMP/runs"
SB="$RUNS/sstp1"
mkdir -p "$SB/traces" "$SB/done/agents" "$SB/vm"
printf '{"swarm_id":"sstp1","n":1,"agents":[{"id":"sstp100","role":"worker"}]}\n' > "$SB/team.json"
record() { # <state>
  jq -n --arg sb "$SB" --arg st "$1" '{runs: [{id: "sstp1", label: "stop-test", state: $st, sandbox: $sb, n: 1, isolation: {mode: "microvm", snapshot: false}}]}' > "$RUNS/registry.json"
}

# A stand-in msb: one VM of the run that will not stop.
cat > "$TMP/msb" <<EOF
#!/usr/bin/env bash
case "\$1" in
  list) printf '[{"name":"dfs-sstp1-sstp100","status":"running","labels":{"dev.dfirswarm.run":"sstp1","dev.dfirswarm.agent":"sstp100"}}]\n' ;;
  inspect) printf '{"config":{"labels":{"dev.dfirswarm.run":"sstp1","dev.dfirswarm.agent":"sstp100"}}}\n' ;;
  stop) echo "the VM will not stop" >&2; exit 1 ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$TMP/msb"

echo "# a VM that is still up after stop: not stopped, and said so"
record running
set +e
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop sstp1 --no-custody 2>&1)"
rc=$?
set -e
[[ $rc -eq 3 ]] || fail "stop with a VM still up exited $rc, wanted 3: $out"
grep -q "NOT STOPPED" <<<"$out" || fail "stop did not say the run is not stopped: $out"
grep -q "Stopped sstp1" <<<"$out" && fail "stop said Stopped with a VM up: $out"
[[ "$(jq -r '.runs[0].state' "$RUNS/registry.json")" == "stop_incomplete" ]] || fail "the record does not say stop_incomplete: $(jq -c '.runs[0]' "$RUNS/registry.json")"
pass "a stop that leaves a VM up exits 3 and records stop_incomplete"

echo "# the hub's own clear-up keeps the state the hub recorded"
cat > "$TMP/msb" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  list) printf '[]\n' ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
EOF
record finished
touch "$SB/done/SWARM_DONE"
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop sstp1 --after-hub 2>&1)" || fail "the after-hub stop failed: $out"
[[ "$(jq -r '.runs[0].state' "$RUNS/registry.json")" == "finished" ]] || fail "the after-hub stop changed the hub's state: $(jq -c '.runs[0]' "$RUNS/registry.json")"
grep -q "Custody:.*skipped\|Cleared sstp1 after the hub finished it" <<<"$out" || fail "the after-hub stop did not say what it did: $out"
pass "a stop the hub runs after finishing the run clears up and keeps the state finished"

echo "# a reaped microVM seat has its VM put away, its disk kept"
RS="$TMP/reap-sb"
mkdir -p "$RS/traces" "$RS/done/agents" "$RS/vm" "$RS/locks" "$RS/threads/main"
printf '{"swarm_id":"srp1","n":1,"agents":[{"id":"srp100","role":"worker"}]}\n' > "$RS/team.json"
printf '{"cap_usd":1,"spent_usd":0,"wall_clock_minutes":60,"started_at":"2026-01-01T00:00:00Z","agents":{}}\n' > "$RS/budget.json"
printf '{"agent":"srp100","name":"dfs-srp1-srp100","run":"srp1"}\n' > "$RS/vm/srp100.json"
: > "$RS/traces/events.jsonl"
HUBS="$SWARM_HUBS_DIR"
mkdir -p "$HUBS/dfs-srp1.x1"
chmod 700 "$HUBS"
(cd "$RS" && pwd -P) > "$HUBS/dfs-srp1.x1/sandbox"
printf '{"agents":{"srp100":{"state":"idle"}}}\n' > "$HUBS/dfs-srp1.x1/status.json"
(cd "$HUBS/dfs-srp1.x1" && pwd -P) > "$RS/hub.dir"
cat > "$TMP/msb" <<EOF
#!/usr/bin/env bash
printf '%s\\n' "\$*" >> "$TMP/msb-calls.log"
case "\$1" in
  list) printf '[{"name":"dfs-srp1-srp100","status":"running","labels":{"dev.dfirswarm.run":"srp1","dev.dfirswarm.agent":"srp100"}}]\\n' ;;
  exec) printf '{"baseline":true,"apt":{},"venv":{}}\\n' ;;
  snapshot) for a in "\$@"; do [[ "\$prev" == "-o" ]] && printf 'disk' > "\$a"; prev="\$a"; done ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$TMP/msb"
out="$(TMPDIR="$TMP" SWARM_MSB_BIN="$TMP/msb" HERDR_BIN=/usr/bin/false PATH="/usr/bin:/bin:$(dirname "$(command -v node)"):$(dirname "$(command -v jq)")" bash "$ROOT/scripts/reap.sh" --sandbox "$RS" --timeout 1 --stop 2>&1)" || true
[[ -f "$RS/done/agents/srp100.dead" ]] || fail "the silent seat was not reaped: $out"
grep -q "^stop dfs-srp1-srp100" "$TMP/msb-calls.log" 2>/dev/null || fail "the reaped seat's VM was not stopped: $(cat "$TMP/msb-calls.log" 2>/dev/null); $out"
grep -q "^snapshot create" "$TMP/msb-calls.log" || fail "the reaped seat's disk was not kept"
grep -q "VM of srp100 put away" <<<"$out" || fail "the reaper did not say the VM was put away: $out"
pass "a reaped microVM seat has its VM stopped and its disk kept, as stop would"

echo "# a stop from a shell with another TMPDIR still ends the hub, its keeper and its directory"
TS="$RUNS/stmp1"
mkdir -p "$TS/traces" "$TS/done/agents" "$TS/vm"
printf '{"swarm_id":"stmp1","n":1,"agents":[{"id":"stmp100","role":"worker"}]}\n' > "$TS/team.json"
jq -n --arg sb "$TS" '{runs: [{id: "stmp1", label: "tmpdir", state: "running", sandbox: $sb, n: 1, isolation: {mode: "microvm", snapshot: false}}]}' > "$RUNS/registry.json"
HD="$(cd "$SWARM_HUBS_DIR" && pwd -P)/dfs-stmp1.x1"
mkdir -p "$HD"
(cd "$TS" && pwd -P) > "$HD/sandbox"
printf '{"finished":false}\n' > "$HD/status.json"
printf '{}\n' > "$HD/hub-input.json"
printf '%s\n' "$HD" > "$TS/hub.dir"
bash -c "exec -a 'node vm-hub.ts $TS --dir $HD' sleep 300" &
HUB=$!
disown "$HUB" 2>/dev/null || true
bash -c "exec -a 'bash hub-supervise.sh $TS' sleep 300" &
KEEP=$!
disown "$KEEP" 2>/dev/null || true
echo "$HUB" > "$TS/hub.pid"
echo "$KEEP" > "$HD/supervisor.pid"
cat > "$TMP/msb" <<'EOF2'
#!/usr/bin/env bash
case "$1" in
  list) printf '[]\n' ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
EOF2
chmod +x "$TMP/msb"
sleep 0.3
mkdir -p "$TMP/other-tmp"
out="$(TMPDIR="$TMP/other-tmp" SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop stmp1 --no-custody 2>&1)" || fail "the stop failed: $out"
alive=""
kill -0 "$HUB" 2>/dev/null && alive="the hub"
kill -0 "$KEEP" 2>/dev/null && alive="$alive the keeper"
kill "$HUB" "$KEEP" 2>/dev/null || true
[[ -z "$alive" ]] || fail "a stop with another TMPDIR left$alive running: $out"
[[ ! -d "$HD" ]] || fail "a stop with another TMPDIR left the hub's directory (its tokens): $out"
pass "a stop from a shell with another TMPDIR finds the hub, ends it and its keeper, and removes its directory"

echo "# a disk is never lost to a full disk or a failed second snapshot"
FS="$RUNS/sfs1"
mkdir -p "$FS/vm" "$FS/traces"
printf '{"agent":"sfs100","name":"dfs-sfs1-sfs100","run":"sfs1"}\n' > "$FS/vm/sfs100.json"
cat > "$TMP/msb" <<EOF2
#!/usr/bin/env bash
printf '%s\\n' "\$*" >> "$TMP/fs-calls.log"
case "\$1" in
  list) printf '[{"name":"dfs-sfs1-sfs100","status":"running","labels":{"dev.dfirswarm.run":"sfs1","dev.dfirswarm.agent":"sfs100"}}]\\n' ;;
  exec) printf '{"baseline":true,"apt":{},"venv":{}}\\n' ;;
  snapshot) [[ -n "\${SNAP_FAIL:-}" ]] && { echo "no room for the disk" >&2; exit 1; }; for a in "\$@"; do [[ "\$prev" == "-o" ]] && printf 'disk-v2' > "\$a"; prev="\$a"; done ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
EOF2
chmod +x "$TMP/msb"
: > "$TMP/fs-calls.log"
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_SNAPSHOT_MIN_FREE_BYTES=1000000000000000000 node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" finish --run sfs1 --sandbox "$FS" 2>&1)" && fail "a finish with no room reported success: $out"
grep -q '^snapshot' "$TMP/fs-calls.log" && fail "a snapshot was attempted with no room for it: $(cat "$TMP/fs-calls.log")"
grep -q '^rm ' "$TMP/fs-calls.log" && fail "a VM whose disk could not be kept was removed: $(cat "$TMP/fs-calls.log")"
jq -e '.snapshot.error | test("bytes free")' "$FS/vm/sfs100.json" >/dev/null || fail "the record does not say why the disk was not kept: $(cat "$FS/vm/sfs100.json")"
pass "below the free-space floor the VM is kept, not snapshotted and not removed, and its record says why"
# A disk an earlier finish kept stays when a second attempt fails.
mkdir -p "$FS.vm-snapshots"
printf 'disk-v1' > "$FS.vm-snapshots/sfs100.msb"
jq '.snapshot = {path: "'"$FS.vm-snapshots/sfs100.msb"'", sha256: "x", bytes: 7, integrity: true}' "$FS/vm/sfs100.json" > "$FS/vm/r.tmp" && mv "$FS/vm/r.tmp" "$FS/vm/sfs100.json"
: > "$TMP/fs-calls.log"
out="$(SNAP_FAIL=1 SWARM_MSB_BIN="$TMP/msb" SWARM_SNAPSHOT_MIN_FREE_BYTES=1 node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" finish --run sfs1 --sandbox "$FS" 2>&1)" && fail "a failed snapshot reported success: $out"
[[ "$(cat "$FS.vm-snapshots/sfs100.msb" 2>/dev/null)" == "disk-v1" ]] || fail "the disk an earlier finish kept was deleted by a failed second snapshot"
[[ "$(jq -r '.snapshot.path' "$FS/vm/sfs100.json")" == "$FS.vm-snapshots/sfs100.msb" ]] || fail "the record lost the earlier disk: $(cat "$FS/vm/sfs100.json")"
jq -e '.snapshot_retry_error | test("no room")' "$FS/vm/sfs100.json" >/dev/null || fail "the failed retry is not on the record"
grep -q '^rm ' "$TMP/fs-calls.log" && fail "the VM was removed after its snapshot failed"
# And a second attempt that works replaces it.
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_SNAPSHOT_MIN_FREE_BYTES=1 node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" finish --run sfs1 --sandbox "$FS" 2>&1)" || fail "a working second snapshot failed: $out"
[[ "$(cat "$FS.vm-snapshots/sfs100.msb")" == "disk-v2" && ! -e "$FS.vm-snapshots/sfs100.msb.new" ]] || fail "the new disk did not replace the earlier one"
jq -e '(.snapshot_retry_error | not) and (.msb_db != null)' "$FS/vm/sfs100.json" >/dev/null || fail "the record after the retry: $(cat "$FS/vm/sfs100.json")"
pass "a disk an earlier finish kept survives a failed second snapshot, and a working one replaces it; the record carries the msb database's outcome"

echo "# a custody that could not run does not pass an earlier verdict off as this stop's"
CS="$RUNS/scus1"
mkdir -p "$CS/traces"
printf '{"swarm_id":"scus1","n":1,"agents":[{"id":"scus100","role":"worker"}]}\n' > "$CS/team.json"
printf '{"at":"2020-01-01T00:00:00.000Z","summary":"OLD VERDICT FROM AN EARLIER STOP"}\n' > "$CS/custody.json"
jq -n --arg sb "$CS" '{runs: [{id: "scus1", label: "custody", state: "running", sandbox: $sb, n: 1, isolation: {mode: "host"}}]}' > "$RUNS/registry.json"
# traces/ not writable: custody's own log cannot be opened, so custody never runs.
chmod a-w "$CS/traces"
out="$(SWARM_RUNS_DIR="$RUNS" bash "$ROOT/scripts/swarm.sh" stop scus1 --custody-timeout 30 2>&1)" || true
chmod u+w "$CS/traces"
grep -q 'Custody: *OLD VERDICT' <<<"$out" && fail "stop printed an earlier verdict as this stop's: $out"
grep -q "the custody check did not finish" <<<"$out" || fail "stop did not say custody did not finish: $out"
grep -q "an earlier one (2020-01-01" <<<"$out" || fail "stop did not say the verdict on disk is an earlier one: $out"
grep -q "nothing of run scus1 was alive" <<<"$out" || fail "a run recorded as running with nothing alive was not said to have crashed or lost its host: $out"
pass "a custody that did not run is said, and the verdict left from an earlier stop is named as that; a run with nothing alive is said to have crashed or lost its host"

echo "# a run on hold keeps its VMs from the reaper"
HR="$TMP/hold-runs"
mkdir -p "$HR/shd1"
jq -n --arg sb "$HR/shd1" '{runs: [{id: "shd1", label: "held", state: "stopped", sandbox: $sb, n: 1, hold: {reason: "matter", at: "t", by: "x"}}]}' > "$HR/registry.json"
label="$(node --experimental-strip-types --no-warnings -e 'import(process.argv[2]).then((V) => console.log(V.registryLabel(process.argv[3])))' -- x "$ROOT/scripts/vm.ts" "$HR/registry.json")"
: > "$TMP/msb-hold.log"
cat > "$TMP/msb" <<EOF
#!/usr/bin/env bash
printf '%s\\n' "\$*" >> "$TMP/msb-hold.log"
case "\$1" in
  list) printf '[{"name":"dfs-shd1-shd100","status":"stopped","labels":{"dev.dfirswarm.run":"shd1","dev.dfirswarm.agent":"shd100","dev.dfirswarm.registry":"$label"}}]\\n' ;;
  inspect) printf '{"config":{"labels":{"dev.dfirswarm.run":"shd1","dev.dfirswarm.agent":"shd100","dev.dfirswarm.registry":"$label"}}}\\n' ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$TMP/msb"
out="$(SWARM_MSB_BIN="$TMP/msb" node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" reap --registry "$HR/registry.json" 2>&1)" || fail "reap failed: $out"
grep -q '^stop dfs-shd1\|^rm dfs-shd1\|^snapshot' "$TMP/msb-hold.log" && fail "the reaper touched a held run's VM: $(cat "$TMP/msb-hold.log")"
# Released, the same VM is the reaper's.
jq '.runs[0].hold = null' "$HR/registry.json" > "$HR/r" && mv "$HR/r" "$HR/registry.json"
out="$(SWARM_MSB_BIN="$TMP/msb" node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" reap --registry "$HR/registry.json" 2>&1)" || true
grep -q '^rm dfs-shd1-shd100\|^snapshot' "$TMP/msb-hold.log" || fail "a released run's VM was not reaped: $(cat "$TMP/msb-hold.log")"
pass "a held run's VM is left alone by the reaper, and reaped once released"

echo "stop.test.sh: all checks passed"
