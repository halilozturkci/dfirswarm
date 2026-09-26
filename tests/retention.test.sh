#!/usr/bin/env bash
# Retention: hold, release, purge, and what the kickoff records about the
# volume a run is kept on. No model, no Herdr, no VM.
#
# - a held run is kept from purge and from a new run in its sandbox;
# - purge deletes the sandbox, this run's kept disks (and no other run's,
#   in a shared --vm-snapshot-dir) and its hub directory, keeps the registry
#   entry as purged, and writes the destruction record on the audit;
# - the kickoff records disk_encryption as on, off or unknown.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/retention.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
RUNS="$TMP/runs"
export SWARM_RUNS_DIR="$RUNS"
: "${SWARM_HUBS_DIR:=$(mktemp -d /tmp/dfh.XXXXXX)/dfirswarm-hubs}"
export SWARM_HUBS_DIR
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }

# A finished VM run as a stop leaves it: a read-only evidence copy, a
# custody verdict, a package, its disks in a directory it shares with
# another run, and a hub directory.
SB="$RUNS/srt1"
mkdir -p "$SB/inputs" "$SB/traces" "$SB/package" "$TMP/disks"
printf 'evidence\n' > "$SB/inputs/a.bin"
printf '{"files":[]}\n' > "$SB/inputs.json"
printf '{"summary":"evidence unchanged"}\n' > "$SB/custody.json"
printf 'abc  ./x\n' > "$SB/package/MANIFEST.txt"
chmod -R a-w "$SB/inputs" "$SB/inputs.json"
printf 'disk' > "$TMP/disks/srt100.msb"
mkdir -p "$TMP/disks/srt100.logs" && printf 'log' > "$TMP/disks/srt100.logs/kernel.log"
printf 'other run' > "$TMP/disks/sother00.msb"
ln -s "$TMP/disks" "$SB.vm-snapshots"
mkdir -p "$SWARM_HUBS_DIR" && chmod 700 "$SWARM_HUBS_DIR"
HUBS_REAL="$(cd "$SWARM_HUBS_DIR" && pwd -P)"
mkdir -p "$HUBS_REAL/dfs-srt1.x1"
(cd "$SB" && pwd -P) > "$HUBS_REAL/dfs-srt1.x1/sandbox"
printf '%s\n' "$HUBS_REAL/dfs-srt1.x1" > "$SB/hub.dir"
cat > "$TMP/msb" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  list) printf '[]\n' ;;
  --version) echo "msb 0.7.2" ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$TMP/msb"
export SWARM_MSB_BIN="$TMP/msb"
jq -n --arg sb "$SB" '{runs: [{id: "srt1", label: "held", state: "done", sandbox: $sb, n: 1, agents: ["srt100"], case_id: "CASE-7",
  inputs_manifest_sha256: "m4n1f35t", isolation: {mode: "microvm"}}]}' > "$RUNS/registry.json"

echo "# hold keeps the material; release lets it go"
out="$(swarm hold srt1 --reason "legal hold, matter 12")" || fail "hold failed: $out"
jq -e '.runs[0].hold.reason == "legal hold, matter 12" and (.runs[0].hold.at | test("Z$")) and (.runs[0].hold.by | length > 0)' "$RUNS/registry.json" >/dev/null \
  || fail "the hold is not recorded: $(jq -c '.runs[0].hold' "$RUNS/registry.json")"
set +e
out="$(swarm purge srt1 --yes)"; rc=$?
set -e
[[ $rc -eq 2 ]] || fail "purge of a held run exited $rc: $out"
grep -q "on hold (legal hold, matter 12)" <<<"$out" || fail "the refusal does not name the hold: $out"
[[ -d "$SB/inputs" ]] || fail "a held run's material was deleted"
# A new run in a held run's sandbox would clear it.
set +e
out="$(swarm start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off --sandbox "$SB" --label reuse)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q "run srt1 in .* is on hold" <<<"$out" || fail "a new run in a held sandbox was not refused (rc $rc): $out"
[[ -f "$SB/custody.json" ]] || fail "the refused kickoff cleared the held run"
grep -q '"command":"hold"' "$RUNS/operator-audit.jsonl" || fail "the hold is not on the operator's audit"
out="$(swarm release srt1)" || fail "release failed: $out"
jq -e '.runs[0].hold == null and .runs[0].released.reason == "legal hold, matter 12"' "$RUNS/registry.json" >/dev/null || fail "the release is not recorded: $(jq -c '.runs[0]' "$RUNS/registry.json")"
pass "a held run is kept from purge and from a new run in its sandbox; release records what was held"

echo "# purge deletes this run's material and writes the destruction record"
set +e
out="$(swarm purge srt1)"; rc=$?
set -e
[[ $rc -eq 2 ]] || fail "purge without --yes exited $rc"
grep -q "$SB" <<<"$out" || fail "purge without --yes does not list what it would delete: $out"
[[ -d "$SB" ]] || fail "purge without --yes deleted something"
out="$(swarm purge srt1 --yes)" || fail "purge failed: $out"
[[ ! -e "$SB" ]] || fail "the sandbox is still there"
[[ ! -e "$TMP/disks/srt100.msb" && ! -e "$TMP/disks/srt100.logs" ]] || fail "this run's kept disks are still there"
[[ -f "$TMP/disks/sother00.msb" ]] || fail "purge deleted another run's disk in the shared snapshot directory"
[[ ! -L "$SB.vm-snapshots" ]] || fail "the disks' link is still there"
[[ ! -e "$HUBS_REAL/dfs-srt1.x1" ]] || fail "the hub directory is still there"
[[ "$(jq -r '.runs[0].state' "$RUNS/registry.json")" == purged ]] || fail "the registry does not keep the run as purged"
rec="$(grep '"command":"purge_record"' "$RUNS/operator-audit.jsonl" | tail -1)"
[[ -n "$rec" ]] || fail "no destruction record on the audit"
jq -e '.detail.run == "srt1" and .detail.case_id == "CASE-7" and .detail.inputs_manifest_sha256 == "m4n1f35t"
  and (.detail.custody_sha256 | length == 64) and (.detail.package_manifest_sha256 | length == 64)
  and ([.detail.deleted[].path] | length >= 3) and .detail.not_deleted == [] and (.os_user | length > 0)' <<<"$rec" >/dev/null \
  || fail "the destruction record is not what was deleted: $rec"
# The audit stays a chain across it.
python3 - "$RUNS/operator-audit.jsonl" <<'PY' || fail "the audit chain broke across the purge"
import hashlib, json, sys
prev = None
for line in open(sys.argv[1], encoding="utf-8").read().splitlines():
    rec = json.loads(line)
    assert rec.get("prev") == prev, rec
    prev = hashlib.sha256(line.encode()).hexdigest()
PY
set +e
out="$(swarm purge srt1 --yes)"; rc=$?
set -e
[[ $rc -eq 0 ]] && grep -q "purged already" <<<"$out" || fail "a second purge is not said: $out"
pass "purge deletes the sandbox, this run's disks (not another's) and its hub directory, keeps the run as purged, and records what it destroyed"

echo "# a running run is not purged"
jq -n --arg sb "$RUNS/srt2" '{runs: [{id: "srt2", label: "live", state: "running", sandbox: $sb, n: 1}]}' > "$RUNS/registry.json"
mkdir -p "$RUNS/srt2"
set +e
out="$(swarm purge srt2 --yes)"; rc=$?
set -e
[[ $rc -eq 2 && -d "$RUNS/srt2" ]] || fail "a running run was purged (rc $rc): $out"
pass "a running run is refused"

echo "# the kickoff records whether the runs volume is encrypted at rest"
out="$(swarm start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off --label enc)" || fail "kickoff failed: $out"
enc="$(jq -r '.runs[] | select(.label == "enc") | .disk_encryption' "$RUNS/registry.json")"
case "$enc" in on|off|unknown) ;; *) fail "disk_encryption is '$enc'" ;; esac
grep -q '^Disk: ' <<<"$out" || fail "the kickoff does not say what it found: $out"
if [[ "$enc" == off ]]; then grep -q 'not encrypted at rest' <<<"$out" || fail "an unencrypted volume is not warned about"; fi
[[ "$(jq -r '.runs[] | select(.label == "enc") | .hold' "$RUNS/registry.json")" == null ]] || fail "a new run starts on hold"
pass "the kickoff records disk_encryption ($enc) and warns when it is off"

echo "retention.test.sh: all checks passed"
