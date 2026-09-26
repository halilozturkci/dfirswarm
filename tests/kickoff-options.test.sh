#!/usr/bin/env bash
# Kickoff options that decide whether a run may start where it is asked to:
# as root, and in a folder a sync client uploads. No model, no Herdr, no VM;
# root is a stand-in `id` on PATH.
#
# - a host run as root is refused unless --allow-root, and warned about when
#   allowed (a microVM run as root is warned about, not refused: that one is
#   in microvm-flags, which kicks VM runs off);
# - a copy of the evidence bound for a synced folder is refused, and let
#   through by --allow-synced-folder or by a .dfirswarm-allow-synced marker at
#   the synced folder's top, which the registry records as flag or marker.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/kickoff-options.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
HELLO="$ROOT/prompts/goals/hello.md"
kick() { # <runs dir> <args...>
  local runs="$1"
  shift
  SWARM_RUNS_DIR="$runs" bash "$ROOT/scripts/swarm.sh" start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --toolbox off "$@" 2>&1
}
mkdir -p "$TMP/ev"
printf 'evidence\n' > "$TMP/ev/a.txt"

echo "# root"
mkdir -p "$TMP/rootbin"
cat > "$TMP/rootbin/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-u" ]]; then echo 0; else exec /usr/bin/id "$@"; fi
EOF
chmod +x "$TMP/rootbin/id"
set +e
out="$(PATH="$TMP/rootbin:$PATH" kick "$TMP/runs" --label as-root)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'BLOCKER: a host run as root' <<<"$out" || fail "a host run as root was not refused (rc $rc): $out"
grep -q -- '--allow-root' <<<"$out" || fail "the refusal does not name --allow-root: $out"
out="$(PATH="$TMP/rootbin:$PATH" kick "$TMP/runs" --label as-root-allowed --allow-root)" || fail "--allow-root was refused: $out"
grep -q 'WARN: this run is started as root' <<<"$out" || fail "an allowed root run is not warned about: $out"
[[ "$(jq -r '.runs[] | select(.label == "as-root-allowed") | .allow_root' "$TMP/runs/registry.json")" == true ]] || fail "--allow-root is not recorded"
pass "a host run as root is refused unless --allow-root, which is recorded and warned about"

echo "# a synced folder"
mkdir -p "$TMP/Dropbox/cases"
SYNC="$(cd "$TMP/Dropbox" && pwd -P)"
set +e
out="$(kick "$SYNC/cases/runs" --inputs "$TMP/ev" --label synced)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'go into a folder a sync client uploads' <<<"$out" || fail "a copy of the evidence into a synced folder was not refused (rc $rc): $out"
grep -q '.dfirswarm-allow-synced' <<<"$out" || fail "the refusal does not name the marker: $out"
out="$(kick "$SYNC/cases/runs" --inputs "$TMP/ev" --label by-flag --allow-synced-folder)" || fail "--allow-synced-folder was refused: $out"
[[ "$(jq -r '.runs[] | select(.label == "by-flag") | .synced_folder_allowed_by' "$SYNC/cases/runs/registry.json")" == flag ]] || fail "the flag is not recorded"
# The marker at the synced folder's top lets it through, said by name.
printf 'case material may be uploaded here\n' > "$SYNC/.dfirswarm-allow-synced"
out="$(kick "$SYNC/cases/runs" --inputs "$TMP/ev" --label by-marker)" || fail "the marker did not let the run through: $out"
grep -q "WARN: going into a synced folder as the marker $SYNC/.dfirswarm-allow-synced allows" <<<"$out" || fail "the marker is not named in the WARN: $out"
[[ "$(jq -r '.runs[] | select(.label == "by-marker") | .synced_folder_allowed_by' "$SYNC/cases/runs/registry.json")" == marker ]] || fail "the marker is not recorded"
# A marker in a folder between the top and the run works too; a link does not.
rm -f "$SYNC/.dfirswarm-allow-synced"
printf 'here\n' > "$SYNC/cases/.dfirswarm-allow-synced"
out="$(kick "$SYNC/cases/runs" --inputs "$TMP/ev" --label by-inner-marker)" || fail "a marker between the top and the run was not taken: $out"
rm -f "$SYNC/cases/.dfirswarm-allow-synced"
printf 'elsewhere\n' > "$TMP/marker-elsewhere"
ln -s "$TMP/marker-elsewhere" "$SYNC/.dfirswarm-allow-synced"
set +e
out="$(kick "$SYNC/cases/runs" --inputs "$TMP/ev" --label by-link)"; rc=$?
set -e
[[ $rc -eq 2 ]] || fail "a marker that is a link let the run through (rc $rc): $out"
pass "a synced folder is refused, and let through by --allow-synced-folder or a .dfirswarm-allow-synced file (not a link), recorded as flag or marker"

echo "kickoff-options.test.sh: all checks passed"
