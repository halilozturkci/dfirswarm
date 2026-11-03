#!/usr/bin/env bash
# scripts/ci-report-failure.sh, against a fake `gh` that records its calls. No
# network, no GitHub.
#
# What must hold: a failed scheduled or main run with no open issue creates one
# (labelled, with the run's URL, the event and the failed jobs); with one it
# comments; a green run with one open closes it; a green run with none does
# nothing; a pull request, a push to another branch and a run by hand do
# nothing at all; a cancelled job is a failure and a skipped one is not.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ci-report-failure.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
S="$ROOT/scripts/ci-report-failure.sh"
[[ -f "$S" ]] || fail "scripts/ci-report-failure.sh does not exist"

mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'EOF'
#!/usr/bin/env bash
args="$*"; printf '%s\n' "${args//$'\n'/ | }" >> "$GH_LOG"
if [[ "$1 $2" == "issue list" ]]; then cat "$GH_OPEN"; fi
exit 0
EOF
chmod +x "$TMP/bin/gh"

# run <event> <ref> <needs json> <open issues json>: the script's output; the gh calls in $TMP/gh.log
run() {
  : > "$TMP/gh.log"
  printf '%s\n' "$4" > "$TMP/open.json"
  PATH="$TMP/bin:$PATH" GH_LOG="$TMP/gh.log" GH_OPEN="$TMP/open.json" EVENT_NAME="$1" REF="$2" NEEDS_JSON="$3" \
    RUN_URL="https://example.test/runs/7" WORKFLOW="CI" bash "$S" 2>&1
}
calls() { grep -v '^label create' "$TMP/gh.log" | grep -v '^issue list'; }

OK='{"select":{"result":"success"},"test":{"result":"success"},"microvm":{"result":"skipped"}}'
BAD='{"select":{"result":"success"},"test":{"result":"failure"},"microvm":{"result":"skipped"},"node-24":{"result":"cancelled"}}'
NONE='[]'
ONE='[{"number":41,"title":"CI failure: CI"},{"number":42,"title":"CI failure: image boot"}]'

out="$(run schedule refs/heads/main "$BAD" "$NONE")" || fail "a failed scheduled run: $out"
[[ "$(calls | wc -l)" == 1 ]] && calls | grep -q '^issue create --title CI failure: CI --label ci-failure --body ' || fail "no issue was created for a failure with none open: $(cat "$TMP/gh.log")"
calls | grep -q 'Run: https://example.test/runs/7' || fail "the issue does not carry the run's URL"
calls | grep -q 'Event: schedule' || fail "the issue does not carry the event"
calls | grep -q 'Failed jobs: test (failure), node-24 (cancelled)' || fail "the issue does not name the failed jobs, a cancelled one included: $(cat "$TMP/gh.log")"
calls | grep -q 'microvm\|select' && fail "the issue names a job that did not fail"
grep -q '^label create ci-failure' "$TMP/gh.log" || fail "the label was not created when missing"
pass "a failed scheduled run with no open issue creates one, labelled, with the run, the event and the failed jobs (a cancelled job too, a skipped one not)"

out="$(run push refs/heads/main "$BAD" "$ONE")" || fail "a failed main push: $out"
calls | grep -q '^issue comment 41 --body ' || fail "a failure with an open issue did not comment on it: $(cat "$TMP/gh.log")"
calls | grep -q 'issue create' && fail "a second issue was opened"
calls | grep -q 'issue comment 42' && fail "another workflow's issue was commented on"
pass "a failure with the workflow's issue open comments on it, never on another workflow's, and opens no second"

out="$(run schedule refs/heads/main "$OK" "$ONE")" || fail "a green run: $out"
calls | grep -q '^issue close 41 --comment The CI run is green again: https://example.test/runs/7' || fail "a green run did not close the open issue: $(cat "$TMP/gh.log")"
[[ "$(calls | wc -l)" == 1 ]] || fail "a green run did more than close: $(calls)"
pass "a green run closes the open issue"

out="$(run schedule refs/heads/main "$OK" "$NONE")" || fail "a green run with nothing open: $out"
[[ -z "$(calls)" ]] || fail "a green run with no open issue called gh: $(calls)"
pass "a green run with no open issue does nothing"

for case in "pull_request refs/pull/3/merge" "workflow_dispatch refs/heads/main" "push refs/heads/topic" "" ; do
  set -- $case
  out="$(run "${1:-}" "${2:-}" "$BAD" "$ONE")" || fail "a ${1:-empty} run: $out"
  [[ ! -s "$TMP/gh.log" ]] || fail "a ${1:-empty} run on ${2:-no ref} called gh: $(cat "$TMP/gh.log")"
done
pass "a pull request, a run by hand, a push to another branch and an unknown event are never reported"

echo "ci-report-failure: all checks passed"
