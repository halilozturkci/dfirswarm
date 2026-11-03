#!/usr/bin/env bash
# A failed scheduled or main run opens (or comments on) one tracking issue,
# and the next such run that is green closes it. Run by a last job of
# .github/workflows/ci.yml and .github/workflows/image-boot.yml, which are
# not required checks: this only reports.
#
#   NEEDS_JSON         the jobs' results (toJSON(needs)): {"job": {"result": "success|failure|cancelled|skipped"}, ...}
#   EVENT_NAME         github.event_name
#   REF                github.ref
#   RUN_URL            the run's URL
#   WORKFLOW           the workflow's name
#   GH_TOKEN, GH_REPO  for gh (issues: write)
#
# Only a schedule or a push to main is reported; a pull request, a run by hand
# and anything else do nothing. A job counts as failed when its result is
# `failure` or `cancelled`; `skipped` and `success` do not. The issue carries
# the run's URL, the event and the names of the failed jobs, and nothing else.
# One open issue per workflow, found by the label `ci-failure` and the title.
set -euo pipefail

event="${EVENT_NAME:-}"
case "$event" in
  schedule) ;;
  push) [[ "${REF:-}" == refs/heads/main ]] || { echo "ci-report-failure: a push to ${REF:-?}, not main: nothing to report"; exit 0; } ;;
  *) echo "ci-report-failure: a ${event:-?} run is not reported"; exit 0 ;;
esac
: "${NEEDS_JSON:?NEEDS_JSON is the results of the jobs}" "${WORKFLOW:?WORKFLOW is the name of the workflow}" "${RUN_URL:?RUN_URL is the URL of the run}"

failed="$(jq -r 'to_entries | map(select(.value.result == "failure" or .value.result == "cancelled")) | map("\(.key) (\(.value.result))") | join(", ")' <<<"$NEEDS_JSON")"
label="ci-failure"
title="CI failure: $WORKFLOW"

gh label create "$label" --description "A scheduled or main run failed" --color B60205 >/dev/null 2>&1 || true
number="$(gh issue list --label "$label" --state open --json number,title | jq -r --arg t "$title" '[.[] | select(.title == $t)] | .[0].number // empty')"

if [[ -n "$failed" ]]; then
  body="The $WORKFLOW run failed.

- Run: $RUN_URL
- Event: $event
- Failed jobs: $failed"
  if [[ -n "$number" ]]; then
    gh issue comment "$number" --body "$body"
    echo "ci-report-failure: commented on #$number"
  else
    gh issue create --title "$title" --label "$label" --body "$body"
    echo "ci-report-failure: opened an issue"
  fi
elif [[ -n "$number" ]]; then
  gh issue close "$number" --comment "The $WORKFLOW run is green again: $RUN_URL"
  echo "ci-report-failure: closed #$number"
else
  echo "ci-report-failure: green, and no open issue"
fi
