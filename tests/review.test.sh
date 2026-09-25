#!/usr/bin/env bash
# The examiner's review of a ledger (swarm.sh review, scripts/review.ts) and
# an earlier run's claims brought into a new run as hypotheses
# (--ledger-from). No model, no Herdr, no VM.
#
# - accept, reject and amend name an entry by seq and keep its hash; reject
#   and amend need a note; the sign-off is over the ledger's head and is
#   refused while the run is running;
# - the review is a chain beside the registry: a line changed breaks it;
# - --ledger-from brings only the accepted (or amended) entries when there
#   is a review, every entry marked unreviewed when there is none, read-only,
#   never into the new ledger, and says so in SWARM.md; it refuses a run that
#   is still running, or held for another case.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/review-test.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
RUNS="$TMP/runs"
export SWARM_RUNS_DIR="$RUNS"
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
HELLO="$ROOT/prompts/goals/hello.md"
kick() { swarm start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --toolbox off "$@"; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }

# An earlier run, ended, with three chained entries.
OLD="$RUNS/srv1"
mkdir -p "$OLD/ledger"
cat > "$OLD/ledger/entries.jsonl" <<'EOF'
{"v":2,"seq":1,"kind":"event","ts":"2024-01-15T12:44:22Z","value":"Admin logon from 10.0.0.5","source":"Security.evtx 4624","evidence":"record 8812","confidence":"high","by":"srv100","authors":["srv100"],"at":"t","prev":"genesis","hash":"a1"}
{"v":2,"seq":2,"kind":"ioc","value":"evil.example.test","source":"hosts file","evidence":"line 3","by":"srv100","authors":["srv100"],"at":"t","prev":"a1","hash":"a2"}
{"v":2,"seq":3,"kind":"finding","value":"Persistence by a scheduled task\nnamed Updater","source":"Tasks","evidence":"XML","by":"srv100","authors":["srv100"],"at":"t","prev":"a2","hash":"a3"}
EOF
jq -n --arg sb "$OLD" '{runs: [{id: "srv1", label: "old", state: "running", sandbox: $sb, n: 1, case_id: "CASE-1", examiner: "Run Examiner"}]}' > "$RUNS/registry.json"

echo "# accept, reject, amend; the sign-off waits for the run to end"
out="$(swarm review srv1 --accept 1 --examiner "H. Examiner")" || fail "accept failed: $out"
set +e
out="$(swarm review srv1 --reject 2 --examiner "H. Examiner")"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'needs a note' <<<"$out" || fail "a reject with no note was taken (rc $rc): $out"
out="$(swarm review srv1 --reject 2 --note "the hosts file is the analyst's own" --examiner "H. Examiner")" || fail "reject failed: $out"
out="$(swarm review srv1 --amend 3 --note "the task is named Updater2" --examiner "H. Examiner")" || fail "amend failed: $out"
set +e
out="$(swarm review srv1 --accept 9 --examiner "H. Examiner")"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'no ledger entry 9' <<<"$out" || fail "an entry that does not exist was reviewed (rc $rc): $out"
set +e
out="$(swarm review srv1 --sign --examiner "H. Examiner")"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'still running' <<<"$out" || fail "a running run's ledger was signed off (rc $rc): $out"
jq '.runs[0].state = "done"' "$RUNS/registry.json" > "$TMP/r" && mv "$TMP/r" "$RUNS/registry.json"
out="$(swarm review srv1 --sign)" || fail "the sign-off (examiner from the run's record) failed: $out"
grep -q 'by Run Examiner' <<<"$out" || fail "the run's recorded examiner was not used: $out"
F="$RUNS/reviews/srv1.jsonl"
[[ "$(wc -l < "$F" | tr -d ' ')" == 4 ]] || fail "the review holds $(wc -l < "$F") lines, wanted 4"
mode="$(stat -c %a "$F" 2>/dev/null || stat -f %Lp "$F")"
[[ "$mode" == 600 ]] || fail "the review is mode $mode"
jq -s -e '.[0].action == "accept" and .[0].entry_hash == "a1" and .[1].note == "the hosts file is the analyst'"'"'s own"
  and .[3].action == "sign" and .[3].ledger_head == "a3" and .[3].ledger_entries == 3 and .[0].prev == null and (.[1].prev | length == 64)' "$F" >/dev/null \
  || fail "the review lines are not what was done: $(cat "$F")"
out="$(swarm review srv1 --show)" || fail "show failed: $out"
grep -q 'the chain verifies' <<<"$out" && grep -q 'over ledger head a3' <<<"$out" || fail "show does not say what was reviewed: $out"
grep -q '"command":"review"' "$RUNS/operator-audit.jsonl" || fail "the review is not on the operator's audit"
pass "accept, reject and amend name the entry and its hash, a reject needs a note, and the sign-off is over the ledger's head once the run has ended"

echo "# a review line changed breaks the chain, and nothing is added to it"
cp "$F" "$TMP/review.bak"
sed -i.bak 's/"accept"/"reject"/' "$F" && rm -f "$F.bak"
set +e
out="$(swarm review srv1 --show)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'BROKEN' <<<"$out" || fail "a changed review line was not caught (rc $rc): $out"
set +e
out="$(swarm review srv1 --accept 2 --examiner x)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'broken' <<<"$out" || fail "an act was added to a broken review (rc $rc): $out"
cp "$TMP/review.bak" "$F"
pass "the review is a chain: an edited line is BROKEN and nothing is added to it"

echo "# --ledger-from: the accepted and amended entries, as hypotheses"
out="$(kick --label new --ledger-from srv1 --case-id CASE-1)" || fail "a kickoff with --ledger-from failed: $out"
sb="$(sandbox_of "$out")"
P="$sb/prior/ledger.md"
[[ -f "$P" ]] || fail "no prior/ledger.md"
grep -q '## srv1#1 · event · accepted by the examiner' "$P" || fail "the accepted entry is not there: $(cat "$P")"
grep -q '## srv1#3 · finding · amended by the examiner' "$P" && grep -q "the task is named Updater2" "$P" || fail "the amended entry or its note is not there"
grep -q 'srv1#2' "$P" && fail "a rejected entry was brought in"
grep -q 'Entry hash: `a1`' "$P" || fail "an entry's hash is not given"
grep -q 'named Updater' "$P" || fail "a multi-line claim was cut"
has_write() { python3 -c 'import os, sys; sys.exit(0 if os.stat(sys.argv[1]).st_mode & 0o222 else 1)' "$1"; }
has_write "$P" && fail "prior/ledger.md is writable"
has_write "$sb/prior" && fail "prior/ is writable"
[[ ! -s "$sb/ledger/entries.jsonl" ]] || fail "the prior entries went into the new ledger"
grep -q "An earlier run's claims (prior/ledger.md)" "$sb/SWARM.md" && grep -q 'the ones its examiner accepted' "$sb/SWARM.md" || fail "SWARM.md does not say what prior/ledger.md is"
jq -e --arg sb "$sb" '.runs[] | select(.sandbox == $sb) | .ledger_from | .run == "srv1" and .entries == 2 and .reviewed == true and (.ledger_sha256 | length == 64)' "$RUNS/registry.json" >/dev/null \
  || fail "the registry does not record what was brought in"
pass "--ledger-from brings the accepted and amended entries, read-only, out of the new ledger, and SWARM.md says what they are"

echo "# without a review, every entry, marked unreviewed"
mv "$F" "$TMP/review.saved"
out="$(kick --label unreviewed --ledger-from srv1 --case-id CASE-1)" || fail "kickoff failed: $out"
sb="$(sandbox_of "$out")"
[[ "$(grep -c '^## srv1#' "$sb/prior/ledger.md")" == 3 ]] || fail "not every entry was brought in: $(cat "$sb/prior/ledger.md")"
grep -q 'unreviewed' "$sb/prior/ledger.md" && grep -q 'unreviewed: no examiner has accepted any of them' "$sb/SWARM.md" || fail "the entries are not marked unreviewed"
mv "$TMP/review.saved" "$F"
pass "without a review every entry comes, marked unreviewed"

echo "# refused: a run still running, one held for another case, one that does not exist"
jq '.runs[0].state = "running"' "$RUNS/registry.json" > "$TMP/r" && mv "$TMP/r" "$RUNS/registry.json"
set +e
out="$(kick --label r1 --ledger-from srv1)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'still running' <<<"$out" || fail "a running run's ledger was brought in (rc $rc): $out"
jq '(.runs[] | select(.id == "srv1")) |= (.state = "done" | .hold = {reason: "matter", at: "t", by: "x"})' "$RUNS/registry.json" > "$TMP/r" && mv "$TMP/r" "$RUNS/registry.json"
set +e
out="$(kick --label r2 --ledger-from srv1 --case-id CASE-2)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'on hold for case CASE-1' <<<"$out" || fail "a run held for another case lent its claims (rc $rc): $out"
out="$(kick --label r3 --ledger-from srv1 --case-id CASE-1)" || fail "the same case was refused: $out"
set +e
out="$(kick --label r4 --ledger-from snosuch)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'no such run' <<<"$out" || fail "a run that does not exist was not refused (rc $rc): $out"
pass "--ledger-from refuses a running run, a run held for another case, and a run that does not exist"

echo "# a FIFO or a link in the review's place is refused by name, never read or waited on"
F="$RUNS/reviews/srv1.jsonl"
cp "$F" "$TMP/review.keep"
rm -f "$F"
mkfifo "$F"
started=$SECONDS
set +e
out="$(swarm review srv1 --show)"; rc=$?
set -e
(( SECONDS - started < 10 )) || fail "a FIFO in the review's place hung the read"
[[ $rc -ne 0 ]] && grep -q 'is not a regular file; it is not read' <<<"$out" || fail "a FIFO was not refused by name (rc $rc): $out"
set +e
out="$(swarm review srv1 --accept 1 --examiner x)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'not a regular file' <<<"$out" || fail "an act was written through a FIFO (rc $rc): $out"
rm -f "$F"
printf 'elsewhere\n' > "$TMP/elsewhere.jsonl"
ln -s "$TMP/elsewhere.jsonl" "$F"
set +e
out="$(swarm review srv1 --accept 1 --examiner x)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'a link' <<<"$out" || fail "an act was written through a link (rc $rc): $out"
[[ "$(cat "$TMP/elsewhere.jsonl")" == elsewhere ]] || fail "the link's target was written"
rm -f "$F"
cp "$TMP/review.keep" "$F"
pass "a FIFO or a link in the review's place is refused by name; nothing is read through it, waited on or written through it"

echo "review.test.sh: all checks passed"
