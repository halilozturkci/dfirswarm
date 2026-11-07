#!/usr/bin/env bash
# swarm.sh resume (docs/adr/0013): a stopped run goes on in the same sandbox,
# on the same chains. Refused while the run is going, and for a run whose
# start options were not kept (given after -- instead); the stop moved aside
# whole; the question asked for the continuation admitted as an analyst's;
# each seat's hand-off put where it starts; the resume on the operator's
# record, the registry and the custody anchor; the next stop seals a new
# verdict and a new draft, and custody-verify holds the first seal as a
# prefix of the run now. No model, no VM; Herdr is never started (--no-start).
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Short, for the collector's socket path: a trace no collector chained is
# not the run this test continues.
TMP="$(mktemp -d /tmp/rsm.XXXXXX)"
LIVE=()
trap 'for p in ${LIVE[@]+"${LIVE[@]}"}; do kill "$p" 2>/dev/null || true; done; chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
HELLO="$ROOT/prompts/goals/hello.md"
export SWARM_RUNS_DIR="$TMP/runs" DFIRSWARM_HOME="$TMP/home" SWARM_SIGNERS_HOME="$TMP/home"
mkdir -p "$DFIRSWARM_HOME"
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
kick() { swarm start --model solo/model --n 2 --no-start --goal-file "$HELLO" --toolbox off "$@"; }
sandbox_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .sandbox' "$TMP/runs/registry.json"; }
id_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .id' "$TMP/runs/registry.json"; }
state_of() { jq -r --arg id "$1" '.runs[] | select(.id == $id) | .state' "$TMP/runs/registry.json"; }
set_state() { local t; t="$(mktemp)"; jq --arg id "$1" --arg s "$2" '(.runs[] | select(.id == $id) | .state) = $s' "$TMP/runs/registry.json" > "$t" && mv "$t" "$TMP/runs/registry.json"; }

# A stop finds a run with nothing alive and records it as ended (cause unknown), not stopped.
# These runs are not started (--no-start), so a stand-in collector gives the stop something
# alive to stop; the stop ends it.
alive() { # <sandbox>
  bash -c 'exec -a "trace-collector.mjs $0" sleep 300' "$1" >/dev/null 2>&1 &
  LIVE+=("$!"); printf '%s
' "$!" > "$1/collector.pid"
}

echo "# the kickoff keeps its options for a resume"
out="$(kick --cap-usd 5 --wall-clock 30 --label r1)" || fail "the kickoff was refused: $out"
id="$(id_of r1)"; sb="$(sandbox_of r1)"
argv="$TMP/runs/resume/$id.argv.json"
[[ -f "$argv" ]] || fail "the start options were not kept"
[[ "$(stat -c %a "$argv" 2>/dev/null || stat -f %Lp "$argv")" == 600 ]] || fail "the kept options are not 0600"
jq -e '.argv | index("--cap-usd") != null and index("--label") != null' "$argv" >/dev/null || fail "the kept options are not the kickoff's: $(cat "$argv")"
pass "the kickoff keeps its start options outside the run, 0600"

echo "# refused while the run is going, or never started"
set +e
out="$(swarm resume "$id" --no-start)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'is prepared and never started: there is nothing to continue' <<<"$out" || fail "a prepared run was resumed (rc $rc): $out"
set_state "$id" running
set +e
out="$(swarm resume "$id" --no-start)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q "a resume continues a run that has ended. A running or paused one is given more with swarm.sh extend $id" <<<"$out" || fail "a running run was resumed (rc $rc): $out"
pass "a running run is extended, not resumed; a prepared one is refused"

echo "# the stop, then the resume"
# A seat's hand-off note, as self-compaction writes it into its Pi session.
a0="$(jq -r '.agents[0].id' "$sb/team.json")"; a1="$(jq -r '.agents[1].id' "$sb/team.json")"
mkdir -p "$sb/.pi-sessions/$a0"
note="name $a0, slice: the logs; NEXT ACTION: read from line 5000; $(printf 'x%.0s' $(seq 1 3000))"
jq -nc --arg n "$note" '{type: "custom_message", id: "h1", parentId: null, timestamp: "2026-09-28T10:00:00.000Z", customType: "self-compact-handoff", content: "", details: {note: $n}, display: true}' > "$sb/.pi-sessions/$a0/s.jsonl"
alive "$sb"
out="$(swarm stop "$id")" || fail "stop failed: $out"
[[ "$(state_of "$id")" == stopped && -f "$sb/done/STOPPED" && -f "$sb/custody.json" ]] || fail "the stop did not end the run as stopped with a verdict: $out"
first_at="$(jq -r '.at' "$sb/custody.json")"
[[ -f "$sb/release/v0/release.json" ]] || fail "the stop wrote no draft: $out"
out="$(swarm resume "$id" --no-start --question "Was the host reached again after the first day?" --minutes 10)" || fail "the resume was refused: $out"
grep -q "^Resume:       run $id, which stopped, goes on; segment 1" <<<"$out" || fail "the resume does not say what goes on: $out"
grep -q "^Hand-off:     $a0 starts from its last hand-off note" <<<"$out" || fail "the hand-off is not named: $out"
grep -q "^Hand-off:     $a1 starts from the registers (it left no note)" <<<"$out" || fail "a seat with no note is not named: $out"
grep -q '^Question:     Q-[0-9]* (in_scope)' <<<"$out" || fail "the continuation's question was not admitted: $out"
grep -q "^Resume:       run $id goes on in $sb, on its own chains (nothing cleared)" <<<"$out" || fail "the start does not say it continues: $out"
[[ -f "$sb/done/history/1/STOPPED" && ! -f "$sb/done/STOPPED" ]] || fail "the stop was not moved aside whole"
grep -qF "$note" "$sb/inbox/$a0/resume.md" || fail "the hand-off note is not in the seat's resume file, whole"
[[ -f "$sb/ledger/entries.jsonl" || -d "$sb/ledger" ]] || fail "the ledger went"
jq -e '(.resumes | length) == 1 and .resumes[0].from == "stopped" and (.wall_clock_minutes == 40)' "$sb/budget.json" >/dev/null || fail "the budget does not hold the resume: $(jq -c '{resumes, wall_clock_minutes}' "$sb/budget.json")"
jq -e --arg id "$id" '.runs[] | select(.id == $id) | (.resumes | length) == 1 and .resumes[0].from == "stopped" and .state == "prepared"' "$TMP/runs/registry.json" >/dev/null || fail "the registry does not hold the resume"
jq -e '(.resumes | length) == 1 and .resumes[0].by == "operator" and .resumes[0].segment == 1' "$sb.custody-anchor.json" >/dev/null || fail "the resume is not anchored beside the run: $(jq -c '.resumes' "$sb.custody-anchor.json")"
grep -q '"command":"resume_prepared"' "$TMP/runs/operator-audit.jsonl" || fail "the resume is not on the operator's record"
resumed="$(grep '"tool":"run_resumed"' "$sb/traces/events.jsonl" | tail -n 1 || true)"
[[ -n "$resumed" ]] || fail "the resume is not on the run's trace as run_resumed"
jq -e '.agent == "system" and .args.from == "stopped" and .args.segment == 1' <<<"$resumed" >/dev/null || fail "run_resumed does not say what it resumed from and the segment: $resumed"
grep -q '"origin":{"kind":"analyst"' "$sb/questions/questions.jsonl" || fail "the continuation's question is not an analyst's"
if grep -q '"after_done"' "$sb/questions/questions.jsonl"; then fail "the continuation's question was taken as a follow-up of an ended run"; fi
pass "the resume: the stop moved aside, the question admitted, the hand-offs placed, on the budget, the registry, the anchor and the operator's record"

echo "# a prepared resume is started as prepared, not prepared twice"
set +e
out="$(swarm resume "$id" --no-start --minutes 5)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'its caps are changed with swarm.sh caps' <<<"$out" || fail "a second prepare with caps was not refused (rc $rc): $out"
out="$(swarm resume "$id" --no-start)" || fail "the prepared resume was not started: $out"
grep -q 'was prepared for its resume already' <<<"$out" || fail "the prepared resume does not say so: $out"
jq -e '(.resumes | length) == 1' "$sb/budget.json" >/dev/null || fail "the resume was recorded twice"
jq -e --arg id "$id" '.runs[] | select(.id == $id) | (.resumes | length) == 1' "$TMP/runs/registry.json" >/dev/null || fail "the registry holds the resume twice"
pass "a prepared resume starts as prepared"

echo "# the next stop seals the continuation; the first seal holds as a prefix"
out="$(swarm stop "$id")" || fail "the second stop failed: $out"
[[ "$(jq -r '.at' "$sb/custody.json")" != "$first_at" ]] || fail "the second stop took no new verdict"
[[ -f "$sb/release/v1/release.json" ]] || fail "the second stop wrote no new draft: $out"
out="$(swarm custody-verify "$id")" || fail "custody-verify failed after the resume: $out"
grep -q "^Earlier seal: $first_at ([0-9a-f]*), before a resume: holds as a prefix: the trace" <<<"$out" || fail "custody-verify does not show the earlier seal: $out"
out="$(swarm releases "$id" --verify)" || fail "the releases do not verify after the resume: $out"
grep -q '^Release v0:.*binds an earlier custody verdict' <<<"$out" || fail "v0 is not verified as an earlier seal: $out"
pass "custody-verify shows both seals, and both drafts verify"

echo "# a run started before its options were kept"
out="$(kick --cap-usd 5 --label r2)" || fail "the second kickoff was refused: $out"
id2="$(id_of r2)"
set_state "$id2" running
swarm stop "$id2" --no-custody >/dev/null || fail "the second run's stop failed"
rm -f "$TMP/runs/resume/$id2.argv.json"
set +e
out="$(swarm resume "$id2" --no-start)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'was started before its start options were kept for a resume. Give them after --' <<<"$out" || fail "a resume with no kept options was not refused (rc $rc): $out"
[[ -f "$(sandbox_of r2)/done/STOPPED" ]] || fail "a refused resume moved the stop"
out="$(swarm resume "$id2" --no-start -- --model solo/model --n 2 --goal-file "$HELLO" --toolbox off --cap-usd 5 --label r2)" || fail "a resume with its options given was refused: $out"
[[ -f "$(sandbox_of r2)/done/history/1/STOPPED" ]] || fail "the given options' resume did not move the stop"
set_state "$id2" stopped
set +e
out="$(swarm resume "$id2" --no-start -- --model solo/model --n 3 --goal-file "$HELLO" --toolbox off --cap-usd 5)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'a resume continues the same seats (give --n 2)' <<<"$out" || fail "a resume with other seats was not refused (rc $rc): $out"
pass "a run with no kept options is resumed with them given after --, and with the same seats only"

echo "# a question the register would refuse refuses the resume before anything moves"
out="$(kick --cap-usd 5 --label r5)" || fail "the fifth kickoff was refused: $out"
id5="$(id_of r5)"; sb5="$(sandbox_of r5)"
set_state "$id5" running
swarm stop "$id5" --no-custody >/dev/null || fail "the fifth run's stop failed"
set +e
out="$(swarm resume "$id5" --no-start --question "Was the host reached again after the first day?" --as operator)"; rc=$?
set -e
[[ $rc -eq 2 ]] || fail "a resume whose question cannot be admitted was not refused (rc $rc): $out"
grep -q 'BLOCKER: the question "Was the host reached again after the first day?" cannot be admitted: --as operator: no one is enrolled on this install under operator' <<<"$out" || fail "the refusal does not name the question and why: $out"
grep -q 'Nothing was changed' <<<"$out" && grep -q -- '--skip-refused-questions' <<<"$out" || fail "the refusal does not say nothing moved and how to go on without it: $out"
[[ -f "$sb5/done/STOPPED" && ! -d "$sb5/done/history" ]] || fail "a refused resume moved the stop"
jq -e '(.resumes // []) | length == 0' "$sb5/budget.json" >/dev/null || fail "a refused resume was recorded in the budget"
out="$(swarm resume "$id5" --no-start --question "Was the host reached again after the first day?" --as operator --skip-refused-questions)" || fail "a resume told to go on without the refused question was refused: $out"
grep -q 'WARN: the question "Was the host reached again after the first day?" cannot be admitted (--as operator: no one is enrolled' <<<"$out" || fail "the question left out is not said: $out"
[[ -f "$sb5/done/history/1/STOPPED" ]] || fail "the resume with --skip-refused-questions did not go on"
grep -q 'Was the host reached again' "$sb5/questions/questions.jsonl" 2>/dev/null && fail "the refused question was admitted after all"
pass "a question the register would refuse refuses the resume before anything moves, naming why; --skip-refused-questions goes on without it, and says so"

echo "# the start options kept for a resume hold no secret a pane could read"
# A typed target's delivery (an ntfy push) goes to a stand-in curl, never out.
mkdir -p "$TMP/fake-bin"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s/curl.got"\n' "$TMP" > "$TMP/fake-bin/curl"
chmod +x "$TMP/fake-bin/curl"
export PATH="$TMP/fake-bin:$PATH"
out="$(kick --cap-usd 5 --label r3 --no-write-guard --accept-signer-exposure --env CASE_HINT=s3cr3t-value-77 --notify "cat > /dev/null" --notify ntfy:dfs-resume-topic)" || fail "the unguarded kickoff was refused: $out"
id3="$(id_of r3)"
kept="$TMP/runs/resume/$id3.argv.json"
if grep -q 's3cr3t-value-77' "$kept"; then fail "an --env value the panes could read was kept: $(cat "$kept")"; fi
if grep -q 'cat > /dev/null' "$kept"; then fail "the notify command was kept with the start options: $(cat "$kept")"; fi
if grep -q 'dfs-resume-topic' "$kept"; then fail "a notify target (an ntfy topic is its secret) was kept with the start options: $(cat "$kept")"; fi
jq -e '.dropped_env == ["CASE_HINT"] and .notify == true and (.argv | index("--env") == null)' "$kept" >/dev/null || fail "the kept options do not say what was left out: $(cat "$kept")"
[[ -f "$TMP/runs/notify/$id3.cmd" ]] || fail "the notify command is not in its own store"
grep -qx 'ntfy:dfs-resume-topic' "$TMP/runs/notify/$id3.targets" || fail "the notify target is not in its own store"
set_state "$id3" running
swarm stop "$id3" --no-custody >/dev/null || fail "the third run's stop failed"
set +e
out="$(swarm resume "$id3" --no-start)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q "started with --env CASE_HINT, whose value was not kept" <<<"$out" || fail "a resume without the value not kept was not refused (rc $rc): $out"
[[ -f "$(sandbox_of r3)/done/STOPPED" ]] || fail "a refused resume moved the stop"
out="$(swarm resume "$id3" --no-start --env CASE_HINT=s3cr3t-value-77)" || fail "a resume with the value given again was refused: $out"
jq -e --arg id "$id3" '.runs[] | select(.id == $id) | .notify == true' "$TMP/runs/registry.json" >/dev/null || fail "the resumed run lost its notify command"
grep -qx 'cat > /dev/null' "$TMP/runs/notify/$id3.cmd" && grep -qx 'ntfy:dfs-resume-topic' "$TMP/runs/notify/$id3.targets" || fail "the resumed run's notify store is not as it was: $(cat "$TMP/runs/notify/$id3.cmd" "$TMP/runs/notify/$id3.targets" 2>&1)"
grep -q 'told of the same events, by ids only' <<<"$out" || fail "the resume's kickoff does not say its typed targets are told: $out"
if grep -rq 'dfs-resume-topic' "$TMP/runs/registry.json" "$TMP/runs/operator-audit.jsonl" "$(sandbox_of r3)" 2>/dev/null; then fail "the ntfy topic reached the registry, the operator's record or the run"; fi
if grep -q 's3cr3t-value-77' "$TMP/runs/operator-audit.jsonl"; then fail "the operator's record holds the --env value"; fi
# Where the guard can deny the stores, they are denied, and the value is kept.
out="$(kick --cap-usd 5 --label r4 --env CASE_HINT=s3cr3t-value-88)" || fail "the guarded kickoff was refused: $out"
id4="$(id_of r4)"
if [[ "$(jq -r --arg id "$id4" '.runs[] | select(.id == $id) | .earlier_runs_hidden.by // empty' "$TMP/runs/registry.json")" != "" ]]; then
  jq -e --arg id "$id4" '.runs[] | select(.id == $id) | .earlier_runs_hidden.stores == ["resume", "notify"]' "$TMP/runs/registry.json" >/dev/null || fail "the stores are not recorded as denied to the panes"
  plan="$(cat "$(sandbox_of r4)/.fsguard/plan.txt")"
  grep -qxF "no-read: $(cd "$TMP/runs/resume" && pwd -P)" <<<"$plan" && grep -qxF "no-read: $(cd "$TMP/runs/notify" && pwd -P)" <<<"$plan" || fail "the pane plan does not deny the stores: $plan"
  jq -e '.dropped_env == []' "$TMP/runs/resume/$id4.argv.json" >/dev/null && grep -q 's3cr3t-value-88' "$TMP/runs/resume/$id4.argv.json" || fail "a value no pane can read was not kept"
else
  jq -e '.dropped_env == ["CASE_HINT"]' "$TMP/runs/resume/$id4.argv.json" >/dev/null || fail "a value the panes could read was kept"
fi
pass "the kept start options hold no secret a pane could read: --env values given again, the notify command and targets from their own store, the stores denied where the guard can"
