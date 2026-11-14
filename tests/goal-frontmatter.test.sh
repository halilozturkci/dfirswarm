#!/usr/bin/env bash
# A library entry opens with a metadata block between two `---` lines: the
# picker's title, summary and suggestions. The contract starts after it. The
# console strips the block before it sends the text; a file launched from the
# CLI (`--goal-file library/<category>/<slug>.md`) has to be stripped by
# swarm.sh the same way, in the contract and in the registry the checks are
# read from. A goal with no block is left exactly as written.
set -euo pipefail
# This suite tests host runs, and a run is in microVMs unless it says
# otherwise: it names host. An image, a lock file or another pack home
# exported in the shell would point its kickoffs somewhere else.
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/goal-frontmatter.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
swarm() { SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }

entry="$ROOT/library/windows/host-intrusion.md"
[[ -f "$entry" ]] || fail "the library entry this test launches is missing: $entry"
head -n 1 "$entry" | grep -qx -- '---' || fail "the entry does not open with a metadata block"

out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$entry" --label fromlib)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -f "$sb/SWARM.md" ]] || fail "no sandbox or no contract: $out"
grep -q '^## Goal' "$sb/SWARM.md" || fail "the contract lost the goal"
grep -q '^## Definition of done' "$sb/SWARM.md" || fail "the contract lost the definition of done"
grep -qE '^(title|summary|cap_usd|wall_clock|seats): ' "$sb/SWARM.md" && fail "the metadata block leaked into the contract"
grep -qx -- '---' "$sb/SWARM.md" && fail "a --- line from the metadata block is in the contract"
reg_goal="$(jq -r '.runs[] | select(.label == "fromlib") | .goal' "$TMP/runs/registry.json")"
[[ "$reg_goal" == "## Goal"* ]] || fail "the registry's goal (what the checks are read from) does not start at ## Goal: $(printf '%s' "$reg_goal" | head -c 60)"
echo "ok - a library entry launched from the CLI is stripped of its metadata block, in the contract and in the registry"

# The whole contract still carries the entry's own checks, counted the way await-done.sh counts them.
n_entry="$(sed -n '/^## Checks$/,$p' "$entry" | grep -c '^- `')"
n_contract="$(sed -n '/^## Checks$/,/^## /p' "$sb/SWARM.md" | grep -c '^- `')"
[[ "$n_contract" -eq "$n_entry" ]] || fail "the contract carries $n_contract checks, the entry $n_entry"
echo "ok - the entry's $n_entry checks are in the contract"

# A goal with no block is untouched: hello.md is the reference.
out2="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --label plain)"
sb2="$(sandbox_of "$out2")"
grep -q 'work/hello.txt' "$sb2/SWARM.md" || fail "a plain goal was damaged"
echo "ok - a goal without a metadata block is left as written"

# A block that never closes is not a block: the text is taken as it is, and
# the definition-of-done gate is what refuses it.
printf -- '---\ntitle: never closed\n## Goal\n\nx\n' > "$TMP/open.md"
if swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/open.md" --label open >/dev/null; then
  fail "a goal with an unclosed block and no definition of done was accepted"
fi
echo "ok - an unclosed block is not stripped and the goal is refused for what it lacks"

# A goal with a case brief and no premises designated is warned about at the
# kickoff and in start --check (c10 run sd9645b: 4 of its 10 open parts were
# givens of the brief, held open as parts to prove). A warning, never a
# refusal: the start goes ahead. Designated in the front matter (premises:)
# or in a Premises section, it is not warned about.
brief_goal() { # <file> <front matter lines, or empty> <extra body>
  { if [[ -n "$2" ]]; then printf -- '---\n%s\n---\n' "$2"; fi
    printf '## Goal\n\nMax is suspected of meeting an unknown party. `inputs/CASE.md` is the published brief.\n\n%s\n### Questions the report has to answer\n\n1. Where are they meeting?\n\n## Definition of done\n\n`work/report.md` exists.\n\n## Checks\n\n- `test -f work/report.md`\n' "$3"; } > "$1"
}
check() { SWARM_RUNS_DIR="$TMP/check-runs" bash "$ROOT/scripts/swarm.sh" start --check --isolation host --model solo/model --provider-host solo=api.solo.example --n 2 --cap-usd 1 --toolbox off --no-start "$@" 2>&1; }
WARNED='WARN: the goal has a case brief'

brief_goal "$TMP/brief.md" "" ""
out="$(check --goal-file "$TMP/brief.md")" || fail "a goal with a brief and no premises was refused by --check: $out"
grep -q "^$WARNED (it names one, \"published brief\") and designates no premises" <<<"$out" || fail "--check does not warn of a brief without premises: $out"
grep -q 'premises: list in the goal.s front matter' <<<"$out" || fail "the warning does not say how to designate them in the front matter: $out"
grep -q 'swarm.sh question <run> premise add --text' <<<"$out" || fail "the warning does not say how to designate them on a run: $out"
grep -q '^Check:        the start would go ahead' <<<"$out" || fail "the warning held the start: $out"
[[ ! -e "$TMP/check-runs" ]] || fail "--check wrote under the runs directory"
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/brief.md" --label briefnoprem)"
grep -q "^$WARNED" <<<"$out" || fail "the kickoff does not warn of a brief without premises: $out"
[[ -n "$(sandbox_of "$out")" ]] || fail "the kickoff with the warning did not prepare the run: $out"
echo "ok - a brief without premises is warned about by the kickoff and by start --check, with how to designate them, and nothing is refused"

brief_goal "$TMP/brief-premised.md" $'premises:\n  - inputs/Case4.E01 is an image of Max\'s machine; this is the only system he uses. [scope: entities Max]' ""
out="$(check --goal-file "$TMP/brief-premised.md")" || fail "--check refused a goal with premises: $out"
grep -q "$WARNED" <<<"$out" && fail "a goal whose front matter designates premises was warned about: $out"
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/brief-premised.md" --label briefprem)"
grep -q "$WARNED" <<<"$out" && fail "the kickoff warned of a goal with premises: $out"
sb3="$(sandbox_of "$out")"
grep -q "^- inputs/Case4.E01 is an image of Max's machine; this is the only system he uses. \[scope: entities Max\]" "$sb3/SWARM.md" || fail "the front matter's premise is not in the contract's Premises section"
echo "ok - premises: in the front matter designate the brief's givens: no warning, and each is in the contract"

brief_goal "$TMP/brief-section.md" "" $'## Premises\n\n- Max uses only this system. [scope: entities Max]\n'
out="$(check --goal-file "$TMP/brief-section.md")"
grep -q "$WARNED" <<<"$out" && fail "a goal with a Premises section was warned about: $out"
printf '## Goal\n\nA case.\n\n## Scenario\n\nThe laptop was found in a car.\n\n## Premises\n\n## Definition of done\n\nx\n\n## Checks\n\n- `true`\n' > "$TMP/scenario.md"
out="$(check --goal-file "$TMP/scenario.md")"
grep -q "^$WARNED (its section \"Scenario\")" <<<"$out" || fail "a Scenario section with an empty Premises section was not warned about: $out"
out="$(check --goal-file "$ROOT/prompts/goals/hello.md")"
grep -q "$WARNED" <<<"$out" && fail "a goal with no brief was warned about: $out"
echo "ok - a Premises section designates them too; an empty one does not; a scenario heading is a brief; a goal with no brief is not warned about"

# What a question presumes (docs/adr/0011, "What a question presumes"): the
# front matter's presumes: list is carried into a Presumptions section, and
# the question register seeds each on the question it names.
printf -- '---\npresumes:\n  - 1: The drive was connected to the workstation.\n---\n## Goal\n\nA case.\n\n### Questions the report has to answer\n\n1. When was the drive first connected?\n\n## Premises\n\n- The drive is the company%ss. [scope: entities the drive]\n\n## Definition of done\n\n`work/report.md` exists.\n\n## Checks\n\n- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1`\n' "'" > "$TMP/presumed.md"
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/presumed.md" --label presumed)"
sb4="$(sandbox_of "$out")"
[[ -n "$sb4" && -f "$sb4/SWARM.md" ]] || fail "no sandbox for the presumed goal: $out"
grep -q '^## Presumptions$' "$sb4/SWARM.md" || fail "the front matter's presumes is not in a Presumptions section of the contract"
grep -q '^- 1: The drive was connected to the workstation\.$' "$sb4/SWARM.md" || fail "the presumption is not in the contract verbatim"
grep -q '^presumes:' "$sb4/SWARM.md" && fail "the front matter leaked into the contract"
pid="$(jq -r '.runs[] | select(.label == "presumed") | .id' "$TMP/runs/registry.json")"
got="$(swarm question "$pid" list --json | jq -r '.questions[] | select(.id == "Q-1") | .presumes.text')"
[[ "$got" == "The drive was connected to the workstation." ]] || fail "the register does not hold what Q-1 presumes: $got"
echo "ok - presumes: in the front matter is carried into the contract's Presumptions section, and the register holds it on its question"

# The shipped goals: each with a brief designates its givens, so none is warned about.
for g in "$ROOT"/prompts/goals/*.md; do
  out="$(check --goal-file "$g")" || fail "$(basename "$g"): --check refused it: $out"
  grep -q "$WARNED" <<<"$out" && fail "$(basename "$g") has a brief and designates no premises: $out"
done
echo "ok - no shipped goal has a brief without premises"

# The questions that must be established (docs/adr/0013, "A question that
# must be established"): the front matter's must_establish: list is carried
# into a Must establish section, the register holds the requirement on each
# question it names, the kickoff says so, and a name the goal does not number
# is warned about (it requires nothing).
printf -- '---\nmust_establish: [1, 7]\n---\n## Goal\n\nA case.\n\n### Questions the report has to answer\n\n1. What is the flag?\n2. Which file held it?\n\n## Definition of done\n\n`work/report.md` exists.\n\n## Checks\n\n- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2`\n' > "$TMP/required.md"
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/required.md" --label required)"
sb5="$(sandbox_of "$out")"
[[ -n "$sb5" && -f "$sb5/SWARM.md" ]] || fail "no sandbox for the goal with must_establish: $out"
grep -q '^## Must establish$' "$sb5/SWARM.md" || fail "the front matter's must_establish is not in a Must establish section of the contract"
grep -q '^- 1$' "$sb5/SWARM.md" && grep -q '^- 7$' "$sb5/SWARM.md" || fail "the contract's Must establish section does not name the questions as given"
grep -q '^must_establish:' "$sb5/SWARM.md" && fail "the front matter leaked into the contract"
grep -q '^Required:     Q-1 must be established' <<<"$out" || fail "the kickoff does not say which questions must be established: $out"
grep -q '^WARN: the goal says these must be established and numbers no such question, so nothing is required of them: 7\.' <<<"$out" || fail "a name the goal does not number was not warned about: $out"
rid="$(jq -r '.runs[] | select(.label == "required") | .id' "$TMP/runs/registry.json")"
got="$(swarm question "$rid" list --json | jq -c '[.questions[] | {id, required: (.must_establish.required // false)}]')"
[[ "$got" == '[{"id":"Q-1","required":true},{"id":"Q-2","required":false}]' ]] || fail "the register does not hold the requirement on Q-1 alone: $got"
out="$(swarm question "$rid" amend Q-2 --expect-rev 1 --must-establish --why "the file is the evidence")" || fail "the operator could not require Q-2: $out"
[[ "$(swarm question "$rid" list --json | jq -r '.questions[] | select(.id == "Q-2") | .must_establish.required')" == true ]] || fail "the amendment did not require Q-2"
set +e
out="$(swarm question "$rid" amend Q-2 --expect-rev 1 --no-must-establish)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'a release of the requirement says why' <<<"$out" || fail "a release without why was not refused (rc $rc): $out"
echo "ok - must_establish: in the front matter is carried into the contract's Must establish section, held on its questions, said at the kickoff, and a name the goal does not number is warned about; the operator requires and releases on the record"

# The list's forms, so a typo never quietly lowers the bar: items at column 0
# are YAML too and are read; a key that names nothing is warned about; a
# list beside the goal's own Must establish section is merged into it.
qgoal() { # <file> <front matter lines> <body section lines>
  printf -- '---\n%b---\n## Goal\n\nA case.\n\n### Questions\n\n1. What is the flag?\n2. Which file held it?\n\n%b## Definition of done\n\n`work/report.md` exists.\n\n## Checks\n\n- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2`\n' "$2" "$3" > "$1"
}
required_of() { swarm question "$(jq -r --arg l "$1" '.runs[] | select(.label == $l) | .id' "$TMP/runs/registry.json")" list --json | jq -c '[.questions[] | select(.must_establish.required == true) | .id]'; }
qgoal "$TMP/col0.md" 'must_establish:\n- 1\n- 2\n' ''
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/col0.md" --label col0)"
grep -q '^Required:     Q-1, Q-2 must be established' <<<"$out" || fail "a list at column 0 was not read: $out"
[[ "$(required_of col0)" == '["Q-1","Q-2"]' ]] || fail "the register does not hold the column-0 list: $(required_of col0)"
qgoal "$TMP/empty.md" 'must_establish:\n' ''
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/empty.md" --label emptyreq)"
grep -q "^WARN: the goal's metadata block has must_establish: and names no question in it" <<<"$out" || fail "a must_establish: key that names nothing was not warned about: $out"
[[ "$(required_of emptyreq)" == '[]' ]] || fail "an empty key required something: $(required_of emptyreq)"
qgoal "$TMP/both.md" 'must_establish: [2]\n' '## Must establish\n\n- 1\n\n'
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/both.md" --label bothreq)"
sbb="$(sandbox_of "$out")"
[[ "$(grep -c '^## Must establish$' "$sbb/SWARM.md")" -eq 1 ]] || fail "the front matter's list was not merged into the goal's own section"
[[ "$(required_of bothreq)" == '["Q-1","Q-2"]' ]] || fail "the front matter's list beside the goal's section was dropped: $(required_of bothreq)"
echo "ok - must_establish: items at column 0 are read, a key that names nothing is warned about, and a list beside the goal's own section is merged into it"

# requires: what the case's questions need done, checked before the run starts
# where the agents run (here, this host): met by a program that does the work,
# said in SWARM.md, a warning when not met; --requires names it on the CLI.
mkdir -p "$TMP/capbin"
printf '#!/usr/bin/env bash\nexit 4\n' > "$TMP/capbin/zbarimg"
chmod +x "$TMP/capbin/zbarimg"
qgoal "$TMP/req.md" 'requires: qr-decode, ocr\n' ''
out="$(PATH="$TMP/capbin:$PATH" swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/req.md" --label reqcaps)"
sbr="$(sandbox_of "$out")"
[[ -f "$sbr/toolbox.json" ]] || fail "a goal that says what it requires was not checked (no toolbox.json): $out"
jq -e '.requires[] | select(.capability == "qr-decode" and .met == true)' "$sbr/toolbox.json" >/dev/null || fail "qr-decode is met by a zbarimg that reads the probe: $(jq -c .requires "$sbr/toolbox.json")"
if ! command -v tesseract >/dev/null 2>&1; then
  grep -q "^WARN: the case requires ocr and this host cannot do it (none of: tesseract)" <<<"$out" || fail "an unmet capability is a warning before the start: $out"
  grep -q '| ocr | not met (none of `tesseract`)' "$sbr/SWARM.md" || fail "SWARM.md does not say ocr is not met: $(grep -n 'ocr' "$sbr/SWARM.md")"
fi
grep -q '| qr-decode | `zbarimg` |' "$sbr/SWARM.md" || fail "SWARM.md does not say what meets qr-decode"
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/req.md" --requires teleport --label reqbad || true)"
grep -q "^BLOCKER: requires: teleport names a capability the toolbox does not know" <<<"$out" || fail "an unknown capability was not refused: $out"
echo "ok - requires: is checked at kickoff where the agents run, said in SWARM.md, warned about when not met; an unknown capability is refused"
