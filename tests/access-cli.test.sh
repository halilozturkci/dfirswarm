#!/usr/bin/env bash
# swarm.sh access <id> [--job jN] [--seat NAME] [--json]: a run found by its id in the registry, the access
# record read from its own chains by the one reader (scripts/sensitive-access.ts; tests/sensitive-access.test.ts
# checks the record), nothing written into the run and nothing added to the operator's audit; the list ends
# with the fixed lower-bound sentence; an unknown id, a missing id and a bad option are refused.
set -uo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/access-cli.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
export SWARM_RUNS_DIR="$TMP/runs"
mkdir -p "$SWARM_RUNS_DIR"
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }
id_of() { printf '%s\n' "$1" | sed -n 's/^Swarm id: *//p' | tail -1; }

cat > "$TMP/goal.md" <<'GOAL'
## Goal

Examine the archive.

### Questions

1. Which account created the archive?

## Definition of done

Every question answered in the ledger.

## Checks

- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,summary,narrative`
GOAL
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/goal.md" --label access-a)"
ID="$(id_of "$out")"; S="$(sandbox_of "$out")"
[[ -n "$ID" && -d "$S" ]] || fail "no run: $out"

# The chains of a run with sensitive outputs, as the access-record suites write them (tests/sensitive-access-fixture.ts).
cat > "$TMP/write-fixture.ts" <<'TS'
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fixtureFiles } from "$FIXTURE";
const sandbox = process.argv[2];
for (const [rel, text] of Object.entries(fixtureFiles())) {
  if (!rel.startsWith("run1/") || rel === "run1/team.json") continue;
  const to = join(sandbox, rel.slice("run1/".length));
  await mkdir(dirname(to), { recursive: true });
  await writeFile(to, text);
}
TS
sed "s|\$FIXTURE|$ROOT/tests/sensitive-access-fixture.ts|" "$TMP/write-fixture.ts" > "$TMP/write-fixture.sed" && mv "$TMP/write-fixture.sed" "$TMP/write-fixture.ts"  # no sed -i: BSD sed takes the next word as a suffix
node --experimental-strip-types --no-warnings "$TMP/write-fixture.ts" "$S" || fail "the fixture was not written"
rm -f "$TMP/write-fixture.ts"

LOWER="Reads through a computed path, through a copy that was not a recorded page, or by a program that opened it by a name the command does not hold are not seen. This list is a lower bound."
audit_before="$(cat "$SWARM_RUNS_DIR/operator-audit.jsonl" 2>/dev/null | shasum)"
before="$(find "$S" -type f -print0 | sort -z | xargs -0 shasum 2>/dev/null | shasum)"

text="$(swarm access "$ID")" || fail "access failed: $text"
grep -q "^Access to sensitive outputs: " <<<"$text" || fail "no list: $text"
grep -q "j000001  tool  agent-2  secret_output" <<<"$text" || fail "the secret_output job is not listed: $text"
grep -q "used by j000034" <<<"$text" || fail "the job made from it is not listed: $text"
[[ "$(tail -n 1 <<<"$text")" == "$LOWER" ]] || fail "the list does not end with the lower-bound sentence: $(tail -n 1 <<<"$text")"
pass "access <id> prints the list and ends with the lower-bound sentence"

json="$(swarm access "$ID" --json)" || fail "access --json failed: $json"
[[ "$(jq -r '.record.lower_bound' <<<"$json")" == "$LOWER" ]] || fail "the JSON does not carry the sentence: $json"
[[ "$(jq -r '.provenance.roots | map(.job) | join(",")' <<<"$json")" == "j000001" ]] || fail "the root is not j000001: $json"
pass "access <id> --json"

job="$(swarm access "$ID" --json --job j000034)" || fail "access --job failed: $job"
[[ "$(jq -r '[.record.events[] | select(.job != "j000034" and .by_job != "j000034")] | length' <<<"$job")" == 0 && "$(jq -r '.record.events | length' <<<"$job")" -gt 0 ]] || fail "--job j000034 is not narrowed: $job"
seat="$(swarm access "$ID" --json --seat agent-3)" || fail "access --seat failed: $seat"
[[ "$(jq -r '[.record.events[] | select(.seat != "agent-3")] | length' <<<"$seat")" == 0 && "$(jq -r '.record.events | length' <<<"$seat")" -gt 0 ]] || fail "--seat agent-3 is not narrowed: $seat"
pass "access <id> --job and --seat"

after="$(find "$S" -type f -print0 | sort -z | xargs -0 shasum 2>/dev/null | shasum)"
[[ "$before" == "$after" ]] || fail "access wrote into the run"
[[ "$audit_before" == "$(cat "$SWARM_RUNS_DIR/operator-audit.jsonl" 2>/dev/null | shasum)" ]] || fail "access added a line to the operator's audit: it only reads"
pass "nothing is written into the run or the audit"

# It calls the reader and nothing else.
body="$(awk '/^cmd_access\(\) \{/,/^}/' "$ROOT/scripts/swarm.sh")"
[[ "$(grep -c 'node --experimental-strip-types' <<<"$body")" == 1 ]] && grep -q 'scripts/sensitive-access.ts' <<<"$body" || fail "cmd_access does more than call the reader"
pass "swarm.sh access only calls the reader"

swarm access nosuchrun >/dev/null; [[ $? -eq 1 ]] || fail "an unknown id is not refused with 1"
swarm access >/dev/null; [[ $? -eq 2 ]] || fail "no id is not a usage error"
swarm access "$ID" --bogus >/dev/null; [[ $? -eq 2 ]] || fail "an unknown option is not a usage error"
swarm access "$ID" --job 'a b' >/dev/null; [[ $? -eq 2 ]] || fail "a job that is not an id is not refused"
swarm access "$ID" --seat >/dev/null; [[ $? -eq 2 ]] || fail "--seat without a name is not refused"
swarm help access | grep -q 'lower bound' || fail "the help page does not say the list is a lower bound"
swarm 2>&1 | grep -q '^  access <id> ' || fail "the command list does not name access"
pass "refusals and help"
echo "access-cli: all passed"
