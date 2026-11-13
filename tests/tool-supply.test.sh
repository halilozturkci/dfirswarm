#!/usr/bin/env bash
# Supplying a tool to a running run, at the operator's side (swarm.sh
# tool-supply, scripts/material.ts, docs/adr/0014): a program no image holds,
# handed over with where it came from, how it was built and the hashes
# checked, sealed as operator-supplied material and told to the seats with the
# way to run it. The case policy's presets admit it, a policy that says
# operator_supplied=none refuses it, and a hub started by an older harness
# that takes it as plain material is said. Host runs, --no-start: no model, no
# VM, no Herdr; the node suite (tests/tool-supply.test.ts) holds the rest.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Short, for the collector's socket path.
TMP="$(mktemp -d /tmp/tsup.XXXXXX)"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
export SWARM_RUNS_DIR="$TMP/runs" DFIRSWARM_HOME="$TMP/home" SWARM_SIGNERS_HOME="$TMP/home"
mkdir -p "$DFIRSWARM_HOME"
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
sandbox_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .sandbox' "$TMP/runs/registry.json"; }
id_of() { jq -r --arg l "$1" '.runs[] | select(.label == $l) | .id' "$TMP/runs/registry.json"; }
sha() { { shasum -a 256 "$1" 2>/dev/null || sha256sum "$1"; } | cut -d' ' -f1; }

GOAL="$TMP/goal.md"
cat > "$GOAL" <<'EOF'
## Goal

Establish which program held the key.

### Questions

1. Which program held the key?

## Definition of done

d

## Checks

- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,summary,narrative`
EOF
kick() { swarm start --model solo/model --n 2 --cap-usd 1 --no-start --toolbox off --goal-file "$GOAL" "$@"; }

echo "# a run with a request that asks for a program"
out="$(kick --label t1)" || fail "the kickoff was refused: $out"
id="$(id_of t1)"; sb="$(sandbox_of t1)"
node --experimental-strip-types --no-warnings --input-type=module -e '
  const L = await import(process.argv[1]);
  const ctx = { sandboxRoot: process.argv[2], agentId: process.argv[3] };
  let r = await L.openLead(ctx, { title: "Find the key", why: "Q1 wants the program", answers: ["1"], take: true });
  if (!r.ok) throw new Error(r.reason);
  r = await L.closeLead(ctx, "L-1", { disposition: "needs_operator", ref: "no image holds a program that finds the key" });
  if (!r.ok || r.request?.id !== "R-1") throw new Error(JSON.stringify(r));
' "$ROOT/extensions/leads.ts" "$sb" "$(jq -r '.agents[0].id' "$sb/team.json")" || fail "the agent's ask was not recorded"

mkdir -p "$TMP/supply"
printf '#!/bin/sh\necho scanning\n' > "$TMP/supply/finder"
chmod +x "$TMP/supply/finder"
want="$(sha "$TMP/supply/finder")"

echo "# refused: no source, a hash that is none of the files, a request that does not exist, a path inside the run"
out="$(swarm tool-supply "$id" add "$TMP/supply/finder" --why "a key finder")" && fail "a tool with no source was taken: $out"
grep -q 'says where the tool came from (--source)' <<<"$out" || fail "$out"
out="$(swarm tool-supply "$id" add "$TMP/supply/finder" --why "a key finder" --source "the operator's build" --sha256 "$(printf '0%.0s' $(seq 1 64))")" && fail "a hash that is none of the files was taken: $out"
grep -q "is none of the supplied files' sha256" <<<"$out" || fail "$out"
out="$(swarm tool-supply "$id" add "$TMP/supply/finder" --why "a key finder" --source "the operator's build" --for R-9)" && fail "a request that does not exist was taken: $out"
grep -q 'R-9 is not a request of this run' <<<"$out" || fail "$out"
out="$(swarm tool-supply "$id" add "$sb/SWARM.md" --why "x" --source "y")" && fail "a path inside the run was taken: $out"
grep -q 'is inside the run' <<<"$out" || fail "$out"
mkdir -p "$TMP/bundle"
printf 'TOKEN=abc\n' > "$TMP/bundle/.env"
printf 'x\n' > "$TMP/bundle/prog"
out="$(swarm tool-supply "$id" add "$TMP/bundle" --why "a bundle" --source "y")" && fail "a directory with a hidden file was taken: $out"
grep -q 'holds hidden files or directories (.env)' <<<"$out" || fail "$out"
out="$(swarm tool-supply "$id" add "$(dirname "$sb")" --why "all" --source "y")" && fail "a path that holds the run was taken: $out"
grep -q 'holds the run' <<<"$out" || fail "$out"
out="$(swarm tool-supply "$id" add)" && fail "no path was taken: $out"
out="$(swarm tool-supply "$id" frobnicate x)" && fail "an unknown subcommand was taken: $out"
grep -q 'tool-supply takes add or list' <<<"$out" || fail "$out"
[[ -z "$(ls "$sb/store/imports" 2>/dev/null)" ]] || fail "a refusal left something sealed: $(ls "$sb/store/imports")"
pass "a tool with no source, a stray hash, an unknown request or a path inside the run is refused and leaves nothing"

echo "# supplied: sealed, on the journal and the ledger with its provenance, told to the seats"
out="$(swarm tool-supply "$id" add "$TMP/supply/finder" --why "a key finder the images lack" --source "vendor source 1.0, sha256 abc" --built "make in a clean container, arm64" --sha256 "$want" --for R-1)" || fail "tool-supply failed: $out"
grep -q '^Added mat-0001 (operator_supplied; 1 file(s)' <<<"$out" || fail "$out"
grep -q 'Tool: source: vendor source 1.0, sha256 abc; built: make in a clean container, arm64; 1 hash(es) given, each held to the sealed bytes; for R-1, L-1 (this closes neither the request nor the lead: answer them with swarm.sh requests '"$id"' answer R-n TEXT' <<<"$out" || fail "$out"
grep -q 'Sealed: finder ([0-9]* bytes); every seat can read each of them\.' <<<"$out" || fail "the reply does not list the sealed files: $out"
grep -q 'The agents can read it now, read-only, at store/imports/mat-0001/out/' <<<"$out" || fail "$out"
grep -q 'WARN' <<<"$out" && fail "a warning for a hub that recorded it: $out"
[[ "$(sha "$sb/store/imports/mat-0001/out/finder")" == "$want" ]] || fail "the import is not the file"
[[ -z "$(find "$sb/store/imports/mat-0001/out/finder" -perm -u+x)" ]] || fail "a sealed file has an execute bit"
jq -e --arg h "$want" '.tool.source == "vendor source 1.0, sha256 abc" and .tool.built == "make in a clean container, arm64" and .tool.checked == [$h] and .tool.for == ["R-1", "L-1"] and .class == "operator_supplied"' "$sb/store/imports/mat-0001/material.json" >/dev/null || fail "material.json: $(cat "$sb/store/imports/mat-0001/material.json")"
grep -q '"type":"material_added"' "$sb/store/journal.jsonl" || fail "no journal line"
jq -e --arg h "$want" 'select(.kind == "external") | .source_class == "operator_supplied" and .provenance.tool.checked == [$h] and .provenance.tool.for == ["R-1", "L-1"] and .refs == ["import:mat-0001/finder"]' "$sb/ledger/entries.jsonl" >/dev/null || fail "the ledger: $(cat "$sb/ledger/entries.jsonl")"
post="$(cat "$sb"/threads/main/*-system.md | grep 'TOOL SUPPLIED')" || fail "no board post"
grep -q 'job_run with programs \["import:mat-0001"\] (and inputs \["import:mat-0001/finder"\] when you declare them)' <<<"$post" || fail "$post"
grep -q 'Nothing in the store or in a job.s $OUT can be executed where it stands (sealed files have no execute bit, $OUT is no-exec)' <<<"$post" || fail "$post"
grep -q 'copies it into an executable directory in the worker' <<<"$post" || fail "$post"
grep -q '"command":"tool-supply"' "$TMP/runs/operator-audit.jsonl" && grep -q '"command":"tool_supply_outcome"' "$TMP/runs/operator-audit.jsonl" || fail "the act is not on the operator's record"
pass "a tool is sealed with its provenance, on the ledger, on the journal and on the board with the way to run it"

echo "# listed"
out="$(swarm tool-supply "$id" list)" || fail "list failed: $out"
grep -q '^mat-0001 operator_supplied ' <<<"$out" && grep -q 'tool, from vendor source 1.0, sha256 abc' <<<"$out" && grep -q "hashes checked against the sealed bytes: $want" <<<"$out" && grep -q '; for R-1, L-1' <<<"$out" || fail "$out"
out="$(swarm material "$id" list)" || fail "material list failed: $out"
grep -q '^mat-0001 operator_supplied ' <<<"$out" || fail "a tool is material, and material list shows it: $out"
out="$(swarm evidence "$id" list)" || fail "evidence list failed: $out"
grep -q 'No evidence was added to this run' <<<"$out" || fail "a tool is not evidence: $out"
out="$(swarm tool-supply "$id" list --json)" || fail "list --json failed: $out"
jq -e '.material[0].tool.checked | length == 1' <<<"$out" >/dev/null || fail "$out"
pass "tool-supply list shows where it came from and what was checked; a tool is material, never evidence"

echo "# the other presets, and a policy that says none"
out="$(kick --policy ctf --label t2)" || fail "the ctf kickoff was refused: $out"
id2="$(id_of t2)"
printf 'another\n' > "$TMP/supply/other"
out="$(swarm tool-supply "$id2" add "$TMP/supply/other" --why "another" --source "the operator's build")" || fail "ctf refused a tool: $out"
grep -q '^Added mat-0001 (operator_supplied' <<<"$out" || fail "$out"
out="$(swarm evidence "$id2" add "$TMP/supply/other" --why "x")" && fail "ctf took evidence after the kickoff"
out="$(kick --policy internal --label t3)" || fail "the internal kickoff was refused: $out"
out="$(swarm tool-supply "$(id_of t3)" add "$TMP/supply/other" --why "another" --source "the operator's build")" || fail "internal refused a tool: $out"
out="$(kick --material-use operator_supplied=none --label t4)" || fail "the kickoff was refused: $out"
out="$(swarm tool-supply "$(id_of t4)" add "$TMP/supply/other" --why "another" --source "the operator's build")" && fail "a tool was taken where operator_supplied is none: $out"
grep -q 'material_use operator_supplied=none): a tool supplied under it could be run but nothing recorded on its output could be kept; nothing was added' <<<"$out" || fail "$out"
[[ -z "$(ls "$(sandbox_of t4)/store/imports" 2>/dev/null)" ]] || fail "the refusal left something sealed"
pass "standard, ctf and internal admit a tool (the node suite holds the fourth); operator_supplied=none refuses it before anything is sealed"

echo "# a hub that runs an older harness takes it as plain material: said"
FAKE="$TMP/fakebin"; mkdir -p "$FAKE"
REAL_NODE="$(command -v node)"
cat > "$FAKE/node" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do
  if [[ "\$a" == tool-add ]]; then
    printf '%s\n' '{"ok":true,"import":"mat-0002","mode":"material","class":"operator_supplied","files":[{"path":"finder","sha256":"x","bytes":1}],"manifest_sha256":"m","journal_seq":3,"entry":2,"permitted_use":"reference: x","complete":true}'
    exit 0
  fi
done
exec "$REAL_NODE" "\$@"
EOF
chmod +x "$FAKE/node"
out="$(PATH="$FAKE:$PATH" swarm tool-supply "$id" add "$TMP/supply/finder" --why "again" --source "s")" || fail "the stand-in hub's answer was refused: $out"
grep -q "WARN: the run's hub did not record the tool's provenance" <<<"$out" || fail "no warning: $out"
grep -q 'Added mat-0002 (operator_supplied' <<<"$out" || fail "$out"
pass "a hub that does not know tools is said, not trusted"

echo "# help"
swarm help tool-supply | grep -q 'tool-supply <id> add PATH --why W --source TEXT' || fail "help tool-supply"
swarm --help | grep -q 'tool-supply <id>' || fail "the short help does not name tool-supply"
pass "tool-supply has its help and is in the short help"
