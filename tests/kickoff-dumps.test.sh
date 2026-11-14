#!/usr/bin/env bash
# E7: a process or memory dump at the top of an --inputs directory adds the
# memory pack to a run that has packs, said at kickoff and in SWARM.md with
# each dump's size; --no-pack keeps it out (said, never silently), a run
# without --pack stays without, a pack this host has not installed is said,
# and a pack named in both --pack and --no-pack is refused. The packs are the
# test's own, installed into a home of its own (the shipped packs change).
# No model, no Herdr, no VM.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/kickoff-dumps.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
export SWARM_RUNS_DIR="$TMP/runs" SWARM_SIGNERS_HOME="$TMP/signers" SWARM_HUBS_DIR="$TMP/hubs"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# The evidence: a minidump under a name that says nothing (found by its header),
# a hibernation file by its name, a text file, and a dump one folder down
# (not the kickoff's: the catalogue says it once it lists it).
EV="$TMP/evidence with space"
mkdir -p "$EV/deeper"
printf 'MDMP\x93\xa7\x00\x00' > "$EV/crash.bin"
head -c 3000 /dev/zero >> "$EV/crash.bin"
printf 'not a header, a name\n' > "$EV/hiberfil.sys"
printf 'just text\n' > "$EV/notes.txt"
printf 'MDMP' > "$EV/deeper/inner.dmp"
EV_NONE="$TMP/plain"
mkdir -p "$EV_NONE"
printf 'just text\n' > "$EV_NONE/notes.txt"

make_pack() { # <id> [tool]
  local id="$1" tool="${2:-}" d="$TMP/packsrc/$1"
  mkdir -p "$d/skills/area" "$d/requires"
  printf 'Test pack.\n' > "$d/LICENCE"
  printf '{ "binaries": [] }\n' > "$d/requires/host.json"
  printf '%s\n' '---' 'id: area/start' 'title: Where to start' 'when: First.' 'needs: []' 'tools: []' 'requires_host: []' 'router: true' '---' '' 'Router body.' > "$d/skills/area/start.md"
  printf '{ "id": "%s", "name": "%s", "version": "1.0.0", "description": "A pack for the test.", "licence": "AGPL-3.0-or-later", "depends": [], "requires": { "host": "requires/host.json" }, "secrets": [] }\n' "$id" "$id" > "$d/pack.json"
  bash "$ROOT/scripts/pack.sh" seal "$d" >/dev/null || fail "pack $id did not seal"
  bash "$ROOT/scripts/pack.sh" install "$d" --no-secrets >/dev/null || fail "pack $id did not install"
}

export DFIRSWARM_HOME="$TMP/home"
make_pack case-pack
make_pack memory-forensics

base=(--model solo/model --n 1 --cap-usd 1 --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off)
start() { # <label> <args...> -> out, rc, sb
  local label="$1"; shift
  set +e
  out="$(bash "$ROOT/scripts/swarm.sh" start --no-start --label "$label" "${base[@]}" "$@" 2>&1)"
  rc=$?
  set -e
  sb="$(sed -n 's/^SANDBOX=//p' <<<"$out" | tail -1)"
}
record_packs() { # <sandbox> -> the run record's pack ids
  jq -r --arg sb "$1" '[.runs[] | select(.sandbox == $sb) | .packs[]?.id] | join(",")' "$SWARM_RUNS_DIR/registry.json"
}

echo "# a run with packs and a dump among its inputs gains the memory pack"
start added --inputs "$EV" --pack case-pack
[[ $rc -eq 0 && -n "$sb" ]] || fail "the kickoff failed (rc $rc): $out"
grep -q '^Packs: *memory-forensics added: 2 process or memory dump(s) at the top of the inputs' <<<"$out" || fail "the addition is not said: $out"
grep -q 'inputs/crash.bin (3 KiB, process or crash dump)' <<<"$out" || fail "the console line does not name the dump with its size: $out"
[[ ",$(record_packs "$sb")," == *,memory-forensics,* ]] || fail "the run record does not carry memory-forensics: $(record_packs "$sb")"
grep -q '^## Dumps among the inputs' "$sb/SWARM.md" || fail "SWARM.md has no dumps section"
grep -q '^- `inputs/crash.bin` (3 KiB, process or crash dump, by its header)' "$sb/SWARM.md" || fail "SWARM.md does not list the minidump with its size: $(grep -A8 'Dumps among' "$sb/SWARM.md")"
grep -q '^- `inputs/hiberfil.sys` (21 B, hibernation file, by its name)' "$sb/SWARM.md" || fail "SWARM.md does not list the hibernation file with its size"
grep -q 'The kickoff added memory-forensics' "$sb/SWARM.md" || fail "SWARM.md does not say the pack was added"
section="$(awk '/^## Dumps among the inputs/{on=1; print; next} on && /^## /{exit} on' "$sb/SWARM.md")"
grep -q 'inner.dmp' <<<"$section" && fail "a dump one folder down was said as the kickoff's: $section"
grep -q 'notes.txt' <<<"$section" && fail "a text file was said as a dump: $section"
jq -e '.decision == "added" and .total == 2 and (.dumps | length) == 2' "$sb/kickoff-dumps.json" >/dev/null || fail "kickoff-dumps.json is not what was found: $(cat "$sb/kickoff-dumps.json")"
pass "a dump at the top of the inputs adds memory-forensics, said on the console, in the record and in SWARM.md with each dump's size"

echo "# --no-pack keeps it out, and says so"
start excluded --inputs "$EV" --pack case-pack --no-pack memory-forensics
[[ $rc -eq 0 && -n "$sb" ]] || fail "the kickoff failed (rc $rc): $out"
grep -q '^NOTE: 2 process or memory dump(s).*memory-forensics was not added: --no-pack excludes it' <<<"$out" || fail "the exclusion is not said: $out"
[[ ",$(record_packs "$sb")," != *,memory-forensics,* ]] || fail "an excluded pack was added: $(record_packs "$sb")"
grep -q 'memory-forensics was not added: the operator excluded it' "$sb/SWARM.md" || fail "SWARM.md does not say why the pack is not there"
grep -q '^- `inputs/crash.bin` (3 KiB' "$sb/SWARM.md" || fail "SWARM.md does not list the dumps when the pack is excluded"
pass "--no-pack memory-forensics leaves the packs as named, and the console and SWARM.md say why"

echo "# a run without --pack stays without"
start no-packs --inputs "$EV"
[[ $rc -eq 0 && -n "$sb" ]] || fail "the kickoff failed (rc $rc): $out"
grep -q 'memory-forensics was not added: the run has no --pack' <<<"$out" || fail "a run without packs does not say why: $out"
[[ -z "$(record_packs "$sb")" ]] || fail "a run without --pack gained packs: $(record_packs "$sb")"
grep -q 'this run was started without packs' "$sb/SWARM.md" || fail "SWARM.md does not say why the pack is not there"
pass "a run without --pack carries no pack, and says the dumps and why"

echo "# a run whose inputs hold no dump is as before"
start none --inputs "$EV_NONE" --pack case-pack
[[ $rc -eq 0 && -n "$sb" ]] || fail "the kickoff failed (rc $rc): $out"
grep -q 'memory-forensics\|process or memory dump' <<<"$out" && fail "a run with no dump says one: $out"
[[ "$(record_packs "$sb")" == case-pack ]] || fail "the packs changed without a dump: $(record_packs "$sb")"
[[ ! -e "$sb/kickoff-dumps.json" ]] || fail "kickoff-dumps.json written with no dump"
grep -q 'Dumps among the inputs' "$sb/SWARM.md" && fail "SWARM.md has a dumps section with no dump"
pass "with no dump among the inputs the packs and SWARM.md are as named"

echo "# the operator's own --pack memory-forensics"
start named --inputs "$EV" --pack case-pack,memory-forensics
[[ $rc -eq 0 ]] || fail "the kickoff failed (rc $rc): $out"
grep -q '^Dumps: .*memory-forensics is among the run.s packs' <<<"$out" || fail "a named pack is not said: $out"
grep -q 'The run carries memory-forensics, as the operator named it' "$sb/SWARM.md" || fail "SWARM.md does not say the pack was named"
pass "a memory pack the operator named is said as named"

echo "# --pack and --no-pack naming one pack is refused"
start both --inputs "$EV" --pack case-pack --no-pack case-pack
[[ $rc -eq 2 ]] || fail "--pack and --no-pack of one pack was not refused (rc $rc): $out"
grep -q 'BLOCKER: --pack and --no-pack both name case-pack' <<<"$out" || fail "not the refusal: $out"
pass "--pack and --no-pack of one pack is a BLOCKER"

echo "# --check says the same as the start"
set +e
out="$(bash "$ROOT/scripts/swarm.sh" start --check --no-start --label check "${base[@]}" --inputs "$EV" --pack case-pack 2>&1)"
rc=$?
set -e
[[ $rc -eq 0 ]] || fail "the check failed (rc $rc): $out"
grep -q '^Packs: *memory-forensics added' <<<"$out" || fail "the check does not say the pack would be added: $out"
pass "--check says the memory pack would be added"

echo "# a memory pack this host has not installed is said, not added"
export DFIRSWARM_HOME="$TMP/home2"
make_pack case-pack
start unavailable --inputs "$EV" --pack case-pack
[[ $rc -eq 0 && -n "$sb" ]] || fail "the kickoff failed (rc $rc): $out"
grep -q '^WARN: .*memory-forensics was not added: it is not installed on this host' <<<"$out" || fail "a missing pack is not said: $out"
[[ "$(record_packs "$sb")" == case-pack ]] || fail "the packs changed: $(record_packs "$sb")"
grep -q 'memory-forensics was not added: it is not installed on this host' "$sb/SWARM.md" || fail "SWARM.md does not say why the pack is not there"
pass "a memory pack not installed is said on the console and in SWARM.md, and the run goes on"
