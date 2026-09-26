#!/usr/bin/env bash
# A pack's own tests (packs/<id>/tests/pack.test.sh), which its reviewer wrote
# beside its tools on synthetic fixtures: run here so a change to a pack is
# held to them, not only when someone remembers they exist. Each skips what
# needs a program this host does not have and says so.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
n=0
for t in "$ROOT"/packs/*/tests/pack.test.sh; do
  [[ -f "$t" ]] || continue
  pack="$(basename "$(dirname "$(dirname "$t")")")"
  out="$(bash "$t" 2>&1)" || fail "packs/$pack/tests/pack.test.sh failed:
$out"
  printf '%s\n' "$out" | sed "s/^/  [$pack] /"
  n=$((n + 1))
done
[[ "$n" -gt 0 ]] || fail "no pack carries its own tests; this suite would pass on nothing"
echo "ok - the $n packs' own tests pass"
