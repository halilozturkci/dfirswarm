#!/usr/bin/env bash
# The seal gives one pack.json for one pack, whatever order the file system
# lists its directories in.
#
# os.walk gives directories in the file system's order (macOS, ext4 and NTFS
# differ), and the checksum map used to be written in that order, so a pack
# sealed on another file system was rewritten whole with no file changed. Two
# copies of one pack are built with their directories created in opposite
# orders, on a file system whose listing follows creation order where there is
# one (tmpfs), then sealed; their pack.json must be byte-identical and the
# checksum map must be sorted by path. The sorted-map check holds on any file
# system; the opposite-order check is skipped, said, where the two listings
# came out the same.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK="$ROOT/scripts/pack.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

BASE=""
for cand in /dev/shm "${TMPDIR:-/tmp}"; do
  if [ -d "$cand" ] && [ -w "$cand" ]; then BASE="$(mktemp -d "$cand/seal-order.XXXXXX")" && break; fi
done
[ -n "$BASE" ] || fail "no writable scratch directory"
trap 'rm -rf "$BASE"' EXIT

mk_pack() { # <dir> <space-separated skill dirs> <space-separated data dirs>
  local d="$1" sk d2
  mkdir -p "$d/requires"
  printf 'Test pack.\n' > "$d/LICENCE"
  printf '{ "binaries": [] }\n' > "$d/requires/host.json"
  for sk in $2; do
    mkdir -p "$d/skills/$sk"
    printf -- '---\nid: %s/first\ntitle: Skill %s\nwhen: When %s is the question.\nneeds: []\ntools: []\nrequires_host: []\n---\n\nA body.\n' "$sk" "$sk" "$sk" > "$d/skills/$sk/first.md"
  done
  for d2 in $3; do
    mkdir -p "$d/vendor/$d2"
    printf 'file %s\n' "$d2" > "$d/vendor/$d2/f.txt"
  done
  python3 - "$d/pack.json" <<'PY'
import json, sys
m = {"id": "seal-order", "name": "seal-order", "version": "1.0.0", "description": "A pack for the suite.",
     "licence": "AGPL-3.0-or-later", "depends": [], "requires": {"host": "requires/host.json"}, "secrets": []}
json.dump(m, open(sys.argv[1], "w"), indent=2)
PY
}

mkdir -p "$BASE/fwd" "$BASE/rev"
mk_pack "$BASE/fwd" "alpha beta gamma delta" "a m z q"
mk_pack "$BASE/rev" "delta gamma beta alpha" "q z m a"

"$PACK" seal "$BASE/fwd" >/dev/null || fail "seal should succeed on the forward pack"
"$PACK" seal "$BASE/rev" >/dev/null || fail "seal should succeed on the reverse pack"

python3 - "$BASE/fwd/pack.json" <<'PY' || fail "the checksum map is not written sorted by path"
import json, sys
keys = list(json.load(open(sys.argv[1]))["checksums"]["sha256"])
if keys != sorted(keys):
    sys.exit("checksum keys out of order: %r" % keys)
PY
pass "the checksum map is written sorted by path (skills/INDEX.md in its sorted place)"

listing_a="$(ls -U "$BASE/fwd/skills" | tr '\n' ' ')"
listing_b="$(ls -U "$BASE/rev/skills" | tr '\n' ' ')"
if [ "$listing_a" = "$listing_b" ]; then
  echo "skip - this file system lists both copies in the same order, so the opposite-order comparison proves nothing here"
else
  cmp -s "$BASE/fwd/pack.json" "$BASE/rev/pack.json" || fail "two copies of one pack sealed to different pack.json when their directories were created in opposite orders"
  pass "directories created in opposite orders seal to a byte-identical pack.json"
fi

cp "$BASE/fwd/pack.json" "$BASE/first.json"
"$PACK" seal "$BASE/fwd" >/dev/null || fail "second seal failed"
cmp -s "$BASE/fwd/pack.json" "$BASE/first.json" || fail "a second seal changed pack.json"
pass "sealing twice leaves pack.json byte-identical"
