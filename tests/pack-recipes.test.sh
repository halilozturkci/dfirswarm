#!/usr/bin/env bash
# Pack recipes: the catalogue procedures a pack ships under recipes/<name>/.
# A pack with one seals it (its entry's sha256 in recipe.json, its id in
# pack.json as <pack>/<name>) and installs; a recipe that is malformed, whose
# entry leaves its directory, or whose auto names a trigger that does not
# exist, keeps the pack from sealing. The shipped computer-forensics-base
# recipes answer the entry protocol.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK="$ROOT/scripts/pack.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
export DFIRSWARM_HOME="$WORK/home"

mk_pack() { # <dir> <id>
  local d="$1/$2"
  mkdir -p "$d/recipes/list-things" "$d/requires"
  echo "Test pack." > "$d/LICENCE"
  echo '{ "binaries": [] }' > "$d/requires/host.json"
  cat > "$d/recipes/list-things/recipe.json" <<'EOF'
{
  "id": "list-things",
  "version": "1.0.0",
  "description": "List things.",
  "object": "thing",
  "runtime": "python3",
  "entry": "run.py",
  "auto": ["derived"],
  "limits": {"seconds": 60},
  "outputs": ["things.tsv"],
  "covers": "The things; not what is inside them."
}
EOF
  printf 'print("{}")\n' > "$d/recipes/list-things/run.py"
  python3 - "$d/pack.json" "$2" <<'EOF'
import json, sys
json.dump({"id": sys.argv[2], "name": sys.argv[2], "version": "1.0.0", "description": "A pack for the suite.",
           "licence": "AGPL-3.0-or-later", "depends": [], "requires": {"host": "requires/host.json"}, "secrets": []},
          open(sys.argv[1], "w"), indent=2)
EOF
}

mkdir -p "$WORK/src"
mk_pack "$WORK/src" rpack
"$PACK" seal "$WORK/src/rpack" >/dev/null || fail "a pack with a well-formed recipe should seal"
[[ "$(jq -c '.recipes' "$WORK/src/rpack/pack.json")" == '["rpack/list-things"]' ]] || fail "pack.json should name the recipe as <pack>/<name>: $(jq -c . "$WORK/src/rpack/pack.json")"
[[ "$(jq -r '.sha256' "$WORK/src/rpack/recipes/list-things/recipe.json")" == "$(shasum -a 256 "$WORK/src/rpack/recipes/list-things/run.py" | cut -d' ' -f1)" ]] \
  || fail "recipe.json should carry its entry's sha256"
"$PACK" install "$WORK/src/rpack" --no-secrets >/dev/null || fail "a sealed pack with a recipe should install"
"$PACK" verify rpack >/dev/null || fail "the installed pack should verify"
pass "a recipe is sealed with its entry's sha256, named <pack>/<name>, and installs"

# A changed entry after sealing is caught by the checksums.
echo '# changed' >> "$WORK/home/packs/rpack/recipes/list-things/run.py"
"$PACK" verify rpack >/dev/null 2>&1 && fail "a recipe changed after sealing should not verify"
pass "a recipe changed after sealing does not verify"

refuse() { # <what> <python that edits recipe.json r in place> <expected error text>
  local d="$WORK/bad-$RANDOM"
  mkdir -p "$d"
  mk_pack "$d" bad
  python3 - "$d/bad/recipes/list-things/recipe.json" "$2" <<'EOF'
import json, sys
p, code = sys.argv[1], sys.argv[2]
r = json.load(open(p))
exec(code)
json.dump(r, open(p, "w"), indent=2)
EOF
  out="$("$PACK" seal "$d/bad" 2>&1)" && fail "$1 should keep the pack from sealing: $out"
  grep -q -- "$3" <<<"$out" || fail "$1: the refusal should say \"$3\": $out"
}
refuse "an entry outside the recipe's directory" 'r["entry"] = "../../pack.json"' "must be a file inside the recipe's directory"
refuse "an absolute entry" 'r["entry"] = "/etc/passwd"' "must be a file inside the recipe's directory"
refuse "a trigger that does not exist" 'r["auto"] = ["always"]' "auto is a list of derived, kickoff"
refuse "a missing covers" 'del r["covers"]' "missing covers"
refuse "a runtime the harness does not run" 'r["runtime"] = "perl"' "runtime must be python3 or bash"
refuse "no time limit" 'r["limits"] = {}' "limits.seconds is a whole number"
refuse "a recipe whose id is not its directory" 'r["id"] = "other"' "declares the id"
pass "a malformed recipe keeps the pack from sealing, with the reason"

# The shipped recipes answer the protocol: detect exits 0 or 1 with a why,
# run writes coverage.json and index.tsv.
CFB="$ROOT/packs/computer-forensics-base"
"$PACK" verify "$CFB" >/dev/null 2>&1 || "$PACK" install "$CFB" --no-secrets >/dev/null 2>&1 || true
T="$WORK/proto"; mkdir -p "$T"
python3 - "$T/a.zip" <<'EOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("x.txt", "x")
EOF
for r in archive-members disk-volumes memory-windows; do
  rj="$CFB/recipes/$r/recipe.json"
  [[ -f "$rj" ]] || fail "computer-forensics-base should ship the $r recipe"
  entry="$CFB/recipes/$r/$(jq -r .entry "$rj")"
  rt="$(jq -r .runtime "$rj")"
  v="$("$rt" "$entry" detect --target "{\"paths\": [\"$T/a.zip\"], \"name\": \"inputs/a.zip\"}" 2>/dev/null)"; rc=$?
  [[ "$rc" -eq 0 || "$rc" -eq 1 ]] || fail "$r detect should exit 0 or 1, not $rc: $v"
  jq -e 'has("why")' <<<"$v" >/dev/null || fail "$r detect should say why: $v"
done
python3 "$CFB/recipes/archive-members/run.py" run --target "{\"paths\": [\"$T/a.zip\"]}" --out "$T/out" >/dev/null || fail "archive-members should catalogue a zip"
[[ "$(jq -r .status "$T/out/coverage.json")" == complete && -s "$T/out/index.tsv" && -s "$T/out/members.tsv" ]] || fail "archive-members should write coverage.json, index.tsv and members.tsv"
pass "the shipped recipes answer detect and run as the runner expects"
