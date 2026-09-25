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

# Hostile archives: names that climb out, absolute names, duplicates, links,
# a zip bomb's ratio, an encrypted member, a truncated tar and a central
# directory that declares more members than the limit.
H="$WORK/hostile"; mkdir -p "$H"
python3 - "$H" <<'PY'
import io, os, struct, sys, tarfile, zipfile
d = sys.argv[1]
def add(tf, name, data=b"x", typ=tarfile.REGTYPE, link=""):
    ti = tarfile.TarInfo(name); ti.type = typ; ti.linkname = link; ti.mtime = 1700000000
    ti.size = len(data) if typ == tarfile.REGTYPE else 0
    tf.addfile(ti, io.BytesIO(data) if typ == tarfile.REGTYPE else None)
with tarfile.open(os.path.join(d, "evil.tar"), "w") as tf:
    add(tf, "../../etc/cron.d/x"); add(tf, "/abs/path"); add(tf, "dup"); add(tf, "dup", b"yy")
    add(tf, "ln", typ=tarfile.SYMTYPE, link="/etc/shadow")
open(os.path.join(d, "cut.tar"), "wb").write(open(os.path.join(d, "evil.tar"), "rb").read()[:2000])
with zipfile.ZipFile(os.path.join(d, "bomb.zip"), "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.writestr("zeros.bin", b"\0" * 20_000_000)
    z.writestr("..\\windows\\evil.dll", b"MZ")
# An encrypted member: the flag bit set by hand on a stored entry.
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("secret.txt", b"hidden")
raw = bytearray(buf.getvalue())
for sig in (b"PK\x03\x04", b"PK\x01\x02"):
    i = raw.find(sig)
    off = 6 if sig == b"PK\x03\x04" else 8
    flags = struct.unpack_from("<H", raw, i + off)[0] | 1
    struct.pack_into("<H", raw, i + off, flags)
open(os.path.join(d, "enc.zip"), "wb").write(bytes(raw))
with zipfile.ZipFile(os.path.join(d, "many.zip"), "w") as z:
    for i in range(30):
        z.writestr("f%02d" % i, b"")
PY
AM="$ROOT/packs/computer-forensics-base/recipes/archive-members/run.py"
run_am() { python3 "$AM" run --target "{\"paths\": [\"$H/$1\"]}" --out "$H/out-$1" >/dev/null; }
run_am evil.tar
flags_of() { awk -F'\t' -v p="$2" '$3 == p { print $14 }' "$H/out-$1/members.tsv"; }
[[ "$(flags_of evil.tar '../../etc/cron.d/x')" == escapes-root ]] || fail "a name that climbs out should be flagged: $(cat "$H/out-evil.tar/members.tsv")"
[[ "$(flags_of evil.tar '/abs/path')" == escapes-root ]] || fail "an absolute name should be flagged"
[[ "$(awk -F'\t' '$3 == "dup"' "$H/out-evil.tar/members.tsv" | wc -l | tr -d ' ')" -eq 2 ]] || fail "duplicate names are two rows"
[[ "$(awk -F'\t' '$3 == "ln" { print $2 "|" $12 }' "$H/out-evil.tar/members.tsv")" == "symlink|/etc/shadow" ]] || fail "a link is listed as one, with its target, never followed"
run_am cut.tar || true
[[ "$(jq -r .status "$H/out-cut.tar/coverage.json")" == partial ]] || fail "a truncated tar is partial: $(cat "$H/out-cut.tar/coverage.json")"
run_am bomb.zip
[[ "$(flags_of bomb.zip zeros.bin)" == 'ratio>1000' ]] || fail "a zip bomb's ratio is flagged: $(cat "$H/out-bomb.zip/members.tsv")"
# (the shown name escapes each backslash, and awk -v reads escapes once more)
[[ "$(flags_of bomb.zip '..\\\\windows\\\\evil.dll')" == escapes-root ]] || fail "a backslash path that climbs out is flagged: $(cat "$H/out-bomb.zip/members.tsv")"
[[ ! -e "$H/out-bomb.zip/zeros.bin" ]] || fail "nothing is extracted"
run_am enc.zip
[[ "$(flags_of enc.zip secret.txt)" == encrypted ]] || fail "an encrypted member is flagged: $(cat "$H/out-enc.zip/members.tsv")"
RECIPE_MEMBERS=10 python3 "$AM" run --target "{\"paths\": [\"$H/many.zip\"]}" --out "$H/out-many" >/dev/null || true
jq -e '.limits_hit[0] | test("declares 30, more than the limit of 10")' "$H/out-many/coverage.json" >/dev/null || fail "a directory past the limit is not loaded, and says so: $(cat "$H/out-many/coverage.json")"
pass "hostile archives are listed as data: escapes, duplicates, links, bombs, encryption, truncation and a limit, each named"
