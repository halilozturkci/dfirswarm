#!/usr/bin/env bash
# Packs: seal, install, verify, tamper, zip, dependencies and refusals.
#
# A pack is the unit an operator imports, so the refusals matter as much as the
# happy path: a pack that does not match its checksums, whose dependency is
# missing, whose skill points at a tool it does not carry, or whose zip holds
# anything above the pack directory, must not install.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK="$ROOT/scripts/pack.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
export DFIRSWARM_HOME="$WORK/home"

# A minimal pack we build by hand, so the suite does not depend on the shipped ones.
mk_pack() { # <dir> <id> [depends]
  local d="$1/$2" id="$2" dep="${3:-}"
  mkdir -p "$d/skills/alpha" "$d/tools/echo_tool" "$d/requires"
  cat > "$d/LICENCE" <<'EOF'
Test pack.
EOF
  cat > "$d/skills/alpha/first.md" <<'EOF'
---
id: alpha/first
title: The first skill
when: Whenever the suite asks for it.
needs: []
tools: [echo_tool]
requires_host: []
---

A body, so the validator has something to accept.
EOF
  cat > "$d/tools/echo_tool/manifest.json" <<'EOF'
{
  "name": "echo_tool",
  "description": "Echo a string back, so a pack has a tool that runs anywhere.",
  "params": { "text": { "type": "string", "description": "What to echo" } },
  "runtime": "python3",
  "entry": "run.py",
  "timeout_seconds": 10
}
EOF
  cat > "$d/tools/echo_tool/run.py" <<'EOF'
import json, sys
d = json.loads(sys.stdin.read() or "{}")
print(json.dumps({"ok": True, "text": d.get("text", "")}))
EOF
  cat > "$d/requires/host.json" <<'EOF'
{ "binaries": [] }
EOF
  python3 - "$d/pack.json" "$id" "$dep" <<'EOF'
import json, sys
path, pid, dep = sys.argv[1], sys.argv[2], sys.argv[3]
m = {"id": pid, "name": pid, "version": "1.0.0", "description": "A pack for the suite.",
     "licence": "AGPL-3.0-or-later", "depends": [dep] if dep else [],
     "requires": {"host": "requires/host.json"}, "secrets": []}
json.dump(m, open(path, "w"), indent=2)
EOF
}

mkdir -p "$WORK/src"
mk_pack "$WORK/src" base-pack
"$PACK" seal "$WORK/src/base-pack" >/dev/null || fail "seal should succeed on a well-formed pack"
pass "seal writes checksums and the skill index"
[[ -f "$WORK/src/base-pack/skills/INDEX.md" ]] || fail "seal should generate skills/INDEX.md"
grep -q 'alpha/first' "$WORK/src/base-pack/skills/INDEX.md" || fail "the index should name every skill"
pass "the index is generated from the skills' own front matter"
grep -q '^Router:' "$WORK/src/base-pack/skills/INDEX.md" && fail "a pack with no router has a Router line in its index (every sealed pack's index would change)"
pass "a pack that names no router has no Router line: its index is as it was"

# A pack names at most one router, in its own front matter; the index says which.
add_skill() { # <dir> <name> <extra front matter line>
  cat > "$1/skills/alpha/$2.md" <<EOF
---
id: alpha/$2
title: Skill $2
when: When $2 is the question.
needs: []
tools: []
requires_host: []
$3
---

Body of $2.
EOF
}
mk_pack "$WORK/src" router-pack
add_skill "$WORK/src/router-pack" start "router: true"
add_skill "$WORK/src/router-pack" leaf "router: false"
"$PACK" seal "$WORK/src/router-pack" >/dev/null || fail "seal should accept one router and a router: false"
[[ "$(sed -n '/^Router:/p' "$WORK/src/router-pack/skills/INDEX.md")" == 'Router: `alpha/start`' ]] || fail "the index should name the router: $(cat "$WORK/src/router-pack/skills/INDEX.md")"
grep -q '^- `alpha/start` ' "$WORK/src/router-pack/skills/INDEX.md" || fail "the router is still an entry of the index"
# Installed into a home of its own: the list assertions below count on one pack.
DFIRSWARM_HOME="$WORK/home-router" "$PACK" install "$WORK/src/router-pack" --no-secrets >/dev/null && DFIRSWARM_HOME="$WORK/home-router" "$PACK" verify router-pack >/dev/null || fail "a sealed pack with a router should install and verify"
pass "a skill that says router: true is named by a Router line in the generated index, and is still listed"

mk_pack "$WORK/src" two-routers
add_skill "$WORK/src/two-routers" start "router: true"
add_skill "$WORK/src/two-routers" other "router: true"
out="$("$PACK" seal "$WORK/src/two-routers" 2>&1)"; rc=$?
[[ $rc -ne 0 ]] || fail "two routers should be refused: $out"
grep -q 'at most one router' <<<"$out" || fail "the refusal should say why: $out"
mk_pack "$WORK/src" bad-router
add_skill "$WORK/src/bad-router" start "router: yes"
out="$("$PACK" seal "$WORK/src/bad-router" 2>&1)"; rc=$?
[[ $rc -ne 0 ]] && grep -q 'router must be true or false' <<<"$out" || fail "router: yes should be refused, naming the rule: $out"
pass "a second router, and a router that is not true or false, are refused at seal"

"$PACK" install "$WORK/src/base-pack" --no-secrets >/dev/null || fail "install should accept a sealed pack"
"$PACK" verify base-pack >/dev/null || fail "a freshly installed pack should verify"
pass "install and verify"

"$PACK" list | grep -q 'base-pack' || fail "list should show an installed pack"
[[ "$("$PACK" path base-pack)" == "$DFIRSWARM_HOME/packs/base-pack" ]] || fail "path should print the install directory"
pass "list and path"

# A tampered file must be caught by the checksums.
echo "extra" >> "$DFIRSWARM_HOME/packs/base-pack/skills/alpha/first.md"
"$PACK" verify base-pack >/dev/null 2>&1 && fail "verify should refuse a tampered skill"
pass "a tampered file is refused"
"$PACK" install "$WORK/src/base-pack" --no-secrets >/dev/null || fail "re-install should repair"

# An unsealed pack has no checksums and must not install.
mk_pack "$WORK/src" unsealed-pack
"$PACK" install "$WORK/src/unsealed-pack" --no-secrets >/dev/null 2>&1 && fail "an unsealed pack should not install"
pass "a pack with no checksums is refused"

# A skill may name a tool a dependency carries, so this is a warning and not a
# refusal. What must not happen is silence: the name has to be reported.
mk_pack "$WORK/src" broken-pack
sed -i.bak 's/tools: \[echo_tool\]/tools: [no_such_tool]/' "$WORK/src/broken-pack/skills/alpha/first.md"
rm -f "$WORK/src/broken-pack/skills/alpha/first.md.bak"
warn="$("$PACK" seal "$WORK/src/broken-pack" 2>&1 >/dev/null)" || fail "seal should accept a skill naming a dependency's tool"
grep -q "no_such_tool" <<<"$warn" || fail "seal should name the tool it could not find, got: $warn"
pass "a tool a pack does not carry is reported, and left to a dependency"

# A skill with no body at all is still a broken pack.
mk_pack "$WORK/src" empty-pack
cat > "$WORK/src/empty-pack/skills/alpha/first.md" <<'EOF'
---
id: alpha/first
title: The first skill
when: Whenever the suite asks for it.
needs: []
tools: [echo_tool]
requires_host: []
---
EOF
"$PACK" seal "$WORK/src/empty-pack" >/dev/null 2>&1 && fail "seal should refuse a skill with no body"
pass "a skill with no body is refused"

# Dependencies resolve, and a missing one is named.
mk_pack "$WORK/src" child-pack base-pack
"$PACK" seal "$WORK/src/child-pack" >/dev/null || fail "seal child"
"$PACK" install "$WORK/src/child-pack" --no-secrets >/dev/null || fail "install should accept a pack whose dependency is present"
out="$("$PACK" resolve child-pack)"
[[ "$(head -1 <<<"$out")" == *"base-pack" ]] || fail "resolve should put the dependency first, got: $out"
[[ "$(sed -n 2p <<<"$out")" == *"child-pack" ]] || fail "resolve should then give the pack itself"
pass "dependencies resolve, in order"

# A name its dependency carries is no warning, where the dependency sits
# beside the pack: in the checkout when sealing, installed when verifying.
# One no pack in the set carries still is, and so is a dependency that is
# not there. (Kickoffs printed a warning per dependency tool on every run.)
mk_pack "$WORK/src" uses-dep base-pack
sed -i.bak 's/tools: \[echo_tool\]/tools: [echo_tool, base_only_tool]/' "$WORK/src/uses-dep/skills/alpha/first.md"
rm -f "$WORK/src/uses-dep/skills/alpha/first.md.bak"
mkdir -p "$WORK/src/base-pack/tools/base_only_tool"
cp "$WORK/src/base-pack/tools/echo_tool/run.py" "$WORK/src/base-pack/tools/base_only_tool/run.py"
sed 's/"echo_tool"/"base_only_tool"/' "$WORK/src/base-pack/tools/echo_tool/manifest.json" > "$WORK/src/base-pack/tools/base_only_tool/manifest.json"
"$PACK" seal "$WORK/src/base-pack" >/dev/null 2>&1 || fail "reseal base-pack with its new tool"
warn="$("$PACK" seal "$WORK/src/uses-dep" 2>&1 >/dev/null)" || fail "seal uses-dep"
grep -q "base_only_tool" <<<"$warn" && fail "a tool the dependency beside it carries was still warned about: $warn"
sed -i.bak 's/base_only_tool\]/base_only_tool, nowhere_tool]/' "$WORK/src/uses-dep/skills/alpha/first.md"
rm -f "$WORK/src/uses-dep/skills/alpha/first.md.bak"
warn="$("$PACK" seal "$WORK/src/uses-dep" 2>&1 >/dev/null)" || fail "seal uses-dep again"
grep -q "nowhere_tool.*neither this pack nor its dependencies carry" <<<"$warn" || fail "a tool no pack in the set carries was not named: $warn"
mk_pack "$WORK/src" orphan-dep not-here-pack
sed -i.bak 's/tools: \[echo_tool\]/tools: [elsewhere_tool]/' "$WORK/src/orphan-dep/skills/alpha/first.md"
rm -f "$WORK/src/orphan-dep/skills/alpha/first.md.bak"
warn="$("$PACK" seal "$WORK/src/orphan-dep" 2>&1 >/dev/null)" || fail "seal orphan-dep"
grep -q "elsewhere_tool.*not-here-pack is not beside it" <<<"$warn" || fail "a missing dependency was not named: $warn"
pass "a name a dependency carries is no warning; one no pack carries, or a dependency that is absent, is"

# Two packs with a tool of the same name: one run holds one tool per name, so
# the kickoff is told which packs collide. The same script twice is one tool.
mk_pack "$WORK/src" twin-pack
printf 'print("the twin")\n' >> "$WORK/src/twin-pack/tools/echo_tool/run.py"
"$PACK" seal "$WORK/src/twin-pack" >/dev/null || fail "seal twin"
"$PACK" install "$WORK/src/twin-pack" --no-secrets >/dev/null || fail "install twin"
out="$("$PACK" resolve base-pack,twin-pack 2>"$WORK/resolve.err")" || fail "resolve refused two packs that share a tool name"
[[ "$(wc -l <<<"$out" | tr -d ' ')" == 2 ]] || fail "resolve should still give both packs, got: $out"
grep -q 'packs base-pack and twin-pack both carry a tool named echo_tool' "$WORK/resolve.err" \
  || fail "resolve did not name both packs and the tool they share: $(cat "$WORK/resolve.err")"
mk_pack "$WORK/src" same-pack
"$PACK" seal "$WORK/src/same-pack" >/dev/null || fail "seal same"
"$PACK" install "$WORK/src/same-pack" --no-secrets >/dev/null || fail "install same"
"$PACK" resolve base-pack,same-pack >/dev/null 2>"$WORK/resolve.err" || fail "resolve refused two packs with the same tool"
[[ ! -s "$WORK/resolve.err" ]] || fail "the same script in two packs is one tool, not a collision: $(cat "$WORK/resolve.err")"
pass "two packs carrying different tools of one name are named at resolve; the same tool twice is not"

"$PACK" remove base-pack >/dev/null
"$PACK" resolve child-pack >/dev/null 2>&1 && fail "resolve should refuse when a dependency is gone"
pass "a missing dependency is refused"
"$PACK" install "$WORK/src/base-pack" --no-secrets >/dev/null

mk_pack "$WORK/src" orphan-pack absent-pack
"$PACK" seal "$WORK/src/orphan-pack" >/dev/null || fail "seal orphan"
"$PACK" install "$WORK/src/orphan-pack" --no-secrets >/dev/null 2>&1 && fail "install should refuse a pack whose dependency is not installed"
pass "install refuses a pack whose dependency is missing"

# The zip is the import format, and its shape is checked.
if command -v zip >/dev/null 2>&1 && command -v unzip >/dev/null 2>&1; then
  ( cd "$WORK/src" && zip -qr "$WORK/base-pack.zip" base-pack )
  "$PACK" remove base-pack >/dev/null
  "$PACK" install "$WORK/base-pack.zip" --no-secrets >/dev/null || fail "install should accept a zip holding one pack directory"
  "$PACK" verify base-pack >/dev/null || fail "a pack installed from a zip should verify"
  pass "a pack imports from a zip"
  ( cd "$WORK/src" && zip -qr "$WORK/bad.zip" base-pack child-pack )
  "$PACK" install "$WORK/bad.zip" --no-secrets >/dev/null 2>&1 && fail "a zip with two directories at its top should be refused"
  pass "a zip must hold exactly one pack directory"
else
  echo "skip - zip/unzip are not on this host"
fi

# A secret is stored 0600 and never in the pack's own tree.
mk_pack "$WORK/src" secret-pack
python3 - "$WORK/src/secret-pack/pack.json" <<'EOF'
import json, sys
m = json.load(open(sys.argv[1]))
m["secrets"] = [{"name": "TEST_API_KEY", "title": "A key", "why": "So the suite can check the store.", "required": False}]
json.dump(m, open(sys.argv[1], "w"), indent=2)
EOF
"$PACK" seal "$WORK/src/secret-pack" >/dev/null || fail "seal secret pack"
TEST_API_KEY=hunter2 "$PACK" install "$WORK/src/secret-pack" >/dev/null 2>&1 || fail "install should take a secret from the environment"
env_file="$DFIRSWARM_HOME/secrets/secret-pack.env"
[[ ! -e "$DFIRSWARM_HOME/packs/secret-pack/secrets.env" ]] || fail "the secret was written inside the pack directory, which every VM mounts"
"$PACK" verify secret-pack >/dev/null || fail "a pack with a stored secret must still verify"
[[ -f "$env_file" ]] || fail "the secret should be stored"
grep -q 'TEST_API_KEY=hunter2' "$env_file" || fail "the stored secret should hold the value"
# GNU stat first: its -f means --file-system, so asking BSD-style first prints a
# block of filesystem text on Linux before it fails, and that lands in perm.
perm="$(stat -c '%a' "$env_file" 2>/dev/null || stat -f '%Lp' "$env_file")"
[[ "$perm" == "600" ]] || fail "secrets.env should be 0600, got $perm"
pass "a declared secret is stored 0600, outside the pack's sealed files"

# A saved tool taken into a pack: sealed, reduced to what a pack tool says.
mkdir -p "$WORK/saved/carve_it"
printf 'print("carved")\n' > "$WORK/saved/carve_it/run.py"
csha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$WORK/saved/carve_it/run.py")"
printf '{"name": "carve_it", "description": "Carve it.", "params": {}, "runtime": "python3", "entry": "run.py", "timeout_seconds": 30, "by": "s1", "at": "t", "version": 3, "sha256": "%s", "pack": "other-pack"}\n' "$csha" > "$WORK/saved/carve_it/manifest.json"
printf '{"saved_from_run": "s1"}\n' > "$WORK/saved/carve_it/provenance.json"
mk_pack "$WORK/src" adopt-pack
"$PACK" adopt "$WORK/saved/carve_it" "$WORK/src/adopt-pack" >/dev/null || fail "adopt refused a sealed tool"
jq -e '(has("by") or has("pack") or has("sha256") or has("version")) | not' "$WORK/src/adopt-pack/tools/carve_it/manifest.json" >/dev/null \
  || fail "the adopted manifest kept the run's fields: $(cat "$WORK/src/adopt-pack/tools/carve_it/manifest.json")"
[[ -f "$WORK/src/adopt-pack/tools/carve_it/provenance.json" ]] || fail "the provenance did not come along"
"$PACK" seal "$WORK/src/adopt-pack" >/dev/null 2>&1 || fail "a pack with an adopted tool does not seal"
"$PACK" adopt "$WORK/saved/carve_it" "$WORK/src/adopt-pack" >/dev/null 2>&1 && fail "adopt replaced a tool without --replace"
printf 'print("changed")\n' >> "$WORK/saved/carve_it/run.py"
"$PACK" adopt "$WORK/saved/carve_it" "$WORK/src/adopt-pack" --replace >/dev/null 2>&1 && fail "adopt took a tool whose script no longer matches its sha256"
pass "adopt takes a sealed saved tool into a pack without the run's fields, and refuses a changed one"

# Every shipped pack must be sealed, must install and must verify. Install in
# dependency order rather than alphabetically: a pack whose dependency is not
# installed yet is refused, which is the behaviour the tests above assert.
remaining=()
for p in "$ROOT"/packs/*/; do
  [[ -f "$p/pack.json" ]] && remaining+=("$p")
done
installed=0
while ((${#remaining[@]})); do
  progress=0
  left=()
  for p in "${remaining[@]}"; do
    id="$(basename "$p")"
    if "$PACK" install "$p" --no-secrets >/dev/null 2>&1; then
      "$PACK" verify "$id" >/dev/null || fail "the shipped pack $id does not verify"
      pass "shipped pack $id installs and verifies"
      progress=1
      installed=$((installed + 1))
    else
      left+=("$p")
    fi
  done
  if ((progress == 0)); then
    for p in "${left[@]}"; do
      id="$(basename "$p")"
      "$PACK" install "$p" --no-secrets >/dev/null || true
    done
    fail "these shipped packs never became installable: ${left[*]}"
  fi
  remaining=(${left[@]+"${left[@]}"})
done
[[ "$installed" -ge 2 ]] || fail "expected at least the two original packs, installed $installed"
pass "all $installed shipped packs install in dependency order and verify"

echo "packs: all checks passed"
