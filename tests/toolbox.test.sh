#!/usr/bin/env bash
# The crypto set's aescrypt row is pyAesCrypt, not a PATH binary named aescrypt.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/toolbox.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/sb"

# python3 answers the pyAesCrypt probe; nothing named aescrypt is on PATH.
cat > "$TMP/bin/python3" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
  echo "Python 3.12.0"
  exit 0
fi
if [[ "${1:-}" == "-c" ]]; then
  case "${2:-}" in
    *pyAesCrypt*) echo "pyAesCrypt ok"; exit 0 ;;
  esac
  exit 1
fi
exit 1
EOF
chmod +x "$TMP/bin/python3"
command -v jq >/dev/null || fail "jq required"
ln -s "$(command -v jq)" "$TMP/bin/jq"

# Keep the usual shell tools, but never an aescrypt binary.
PATH="$TMP/bin:/usr/bin:/bin"
command -v aescrypt >/dev/null 2>&1 && fail "this test needs a PATH with no aescrypt binary"

bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" crypto >/dev/null
jq -e '.present[] | select(.name == "aescrypt")' "$TMP/sb/toolbox.json" >/dev/null \
  || fail "pyAesCrypt is installed (the probe succeeded) but aescrypt was listed missing: $(cat "$TMP/sb/toolbox.json")"
jq -e '.missing[] | select(.name == "aescrypt")' "$TMP/sb/toolbox.json" >/dev/null \
  && fail "aescrypt must not be missing when import pyAesCrypt works"
pass "toolbox crypto treats pyAesCrypt as aescrypt, without a PATH binary"

# And when the import fails, it is missing — --toolbox-required is a BLOCKER.
cat > "$TMP/bin/python3" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == "--version" ]] && { echo "Python 3.12.0"; exit 0; }
exit 1
EOF
chmod +x "$TMP/bin/python3"
rm -f "$TMP/sb/toolbox.json"
set +e
out="$(bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" crypto --required 2>&1)"
rc=$?
set -e
[[ "$rc" -eq 3 ]] || fail "missing pyAesCrypt with --required should exit 3, got $rc: $out"
grep -q "aescrypt" <<<"$out" || fail "the BLOCKER should name aescrypt: $out"
jq -e '.missing[] | select(.name == "aescrypt")' "$TMP/sb/toolbox.json" >/dev/null \
  || fail "toolbox.json should list aescrypt as missing when the import fails"
pass "toolbox crypto reports aescrypt missing when pyAesCrypt cannot be imported"

# In a microVM run's image: every program the packs name is checked too, the
# hints are the VM's, and --required holds only for what a pack requires.
cat > "$TMP/image.json" <<'JSON'
{"image": "dfirswarm-disk:dev-arm64", "programs": [
  {"name": "dfs-needed-tool", "why": "a pack requires it", "pack": "p1", "required": true},
  {"name": "dfs-nice-tool", "why": "a pack may use it", "pack": "p1", "required": false}
]}
JSON
rm -f "$TMP/sb/toolbox.json"
set +e
out="$(bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" crypto --required --image "$TMP/image.json" 2>&1)"; rc=$?
set -e
[[ "$rc" -eq 3 ]] || fail "a program a pack requires, missing from the image, with --required should exit 3, got $rc: $out"
grep -q 'BLOCKER: --toolbox-required and these tools are missing: dfs-needed-tool\.' <<<"$out" \
  || fail "only the pack's required program should block, not the crypto presets the image lacks: $out"
jq -e '.context == "image" and .image == "dfirswarm-disk:dev-arm64"' "$TMP/sb/toolbox.json" >/dev/null || fail "toolbox.json does not say it describes the image"
jq -e '.missing[] | select(.name == "dfs-nice-tool") | .use == "a pack may use it (p1)"' "$TMP/sb/toolbox.json" >/dev/null || fail "an optional pack program is not listed with its pack"
if jq -r '.missing[].install' "$TMP/sb/toolbox.json" | grep -q -E 'brew|--user'; then fail "a VM's install hint says brew or pip --user"; fi
cat > "$TMP/image.json" <<'JSON'
{"image": "x", "programs": [{"name": "dfs-nice-tool", "why": "optional", "pack": "p1", "required": false}]}
JSON
bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" crypto --required --image "$TMP/image.json" >/dev/null 2>&1 \
  || fail "in an image, a preset tool or an optional pack program the image lacks should not block"
pass "in an image, pack programs are checked, the hints are the VM's, and --required holds only for what packs require"

# A program another system has (Apple's log, a collector run on the source
# host) is said to be not applicable in an image: never missing, never
# blocking, even when a pack were to require it.
cat > "$TMP/image.json" <<'JSON'
{"image": "x", "programs": [
  {"name": "dfs-mac-only", "why": "Apple's reader", "pack": "p2", "required": true, "not_in_image": "Only macOS has it."},
  {"name": "dfs-nice-tool", "why": "optional", "pack": "p1", "required": false}
]}
JSON
rm -f "$TMP/sb/toolbox.json"
bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" dfir --required --image "$TMP/image.json" >/dev/null 2>&1 \
  || fail "another system's program blocked the image check"
jq -e '.not_applicable == [{"name": "dfs-mac-only", "pack": "p2", "why": "Only macOS has it."}]' "$TMP/sb/toolbox.json" >/dev/null \
  || fail "another system's program is not listed as not applicable: $(jq -c '.not_applicable' "$TMP/sb/toolbox.json")"
jq -e '[.present[], .missing[]] | map(.name) | index("dfs-mac-only") == null' "$TMP/sb/toolbox.json" >/dev/null \
  || fail "another system's program was looked for in the image"
jq -e '.missing | map(.name) | index("dfs-nice-tool") != null' "$TMP/sb/toolbox.json" >/dev/null || fail "the other pack programs are still checked"
rm -f "$TMP/sb/toolbox.json"
bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" dfir >/dev/null 2>&1 || true
jq -e 'has("not_applicable") | not' "$TMP/sb/toolbox.json" >/dev/null || fail "a host check lists programs as not applicable"
pass "in an image, a program another system has is listed as not applicable, never missing or blocking"

# An image that describes itself: toolbox.json says where its tools.md is, so
# the contract can point at that file instead of listing programs. Only an
# image check says so; a host has no such file.
printf '# Programs in this VM\n' > "$TMP/tools.md"
rm -f "$TMP/sb/toolbox.json"
DFIRSWARM_TOOLS_MD="$TMP/tools.md" bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" dfir --image "$TMP/image.json" >/dev/null 2>&1 || true
jq -e '.tools_md == "/etc/dfirswarm/tools.md"' "$TMP/sb/toolbox.json" >/dev/null || fail "an image with tools.md is not recorded as having it: $(cat "$TMP/sb/toolbox.json")"
rm -f "$TMP/sb/toolbox.json"
DFIRSWARM_TOOLS_MD="$TMP/no-such.md" bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" dfir --image "$TMP/image.json" >/dev/null 2>&1 || true
jq -e 'has("tools_md") | not' "$TMP/sb/toolbox.json" >/dev/null || fail "an image without tools.md was said to have one"
rm -f "$TMP/sb/toolbox.json"
DFIRSWARM_TOOLS_MD="$TMP/tools.md" bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" dfir >/dev/null 2>&1 || true
jq -e 'has("tools_md") | not' "$TMP/sb/toolbox.json" >/dev/null || fail "a host check claimed an image's tools.md"
pass "an image check records the image's tools.md, and only when the image has one"

# Each tool's fields, whole: the version probe has a pipe of its own, and the
# use column once read " head -1" for every tool.
rm -f "$TMP/sb/toolbox.json"
bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" dfir >/dev/null 2>&1 || true
if jq -r '(.present + .missing)[].use' "$TMP/sb/toolbox.json" | grep -q 'head -1'; then fail "a tool's use is the tail of its version probe"; fi
jq -e '(.present + .missing)[] | select(.name == "mmls") | .use == "partition table of a disk image (The Sleuth Kit)"' "$TMP/sb/toolbox.json" >/dev/null \
  || fail "mmls's use is not what the table says: $(jq -c '(.present + .missing)[] | select(.name == "mmls")' "$TMP/sb/toolbox.json")"
if jq -r '.missing[].install' "$TMP/sb/toolbox.json" | grep -q '|'; then fail "an install hint carries another field"; fi
pass "each tool's use and install hint are its own, not the tail of the version probe"

# A Python library is present when its import works, whatever its name: the
# probe used to be honoured for three names only, so pybde, pyvhdi, pytsk3
# and dfvfs were listed missing on a host that had them.
cat > "$TMP/bin/python3" <<'PYFAKE'
#!/usr/bin/env bash
[[ "${1:-}" == "--version" ]] && { echo "Python 3.12.0"; exit 0; }
if [[ "${1:-}" == "-c" ]]; then
  case "${2:-}" in
    *"import pybde"*|*"import pyvhdi"*|*"import pyvshadow"*|*"import pyvslvm"*) echo "20240101"; exit 0 ;;
  esac
fi
exit 1
PYFAKE
chmod +x "$TMP/bin/python3"
for b in vshadowinfo xfs_db vslvminfo; do printf '#!/usr/bin/env bash\necho "%s 20240101"\n' "$b" > "$TMP/bin/$b"; chmod +x "$TMP/bin/$b"; done
rm -f "$TMP/sb/toolbox.json"
bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" crypto,linux >/dev/null 2>&1 || true
for n in pybde pyvhdi pyvshadow pyvslvm vshadowinfo xfs_db vslvminfo; do
  jq -e --arg n "$n" '.present[] | select(.name == $n)' "$TMP/sb/toolbox.json" >/dev/null \
    || fail "$n is on this host but toolbox.json does not list it present: $(jq -c '.missing | map(.name)' "$TMP/sb/toolbox.json")"
done
jq -e '.missing[] | select(.name == "pytsk3")' "$TMP/sb/toolbox.json" >/dev/null \
  || fail "pytsk3 cannot be imported here and should be missing"
pass "python libraries are probed by import, and the VSS, XFS and LVM readers are checked"

# Each reader is in the set that its cases ask for, and only there.
rm -f "$TMP/sb/toolbox.json"
bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" crypto >/dev/null 2>&1 || true
names="$(jq -r '[.present[], .missing[]] | map(.name) | join(" ")' "$TMP/sb/toolbox.json")"
[[ " $names " == *" vshadowinfo "* && " $names " == *" pyvshadow "* ]] || fail "the crypto set should check libvshadow: $names"
[[ " $names " == *" xfs_db "* || " $names " == *" vslvminfo "* ]] && fail "XFS and LVM readers belong to the linux set: $names"
rm -f "$TMP/sb/toolbox.json"
bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" linux >/dev/null 2>&1 || true
names="$(jq -r '[.present[], .missing[]] | map(.name) | join(" ")' "$TMP/sb/toolbox.json")"
[[ " $names " == *" xfs_db "* && " $names " == *" vslvminfo "* && " $names " == *" pyvslvm "* ]] || fail "the linux set should check xfsprogs and libvslvm: $names"
[[ " $names " == *" vshadowinfo "* ]] && fail "libvshadow belongs to the crypto set: $names"
pass "libvshadow is in the crypto set; xfsprogs and libvslvm are in the linux set"
