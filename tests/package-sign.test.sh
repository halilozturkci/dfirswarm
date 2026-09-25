#!/usr/bin/env bash
# A package signed with the examiner's ssh key (swarm.sh package --sign) and
# checked where it lands (swarm.sh verify): every file against MANIFEST.txt,
# nothing missing or added, and the signature, with exit codes a script can
# act on. No model, no Herdr, no VM; a key made for the test.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/package-sign.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
command -v ssh-keygen >/dev/null 2>&1 || { echo "ok - skipped: no ssh-keygen on this host"; exit 0; }
export SWARM_RUNS_DIR="$TMP/runs"
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
verify() { # <target> [args] -> sets rc and out
  set +e
  out="$(swarm verify "$@")"
  rc=$?
  set -e
}

ssh-keygen -q -t ed25519 -N "" -C "examiner@test" -f "$TMP/key" >/dev/null
out="$(swarm start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off --label signed --examiner "A. Examiner")" || fail "kickoff failed: $out"
id="$(printf '%s\n' "$out" | sed -n 's/^Swarm id: *//p' | tail -1)"
sb="$(printf '%s\n' "$out" | sed -n 's/^SANDBOX=//p' | tail -1)"

echo "# package --sign signs MANIFEST.txt with the key it is given"
out="$(swarm package "$id" --sign --key "$TMP/key")" || fail "package --sign failed: $out"
pkg="$sb/package"
[[ -s "$pkg/MANIFEST.txt.sig" && -s "$pkg/signer.pub" && -s "$pkg/SIGNER.txt" ]] || fail "the signature, the key or the signer is missing: $(ls "$pkg")"
grep -q '^examiner A. Examiner$' "$pkg/SIGNER.txt" || fail "SIGNER.txt does not name the examiner: $(cat "$pkg/SIGNER.txt")"
principal="$(awk '$1 == "principal" {print $2}' "$pkg/SIGNER.txt")"
printf '%s %s\n' "$principal" "$(awk '{print $1, $2}' "$TMP/key.pub")" > "$TMP/allowed"
grep -q "^Signed: " <<<"$out" || fail "the signing is not said: $out"
pass "package --sign writes MANIFEST.txt.sig, signer.pub and SIGNER.txt"

echo "# verify: exit 0 signed by an allowed signer, 3 signer not checked, 4 unsigned, 1 anything off"
verify "$pkg" --allowed-signers "$TMP/allowed"
[[ $rc -eq 0 ]] || fail "a sound package from an allowed signer exited $rc: $out"
grep -q '^VERIFIED: ' <<<"$out" || fail "the verdict is not said: $out"
verify "$pkg"
[[ $rc -eq 3 ]] || fail "without --allowed-signers the verdict exited $rc, wanted 3: $out"
grep -q 'who signed was not checked' <<<"$out" || fail "an unchecked signer is not said: $out"
# Another key the allowed list does not name.
ssh-keygen -q -t ed25519 -N "" -f "$TMP/other" >/dev/null
printf '%s %s\n' "$principal" "$(awk '{print $1, $2}' "$TMP/other.pub")" > "$TMP/allowed-other"
verify "$pkg" --allowed-signers "$TMP/allowed-other"
[[ $rc -eq 1 ]] || fail "a signer the list does not allow exited $rc: $out"
grep -q 'DOES NOT VERIFY' <<<"$out" || fail "a disallowed signer is not said: $out"
# The zip a package is handed over as.
(cd "$sb" && python3 -c 'import os, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    for d, _, fs in os.walk("package"):
        for f in fs: z.write(os.path.join(d, f))' "$TMP/pkg.zip")
verify "$TMP/pkg.zip" --allowed-signers "$TMP/allowed"
[[ $rc -eq 0 ]] || fail "the zip of a sound package exited $rc: $out"
# A byte changed, a file added, a file taken away.
chmod -R u+w "$pkg"
printf 'x' >> "$pkg/team.json"
verify "$pkg" --allowed-signers "$TMP/allowed"
[[ $rc -eq 1 ]] && grep -q 'changed: team.json' <<<"$out" || fail "a changed file was not caught (rc $rc): $out"
out="$(swarm package "$id" --sign --key "$TMP/key")" || fail "repackaging failed"
printf 'late\n' > "$pkg/added.txt"
verify "$pkg" --allowed-signers "$TMP/allowed"
[[ $rc -eq 1 ]] && grep -q 'not in the manifest: added.txt' <<<"$out" || fail "an added file was not caught (rc $rc): $out"
rm -f "$pkg/added.txt" "$pkg/SWARM.md"
verify "$pkg" --allowed-signers "$TMP/allowed"
[[ $rc -eq 1 ]] && grep -q 'missing: SWARM.md' <<<"$out" || fail "a missing file was not caught (rc $rc): $out"
# Unsigned.
out="$(swarm package "$id")" || fail "an unsigned package failed"
[[ ! -e "$pkg/MANIFEST.txt.sig" ]] || fail "an unsigned package kept an old signature"
verify "$pkg"
[[ $rc -eq 4 ]] || fail "an unsigned sound package exited $rc: $out"
# A manifest edited to match a changed file breaks the signature.
out="$(swarm package "$id" --sign --key "$TMP/key")" || fail "repackaging failed"
chmod -R u+w "$pkg"
printf 'x' >> "$pkg/team.json"
new="$( (shasum -a 256 "$pkg/team.json" 2>/dev/null || sha256sum "$pkg/team.json") | cut -d' ' -f1)"
python3 - "$pkg/MANIFEST.txt" "$new" <<'PY'
import sys
p, new = sys.argv[1], sys.argv[2]
lines = open(p).read().splitlines()
lines = [(new + line[64:]) if line.endswith("./team.json") else line for line in lines]
open(p, "w").write("\n".join(lines) + "\n")
PY
verify "$pkg" --allowed-signers "$TMP/allowed"
[[ $rc -eq 1 ]] && grep -q 'DOES NOT VERIFY' <<<"$out" || fail "a manifest rewritten after signing passed (rc $rc): $out"
pass "verify re-hashes every file, catches a change, an addition and a removal, and checks the signature (0/1/3/4)"

echo "# without a key, --sign refuses rather than hand over an unsigned package as signed"
set +e
out="$(HOME="$TMP/nohome" swarm package "$id" --sign)"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'no key to sign the package with' <<<"$out" || fail "--sign with no key did not refuse (rc $rc): $out"
pass "--sign with no key refuses"

echo "package-sign.test.sh: all checks passed"
