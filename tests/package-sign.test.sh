#!/usr/bin/env bash
# A package signed with the examiner's ssh key (swarm.sh package --sign) and
# checked where it lands (swarm.sh verify): every file against MANIFEST.txt,
# nothing missing or added, and the signature, with exit codes a script can
# act on; who signed and when under the signature; the index custody sealed
# carried, and every work/ file held to it. No model, no Herdr, no VM; a key
# made for the test.
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

echo "# who signed and when are under the signature: SIGNER.txt and signer.pub are in the manifest"
out="$(swarm package "$id" --sign --key "$TMP/key")" || fail "repackaging failed: $out"
grep -qE '^[0-9a-f]{64}  \./SIGNER\.txt$' "$pkg/MANIFEST.txt" && grep -qE '^[0-9a-f]{64}  \./signer\.pub$' "$pkg/MANIFEST.txt" || fail "SIGNER.txt or signer.pub is not in the signed manifest: $(cat "$pkg/MANIFEST.txt")"
grep -qE '^[0-9a-f]{64}  \./COMPONENTS\.json$' "$pkg/MANIFEST.txt" || fail "COMPONENTS.json is not in the manifest"
verify "$pkg" --allowed-signers "$TMP/allowed"
[[ $rc -eq 0 ]] && grep -q 'SIGNER.txt (who, which key, when) is in the manifest it covers' <<<"$out" || fail "the signer's place is not said (rc $rc): $out"
chmod -R u+w "$pkg"
sed -i.bak 's/^examiner .*/examiner Someone Else/' "$pkg/SIGNER.txt" && rm -f "$pkg/SIGNER.txt.bak"
verify "$pkg" --allowed-signers "$TMP/allowed"
[[ $rc -eq 1 ]] && grep -q 'changed: SIGNER.txt' <<<"$out" || fail "an examiner's name changed after signing was not caught (rc $rc): $out"
pass "SIGNER.txt and signer.pub are in the manifest the signature covers: a name or a time changed afterwards is caught"

echo "# the package carries the index custody sealed, and every work/ file is held to it"
mkdir -p "$sb/work"
printf '# Report\n\nNothing found.\n' > "$sb/work/report.md"
node --experimental-strip-types --no-warnings "$ROOT/scripts/custody.ts" "$sb" --run "$id" --quiet --runs-dir "$SWARM_RUNS_DIR" >/dev/null 2>&1 || true
[[ -s "$sb/artifacts.json" ]] || fail "custody wrote no index"
out="$(swarm package "$id" --sign --key "$TMP/key")" || fail "packaging after custody failed: $out"
cmp -s "$sb/artifacts.json" "$pkg/artifacts.sealed.json" || fail "the package's sealed index is not the one custody wrote"
jq -e '.components[] | select(.path == "artifacts.sealed.json") | .present == true' "$pkg/COMPONENTS.json" >/dev/null || fail "COMPONENTS.json does not list the sealed index"
verify "$pkg" --allowed-signers "$TMP/allowed"
[[ $rc -eq 0 ]] && grep -q 'Work files:   every packaged work/ file is the one custody sealed: 1 as sealed' <<<"$out" || fail "a sealed package did not verify its work files (rc $rc): $out"
# The report edited in the run after the stop, and the run packaged again: signed, and not as sealed.
printf 'Added after the stop.\n' >> "$sb/work/report.md"
out="$(swarm package "$id" --sign --key "$TMP/key")" || fail "repackaging failed: $out"
verify "$pkg" --allowed-signers "$TMP/allowed"
[[ $rc -eq 1 ]] && grep -q 'NOT AS SEALED: 1 CHANGED (work/report.md)' <<<"$out" || fail "a report edited after custody verified (rc $rc): $out"
grep -q 'CHANGED SINCE CUSTODY' "$pkg/report.html" || fail "the packaged report does not say its own report changed since custody"
pass "the sealed index travels with the package, and a work file changed after the stop fails verify, signed or not"

echo "# the package carries the store sweeps' side lists, and verify holds each to the sha256 its line names"
# A sweep line that found 80 hits: the line keeps a few and names the file that holds them all.
node --experimental-strip-types --no-warnings --input-type=module -e '
const SW = await import(process.argv[1]);
const { writeFileSync, mkdirSync } = await import("node:fs");
const { join } = await import("node:path");
const S = process.argv[2];
mkdirSync(join(S, "ledger"), { recursive: true });
const hits = Array.from({ length: 80 }, (_, i) => ({ ref: `job:j000001/rows/row-${i}.txt`, term: "mallory", count: 1, first_offset: 0, encodings: ["utf-8"] }));
const written = await SW.sweepLineAsWritten(S, { v: 1, seq: 1, target: "0".repeat(64), rules: SW.SWEEP_RULES, state: "hits", terms: ["mallory"], searched: { objects: 80, bytes: 800 }, hits, named_hits: [], echoes: [], unsearched: [], started_at: "2026-11-14T00:00:00.000Z", at: "2026-11-14T00:00:01.000Z" });
const line = { ...written, prev: "genesis" };
line.hash = SW.sweepHash(line, "genesis");
writeFileSync(join(S, "ledger", "sweeps.jsonl"), `${JSON.stringify(line)}\n`);
' "$ROOT/extensions/store-sweep.ts" "$sb" || fail "could not write a sweep line with a side list"
side="$(ls "$sb"/ledger/sweeps/hits-*.jsonl)"
[[ -f "$side" ]] || fail "no side list was written"
# Custody taken again (the report above was edited after the last one): it seals the sweeps and holds the side list to its line.
node --experimental-strip-types --no-warnings "$ROOT/scripts/custody.ts" "$sb" --run "$id" --quiet --runs-dir "$SWARM_RUNS_DIR" >/dev/null 2>&1 || true
jq -e '.sweeps.intact == true and (.sweeps.detail | test("1 side list\\(s\\) of what was not searched or what was found, each as its line names it"))' "$sb/custody.json" >/dev/null || fail "custody did not hold the side list to its line: $(jq -c '.sweeps' "$sb/custody.json")"
out="$(swarm package "$id" --sign --key "$TMP/key")" || fail "packaging with a sweep's side list failed: $out"
[[ -f "$pkg/ledger-sweeps/$(basename "$side")" ]] || fail "the package does not carry the side list: $(ls "$pkg")"
[[ ! -e "$pkg/ledger-sweeps/cache" ]] || fail "the package carries the sweeps' kept results"
grep -qE "^[0-9a-f]{64}  \./ledger-sweeps/$(basename "$side")\$" "$pkg/MANIFEST.txt" || fail "the side list is not in the manifest"
jq -e '.components[] | select(.path == "ledger-sweeps") | .present == true' "$pkg/COMPONENTS.json" >/dev/null || fail "COMPONENTS.json does not list the side lists"
verify "$pkg" --allowed-signers "$TMP/allowed"
[[ $rc -eq 0 ]] && grep -q 'Sweep lists:  1 side list(s) named by the sweep lines, each in ledger-sweeps/ as its line names it' <<<"$out" || fail "a package with a sweep's side list did not verify it (rc $rc): $out"
# The side list changed in the run after its line was written, and the run packaged again: signed, and not as its line names.
chmod u+w "$side"
printf '{"list":"hits","ref":"job:j000001/forged.txt","term":"mallory","count":1,"first_offset":0,"encodings":["utf-8"]}\n' >> "$side"
out="$(swarm package "$id" --sign --key "$TMP/key")" || fail "repackaging failed: $out"
verify "$pkg" --allowed-signers "$TMP/allowed"
[[ $rc -eq 1 ]] && grep -q 'Sweep lists:  1 side list(s) named by the sweep lines, 1 NOT AS NAMED in ledger-sweeps/' <<<"$out" || fail "a side list changed after its line verified (rc $rc): $out"
pass "the store sweeps' side lists travel with the package, under its manifest, and a list that is not the one its line names fails verify"

echo "package-sign.test.sh: all checks passed"
