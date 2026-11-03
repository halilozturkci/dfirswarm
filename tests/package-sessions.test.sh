#!/usr/bin/env bash
# The sessions component of a package (swarm.sh package --with-sessions): an
# opt-in part of an internal handover. The agents' sessions (.pi-sessions/)
# travel as one archive and a manifest, every recorded sensitive value masked
# by a keyed id; `verify` checks them; the flag is refused together with
# --redact; a session file changed after the cutoff is named. No model, no
# Herdr, no VM.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/package-sessions-test.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
export SWARM_RUNS_DIR="$TMP/runs" SWARM_SIGNERS_HOME="$TMP/signers"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
swarm() { bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }

KEY="5f3c9a17e2b84d06a1c7f9e3b2d58a40"
out="$(swarm start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off --label sessions)" || fail "kickoff: $out"
SB="$(sed -n 's/^SANDBOX=//p' <<<"$out" | tail -1)"
ID="$(jq -r --arg sb "$SB" '.runs[] | select(.sandbox == $sb) | .id' "$SWARM_RUNS_DIR/registry.json")"
[[ -n "$SB" && -n "$ID" ]] || fail "no sandbox from the kickoff: $out"
jq --arg id "$ID" '(.runs[] | select(.id == $id) | .state) = "done"' "$SWARM_RUNS_DIR/registry.json" > "$TMP/r" && mv "$TMP/r" "$SWARM_RUNS_DIR/registry.json"
ROOT="$ROOT" node --experimental-strip-types --no-warnings -e '
const [root, key] = process.argv.slice(1);
const P = await import(process.env.ROOT + "/extensions/protocol.ts");
const r = await P.recordEntry({ sandboxRoot: root, agentId: "a0" }, { kind: "ioc", value: `Vault key ${key}`, source: "memory", evidence: "strings over the dump", sensitive: true });
if (!r.ok) { console.error(r.reason); process.exit(1); }
' "$SB" "$KEY" || fail "the sensitive entry was not recorded"

# Two seats' sessions: one holds the value (plain, and in a name), the other none.
mkdir -p "$SB/.pi-sessions/a0" "$SB/.pi-sessions/a1"
printf '{"role":"tool","text":"the vault key is %s"}\n{"role":"assistant","text":"noted"}\n' "$KEY" > "$SB/.pi-sessions/a0/s1.jsonl"
printf '{"role":"assistant","text":"a second seat, nothing sensitive"}\n' > "$SB/.pi-sessions/a1/s2.jsonl"
printf 'a file named after the value\n' > "$SB/.pi-sessions/a0/note-$KEY.txt"
# A link and a FIFO are never followed, nor read.
echo "the operator's own file" > "$TMP/outside.txt"
ln -s "$TMP/outside.txt" "$SB/.pi-sessions/a0/link.jsonl"
mkfifo "$SB/.pi-sessions/a1/pipe"

echo "# a package without the flag carries no sessions"
out="$(swarm package "$ID")" || fail "package: $out"
[[ ! -e "$SB/package/sessions" ]] || fail "a package without --with-sessions carries sessions"
jq -e '.components[] | select(.path == "sessions") | .present == false' "$SB/package/COMPONENTS.json" >/dev/null || fail "COMPONENTS.json does not say sessions are absent"
pass "sessions travel only on request, and COMPONENTS.json says they are absent"

echo "# --with-sessions carries one archive and a manifest, the value masked"
out="$(swarm package "$ID" --with-sessions)" || fail "package --with-sessions: $out"
grep -q '^Sessions: .*3 file(s) in sessions/sessions.tar.gz' <<<"$out" || fail "the sessions are not said: $out"
grep -q "$KEY" <<<"$out" && fail "the package output printed the value"
PK="$SB/package"
[[ -s "$PK/sessions/sessions.tar.gz" && -s "$PK/sessions/sessions.manifest.json" ]] || fail "the archive or its manifest is missing"
M="$PK/sessions/sessions.manifest.json"
jq -e '(.files | length) == 3 and (.skipped | length) == 2 and (.files | all(.size_before > 0 and (.sha256_before | length) == 64 and (.sha256_after | length) == 64 and (.restore_to | startswith(".pi-sessions/")))) and (.cutoff | length) > 0' "$M" >/dev/null || fail "the manifest lacks its sizes, hashes, restore map or cutoff: $(cat "$M")"
[[ "$(jq -r '.archive.sha256' "$M")" == "$(sha256sum "$PK/sessions/sessions.tar.gz" | cut -d' ' -f1)" ]] || fail "the manifest's archive hash is not the archive's"
grep -q "$KEY" "$M" && fail "the manifest names the value"
X="$TMP/restored"
mkdir -p "$X"
tar -xzf "$PK/sessions/sessions.tar.gz" -C "$X"
grep -rq "$KEY" "$X" && fail "the value is in the archive"
grep -q 'hidden-[0-9a-f]\{24\}' "$X/.pi-sessions/a0/s1.jsonl" || fail "the keyed id is not in the session"
grep -q 'the vault key is' "$X/.pi-sessions/a0/s1.jsonl" || fail "masking cut the evidence text the model read"
[[ "$(find "$X/.pi-sessions" -type f | wc -l)" -eq 3 ]] || fail "the archive holds other than three regular files"
[[ ! -e "$X/.pi-sessions/a0/link.jsonl" && ! -e "$X/.pi-sessions/a1/pipe" ]] || fail "a link or a FIFO was carried"
grep -rq "operator's own file" "$X" && fail "the link was followed"
grep -q "$KEY" "$SB/.pi-sessions/a0/s1.jsonl" || fail "the session in the run was edited"
[[ -f "$SB/package.sessions.private.json" ]] && jq -e '.map | keys | map(startswith("hidden-") or startswith("path:")) | any' "$SB/package.sessions.private.json" >/dev/null || fail "the private sidecar is missing"
[[ "$(stat -c %a "$SB/package.sessions.private.json")" == 600 ]] || fail "the private sidecar is not 0600"
grep -q 'sessions/sessions.tar.gz' "$PK/MANIFEST.txt" || fail "the archive is not under MANIFEST.txt"
pass "one archive and a manifest; the value is absent and its keyed id present; links and FIFOs left; the sidecar stays outside"

echo "# verify checks the component"
set +e
out="$(swarm verify "$PK")"; rc=$?
set -e
grep -q '^Sessions: .*match the manifest' <<<"$out" || fail "verify does not say the sessions match (rc $rc): $out"
pass "verify holds the archive and every member to the manifest"

echo "# a tampered archive is refused"
cp "$PK/sessions/sessions.tar.gz" "$TMP/good.tar.gz"
printf 'x' >> "$PK/sessions/sessions.tar.gz"
set +e
out="$(swarm verify "$PK")"; rc=$?
set -e
[[ $rc -ne 0 ]] && grep -q 'sessions.tar.gz DOES NOT MATCH ITS MANIFEST' <<<"$out" || fail "verify did not name the edited archive (rc $rc): $out"
cp "$TMP/good.tar.gz" "$PK/sessions/sessions.tar.gz"
pass "an edited archive is named"

echo "# --with-sessions with --redact is refused"
set +e
out="$(swarm package "$ID" --with-sessions --redact)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'cannot be combined with --redact' <<<"$out" || fail "the combination was not refused (rc $rc): $out"
pass "a redacted package never carries sessions"

echo "# a session file changed after the cutoff is named with both sizes"
rm -rf "$TMP/pk2"
mkdir -p "$TMP/pk2"
# A cutoff before the files were written: every file was changed after it. A cutoff after them: none was.
CUT="$(( $(date +%s) * 1000 - 600000 ))"
out="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/package-tools.ts" sessions "$SB" "$TMP/pk2" --cutoff-ms "$CUT" 2>&1)" || fail "sessions with a cutoff: $out"
[[ "$(jq -r '.changed' <<<"$out")" -ge 1 ]] || fail "no file was named as changed after the cutoff: $out"
jq -e '.changed_files[0] | has("listed_bytes") and has("copied_bytes")' <<<"$out" >/dev/null || fail "the changed file is not named with both sizes: $out"
jq -e '[.files[] | select(.changed_during_copy)] | length >= 1' "$TMP/pk2/sessions/sessions.manifest.json" >/dev/null || fail "the manifest does not name the changed files"
rm -rf "$TMP/pk3"
mkdir -p "$TMP/pk3"
out="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/package-tools.ts" sessions "$SB" "$TMP/pk3" --cutoff-ms "$(( $(date +%s) * 1000 + 60000 ))" 2>&1)" || fail "sessions with a late cutoff: $out"
[[ "$(jq -r '.changed' <<<"$out")" -eq 0 ]] || fail "a file was named as changed before the cutoff: $out"
pass "a file changed after the cutoff is named, with its size at the cutoff and as copied; none is named before it"

echo "package-sessions.test.sh: all checks passed"
