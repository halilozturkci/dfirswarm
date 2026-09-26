#!/usr/bin/env bash
# swarm.sh start --check: every refusal and preflight of a start, the same
# code, and nothing written (no runs directory, registry, audit line, hubs
# directory, sandbox, daemon, VM or pull); exit 0 when the start would go
# ahead, 2 when it would be refused. And image-for, read only. No model, no
# Herdr, no VM: msb is a stand-in where a check reaches it.
set -euo pipefail
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/start-check.XXXXXX)"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
export SWARM_HUBS_DIR="$TMP/hubs"
GOAL="$ROOT/prompts/goals/hello.md"
base=(--model solo/model --provider-host solo=api.solo.example --n 2 --cap-usd 1 --goal-file "$GOAL" --toolbox off)
run() { # <runs dir> <args...> -> out, rc; a real start gets hubs of its own
  local runs="$1" hubs="$SWARM_HUBS_DIR"
  shift
  case " $* " in *" --check "*) ;; *) hubs="$TMP/real-hubs" ;; esac
  set +e
  out="$(SWARM_HUBS_DIR="$hubs" SWARM_RUNS_DIR="$runs" bash "$ROOT/scripts/swarm.sh" start "$@" 2>&1)"
  rc=$?
  set -e
}
nothing_written() { # <runs dir> <what>
  [[ ! -e "$1" ]] || fail "$2 wrote under the runs directory: $(find "$1" | head)"
  [[ ! -e "$SWARM_HUBS_DIR" ]] || fail "$2 made the hubs directory"
}

echo "# a refused --env credential: the same words as a real start, and nothing written"
run "$TMP/runs-check" --check "${base[@]}" --env OPENAI_API_KEY=sk-not-a-key
check_out="$out" check_rc=$rc
run "$TMP/runs-real" "${base[@]}" --env OPENAI_API_KEY=sk-not-a-key
[[ $check_rc -eq 2 && $rc -eq 2 ]] || fail "check exited $check_rc and the start $rc, wanted 2 and 2"
[[ "$check_out" == "$out" ]] || fail "the check does not say what the start says:
--- check
$check_out
--- start
$out"
grep -q 'BLOCKER: --env OPENAI_API_KEY names a credential' <<<"$check_out" || fail "not the credential refusal: $check_out"
nothing_written "$TMP/runs-check" "a refused check"
pass "a refused --env credential is refused by --check in the start's own words, exit 2, with nothing written"

echo "# a clean option set: exit 0, nothing written"
run "$TMP/runs-check" --check --isolation host "${base[@]}" --no-start
[[ $rc -eq 0 ]] || fail "a clean check exited $rc: $out"
grep -q '^Check:        the start would go ahead (host, 2 agent(s)' <<<"$out" || fail "the check does not say the start would go ahead: $out"
nothing_written "$TMP/runs-check" "a clean check"
# The same options really start.
run "$TMP/runs-real2" --isolation host "${base[@]}" --no-start
[[ $rc -eq 0 ]] || fail "the start the check passed was refused: $out"
pass "a clean option set passes --check with exit 0 and nothing written, and the start then goes ahead"

echo "# the checks a start makes once its sandbox exists run too: a missing program"
bin="$TMP/bin"
mkdir -p "$bin"
for c in node jq python3 openssl; do
  p="$(command -v "$c" 2>/dev/null || true)"
  [[ -n "$p" ]] && ln -s "$p" "$bin/$c"
done
if PATH="$bin:/usr/bin:/bin" command -v herdr >/dev/null 2>&1; then
  echo "ok - skipped: herdr is in /usr/bin or /bin here"
else
  set +e
  out="$(PATH="$bin:/usr/bin:/bin" SWARM_RUNS_DIR="$TMP/runs-check" bash "$ROOT/scripts/swarm.sh" start --check --isolation host "${base[@]}" --no-write-guard 2>&1)"
  rc=$?
  set -e
  [[ $rc -eq 2 ]] && grep -q 'BLOCKER: missing herdr' <<<"$out" || fail "--check did not run the program check (rc $rc): $out"
  nothing_written "$TMP/runs-check" "a check refused for a missing program"
  pass "--check runs the checks a start makes after its sandbox exists (a missing program: exit 2, nothing written)"
fi

echo "# a VM run: the host's VM check is run, and a refusal of it is 2"
cat > "$TMP/msb" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  list) printf '[]\n' ;;
  --version) echo "msb 0.7.2" ;;
  doctor) echo "no hypervisor here"; exit 1 ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$TMP/msb"
set +e
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$TMP/runs-check" bash "$ROOT/scripts/swarm.sh" start --check "${base[@]}" 2>&1)"
rc=$?
set -e
[[ $rc -eq 2 ]] || fail "a check on a host that cannot boot VMs exited $rc, wanted 2: $out"
grep -q "BLOCKER: this host cannot run the agents' VMs" <<<"$out" && grep -q 'no hypervisor here' <<<"$out" || fail "the VM check's refusal is not said: $out"
nothing_written "$TMP/runs-check" "a check refused for VMs"
pass "--check runs the VM host check and turns its refusal into exit 2, with nothing written"

echo "# image-for: the image a kickoff would boot, read only"
set +e
out="$(SWARM_MSB_BIN="$TMP/msb" SWARM_RUNS_DIR="$TMP/runs-check" bash "$ROOT/scripts/swarm.sh" image-for 2>/dev/null)"
rc=$?
set -e
[[ $rc -eq 0 ]] || fail "image-for exited $rc: $out"
case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; *) ARCH=amd64 ;; esac
jq -e --arg a "$ARCH" '.ref == "dfirswarm-base:dev-\($a)" and .profile == "base" and .digest == null and .pinned_by == null and (.reason | startswith("no packs: the base image"))' <<<"$out" >/dev/null \
  || fail "image-for with no packs is not the base image: $out"
# A lock that pins the profile by digest: the digest is the lock's.
d="sha256:$(printf 'x%.0s' {1..64} | tr x a)"
jq -n --arg a "$ARCH" --arg r "ghcr.io/example/dfirswarm-base@$d" '{images: {base: {($a): $r}}}' > "$TMP/images.lock.json"
out="$(SWARM_IMAGES_LOCK="$TMP/images.lock.json" SWARM_MSB_BIN="$TMP/msb" bash "$ROOT/scripts/swarm.sh" image-for 2>/dev/null)" || fail "image-for with a lock failed"
jq -e --arg d "$d" --arg l "$TMP/images.lock.json" '.digest == $d and .pinned_by == $l and (.reason | contains("pinned by digest"))' <<<"$out" >/dev/null || fail "image-for does not take the lock's digest: $out"
# A pack: the smallest profile that serves it.
export DFIRSWARM_HOME="$TMP/home"
bash "$ROOT/scripts/pack.sh" install "$ROOT/packs/computer-forensics-base" --yes >/dev/null 2>&1 || fail "the pack did not install"
out="$(SWARM_MSB_BIN="$TMP/msb" bash "$ROOT/scripts/swarm.sh" image-for --pack computer-forensics-base 2>/dev/null)" || fail "image-for with a pack failed"
jq -e '(.packs == ["computer-forensics-base"]) and (.profile | length > 0) and (.ref == "dfirswarm-\(.profile):dev-\(.arch)") and (.reason | contains("computer-forensics-base"))' <<<"$out" >/dev/null \
  || fail "image-for with a pack does not name the pack's image: $out"
set +e
out="$(SWARM_MSB_BIN="$TMP/msb" bash "$ROOT/scripts/swarm.sh" image-for --pack no-such-pack 2>&1)"; rc=$?
set -e
[[ $rc -eq 2 ]] && grep -q 'no-such-pack is not installed' <<<"$out" || fail "a pack that is not installed was not refused (rc $rc): $out"
unset DFIRSWARM_HOME
nothing_written "$TMP/runs-check" "image-for"
pass "image-for says the image, its digest when a lock pins it or msb has it, the profile and why, and writes nothing"

echo "# the check says what the start would set up"
run "$TMP/runs-plan" --check "${base[@]}" --isolation host --no-start
[[ $rc -eq 0 ]] || fail "a host check exited $rc: $out"
grep -q "^Isolation:    host, unisolated" <<<"$out" || fail "the check does not say the run would be unisolated: $out"
run "$TMP/runs-plan" --check --isolation microvm --model openai/gpt-5.4-mini --n 1 --cap-usd 1 --goal-file "$GOAL" --toolbox off --no-start --model-gateway --image dfirswarm-base:dev-test
grep -q "^Isolation:    one microVM per agent (dfirswarm-base:dev-test" <<<"$out" || fail "the check does not name the VMs' image: $out"
grep -q "^Gateway:      every call to openai would go through the model gateway" <<<"$out" || fail "the check does not say the gateway fronts openai: $out"
nothing_written "$TMP/runs-plan" "the plan check"
pass "the check names the isolation, the image and what the model gateway would front"

echo "start-check.test.sh: all checks passed"
