#!/usr/bin/env bash
# The kickoff's --isolation microvm, without a VM: every run here is
# `--no-start`, and we read what the kickoff wrote into the sandbox, the
# registry and the contract. What starting VMs does is
# tests/vm-integration.test.ts, which needs a hypervisor.
#
# What must not go wrong: a VM run must be refused before anything is written
# when a flag cannot mean anything in a VM; the evidence must be used in place
# (no copy, no pristine clone) and recorded as held by the VM; every agent's
# writable holes must exist before a VM mounts over them; the record must say
# microvm wherever the host run says which guard it had; the image must follow
# the packs; and the contract must tell the agents what a VM changes for them.
set -uo pipefail
# A shell with a VM default, an image or a lock file exported, or another pack
# home, would turn this suite's kickoffs into something else (a VM kickoff, another
# image): what the suite checks is the defaults.
unset SWARM_ISOLATION SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/microvm-flags.XXXXXX")"
# The VM hubs' directory is the suite's own, and short: a hub's socket path
# must stay under the 104 bytes macOS allows.
HUBS_TMP="$(mktemp -d /tmp/dfh.XXXXXX)"
export SWARM_HUBS_DIR="$HUBS_TMP/hubs" MSB_HOME="$HUBS_TMP/msb-home"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP" "$HUBS_TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
swarm() { SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" "$@" 2>&1; }
# "solo" is a provider nobody ships: its host is given, as an operator with a
# gateway would give it.
start() { swarm start --model solo/model --provider-host solo=api.solo.example --n 2 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off "$@"; }
bare_start() { swarm start --n 2 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off "$@"; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }
reg() { jq -r --arg l "$1" ".runs[] | select(.[\"label\"] == \$l) | $2" "$TMP/runs/registry.json"; }
case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; *) ARCH=amd64 ;; esac

mkdir -p "$TMP/ev/mail"
printf 'notes\n' > "$TMP/ev/notes.txt"
printf 'attachment' > "$TMP/ev/mail/a.bin"

# --- refusals, before anything is written ---------------------------------------
out="$(start --isolation vmware --label bad-iso)"; rc=$?
[[ $rc -eq 2 ]] || fail "an unknown isolation exited $rc, wanted 2: $out"
grep -q 'BLOCKER: --isolation must be host or microvm' <<<"$out" || fail "no BLOCKER for --isolation vmware: $out"
out="$(start --isolation microvm --probe-violation --label bad-probe)"; rc=$?
[[ $rc -eq 2 ]] || fail "--probe-violation in a VM run exited $rc, wanted 2"
grep -q 'probe-violation' <<<"$out" || fail "the refusal does not name --probe-violation: $out"
out="$(start --isolation microvm --vm-cpus 0 --label bad-cpus)"; rc=$?
[[ $rc -eq 2 ]] || fail "--vm-cpus 0 exited $rc, wanted 2"
out="$(start --isolation microvm --vm-memory 100 --label bad-mem)"; rc=$?
[[ $rc -eq 2 ]] || fail "--vm-memory 100 exited $rc, wanted 2"
out="$(start --isolation microvm --vm-memory 10000000 --label bad-capacity)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'lower --vm-memory or --n' <<<"$out" || fail "VMs larger than this host were not refused: $out"
for flag in --no-write-guard --no-seal-herdr --key-from-env "--inputs-enforce on"; do
  # shellcheck disable=SC2086
  out="$(start --isolation microvm $flag --label bad-hostflag)"; rc=$?
  [[ $rc -eq 2 ]] && grep -q 'none of them means anything' <<<"$out" || fail "$flag was accepted under microvm: $out"
done
out="$(start --isolation microvm --image 'img; rm -rf /' --label bad-image)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'must be an OCI reference' <<<"$out" || fail "an --image that is not an OCI reference was accepted: $out"
out="$(start --isolation microvm --vm-disk 100 --label bad-disk)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'vm-disk is MiB' <<<"$out" || fail "--vm-disk 100 was not refused: $out"
[[ ! -f "$TMP/runs/registry.json" ]] || [[ -z "$(jq -r '.runs[] | select(.label | startswith("bad-")) | .id' "$TMP/runs/registry.json")" ]] \
  || fail "a refused kickoff left a run in the registry"
# Nor a sandbox: "before anything is written" means the directory too.
leftover="$(find "$TMP/runs" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)"
[[ -z "$leftover" ]] || fail "a refused kickoff left a sandbox directory: $leftover"
pass "an isolation that does not exist, a probe with no guard to probe, a host guard's flag, and a VM with no CPU, too little memory or more than the host has are refused before anything is written"

# --- the default is a VM: what cannot be one is refused, and says both ways on --------
# A host guard's flag with no --isolation: the run would be a VM run, so the
# flag means nothing; the refusal says how to ask for a host run.
for flag in --no-write-guard --probe-violation; do
  out="$(start $flag --label bad-default-hostflag)"; rc=$?
  [[ $rc -eq 2 ]] && grep -q -- 'Add --isolation host' <<<"$out" || fail "$flag without --isolation was not refused with the way to a host run: $out"
done
# A host that cannot run the VMs: msb's doctor fails (no KVM, say). The
# kickoff stops before anything is written, names how to fix it and the
# unisolated way on, and never becomes a host run on its own.
cat > "$TMP/msb-no-kvm" <<'MSB'
#!/usr/bin/env bash
case "$1" in
  --version) echo "msb 0.7.2" ;;
  doctor) echo "kvm: /dev/kvm is not accessible" >&2; exit 1 ;;
  *) exit 1 ;;
esac
MSB
chmod +x "$TMP/msb-no-kvm"
out="$(SWARM_MSB_BIN="$TMP/msb-no-kvm" swarm start --model solo/model --provider-host solo=api.solo.example --n 2 --cap-usd 1 --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off --label bad-no-kvm)"; rc=$?
[[ $rc -eq 3 ]] || fail "a host whose msb doctor fails exited $rc, wanted 3: $out"
grep -q "BLOCKER: this host cannot run the agents' VMs" <<<"$out" || fail "no BLOCKER for a host that cannot run VMs: $out"
grep -q 'Apple silicon, or Linux with KVM' <<<"$out" || fail "the refusal does not say what a VM needs: $out"
grep -q -- '--isolation host: each is then a process on this host' <<<"$out" || fail "the refusal does not name the unisolated way on: $out"
# msb itself missing or broken: the id cannot be checked against its VMs.
out="$(SWARM_MSB_BIN="$TMP/msb-no-kvm" start --label bad-no-msb)"; rc=$?
[[ $rc -eq 3 ]] && grep -q 'msb could not list its VMs' <<<"$out" && grep -q -- '--isolation host' <<<"$out" \
  || fail "a broken msb at a --no-start kickoff was not refused with both ways on (exit $rc): $out"
[[ -z "$(jq -r '.runs[]? | select(.label | startswith("bad-")) | .id' "$TMP/runs/registry.json" 2>/dev/null)" ]] || fail "a refused default kickoff left a run in the registry"
pass "under the default, a host guard's flag is refused with the way to a host run, and a host that cannot run the VMs is refused with how to fix it and the unisolated way on, never run on the host instead"

# --no-read: what every VM mounts cannot be hidden, and is not claimed hidden.
out="$(start --isolation microvm --no-read "$ROOT/scripts" --label bad-noread)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'cannot hide what the VMs are given' <<<"$out" || fail "--no-read of a mounted path was accepted under microvm: $out"
mkdir -p "$TMP/private-notes"
out="$(start --isolation microvm --no-read "$TMP/private-notes" --label vm-noread)"; rc=$?
[[ $rc -eq 0 ]] || fail "--no-read of a path no VM mounts was refused: $out"
[[ "$(reg vm-noread '.no_read_applied')" == true ]] || fail "--no-read of an unmounted path was not recorded as applied"
pass "--no-read of a path the VMs mount is refused; of one they do not, recorded as applied"

# No collector: a VM cannot fall back to appending traces/ itself, so the run
# would be all spill. A node that refuses to run the collector stands in for
# one that crashed.
mkdir -p "$TMP/nocollector"
REAL_NODE="$(command -v node)"
cat > "$TMP/nocollector/node" <<EOF
#!/usr/bin/env bash
case "\$*" in *trace-collector.mjs*) exit 1 ;; esac
exec "$REAL_NODE" "\$@"
EOF
chmod +x "$TMP/nocollector/node"
out="$(PATH="$TMP/nocollector:$PATH" start --isolation microvm --label bad-collector)"; rc=$?
[[ $rc -eq 1 ]] || fail "a microvm kickoff with no collector exited $rc, wanted 1: $out"
grep -q 'BLOCKER: the trace collector did not come up' <<<"$out" || fail "no BLOCKER naming the collector: $out"
[[ -z "$(jq -r '.runs[]? | select(.label == "bad-collector") | .id' "$TMP/runs/registry.json" 2>/dev/null)" ]] || fail "the refused kickoff left a run"
out="$(PATH="$TMP/nocollector:$PATH" start --isolation host --label host-no-collector)"; rc=$?
[[ $rc -eq 0 ]] || fail "a host kickoff with no collector should still start, with a warning: $out"
grep -q 'appended by the panes themselves' <<<"$out" || fail "the host fallback is not said: $out"
pass "a microvm run whose trace collector does not come up is refused; a host run falls back and says so"

# --- the network a VM is given -------------------------------------------------
out="$(bare_start --model mystery/m1 --isolation microvm --label bad-provider)"; rc=$?
[[ $rc -eq 2 ]] || fail "a provider with no known host exited $rc under microvm, wanted 2: $out"
grep -q -- '--provider-host mystery=<host>' <<<"$out" || fail "the refusal does not say how to name the host: $out"
out="$(bare_start --model mystery/m1 --isolation microvm --no-netguard --label bad-provider-open)"; rc=$?
[[ $rc -eq 2 ]] || fail "an open network does not make an unknown provider's key reachable, but it exited $rc: $out"
out="$(bare_start --model amazon-bedrock/anthropic.claude-x --isolation microvm --label bad-bedrock)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'signs every request' <<<"$out" || fail "bedrock under microvm was not refused with the reason: $out"
out="$(bare_start --model solo/model --provider-host 'solo' --label bad-ph)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'provider=host' <<<"$out" || fail "a --provider-host without =host was not refused: $out"
out="$(start --isolation microvm --allow-host 'https://mirror.example.org/x' --label bad-allow)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'not a URL' <<<"$out" || fail "an --allow-host a VM would read as nothing was not refused: $out"
out="$(start --isolation microvm --allow-host '*.com' --label bad-tld)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'top-level domain' <<<"$out" || fail "*.com was not refused: $out"
[[ -z "$(jq -r '.runs[]? | select(.label | startswith("bad-")) | .id' "$TMP/runs/registry.json" 2>/dev/null)" ]] || fail "a refused network left a run"
# Pi's own model list names the hosts of the providers it ships.
out="$(bare_start --model groq/llama-3.3-70b-versatile --isolation microvm --allow-host '*.blob.core.windows.net' --allow-host '[::1]:11434' --label vm-groq)"; rc=$?
[[ $rc -eq 0 ]] || fail "a Pi provider with a known host was refused: $out"
sbx="$(sandbox_of "$out")"
jq -e '.providers[] | select(.provider == "groq") | .hosts | index("api.groq.com")' "$sbx/vm-spec.json" >/dev/null \
  || fail "the groq host did not come from Pi's model list: $(jq -c .providers "$sbx/vm-spec.json")"
out="$(start --isolation microvm --no-netguard --label vm-open)"; rc=$?
[[ $rc -eq 0 ]] || fail "an open microvm run was refused: $out"
[[ "$(reg vm-open '.netguard_mode')" == "microvm-open" ]] || fail "an open VM network was recorded as $(reg vm-open '.netguard_mode')"
open_sb="$(reg vm-open '.sandbox')"
grep -q 'Your VM can reach every public host' "$open_sb/SWARM.md" || fail "the contract of an open VM run does not say the network is open"
grep -q 'every public host. and nothing else' "$open_sb/SWARM.md" && fail "the contract says every public host and nothing else"
[[ "$(reg vm-ev '.netguard_mode' 2>/dev/null)" != "microvm-open" ]] || fail "a closed VM network was recorded as open"
pass "a provider with no host, a signing provider, a bad --provider-host or --allow-host are refused under microvm; Pi's list names a shipped provider's host; an open VM network is recorded as open"

# A link in the evidence that leads out of it would dangle in every VM.
mkdir -p "$TMP/ev-link" "$TMP/elsewhere"
printf 'image' > "$TMP/elsewhere/case.E01"
printf 'notes\n' > "$TMP/ev-link/notes.txt"
ln -s "$TMP/elsewhere/case.E01" "$TMP/ev-link/case.E01"
ln -s notes.txt "$TMP/ev-link/inside-link.txt"
out="$(start --isolation microvm --inputs "$TMP/ev-link" --label bad-link)"; rc=$?
[[ $rc -eq 2 ]] || fail "evidence with a link out of it exited $rc under microvm, wanted 2: $out"
grep -q 'case.E01 -> ' <<<"$out" || fail "the refusal does not name the link: $out"
grep -q 'inside-link' <<<"$out" && fail "a link that stays inside the evidence was refused: $out"
[[ -z "$(jq -r '.runs[]? | select(.label == "bad-link") | .id' "$TMP/runs/registry.json" 2>/dev/null)" ]] || fail "the refused kickoff left a run"
rm "$TMP/ev-link/case.E01"
out="$(start --isolation microvm --inputs "$TMP/ev-link" --label vm-inside-link)"; rc=$?
[[ $rc -eq 0 ]] || fail "evidence whose only link stays inside it was refused: $out"
pass "evidence with a link leading out of it is refused under microvm, naming the link; a link that stays inside is fine"

# --- the evidence is used in place and held by the VM ----------------------------
out="$(start --isolation microvm --inputs "$TMP/ev" --label vm-ev)"; rc=$?
[[ $rc -eq 0 ]] || fail "a microvm --no-start kickoff exited $rc: $out"
sbx="$(sandbox_of "$out")"
[[ -L "$sbx/inputs" ]] || fail "inputs/ is not a link to the evidence: a VM run copied it"
[[ "$(cd "$sbx/inputs" && pwd -P)" == "$(cd "$TMP/ev" && pwd -P)" ]] || fail "inputs/ links somewhere else"
[[ ! -e "$sbx/.inputs-pristine" ]] || fail "a VM run made a pristine clone it will never heal from"
[[ "$(jq -r '.guard' "$sbx/inputs.json")" == "microvm" ]] || fail "inputs.json does not say the VM holds the evidence"
[[ "$(jq -r '.held' "$sbx/inputs.json")" == "bind" ]] || fail "inputs.json does not say the evidence was used in place"
[[ "$(reg vm-ev '.isolation.disk_mib')" == "8192" ]] || fail "the VM disk size is not recorded"
[[ "$(jq -r '.files | length' "$sbx/inputs.json")" == "2" ]] || fail "the manifest does not list both files"
# No --quarantine was given, and each seat's holes are no-exec in its VM all
# the same: the record a malware entry's check reads says so.
(cd "$sbx" && grep -q '"quarantine": true' inputs.json) || fail "a VM run is quarantined, and inputs.json does not say so: $(jq -c '{quarantine}' "$sbx/inputs.json")"
grep -q 'kernel guard: microvm' <<<"$out" || fail "the kickoff does not say who holds the evidence: $out"
pass "the evidence is used in place, with no copy and no pristine clone, and the manifest says the VM holds it"

for id in $(jq -r '.agents[].id' "$sbx/team.json"); do
  [[ -d "$sbx/tool-output/$id" ]] || fail "no tool-output/$id for its VM to mount writable"
  [[ -d "$sbx/.pi-sessions/$id" ]] || fail "no .pi-sessions/$id for its VM to mount writable"
  for d in "work/$id" "work/extracted/$id" "work/quarantine/$id"; do
    [[ -d "$sbx/$d" ]] || fail "no $d for its VM to mount writable"
  done
done
grep -q 'publish_file' "$sbx/SWARM.md" || fail "the contract does not tell a VM agent how a shared file is written"
grep -q 'the rest of `work/` is read-only there' "$sbx/SWARM.md" || fail "the contract does not say the shared work/ is read-only in a VM"
pass "every agent's writable holes exist before its VM would mount over them"

[[ "$(reg vm-ev '.isolation.mode')" == "microvm" ]] || fail "the registry does not record the isolation"
[[ "$(reg vm-ev '.isolation.image')" == "dfirswarm-base:dev-$ARCH" ]] || fail "a run with no packs should boot the base image, got $(reg vm-ev '.isolation.image')"
# The default memory is 2048 MiB, or 1024 on a host with less than 8 GiB
# (swarm.sh; CI's macOS runner has 7 GiB).
host_mib="$(node -e 'console.log(Math.floor(require("os").totalmem() / 1048576))')"
want_mib=2048; [[ "$host_mib" -lt 8192 ]] && want_mib=1024
[[ "$(reg vm-ev '.isolation.cpus')" == "2" && "$(reg vm-ev '.isolation.memory_mib')" == "$want_mib" ]] || fail "the VM size is not recorded (wanted 2 vCPU, $want_mib MiB): $(reg vm-ev '.isolation')"
[[ "$(reg vm-ev '.isolation.snapshot')" == "true" ]] || fail "a VM run keeps each disk by default"
[[ "$(reg vm-ev '.write_guard')" == "microvm" ]] || fail "write_guard is $(reg vm-ev '.write_guard'), not microvm"
[[ "$(reg vm-ev '.attribution')" == "channel" ]] || fail "attribution is $(reg vm-ev '.attribution'), not channel"
[[ "$(reg vm-ev '.netguard_mode')" == "microvm" ]] || fail "netguard_mode is $(reg vm-ev '.netguard_mode'), not microvm"
[[ "$(reg vm-ev '.herdr_socket')" == "unreachable" ]] || fail "herdr_socket is $(reg vm-ev '.herdr_socket'), not unreachable"
for f in collector.pid nudge.pid hub.pid gate.pid netguard.pid; do
  [[ ! -f "$sbx/$f" ]] || fail "--no-start left $f behind"
done
[[ ! -e "$sbx/.zsh" && ! -e "$sbx/.fsguard" ]] || fail "a VM run wrote the host's pane guard hook"
pass "the record says microvm wherever a host run says which guard it had, and --no-start leaves no daemon"

# --- the contract tells the agents what a VM changes -----------------------------
grep -q 'own microVM' "$sbx/SWARM.md" || fail "SWARM.md does not tell the agents they are in a VM"
grep -q 'up to five seconds' "$sbx/SWARM.md" || fail "SWARM.md does not warn about a peer's file taking a moment to look current"
grep -q 'written for you' "$sbx/SWARM.md" || fail "SWARM.md does not say the board is written by the harness"
grep -q 'no copy, and the host holds the source read-only' "$sbx/SWARM.md" || fail "SWARM.md does not say how the evidence arrived"
! grep -q 'advisory here (a proxy' "$sbx/SWARM.md" || fail "SWARM.md describes the host's proxy to agents that have none"
grep -q "carries that seat's authority, no more" "$sbx/SWARM.md" || fail "SWARM.md does not say a 'system via' post is a seat's own"
grep -q 'An event.*time you record needs its zone\|time you record needs its zone' "$sbx/SWARM.md" || fail "SWARM.md does not ask for a zone on event times"
pass "the contract says the agent is in its own VM, the board is written for it, a peer's file can lag, and how the evidence arrived"

# --- the image follows the packs, and an operator's image wins ------------------
# In a home of our own: whatever packs this machine has installed are not the test's.
export DFIRSWARM_HOME="$TMP/home"
for p in computer-forensics-base memory-forensics; do
  bash "$ROOT/scripts/pack.sh" install "$ROOT/packs/$p" --yes >/dev/null 2>&1 || fail "could not install pack $p into the test's home"
done
out="$(start --isolation microvm --pack memory-forensics --label vm-mem)"; rc=$?
[[ $rc -eq 0 ]] || fail "a microvm run with a pack exited $rc: $out"
[[ "$(reg vm-mem '.isolation.image')" == "dfirswarm-memory:dev-$ARCH" ]] || fail "memory-forensics should boot the memory image, got $(reg vm-mem '.isolation.image')"
# --pack given twice adds up: the second used to replace the first, and a run
# asked for windows-forensics and memory-forensics got only the latter.
bash "$ROOT/scripts/pack.sh" install "$ROOT/packs/windows-forensics" --yes >/dev/null 2>&1 || fail "could not install pack windows-forensics into the test's home"
out="$(start --isolation microvm --pack windows-forensics --pack memory-forensics --label vm-two-packs)"; rc=$?
[[ $rc -eq 0 ]] || fail "a run with two --pack flags exited $rc: $out"
[[ "$(reg vm-two-packs '.isolation.image')" == "dfirswarm-full:dev-$ARCH" ]] || fail "the first of two --pack flags was dropped: image $(reg vm-two-packs '.isolation.image')"
out="$(start --isolation microvm --image registry.example/dfirswarm-custom@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --label vm-img)"
[[ "$(reg vm-img '.isolation.image')" == "registry.example/dfirswarm-custom@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ]] || fail "--image was not honoured"
out="$(start --label vm-default)"
[[ "$(reg vm-default '.isolation.mode')" == "microvm" ]] || fail "a run without --isolation is not a microVM run: $out"
grep -q "^Isolation:    one microVM per agent (dfirswarm-" <<<"$out" || fail "the kickoff does not say its agents are in VMs: $out"
out="$(SWARM_ISOLATION=host start --label host-env)"
[[ "$(reg host-env '.isolation.mode')" == "host" ]] || fail "SWARM_ISOLATION=host did not make a host run"
out="$(start --isolation host --label host-flag)"
[[ "$(reg host-flag '.isolation.mode')" == "host" ]] || fail "--isolation host did not make a host run"
grep -q "^Isolation:    host, unisolated" <<<"$out" || fail "a host run is not said to be unisolated: $out"
pass "the packs choose the image, --image overrides it, a run is in microVMs unless --isolation host or SWARM_ISOLATION=host says otherwise, and a host run is said to be unisolated"

# --- a run from before isolation was recorded was a host run, and stays one ---------
mkdir -p "$TMP/old-runs"
printf '{"runs":[{"id":"s0old1","state":"stopped","label":"before-isolation","n":2,"model":"deepseek/deepseek-v4-pro","sandbox":"%s/old-runs/s0old1"}]}\n' "$TMP" > "$TMP/old-runs/registry.json"
held="$(SWARM_RUNS_DIR="$TMP/old-runs" bash "$ROOT/scripts/swarm.sh" list 2>&1 | awk '$1 == "s0old1" {print $4}')"
[[ "$held" == "host" ]] || fail "a registry record with no isolation is listed as '$held', wanted host"
pass "a registry record with no isolation (a run from before the default changed) is listed as a host run"

# --- what the VMs would be given: no credential, no host home, the secrets bound ----
# A pack with two secrets: one bound to a host, one with no host to bind to.
mkdir -p "$TMP/psrc/keyed-pack/skills/alpha" "$TMP/psrc/keyed-pack/tools/echo_tool" "$TMP/psrc/keyed-pack/requires"
printf 'Test pack.\n' > "$TMP/psrc/keyed-pack/LICENCE"
cat > "$TMP/psrc/keyed-pack/skills/alpha/first.md" <<'EOF'
---
id: alpha/first
title: The first skill
when: Whenever the suite asks for it.
needs: []
tools: [echo_tool]
requires_host: []
---

A body.
EOF
cat > "$TMP/psrc/keyed-pack/tools/echo_tool/manifest.json" <<'EOF'
{ "name": "echo_tool", "description": "Echo.", "params": { "text": { "type": "string", "description": "What" } }, "runtime": "python3", "entry": "run.py", "timeout_seconds": 10 }
EOF
printf 'import json,sys\nprint(json.dumps({"ok": True}))\n' > "$TMP/psrc/keyed-pack/tools/echo_tool/run.py"
printf '{ "binaries": [] }\n' > "$TMP/psrc/keyed-pack/requires/host.json"
cat > "$TMP/psrc/keyed-pack/pack.json" <<'EOF'
{ "id": "keyed-pack", "name": "keyed-pack", "version": "1.0.0", "description": "A pack for the suite.", "licence": "AGPL-3.0-or-later",
  "depends": [], "requires": { "host": "requires/host.json" },
  "secrets": [
    { "name": "TEST_API_KEY", "title": "A key", "why": "For the suite.", "required": false, "hosts": ["api.example.test"] },
    { "name": "LOOSE_KEY", "title": "A loose key", "why": "For the suite.", "required": false }
  ] }
EOF
bash "$ROOT/scripts/pack.sh" seal "$TMP/psrc/keyed-pack" >/dev/null || fail "seal keyed-pack"
TEST_API_KEY=hunter2-value LOOSE_KEY=loose-value bash "$ROOT/scripts/pack.sh" install "$TMP/psrc/keyed-pack" --yes >/dev/null 2>&1 || fail "install keyed-pack"
mkdir -p "$TMP/home2"
printf 'Summarise the case so far.\n' > "$TMP/home2/prompt.md"
printf '{"not":"a real store"}\n' > "$TMP/home2/auth.json"
# A library tool with a pack tool's name: the pack's copy is kept, and a
# different copy is said, not silently taken.
mkdir -p "$TMP/lib-clash/echo_tool"
printf 'print("the library copy")\n' > "$TMP/lib-clash/echo_tool/run.py"
clash_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TMP/lib-clash/echo_tool/run.py")"
printf '{"name":"echo_tool","description":"Echo, another way.","params":{},"runtime":"python3","entry":"run.py","timeout_seconds":10,"by":"s1","at":"t","version":1,"sha256":"%s"}\n' "$clash_sha" > "$TMP/lib-clash/echo_tool/manifest.json"
out="$(start --isolation host --pack keyed-pack --allow-tool-forging --tools-from "$TMP/lib-clash" --label tool-clash)"; rc=$?
[[ $rc -eq 0 ]] || fail "a kickoff with a pack and a clashing library exited $rc: $out"
clash_sb="$(sandbox_of "$out")"
grep -q 'differs from pack keyed-pack.s echo_tool; the pack.s version is kept' <<<"$out" || fail "the clash was not said: $out"
[[ "$(jq -r '.pack // empty' "$clash_sb/tools/echo_tool/manifest.json")" == keyed-pack ]] || fail "the library's copy replaced the pack's"
pass "a library tool named like a pack tool leaves the pack's copy in place, and the difference is said"
# Without the operator's yes the pack's secrets are withheld in a VM too: its
# placeholder would be in the whole VM's environment, for any process there.
out="$(start --isolation microvm --inputs "$TMP/ev" --pack keyed-pack --label vm-spec-no)"; rc=$?
[[ $rc -eq 0 ]] || fail "a prepared microvm run with a keyed pack and no --allow-pack-secrets exited $rc: $out"
grep -q 'keyed-pack has secret(s).*withheld' <<<"$out" || fail "withholding the pack's secrets was not said: $out"
[[ "$(jq -c '.pack_secrets' "$(sandbox_of "$out")/vm-spec.json")" == "[]" ]] || fail "a secret was bound without --allow-pack-secrets"
[[ "$(reg vm-spec-no '.pack_secrets."keyed-pack".mode')" == "withheld" ]] || fail "the record does not say withheld"
out="$(start --isolation microvm --inputs "$TMP/ev" --pack keyed-pack --allow-pack-secrets --compact-prompt-file "$TMP/home2/prompt.md" --label vm-spec)"; rc=$?
[[ $rc -eq 0 ]] || fail "a prepared microvm run with a keyed pack exited $rc: $out"
sbx="$(sandbox_of "$out")"
[[ -f "$sbx/vm-spec.json" ]] || fail "a prepared microvm run writes vm-spec.json"
while IFS= read -r h; do
  [[ "$h" == "$TMP/home2" || "$h" == "$HOME" ]] && fail "the prompt's directory (or the home) is mounted into the VMs: $h"
  case "$h" in
    *"/secrets"*|*"/docs/use-cases"*|*"/auth.json"*) fail "a mount carries what no VM may see: $h" ;;
  esac
  [[ "$h" == "$TMP/runs"* && "$h" != *"/vm-prepared/runs" ]] && fail "the operator's registry is mounted: $h"
done < <(jq -r '.mounts[].host' "$sbx/vm-spec.json")
[[ -f "$sbx/compact-prompt.md" ]] || fail "the compaction prompt was not copied into the run"
[[ "$(jq -r '.env.SWARM_COMPACT_PROMPT' "$sbx/vm-spec.json")" == "$sbx/compact-prompt.md" ]] || fail "the VMs are not pointed at the run's copy of the prompt"
jq -e --arg f "$DFIRSWARM_HOME/secrets/keyed-pack.env" '.pack_secrets == [{name: "TEST_API_KEY", value_file: $f, hosts: ["api.example.test"]}]' "$sbx/vm-spec.json" >/dev/null \
  || fail "the bound secret is not in the spec as expected: $(jq -c '.pack_secrets' "$sbx/vm-spec.json")"
grep -q 'LOOSE_KEY.*withheld' <<<"$out" || fail "a secret with no hosts is not said to be withheld: $out"
[[ "$(jq -r '.env.SWARM_PACK_SECRETS | fromjson | ."keyed-pack".names | join(",")' "$sbx/vm-spec.json")" == "TEST_API_KEY" ]] || fail "the VM is told the wrong secret names"
grep -rq 'hunter2-value\|loose-value' "$sbx" && fail "a secret's value is in the run"
[[ "$(reg vm-spec '.pack_secrets."keyed-pack".mode')" == "injected" ]] || fail "the record does not say injected"
[[ "$(reg vm-spec '.pack_secrets."keyed-pack".secrets.TEST_API_KEY')" == "injected" ]] || fail "the record does not say which secret was injected"
[[ "$(reg vm-spec '.pack_secrets."keyed-pack".secrets.LOOSE_KEY')" == "withheld: names no host" ]] || fail "the record says the loose secret was injected"
# A secrets.env left inside an installed pack's directory would be mounted
# into every VM, where the guest's root reads it: the kickoff refuses the
# run, by the pack's seal (the file is not part of what was sealed) or by
# the secrets rule, and no spec carries the value.
kp_dir="$(bash "$ROOT/scripts/pack.sh" resolve keyed-pack)"
printf 'TEST_API_KEY=planted-value\n' > "$kp_dir/secrets.env"
out="$(start --isolation microvm --inputs "$TMP/ev" --pack keyed-pack --allow-pack-secrets --label vm-spec-planted)"; rc=$?
rm -f "$kp_dir/secrets.env"
[[ $rc -ne 0 ]] && grep -q "pack keyed-pack does not verify\|has a secrets.env inside its directory, which every VM mounts" <<<"$out" \
  || fail "a secrets.env inside a pack's directory was not refused (rc $rc): $out"
grep -rq 'planted-value' "$TMP/runs" 2>/dev/null && fail "the planted secret's value reached a run"
pass "a pack whose directory holds a secrets.env is refused before any VM could mount it"
# An installed pack older than the one the checkout ships is said: the run
# uses the installed tools, fixes and all.
mkdir -p "$TMP/shipped/keyed-pack"
jq '.version = "9.9.9"' "$(bash "$ROOT/scripts/pack.sh" resolve keyed-pack | tail -1)/pack.json" > "$TMP/shipped/keyed-pack/pack.json"
out="$(SWARM_SHIPPED_PACKS="$TMP/shipped" start --check --isolation host --pack keyed-pack 2>&1)"
grep -q "WARN: pack keyed-pack is installed at .* and this checkout ships 9.9.9; the run uses" <<<"$out" || fail "an installed pack older than the shipped one was not said: $out"
out="$(SWARM_SHIPPED_PACKS="$TMP/no-such-dir" start --check --isolation host --pack keyed-pack 2>&1)"
grep -q "WARN: pack keyed-pack is installed" <<<"$out" && fail "a pack the checkout does not ship was warned about: $out"
pass "an installed pack older than the one this checkout ships is said at kickoff"
# --local-only: nothing of the pack's service is opened, and the secrets are withheld.
out="$(start --isolation microvm --inputs "$TMP/ev" --pack keyed-pack --allow-pack-secrets --local-only --model ollama/qwen3:8b --label vm-local)"
if [[ "$(jq -c '.pack_secrets // [] | length' "$(sandbox_of "$out")/vm-spec.json" 2>/dev/null)" == "0" ]] || grep -q -- '--local-only withholds' <<<"$out"; then :; else fail "--local-only bound a pack secret: $out"; fi
pass "a prepared VM run's spec mounts neither the prompt's directory nor a secret, points at the run's own copy of the prompt, and binds each secret to its hosts"

# --- a credential cannot ride in on --env; a subscription needs an explicit yes ---------
out="$(start --isolation microvm --env FOO_API_KEY=abc --label bad-env)"; rc=$?
[[ $rc -eq 2 ]] || fail "--env FOO_API_KEY under microvm exited $rc, wanted 2: $out"
grep -q 'names a credential' <<<"$out" || fail "the refusal does not say why: $out"
mkdir -p "$TMP/pi"
printf '{"openai-codex": {"type": "oauth", "access": "not-real", "refresh": "not-real", "expires": 1}}\n' > "$TMP/pi/auth.json"
out="$(PI_CODING_AGENT_DIR="$TMP/pi" start --isolation microvm --model openai-codex/gpt-5.4 --label bad-oauth)"; rc=$?
[[ $rc -eq 2 ]] || fail "a subscription provider under microvm exited $rc, wanted 2: $out"
grep -q 'subscription' <<<"$out" || fail "the refusal does not name the subscription: $out"
out="$(PI_CODING_AGENT_DIR="$TMP/pi" start --isolation microvm --model openai-codex/gpt-5.4 --allow-oauth-in-vm --cap-tokens 1000000 --label ok-oauth)"; rc=$?
[[ $rc -eq 0 ]] || fail "--allow-oauth-in-vm did not let the run through: $out"
[[ "$(reg ok-oauth '.isolation.oauth_allowed')" == "true" ]] || fail "the record does not say the subscription was let in on purpose"
sbx="$(sandbox_of "$out")"
[[ "$(jq -r '.providers[] | select(.provider == "openai-codex") | .hosts | join(",")' "$sbx/vm-spec.json")" == "chatgpt.com" ]] \
  || fail "the refresh endpoint is bound though the guest never refreshes: $(jq -c '.providers' "$sbx/vm-spec.json")"
pass "a credential in --env is refused, a subscription needs --allow-oauth-in-vm and is recorded, and its refresh endpoint is never bound"

# --- the evidence: links recorded as links, a second layer on request, a warning ------
mkdir -p "$TMP/ev-mixed/sub"
printf 'a\n' > "$TMP/ev-mixed/a.txt"
printf 'b\n' > "$TMP/ev-mixed/sub/b.txt"
ln -s a.txt "$TMP/ev-mixed/a-link.txt"
ln -s sub "$TMP/ev-mixed/sub-link"
chmod -R a-w "$TMP/ev-mixed"/a.txt "$TMP/ev-mixed/sub/b.txt"
# Its directories too: a writable directory is a place names can change.
chmod a-w "$TMP/ev-mixed/sub" "$TMP/ev-mixed"
out="$(start --isolation microvm --inputs "$TMP/ev-mixed" --label vm-links)"; rc=$?
chmod u+w "$TMP/ev-mixed" "$TMP/ev-mixed/sub"
[[ $rc -eq 0 ]] || fail "evidence with links inside it exited $rc: $out"
sbx="$(sandbox_of "$out")"
jq -e '[.files[] | select(.link)] | map({path, link}) == [{path: "inputs/a-link.txt", link: "a.txt"}, {path: "inputs/sub-link", link: "sub"}]' "$sbx/inputs.json" >/dev/null \
  || fail "the manifest does not record the links as links: $(jq -c '.files' "$sbx/inputs.json")"
[[ "$(jq '[.files[] | select(.link | not)] | length' "$sbx/inputs.json")" == "2" ]] || fail "a directory link was walked into, or a file was lost"
grep -q 'is writable by this account' <<<"$out" && fail "read-only evidence was said to be writable"
node --experimental-strip-types --no-warnings --input-type=module -e "
  const P = await import('$ROOT/extensions/protocol.ts');
  const c = await P.verifyInputs('$sbx');
  if (!c.ok) { console.error(JSON.stringify(c)); process.exit(1); }
" || fail "the agents' own inputs check calls unchanged evidence with links in it changed"
(cd "$sbx" && python3 "$ROOT/packs/computer-forensics-base/tools/check_inputs/run.py" >/dev/null) || fail "the pack's check_inputs calls it changed"
pass "links inside the evidence are recorded as links, and the manifest, the agents' check and check_inputs agree they are unchanged"

chmod u+w "$TMP/ev-mixed/a.txt"
out="$(start --isolation microvm --inputs "$TMP/ev-mixed" --label vm-writable)"
grep -q 'is writable by this account' <<<"$out" || fail "writable evidence used in place is not warned about: $out"
out="$(start --isolation microvm --inputs "$TMP/ev-link" --inputs-copy --label vm-copy)"; rc=$?
[[ $rc -eq 0 ]] || fail "--inputs-copy exited $rc: $out"
sbx="$(sandbox_of "$out")"
[[ -d "$sbx/inputs" && ! -L "$sbx/inputs" ]] || fail "--inputs-copy did not copy the evidence into the run"
[[ "$(jq -r '.held' "$sbx/inputs.json")" == "copy" ]] || fail "the manifest does not say the evidence was copied"
[[ -z "$(find "$sbx/inputs" -type f -perm -u+w)" ]] || fail "the copy is writable"
pass "writable evidence used in place is warned about; --inputs-copy gives the run its own read-only copy"

# --- a reused sandbox starts clean; a prepared VM run touches no host tool ---------------
reuse="$TMP/reused"
out="$(start --isolation microvm --sandbox "$reuse" --label vm-reuse1)"
mkdir -p "$reuse/vm" "$reuse/tools/old_tool" "$reuse/history/x" "$reuse/.pi-sessions/old" "$reuse/tool-output/old"
printf '{}' > "$reuse/vm/old.json"; printf '{"summary":"old"}' > "$reuse/custody.json"; printf 'x' > "$reuse/tools/old_tool/manifest.json"
out="$(start --isolation microvm --sandbox "$reuse" --label vm-reuse2)"; rc=$?
[[ $rc -eq 0 ]] || fail "reusing a sandbox exited $rc: $out"
for gone in vm/old.json custody.json tools/old_tool .pi-sessions/old tool-output/old; do
  [[ ! -e "$reuse/$gone" ]] || fail "a reused sandbox kept the previous run's $gone"
done
# A sandbox a running run still uses is not cleared under it.
reuse_id="$(reg vm-reuse2 '.id')"
jq --arg id "$reuse_id" '.runs = [.runs[] | if .id == $id then .state = "running" else . end]' "$TMP/runs/registry.json" > "$TMP/reg.tmp" && mv "$TMP/reg.tmp" "$TMP/runs/registry.json"
touch "$reuse/work/keep-me"
out="$(start --isolation microvm --sandbox "$reuse" --label vm-reuse3)"; rc=$?
[[ $rc -eq 2 ]] && grep -q "run $reuse_id is still running in" <<<"$out" || fail "a sandbox a running run uses was taken: $out"
[[ -e "$reuse/work/keep-me" ]] || fail "the running run's work was cleared"
jq --arg id "$reuse_id" '.runs = [.runs[] | if .id == $id then .state = "stopped" else . end]' "$TMP/runs/registry.json" > "$TMP/reg.tmp" && mv "$TMP/reg.tmp" "$TMP/runs/registry.json"
pass "a reused sandbox loses the previous run's VM records, custody, tools, sessions and outputs, and one a running run uses is refused"
out="$(start --isolation microvm --inputs "$TMP/ev" --catalog --label vm-prepared)"; rc=$?
[[ $rc -eq 0 ]] || fail "a prepared VM run with --catalog exited $rc: $out"
sbx="$(sandbox_of "$out")"
grep -q 'built in the run.s image when the VMs start' <<<"$out" || fail "a prepared VM run does not say where its catalog will be built: $out"
[[ ! -f "$sbx/catalog/README.md" ]] || fail "a prepared VM run built its catalog with this host's tools"
[[ ! -f "$sbx/toolbox.json" ]] || fail "a prepared VM run checked this host's toolbox"
[[ -f "$TMP/runs/$(basename "$sbx").custody-anchor.json" || -f "$sbx.custody-anchor.json" ]] || fail "no custody anchor outside the run"
pass "a prepared VM run leaves the toolbox and the catalog to the image, and anchors its manifest outside the run"

out="$(start --isolation microvm --no-vm-snapshot --label vm-nosnap)"
[[ "$(reg vm-nosnap '.isolation.snapshot')" == "false" ]] || fail "--no-vm-snapshot is not recorded"
pass "--no-vm-snapshot is recorded for stop to read"

# --- the package carries what a VM run adds -----------------------------------------
pkg_id="$(reg vm-ev '.id')"
pkg_sb="$(reg vm-ev '.sandbox')"
mkdir -p "$pkg_sb/vm" "$pkg_sb/tool-output/${pkg_id}00"
printf '{"agent":"%s00","name":"dfs-x","image":{"ref":"img","manifest_digest":"sha256:aa"}}\n' "$pkg_id" > "$pkg_sb/vm/${pkg_id}00.json"
printf '{"ts":"t","agent":"%s00","tool":"bash","args":{},"result":{}}\n' "$pkg_id" > "$pkg_sb/tool-output/${pkg_id}00/trace-spill.jsonl"
printf '{"ts":"t","agent":"system","tool":"idle_nudge","args":{},"result":{}}\n' > "$pkg_sb/traces/system-spill.jsonl"
out="$(swarm package "$pkg_id")"; rc=$?
[[ $rc -eq 0 ]] || fail "package of a VM run exited $rc: $out"
[[ -f "$pkg_sb/package/vm/${pkg_id}00.json" ]] || fail "the package lacks the VM records"
[[ -f "$pkg_sb/package/trace/spill-${pkg_id}00.jsonl" ]] || fail "the package lacks an agent's trace spill"
[[ -f "$pkg_sb/package/trace/spill-system.jsonl" ]] || fail "the package lacks the watchdogs' spill"
grep -q "vm/${pkg_id}00.json" "$pkg_sb/package/MANIFEST.txt" || fail "the VM record is not in the package's manifest"
pass "a VM run's package carries its VM records and every trace line that missed the chain, in its manifest"
# A link a seat left where its spill should be is not followed into the package.
printf 'OPERATOR SECRET\n' > "$TMP/operator-file"
rm -f "$pkg_sb/tool-output/${pkg_id}00/trace-spill.jsonl"
ln -s "$TMP/operator-file" "$pkg_sb/tool-output/${pkg_id}00/trace-spill.jsonl"
out="$(swarm package "$pkg_id")"; rc=$?
[[ $rc -eq 0 ]] || fail "package with a planted link exited $rc: $out"
[[ ! -e "$pkg_sb/package/trace/spill-${pkg_id}00.jsonl" ]] || fail "the package followed a planted link into a host file"
grep -rq "OPERATOR SECRET" "$pkg_sb/package" && fail "a host file reached the package"
pass "the package copies only regular files: a link a seat left in place of its spill is not followed"

# --- what the review found in the kickoff ----------------------------------------------
# A prepared VM run with forging on writes its spec (the tool list was unset there).
out="$(start --isolation microvm --allow-tool-forging --label vm-forge-prepared)"; rc=$?
[[ $rc -eq 0 ]] || fail "--isolation microvm --allow-tool-forging --no-start exited $rc: $out"
[[ -n "$(jq -r '.env.SWARM_TOOLS // empty' "$(sandbox_of "$out")/vm-spec.json")" ]] || fail "the prepared spec has no tool list"
# --allow-install in a VM installs into the VM's own disk, never a shared toolchain.
out="$(start --isolation microvm --allow-install --label vm-install)"; rc=$?
[[ $rc -eq 0 ]] || fail "a prepared VM run with --allow-install exited $rc: $out"
sbx="$(sandbox_of "$out")"
[[ "$(jq -r '.env.SWARM_TOOLCHAIN' "$sbx/vm-spec.json")" == "/opt/dfir/agent" ]] || fail "the VMs are not pointed at their own disk for installs"
[[ ! -d "$sbx/work/.toolchain" ]] || fail "a VM run made the host's shared toolchain directory"
grep -q "each VM's own disk" <<<"$out" || fail "the Install line does not say where a VM installs: $out"
# A credential name in --env is refused whatever its case, and so is a user:password in a URL.
out="$(start --isolation microvm --env openai_api_key=abc --label bad-env-lower)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'names a credential' <<<"$out" || fail "a lower-case credential name in --env went through: $out"
out="$(start --isolation microvm --env PROXY_URL=https://user:pw@proxy.example --label bad-env-url)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'user and password in a URL' <<<"$out" || fail "a URL credential in --env went through: $out"
# A suffix in the allowlist is said to be a way out as well as in.
out="$(start --isolation microvm --allow-host '*.blob.core.windows.net' --label vm-suffix)"; rc=$?
[[ $rc -eq 0 ]] || fail "a suffix allow entry exited $rc: $out"
grep -q 'lets an agent reach, and send data to, any host under it' <<<"$out" || fail "a suffix allow entry was not warned about: $out"
# A pack that binds a secret to a suffix is refused: msb would put the value on any host under it.
rm -rf "$TMP/psrc/suffix-pack"
cp -R "$TMP/psrc/keyed-pack" "$TMP/psrc/suffix-pack"
jq '.id = "suffix-pack" | .name = "suffix-pack" | del(.checksums) | .secrets = [{name: "WIDE_KEY", title: "A key", why: "For the suite.", required: false, hosts: [".example.test"]}]' \
  "$TMP/psrc/keyed-pack/pack.json" > "$TMP/psrc/suffix-pack/pack.json"
# The pack format refuses it at seal time (the kickoff and the VM manager
# refuse it again, for a pack that got past that).
out="$(bash "$ROOT/scripts/pack.sh" seal "$TMP/psrc/suffix-pack" 2>&1)" && fail "a pack binding a secret to a suffix was sealed: $out"
grep -q 'hosts must be a list of host names' <<<"$out" || fail "the seal refusal does not say why: $out"
# A lock that pins by tag, not digest, is refused.
printf '{"images":{"base":{"%s":"ghcr.io/x/dfirswarm-base:latest"}}}\n' "$ARCH" > "$TMP/tag-lock.json"
out="$(SWARM_IMAGES_LOCK="$TMP/tag-lock.json" start --isolation microvm --label vm-tag-lock)"; rc=$?
[[ $rc -ne 0 ]] && grep -q 'other than its digest' <<<"$out" || fail "a lock pinned by tag went through: $out"
pass "a prepared forging VM run writes its tools, installs go to the VM's disk, --env credentials are refused whatever their case or form, suffixes are warned about, a secret on a suffix and a tag lock are refused"

# --- a synced folder is found before anything is written -------------------------
SYNCED="$TMP/home/Library/CloudStorage/Dropbox-Test"
mkdir -p "$SYNCED"
host_start() { SWARM_RUNS_DIR="$1" bash "$ROOT/scripts/swarm.sh" start --isolation host --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off "${@:2}" 2>&1; }
out="$(host_start "$SYNCED/runs" --inputs "$TMP/ev" --label synced-copy)"; rc=$?
[[ $rc -eq 2 ]] || fail "a copy of the evidence into a synced folder exited $rc, wanted 2: $out"
grep -q 'the copy of the evidence (inputs/ and .inputs-pristine/)' <<<"$out" || fail "the refusal does not name the evidence copy: $out"
[[ -z "$(find "$SYNCED/runs" -name inputs -o -name .inputs-pristine 2>/dev/null)" ]] || fail "the evidence was copied into the synced folder before the refusal"
out="$(host_start "$SYNCED/runs" --inputs "$TMP/ev" --label synced-allowed --allow-synced-folder)"; rc=$?
[[ $rc -eq 0 ]] || fail "--allow-synced-folder did not let the run go: $out"
grep -q 'as --allow-synced-folder asks' <<<"$out" || fail "an allowed synced copy was not said: $out"
out="$(start --isolation microvm --inputs "$TMP/ev" --vm-snapshot-dir "$SYNCED/disks" --label synced-disks)"; rc=$?
[[ $rc -eq 2 ]] || fail "VM disks kept in a synced folder exited $rc, wanted 2: $out"
grep -q "each VM's kept disk ($SYNCED/disks" <<<"$out" || fail "the refusal does not name the disks' folder: $out"
pass "a copy of the evidence or the VMs' disks bound for a synced folder is refused before anything is written, unless --allow-synced-folder"

# --- where the disks are kept, and what is read-only on disk ----------------------
out="$(start --isolation microvm --inputs "$TMP/ev" --vm-snapshot-dir "$TMP/disks" --label vm-disks-dir)"; rc=$?
[[ $rc -eq 0 ]] || fail "--vm-snapshot-dir was refused: $out"
sbx="$(sandbox_of "$out")"
[[ -L "$sbx.vm-snapshots" && "$(readlink "$sbx.vm-snapshots")" == "$(cd "$TMP/disks" && pwd -P)" ]] || fail "the disks' link beside the run does not name --vm-snapshot-dir: $(ls -l "$sbx.vm-snapshots" 2>&1)"
[[ "$(stat -c %a "$TMP/disks" 2>/dev/null || stat -f %Lp "$TMP/disks")" == "700" ]] || fail "the disks' directory is not the user's alone"
# A run whose disks' place already holds an earlier run's disks is refused.
rm -f "$sbx.vm-snapshots"
mkdir -p "$sbx.vm-snapshots"
printf 'disk' > "$sbx.vm-snapshots/old.msb"
out="$(start --isolation microvm --inputs "$TMP/ev" --vm-snapshot-dir "$TMP/disks" --sandbox "$sbx" --label vm-disks-taken)"; rc=$?
[[ $rc -eq 2 ]] && grep -q "already holds an earlier run's disks" <<<"$out" || fail "a disks' place holding an earlier run's disks was not refused ($rc): $out"
[[ -f "$sbx.vm-snapshots/old.msb" ]] || fail "the earlier run's disk was touched"
rm -rf "$sbx.vm-snapshots"
# The manifest and the custody anchor are read-only on disk.
out="$(start --isolation microvm --inputs "$TMP/ev" --label vm-ro-record)"; rc=$?
sbx="$(sandbox_of "$out")"
[[ -f "$sbx/inputs.json" && ! -w "$sbx/inputs.json" ]] || fail "inputs.json is writable on disk"
anchor="$(dirname "$sbx")/$(basename "$sbx").custody-anchor.json"
[[ -f "$anchor" && ! -w "$anchor" ]] || fail "the custody anchor is writable on disk"
[[ "$(jq -r '.isolation' "$anchor")" == "microvm" ]] || fail "the custody anchor does not say how the agents were held: $(cat "$anchor")"
[[ "$(reg vm-ro-record '.inputs_manifest_sha256')" == "$(shasum -a 256 "$sbx/inputs.json" | cut -d' ' -f1)" ]] || fail "the registry does not hold the manifest's sha256"
pass "--vm-snapshot-dir is linked beside the run (0700) and an occupied place refused; the manifest and the anchor are read-only and the anchor says microvm"

# --- the run records what produced it and the host's clock ------------------------
[[ "$(reg vm-ro-record '.provenance.harness_commit')" =~ ^[0-9a-f]{40}$|^not\ a\ git ]] || fail "no harness commit in the record: $(reg vm-ro-record '.provenance')"
[[ "$(reg vm-ro-record '.provenance.node_version')" == "$(node --version)" ]] || fail "the record's Node version is not this Node"
[[ "$(reg vm-ro-record '.provenance.harness_dirty | type')" == "boolean" ]] || fail "the record does not say whether the checkout had local changes"
[[ -n "$(reg vm-ro-record '.host_clock.utc_offset')" && "$(reg vm-ro-record '.host_clock.run_processes_tz')" == "UTC" ]] || fail "the record does not hold the host's clock: $(reg vm-ro-record '.host_clock')"
[[ "$(reg vm-ro-record '.host_clock.synced | type')" =~ ^(boolean|null)$ ]] || fail "host_clock.synced is neither known nor null"
jq -e '.env.TZ == "UTC"' "$sbx/vm-spec.json" >/dev/null || fail "the agents' environment is not in UTC: $(jq -c '.env' "$sbx/vm-spec.json")"
# A proxy the operator's shell uses is the host's, in any case of its name.
out="$(start --isolation microvm --inputs "$TMP/ev" --env https_proxy=http://proxy.example:3128 --env No_Proxy=corp.example --env HTTP_PROXY=http://p:1 --label vm-proxy-env)"; rc=$?
sbp="$(sandbox_of "$out")"
[[ $rc -eq 0 ]] || fail "a kickoff with proxy settings in --env failed: $out"
jq -e '.env | keys | map(ascii_upcase) | (index("HTTPS_PROXY") == null and index("NO_PROXY") == null and index("HTTP_PROXY") == null)' "$sbp/vm-spec.json" >/dev/null || fail "a proxy setting crossed into the VMs: $(jq -c '.env' "$sbp/vm-spec.json")"
out="$(start --isolation microvm --inputs "$TMP/ev" --custody-timeout 900 --label vm-custody-time)"; rc=$?
[[ $rc -eq 0 && "$(reg vm-custody-time '.custody_timeout_sec')" == "900" ]] || fail "--custody-timeout is not recorded for the run: $out"
out="$(start --isolation microvm --inputs "$TMP/ev" --custody-timeout soon --label vm-custody-bad)"; rc=$?
[[ $rc -eq 2 ]] || fail "a --custody-timeout that is not a number was taken ($rc): $out"
grep -q 'SWARM_CUSTODY_TIMEOUT="${custody_timeout' "$ROOT/scripts/swarm.sh" || fail "the hub is not given the run's custody deadline"
pass "the record holds the harness commit, Node, whether the checkout had changes, and the host's clock; the agents run in UTC; the custody deadline is the run's own"

# --- the operator is on the record -----------------------------------------------
audit="$TMP/runs/operator-audit.jsonl"
[[ -s "$audit" ]] || fail "no operator audit record in the runs directory"
last="$(tail -1 "$audit")"
[[ "$(jq -r '.command' <<<"$last")" == "start" && "$(jq -r '.os_user' <<<"$last")" == "$(id -un)" ]] || fail "the audit line does not name the command and the OS user: $last"
python3 - "$audit" <<'PY' || fail "the operator audit record's chain is broken"
import hashlib, sys
lines = [l for l in open(sys.argv[1], encoding="utf-8").read().split("\n") if l]
import json
for a, b in zip(lines, lines[1:]):
    if json.loads(b).get("prev") != hashlib.sha256(a.encode()).hexdigest():
        sys.exit(1)
PY
out="$(swarm start --isolation host --model solo/model --provider-host solo=api.solo.example --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --toolbox off --env SOME_SETTING=hush-hush --label audit-redact)"
! grep -q 'hush-hush' "$audit" || fail "an --env value reached the operator audit record"
pass "every start is on the operator's own record, chained, with the OS user and an --env value left out"

# --- an earlier run's claims in a VM run: on the read-only floor ------------------
mkdir -p "$TMP/runs/sprv9/ledger"
printf '%s\n' '{"v":2,"seq":1,"kind":"finding","value":"earlier claim","by":"sprv900","authors":["sprv900"],"at":"t","prev":"genesis","hash":"p1"}' > "$TMP/runs/sprv9/ledger/entries.jsonl"
jq --arg sb "$TMP/runs/sprv9" '.runs += [{id: "sprv9", label: "prior-run", state: "done", sandbox: $sb, n: 1}]' "$TMP/runs/registry.json" > "$TMP/runs/registry.json.new" && mv "$TMP/runs/registry.json.new" "$TMP/runs/registry.json"
out="$(start --isolation microvm --inputs "$TMP/ev" --ledger-from sprv9 --label vm-prior)"; rc=$?
[[ $rc -eq 0 ]] || fail "a VM run with --ledger-from exited $rc: $out"
sbx="$(sandbox_of "$out")"
[[ -f "$sbx/prior/ledger.md" ]] && grep -q 'earlier claim' "$sbx/prior/ledger.md" || fail "the VM run has no prior/ledger.md"
# What each VM mounts is the spec's mounts plus the floor and the seat's own
# holes (vm.ts mountsFor): the floor is read-only, and no writable mount is
# prior/ or under it.
node --experimental-strip-types --no-warnings -e '
  const [vm, specFile] = process.argv.slice(2);
  import(vm).then((V) => {
    const spec = JSON.parse(require("fs").readFileSync(specFile, "utf8"));
    for (const a of spec.agents) {
      const all = [...V.mountsFor(spec, a.id), ...(spec.mounts ?? []), ...(spec.late_mounts ?? [])];
      if (!all.some((m) => m.host === spec.sandbox && m.readonly)) { console.error("no read-only floor for " + a.id); process.exit(1); }
      const rw = all.filter((m) => !m.readonly && (m.host === spec.sandbox + "/prior" || m.host.startsWith(spec.sandbox + "/prior/")));
      if (rw.length) { console.error("writable over prior/: " + JSON.stringify(rw)); process.exit(1); }
    }
  });
' -- not-a-script "$ROOT/scripts/vm.ts" "$sbx/vm-spec.json" || fail "prior/ is not on the VMs' read-only floor"
pass "an earlier run's claims sit on a VM run's read-only floor, with no writable mount over them"

# --- root: a VM run is warned about, not refused -----------------------------------
mkdir -p "$TMP/rootbin"
printf '#!/usr/bin/env bash\nif [[ "${1:-}" == "-u" ]]; then echo 0; else exec /usr/bin/id "$@"; fi\n' > "$TMP/rootbin/id"
chmod +x "$TMP/rootbin/id"
out="$(PATH="$TMP/rootbin:$PATH" start --isolation microvm --inputs "$TMP/ev" --label vm-root)"; rc=$?
[[ $rc -eq 0 ]] || fail "a VM run as root was refused (rc $rc): $out"
grep -q 'WARN: this run is started as root.*The VMs still hold the evidence read-only' <<<"$out" || fail "a VM run as root is not warned about: $out"
pass "a VM run started as root is warned about, not refused"

# --- the model gateway: VM runs only, recorded, planned from the spec -------------
out="$(start --isolation host --model-gateway --label gw-host)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'BLOCKER: --model-gateway fronts VM runs' <<<"$out" || fail "--model-gateway on a host run was not refused (rc $rc): $out"
out="$(start --isolation microvm --inputs "$TMP/ev" --model-gateway --label gw-vm)"; rc=$?
[[ $rc -eq 0 ]] || fail "a prepared VM run with --model-gateway exited $rc: $out"
[[ "$(reg gw-vm '.isolation.model_gateway.on')" == true ]] || fail "the registry does not record the gateway: $(reg gw-vm '.isolation')"
[[ "$(reg vm-ev '.isolation.model_gateway // "absent"')" == absent ]] || fail "a run without the flag records a gateway"
# The plan from a spec: which providers it fronts, which it leaves to msb,
# each seat's token in a 0600 config, and none of it on stdout.
jq -n --arg sb "$TMP/gw-sb" '{run: "sgw1", sandbox: $sb, image: "i", hub_dir: "/h", mounts: [], env: {}, records_dir: "/r", allow_hosts: [],
  agents: [{id: "sgw100", model: "openai/gpt-5.4-mini"}, {id: "sgw101", model: "openrouter/x"}],
  providers: [{provider: "openai", kind: "api_key", hosts: ["api.openai.com"]}, {provider: "openrouter", kind: "api_key", hosts: ["openrouter.ai"]}]}' > "$TMP/gw-spec.json"
plan="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/vm.ts" gateway-plan --spec "$TMP/gw-spec.json" --out "$TMP/gw-config.json")" || fail "gateway-plan failed: $plan"
jq -e '.providers == ["openai"] and ([.declined[].provider] == ["openrouter"])' <<<"$plan" >/dev/null || fail "the plan does not front openai and leave openrouter: $plan"
mode="$(stat -c %a "$TMP/gw-config.json" 2>/dev/null || stat -f %Lp "$TMP/gw-config.json")"
[[ "$mode" == 600 ]] || fail "the gateway's config is mode $mode"
tok="$(jq -r '.seats.sgw100.token' "$TMP/gw-config.json")"
[[ ${#tok} -ge 32 ]] || fail "the seat has no gateway token"
grep -q "$tok" <<<"$plan" && fail "a seat's token was printed"
jq -e '.seats.sgw100.providers == ["openai"] and .seats.sgw101.providers == []' "$TMP/gw-config.json" >/dev/null || fail "the seats' providers are not what the gateway fronts"
pass "--model-gateway is refused for a host run, recorded for a VM run, and planned from the spec: openai fronted, openrouter left to msb, tokens only in the 0600 config"
