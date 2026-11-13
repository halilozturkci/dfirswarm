#!/usr/bin/env bash
# scripts/render-contract.ts against the Python program it replaces
# (tests/fixtures/render-contract-oracle.py, kept verbatim): the same
# template, goal, sandbox and environment give the same SWARM.md, byte for
# byte. The cases reach every section the contract has:
# - the inputs: a copy, in place, an image, sets, a microVM, more than 40
#   files, and sizes that round on a half;
# - the evidence catalog: fenced, growing, derived, with CRLF lines;
# - the programs: a host table, an image, job images;
# - the pack and seeded tools, this host's guards on Linux, macOS and a
#   microVM, the tool jobs and job images, the case line;
# - the goal: its inputs_check line, a BOM, CRLF;
# - the caps: until solved, cap-pause, cap-stop with tokens.
# No model, no Herdr, no VM.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/render-contract.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
TEMPLATE="$ROOT/prompts/swarm.md.template"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# Renders with both over one sandbox and one environment, and compares.
compare() { # <label> <sandbox> <goal> [ids] [cap] [wall] [n]
  local label="$1" sb="$2" goal="$3" ids="${4:-\`a0\`, \`a1\`}" cap="${5:-5}" wall="${6:-60}" n="${7:-2}"
  python3 "$ROOT/tests/fixtures/render-contract-oracle.py" "$TEMPLATE" "$TMP/py.md" "$goal" "$ids" "$cap" "$wall" "$n" "sw1" "$sb" 2> "$TMP/py.err" || fail "$label: the oracle failed: $(cat "$TMP/py.err")"
  node --experimental-strip-types --no-warnings "$ROOT/scripts/render-contract.ts" "$TEMPLATE" "$TMP/ts.md" "$goal" "$ids" "$cap" "$wall" "$n" "sw1" "$sb" 2> "$TMP/ts.err" || fail "$label: render-contract.ts failed: $(cat "$TMP/ts.err")"
  cmp -s "$TMP/py.md" "$TMP/ts.md" || { diff "$TMP/py.md" "$TMP/ts.md" | head -30 >&2; fail "$label: the contracts differ"; }
  pass "$label: the same SWARM.md ($(wc -c < "$TMP/ts.md" | tr -d ' ') bytes)"
}

manifest() { # <sandbox> <held> <guard> <bytes> [sets]
  python3 - "$@" <<'PY'
import json, sys
sb, held, guard, total = sys.argv[1:5]
sets = sys.argv[5] == "sets" if len(sys.argv) > 5 else False
files = [{"path": f"inputs/dir/file{i:02d}.bin", "bytes": b} for i, b in enumerate([0, 1023, 1024, 1280, 1536, 2560, 1127, 5 * 1024 * 1024 + 51] + [300] * 40)]
m = {"source": "/evidence/case one", "files": files, "bytes": int(total), "guard": guard, "held": held}
if sets:
    m["sets"] = [{"name": "disk", "path": "inputs/disk", "source": "/ev/disk", "files": 30, "bytes": 1}, {"name": "phone", "path": "inputs/phone", "source": "/ev/phone", "files": 18, "bytes": 2}]
json.dump(m, open(f"{sb}/inputs.json", "w"), indent=2)
PY
}

GOAL="$ROOT/prompts/goals/dfir-c10-meeting-location.md"
grep -q '"tool":"inputs_check"' "$GOAL" || fail "the goal used has no inputs_check line"

echo "# a bare sandbox: the goal alone, under each stop policy"
SB="$TMP/bare"; mkdir -p "$SB"
SWARM_CONTRACT_STOP_POLICY=cap-stop compare "cap-stop" "$SB" "$GOAL"
SWARM_CONTRACT_STOP_POLICY=cap-stop SWARM_CONTRACT_CAP_TOKENS=2000000 compare "cap-stop with a tokens cap" "$SB" "$GOAL"
SWARM_CONTRACT_STOP_POLICY=cap-pause compare "cap-pause" "$SB" "$GOAL"
SWARM_CONTRACT_UNTIL_SOLVED=1 SWARM_CONTRACT_CAP_TOKENS=900000 SWARM_CONTRACT_STALL_MINUTES=20 compare "until solved, with figures" "$SB" "$GOAL" '`a0`' 5
SWARM_CONTRACT_UNTIL_SOLVED=1 compare "until solved, no figures" "$SB" "$GOAL" '`a0`' 0
SWARM_CASE_ID="c10" SWARM_EXAMINER="Claude (a team)" compare "the case line" "$SB" "$GOAL"

echo "# the goal as written: a BOM and CRLF lines"
printf '\xef\xbb\xbf' > "$TMP/bom.md"; cat "$ROOT/prompts/goals/hello.md" >> "$TMP/bom.md"
compare "a goal with a BOM" "$SB" "$TMP/bom.md"
sed 's/$/\r/' "$GOAL" > "$TMP/crlf.md"
compare "a goal with CRLF lines" "$SB" "$TMP/crlf.md"

echo "# the inputs, every way they are held"
for held_guard in "copy none 6000" "copy seatbelt 1536" "copy linux 2560" "bind seatbelt 1280" "bind microvm 99999" "image image 3584" "copy microvm 512"; do
  set -- $held_guard
  SB="$TMP/in-$1-$2"; mkdir -p "$SB"; manifest "$SB" "$1" "$2" "$3"
  compare "inputs held $1, guard $2, $3 bytes" "$SB" "$GOAL"
  SB2="$TMP/sets-$1-$2"; mkdir -p "$SB2"; manifest "$SB2" "$1" "$2" "$3" sets
  compare "inputs in sets, held $1, guard $2" "$SB2" "$GOAL"
done

echo "# the evidence catalog"
SB="$TMP/catalog"; mkdir -p "$SB/catalog"
printf '# Evidence index\r\n\r\n| input | status |\r\n| --- | --- |\r\n| disk.E01 | catalogued |\r\n\r\n```\r\nfenced by the evidence\r\n```\r\n  \n' > "$SB/catalog/README.md"
compare "a catalog, fenced, CRLF" "$SB" "$GOAL"
: > "$SB/catalog/plan.json"
compare "a growing catalog" "$SB" "$GOAL"
SWARM_CONTRACT_JOBS='{"derived":true}' compare "a growing catalog, derived" "$SB" "$GOAL"
SWARM_CONTRACT_JOBS='not json' compare "a growing catalog, jobs unreadable" "$SB" "$GOAL"

echo "# the programs"
SB="$TMP/toolbox-host"; mkdir -p "$SB"
printf '%s\n' '{"context":"host","present":[{"name":"fls","version":"4.12","use":"list files"},{"name":"vol","use":"memory"}],"missing":[{"name":"bdemount","use":"BitLocker","install":"brew install libbde"}]}' > "$SB/toolbox.json"
compare "a host toolbox" "$SB" "$GOAL"
SWARM_CONTRACT_ALLOW_INSTALL=1 SWARM_CONTRACT_INSTALL_HOSTS=1 compare "a host toolbox, installs allowed" "$SB" "$GOAL"
SWARM_CONTRACT_ALLOW_INSTALL=1 SWARM_CONTRACT_INSTALL_HOSTS=0 compare "a host toolbox, no index" "$SB" "$GOAL"
SB="$TMP/toolbox-requires"; mkdir -p "$SB"
printf '%s\n' '{"context":"host","present":[{"name":"ffmpeg","version":"7","use":"video"}],"missing":[],"requires":[{"capability":"video-decode","met":true,"by":["ffmpeg"],"wanted":["ffmpeg","ffprobe"],"use":"decode a video"},{"capability":"qr-decode","met":false,"by":[],"wanted":["zbarimg"],"use":"decode QR codes","present_but_failed_probe":["zbarimg"]},{"capability":"ocr","met":false,"by":[],"wanted":["tesseract"],"use":"read text"}]}' > "$SB/toolbox.json"
compare "a host toolbox with what the case requires" "$SB" "$GOAL"
SB="$TMP/toolbox-image"; mkdir -p "$SB"
printf '%s\n' '{"context":"image","image":"dfirswarm-full:dev","tools_md":"/etc/dfirswarm/tools.md"}' > "$SB/toolbox.json"
compare "an image toolbox" "$SB" "$GOAL"
SWARM_CONTRACT_JOBS='{"images":{"disk":"dfirswarm-disk:dev"}}' compare "an image toolbox, job images" "$SB" "$GOAL"
printf '%s\n' '{"context":"image","image":"dfirswarm-full:dev"}' > "$SB/toolbox.json"
compare "an image toolbox without its tools list" "$SB" "$GOAL"

echo "# the pack and seeded tools"
SB="$TMP/tools"; mkdir -p "$SB/tools/zeta" "$SB/tools/alpha" "$SB/tools/packed" "$SB/tools/broken" "$SB/tools/noman"
printf '%s\n' '{"name":"zeta","description":"Reads   inputs/Case4.E01\tat  an offset","params":{"image":{},"offset":{}},"example":"{\"image\":\"inputs/Case4.E01\",\"offset\":2048,\"partition_offset\":\"63\"}"}' > "$SB/tools/zeta/manifest.json"
printf '%s\n' '{"name":"alpha","description":"A general reader","params":{},"example":"not json"}' > "$SB/tools/alpha/manifest.json"
printf '%s\n' '{"name":"mft_timeline","pack":"windows-forensics","description":"x"}' > "$SB/tools/packed/manifest.json"
printf 'not json' > "$SB/tools/broken/manifest.json"
compare "pack and seeded tools" "$SB" "$GOAL"

echo "# this host, its jobs and its images"
SB="$TMP/host"; mkdir -p "$SB"
SWARM_CONTRACT_HOST_CAPS='{"os":"Linux","userns":false,"pidns":false}' SWARM_CONTRACT_WRITE_GUARD=landlock SWARM_CONTRACT_ATTRIBUTION=token-exposed compare "a Linux host without namespaces" "$SB" "$GOAL"
SWARM_CONTRACT_HOST_CAPS='{"os":"Darwin"}' SWARM_CONTRACT_WRITE_GUARD=seatbelt SWARM_CONTRACT_ATTRIBUTION=ancestry compare "a macOS host" "$SB" "$GOAL"
SWARM_CONTRACT_HOST_CAPS='{"os":"Darwin"}' SWARM_CONTRACT_WRITE_GUARD=other compare "a guard not recorded" "$SB" "$GOAL"
JOBS='{"workers":4,"cpus":2,"memoryMib":4096,"allowHosts":["msdl.microsoft.com"],"image":"dfirswarm-full:dev","images":{"linux":"dfirswarm-linux:dev","disk":"dfirswarm-disk:dev"},"packProfiles":{"windows-forensics":"disk","encrypted-containers":"disk","linux-forensics":"linux"}}'
for inst in "0 1" "1 1" "1 0"; do
  set -- $inst
  SWARM_CONTRACT_HOST_CAPS='{"os":"Linux","userns":true,"pidns":true}' SWARM_CONTRACT_WRITE_GUARD=microvm SWARM_CONTRACT_ATTRIBUTION=channel SWARM_CONTRACT_ISOLATION=microvm \
    SWARM_CONTRACT_VM_HOSTS="msdl.microsoft.com, pypi.org" SWARM_CONTRACT_ALLOW_INSTALL="$1" SWARM_CONTRACT_INSTALL_HOSTS="$2" SWARM_CONTRACT_JOBS="$JOBS" \
    compare "a microVM run with jobs and images (install $1, index $2)" "$SB" "$GOAL"
done
SWARM_CONTRACT_HOST_CAPS='{"os":"Linux"}' SWARM_CONTRACT_ISOLATION=microvm SWARM_CONTRACT_VM_HOSTS="every public host" SWARM_CONTRACT_JOBS='{"workers":2}' compare "a microVM run, the network open, two workers" "$SB" "$GOAL"
SWARM_CONTRACT_HOST_CAPS='{"os":"Linux"}' SWARM_CONTRACT_ISOLATION=microvm SWARM_CONTRACT_JOBS='{"workers":"many"}' compare "a microVM run, no hosts, workers unreadable" "$SB" "$GOAL"
SWARM_CONTRACT_HOST_CAPS='not json' compare "host caps unreadable" "$SB" "$GOAL"

echo "# every section at once, a mixed team"
SB="$TMP/all"; mkdir -p "$SB/catalog"; manifest "$SB" copy microvm 12345 sets; cp "$TMP/catalog/catalog/README.md" "$SB/catalog/"; cp -R "$TMP/tools/tools" "$SB/"; cp "$TMP/toolbox-image/toolbox.json" "$SB/"
SWARM_CASE_ID=c10 SWARM_EXAMINER=Claude SWARM_CONTRACT_HOST_CAPS='{"os":"Linux","userns":true,"pidns":true}' SWARM_CONTRACT_WRITE_GUARD=microvm SWARM_CONTRACT_ATTRIBUTION=channel SWARM_CONTRACT_ISOLATION=microvm SWARM_CONTRACT_VM_HOSTS="msdl.microsoft.com" SWARM_CONTRACT_JOBS="$JOBS" SWARM_CONTRACT_STOP_POLICY=cap-pause SWARM_CONTRACT_CAP_TOKENS=5000000 \
  compare "every section at once" "$SB" "$GOAL" '`a0` (openai/gpt), `a1` (anthropic/claude)' 250 0 8
