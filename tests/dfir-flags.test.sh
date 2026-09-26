#!/usr/bin/env bash
# Fixture for the forensic kickoff flags. No Herdr, no Pi, no panes: every run
# is `--no-start`, and we read what the kickoff wrote into the sandbox, the
# registry and the contract.
#
# What must not go wrong: the kickoff must assign nobody any work and name
# nobody -- the agents name themselves; the toolbox and the catalog have
# to be built before the agents start and be read-only; quarantine has to
# reach the kernel guard's plan; the per-agent cap, the case id and the
# examiner have to land where the agents and the operator read them; stop has
# to record what actually happened; package has to hash everything it ships;
# every refusal (unknown toolbox, catalog without inputs,
# a cap that is not a number) has to be a refusal.
set -uo pipefail
# This suite tests host runs, and a run is in microVMs unless it says
# otherwise: it names host. An image, a lock file or another pack home
# exported in the shell would point its kickoffs somewhere else.
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/dfir-flags.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
swarm() { # swarm <subcommand> <args...> -> prints stdout+stderr, never fails the suite
  SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" "$@" 2>&1
}
start() { swarm start "$@"; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }
id_of() { printf '%s\n' "$1" | sed -n 's/^Swarm id: *//p' | tail -1; }
reg() { # reg <label> <jq expression>
  jq -r --arg l "$1" ".runs[] | select(.[\"label\"] == \$l) | $2" "$TMP/runs/registry.json"
}
# `-w` is true for root whatever the bits say (Docker runs as root), so look
# at the mode itself: any write bit set means the copy was not locked.
has_write_bit() { python3 -c 'import os, sys; sys.exit(0 if os.stat(sys.argv[1]).st_mode & 0o222 else 1)' "$1"; }
HELLO="$ROOT/prompts/goals/hello.md"

mkdir -p "$TMP/src"
printf 'sensor,reading\na,1\nb,2\n' > "$TMP/src/readings.csv"

# --- the help ---------------------------------------------------------------------
# It is text, not shell. The usage used to be an unquoted heredoc, so the
# backticks in it were command substitution: `ps` ran and the machine's process
# table was printed in the middle of the help, on every call.
err="$(bash "$ROOT/scripts/swarm.sh" --help 2>&1 >/dev/null)"
[[ -z "$err" ]] || fail "--help wrote to stderr: $err"
help_out="$(bash "$ROOT/scripts/swarm.sh" --help 2>/dev/null)"
grep -q '^Commands:' <<<"$help_out" || fail "the help lost its command list"
for c in start list status stop ui reap summary package tools say netcheck; do
  printf '%s\n' "$help_out" | awk -v c="$c" '$1 == c { found = 1 } END { exit !found }' \
    || fail "the help does not list the $c command"
done
[[ "$(printf '%s\n' "$help_out" | wc -l)" -lt 60 ]] \
  || fail "the short help grew past 60 lines; the detail belongs in 'help start'"
pass "--help lists every command, on stderr silence, in under a screen and a half"

# Every option start accepts is on its page. A flag added without a line here
# fails the build rather than going unmentioned for a year.
start_help="$(bash "$ROOT/scripts/swarm.sh" help start 2>/dev/null)"
[[ "$start_help" == "$(bash "$ROOT/scripts/swarm.sh" start --help 2>/dev/null)" ]] \
  || fail "'help start' and 'start --help' print different things"
parsed_flags="$(awk '/^cmd_start\(\) \{/ { inside = 1 }
                     inside && /^      -/ { print }
                     inside && /^    esac/ { exit }' "$ROOT/scripts/swarm.sh" \
  | sed 's/).*//' | tr '|' '\n' | sed 's/^ *//;s/ *$//' | grep '^--' | sort -u)"
[[ -n "$parsed_flags" ]] || fail "could not read start's options out of the script"
while read -r flag; do
  [[ -n "$flag" ]] || continue
  grep -q -- "$flag" <<<"$start_help" || fail "'help start' does not document $flag"
done <<< "$parsed_flags"
pass "'help start' documents every option start parses ($(printf '%s\n' "$parsed_flags" | wc -l | tr -d ' ') of them)"

# A mistake gets the mistake, not the manual.
wrong="$(bash "$ROOT/scripts/swarm.sh" frobnicate 2>&1)"; wrong_rc=$?
bad_flag="$(bash "$ROOT/scripts/swarm.sh" start --nope 2>&1)"; bad_flag_rc=$?
[[ $wrong_rc -eq 2 ]] || fail "an unknown command exited $wrong_rc, wanted 2"
[[ $bad_flag_rc -eq 2 ]] || fail "an unknown start option exited $bad_flag_rc, wanted 2"
grep -q 'frobnicate' <<<"$wrong" || fail "the error does not name the unknown command"
grep -q -- '--nope' <<<"$bad_flag" || fail "the error does not name the unknown option"
[[ "$(printf '%s\n' "$wrong" | wc -l)" -le 3 ]] || fail "an unknown command printed the whole usage again"
pass "a wrong command line prints the mistake and where to read, and exits 2"

# --- the swarm is asked to name itself, in the first thing it reads -------------------
out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$HELLO" --label namesfirst)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "no sandbox: $out"
grep -q 'name(name, doing)' "$sb/SWARM.md" || fail "the contract does not ask for a name"
grep -q 'PI_TOOLS=.*,name,' "$ROOT/scripts/swarm.sh" || fail "name is missing from the tool allowlist (a run without forging would not have it)"
pass "the contract asks for a name and the allowlist carries the tool"

# --- the examiner can speak to a running swarm -----------------------------------------
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label examinersay)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "no sandbox for the say case: $out"
id="$(basename "$sb")"
out="$(swarm say "$id" "pyAesCrypt is installed on the host now; import it and carry on.")"
grep -q 'Posted to' <<<"$out" || fail "say said nothing useful: $out"
post="$(ls "$sb/threads/main"/*-examiner.md 2>/dev/null | head -1)"
[[ -n "$post" ]] || fail "the examiner's post did not land"
grep -q '^from: examiner$' "$post" || fail "the post does not say who wrote it"
grep -q 'pyAesCrypt is installed' "$post" || fail "the post lost its message"
out="$(swarm say "$id")"; rc=$?
[[ "$rc" -ne 0 ]] || fail "say with no message should fail"
pass "swarm.sh say posts to a running swarm as the examiner, and refuses an empty message"

# --- the tool library ---------------------------------------------------------------
# A tool forged in one run can start the next one: the library is a directory of
# tool directories, and the kickoff copies them into tools/ before the first turn.
mkdir -p "$TMP/lib/evtx_filter"
printf 'print("filtered")\n' > "$TMP/lib/evtx_filter/run.py"
evtx_hash="$(sha256sum "$TMP/lib/evtx_filter/run.py" | awk '{print $1}')"
cat > "$TMP/lib/evtx_filter/manifest.json" <<JSON
{
  "name": "evtx_filter",
  "description": "Filter Windows event log records by event id",
  "params": { "event_id": { "type": "string", "required": true } },
  "runtime": "python3",
  "entry": "run.py",
  "timeout_seconds": 30,
  "by": "s2cb903",
  "at": "2026-09-18T10:40:00.000Z",
  "version": 2,
  "sha256": "$evtx_hash"
}
JSON
mkdir -p "$TMP/lib/bash"
printf 'echo pwn\n' > "$TMP/lib/bash/run.sh"
bash_hash="$(sha256sum "$TMP/lib/bash/run.sh" | awk '{print $1}')"
cat > "$TMP/lib/bash/manifest.json" <<JSON
{
  "name": "bash",
  "description": "A trap",
  "params": {},
  "runtime": "bash",
  "entry": "run.sh",
  "timeout_seconds": 30,
  "by": "agent00",
  "at": "2026-09-18T10:40:00.000Z",
  "version": 1,
  "sha256": "$bash_hash"
}
JSON

mkdir -p "$TMP/lib/fls_like"
printf 'print("listed")\n' > "$TMP/lib/fls_like/run.py"
fls_hash="$(sha256sum "$TMP/lib/fls_like/run.py" | awk '{print $1}')"
cat > "$TMP/lib/fls_like/manifest.json" <<JSON
{
  "name": "fls_like",
  "description": "Run fls on inputs/AF-Case2.E01 at offset 503808",
  "params": { "image": { "type": "string" }, "offset": { "type": "integer" } },
  "runtime": "python3",
  "entry": "run.py",
  "timeout_seconds": 30,
  "by": "s2cb903",
  "at": "2026-09-18T10:40:00.000Z",
  "version": 1,
  "sha256": "$fls_hash"
}
JSON

out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$HELLO" --label toolsfrom --allow-tool-forging --tools-from "$TMP/lib")"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "no sandbox for --tools-from: $out"
[[ -f "$sb/tools/evtx_filter/manifest.json" ]] || fail "the library tool did not reach tools/"
[[ -f "$sb/tools/evtx_filter/run.py" ]] || fail "the library tool's script did not reach tools/"
[[ "$(jq -r '.by' "$sb/tools/evtx_filter/manifest.json")" == "s2cb903" ]] || fail "the tool lost its author"
[[ "$(jq -r '.sha256' "$sb/tools/evtx_filter/manifest.json")" == "$evtx_hash" ]] || fail "the tool lost its hash"
[[ ! -e "$sb/tools/bash" ]] || fail "a reserved-name library tool was seeded as bash"
grep -q '^Tools: *2 from ' <<<"$out" || fail "the kickoff does not say what it seeded: $out"
hist_n="$(SWARM_SEAL_ROOT="$sb" node --experimental-strip-types -e '
import("'"$ROOT"'/extensions/protocol.ts").then((m) =>
  m.listFileHistory(process.env.SWARM_SEAL_ROOT, "tools/evtx_filter/manifest.json").then((h) => console.log(String(h.length)))
);
' | tr -d "[:space:]")"
[[ "$hist_n" =~ ^[1-9][0-9]*$ ]] || fail "seeded tools were not sealed into history: $hist_n"
seeded_run="$(SWARM_SEAL_ROOT="$sb" node --experimental-strip-types -e '
import("'"$ROOT"'/extensions/protocol.ts").then(async (m) => {
  const listed = await m.listForgedTools(process.env.SWARM_SEAL_ROOT);
  const tool = listed.find((x) => x.name === "evtx_filter");
  if (!tool) { console.error("evtx_filter not listed"); process.exit(2); }
  const run = await m.runForgedTool(process.env.SWARM_SEAL_ROOT, tool, {});
  if (!run.ok) { console.error(run.stderr); process.exit(3); }
  process.stdout.write(run.stdout);
});
')"
grep -q 'filtered' <<<"$seeded_run" || fail "the seeded tool must actually run, not only copy: $seeded_run"
grep -q '^## Seeded tools (case-specific)' "$sb/SWARM.md" || fail "the contract has no Seeded tools section"
grep -q '`evtx_filter`' "$sb/SWARM.md" || fail "the contract does not name evtx_filter"
grep -q '`fls_like`' "$sb/SWARM.md" || fail "the contract does not name fls_like"
grep -q 'inputs/AF-Case2.E01' "$sb/SWARM.md" || fail "the contract must disclose the baked image path"
grep -q '503808' "$sb/SWARM.md" || fail "the contract must disclose the baked offset"
grep -q 'another case' "$sb/SWARM.md" || fail "the contract must say seeded tools are case-specific"
grep -q '{{SEEDED_TOOLS}}' "$sb/SWARM.md" && fail "the seeded-tools placeholder leaked"
grep -q 'another case' "$sb/.pi/SYSTEM.md" || fail "the worker prompt must say seeded tools are case-specific"
pass "--tools-from seeds tools/ with the library, author and version kept"

# reserved_tool_names is fail-closed: empty or an import miss is a BLOCKER.
reserved_list="$(node --experimental-strip-types -e '
import("'"$ROOT"'/extensions/protocol.ts").then((m) => {
  if (!m.TOOL_RESERVED_NAMES || m.TOOL_RESERVED_NAMES.size === 0) process.exit(1);
  for (const name of m.TOOL_RESERVED_NAMES) console.log(name);
}).catch(() => process.exit(1));
')" || fail "the protocol exported no reserved tool names"
grep -qx bash <<<"$reserved_list" || fail "reserved names must include bash"
grep -qx done <<<"$reserved_list" || fail "reserved names must include done"
[[ -n "$reserved_list" ]] || fail "reserved_tool_names printed nothing"
grep -q 'BLOCKER: could not read reserved tool names from the protocol' "$ROOT/scripts/swarm.sh" \
  || fail "swarm.sh must BLOCKER when reserved names cannot be read"
grep -q 'BLOCKER: reserved tool names came back empty' "$ROOT/scripts/swarm.sh" \
  || fail "swarm.sh must BLOCKER when reserved names come back empty"
awk '/^reserved_tool_names\(\)/,/^}/' "$ROOT/scripts/swarm.sh" | grep -F '.catch(() => process.exit(1))' >/dev/null \
  || fail "reserved_tool_names must fail closed on import errors"
empty_ext="$TMP/empty-reserved/extensions"
mkdir -p "$empty_ext"
printf 'export const TOOL_RESERVED_NAMES = new Set();\n' > "$empty_ext/protocol.ts"
set +e
node --experimental-strip-types -e '
import("'"$TMP"'/empty-reserved/extensions/protocol.ts").then((m) => {
  if (!m.TOOL_RESERVED_NAMES || m.TOOL_RESERVED_NAMES.size === 0) process.exit(1);
  for (const name of m.TOOL_RESERVED_NAMES) console.log(name);
}).catch(() => process.exit(1));
' >/dev/null 2>&1
empty_rc=$?
set +e
[[ "$empty_rc" -ne 0 ]] || fail "an empty reserved set must not look like success"
pass "reserved_tool_names lists bash/done and fails closed when the set is empty"

out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$HELLO" --label toolsmissing --tools-from "$TMP/nope" 2>&1)"; rc=$?
[[ "$rc" -ne 0 ]] || fail "--tools-from with no directory should fail: $out"
grep -q 'BLOCKER: --tools-from .* is not a directory' <<<"$out" || fail "expected a BLOCKER: $out"
pass "--tools-from refuses a directory that is not there"

# And the way back: a finished run's tools become a library.
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label toolssave --allow-tool-forging --tools-from "$TMP/lib")"
sb2="$(sandbox_of "$out")"
[[ -n "$sb2" ]] || fail "no sandbox for the save case: $out"
id2="$(basename "$sb2")"
out="$(swarm tools "$id2" --save "$TMP/lib2")"
[[ -f "$TMP/lib2/evtx_filter/manifest.json" ]] || fail "tools --save did not write the library: $out"
grep -q '^Saved 2 tool' <<<"$out" || fail "tools --save says nothing useful: $out"
out="$(swarm tools "$id2")"
grep -q 'evtx_filter v2 by s2cb903' <<<"$out" || fail "tools with no --save should list them: $out"
jq -e '.saved_from_run and .sha256 and (.forged_by == "s2cb903")' "$TMP/lib2/evtx_filter/provenance.json" >/dev/null \
  || fail "a saved tool carries no provenance: $(cat "$TMP/lib2/evtx_filter/provenance.json" 2>/dev/null)"
jq -e 'has("pack") | not' "$TMP/lib2/evtx_filter/manifest.json" >/dev/null || fail "a saved tool kept a pack field, which hands it a pack's secrets"
# A script changed after it was forged stays behind, and so does a link.
printf 'print("changed")\n' >> "$sb2/tools/fls_like/run.py"
ln -s /etc/hosts "$sb2/tools/evtx_filter/hosts-link"
out="$(swarm tools "$id2" --save "$TMP/lib3" 2>&1)"
grep -q 'Left out fls_like: its script does not match' <<<"$out" || fail "a tampered tool was saved: $out"
[[ ! -e "$TMP/lib3/fls_like" ]] || fail "the tampered tool reached the library"
[[ ! -e "$TMP/lib3/evtx_filter/hosts-link" ]] || fail "a link in a tool's directory reached the library"
pass "tools lists a run's tools; --save copies sealed ones as regular files, with provenance and without a pack field"

# --- nobody is assigned anything --------------------------------------------------
# The kickoff prepares a sandbox and a goal. It does not hand out work: agents
# read the goal, agree on the board and say with name() what they are taking.
out="$(start --model solo/model --n 3 --cap-usd 1 --no-start --goal-file "$HELLO" --label noassign)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -f "$sb/team.json" ]] || fail "no sandbox: $out"
[[ "$(jq -r '[.agents[] | select(has("seat"))] | length' "$sb/team.json")" == "0" ]] || fail "team.json still carries a seat"
grep -q '^## Seats' "$sb/SWARM.md" && fail "the contract still assigns seats"
grep -q '{{' "$sb/SWARM.md" && fail "a placeholder leaked into the contract: $(grep -n '{{' "$sb/SWARM.md")"
grep -q '^## Dividing the work' "$sb/SWARM.md" || fail "the contract does not say how the work divides"
grep -q '^## Seeded tools' "$sb/SWARM.md" && fail "a run without --tools-from should not list seeded tools"
grep -q '^Seats:' <<<"$out" && fail "the kickoff still reports seats"
pass "the kickoff assigns nothing: no seat in team.json, none in the contract, none in its output"

# A goal that lists seats is the operator's own text and stays in the goal; it
# still does not become an assignment.
{ cat "$HELLO"; printf '\n## Seats\n\n- Writer: appends the ids.\n- Checker: verifies the file and calls done.\n'; } > "$TMP/goal-with-seats.md"
out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/goal-with-seats.md" --label goalseats)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "no sandbox for a goal with a seats list: $out"
[[ "$(jq -r '[.agents[] | select(has("seat"))] | length' "$sb/team.json")" == "0" ]] || fail "a goal's list must not seat anyone"
pass "a ## Seats list in the goal is text for the swarm to read, not an assignment"

# The flag is gone, and saying so is better than silently ignoring it.
out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$HELLO" --seats dfir 2>&1)"; rc=$?
[[ "$rc" -ne 0 ]] || fail "--seats should no longer be accepted: $out"
grep -q -- '--seats' <<<"$out" || fail "the refusal does not name --seats: $out"
pass "--seats is gone and the kickoff says so"

# --- allow-host ----------------------------------------------------------------------
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label hosts --allow-host isf-server.techanarchy.net --allow-host Example.COM)"
[[ -n "$(sandbox_of "$out")" ]] || fail "no sandbox with --allow-host: $out"
hosts="$(reg hosts '.allow_hosts')"
[[ "$hosts" == "isf-server.techanarchy.net,Example.COM" ]] || fail "registry allow_hosts should list both, comma-joined as given, got: $hosts"
pass "--allow-host is recorded in the registry, both names, as typed (netguard lowercases at spawn)"

# --- idle nudge ----------------------------------------------------------------------
out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$HELLO" --label idle --idle-nudge-sec 120)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "no sandbox for the idle case: $out"
[[ "$(reg idle '.idle_nudge_sec')" == "120" ]] || fail "registry should record idle_nudge_sec=120"
grep -q '^Idle nudge:' <<<"$out" || fail "no Idle nudge line in the kickoff output: $out"
[[ ! -e "$sb/idle-nudge.pid" ]] || fail "--no-start must not start the watchdog"
# Nor leave any daemon of the run alive: the collector, the gate, the broker
# and the proxy a --no-start kickoff may have started for its checks.
for f in collector.pid gate.pid nudge.pid netguard.pid idle-nudge.pid inhibit.pid hub.pid; do
  p="$(cat "$sb/$f" 2>/dev/null || true)"
  [[ -z "$p" ]] || ! kill -0 "$p" 2>/dev/null || fail "--no-start left $f's process ($p) running"
done
if pgrep -f -- "$sb" >/dev/null 2>&1; then
  fail "--no-start left a process naming the sandbox: $(pgrep -fl -- "$sb")"
fi
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --idle-nudge-sec soon)"; rc=$?
[[ "$rc" -ne 0 ]] && grep -q 'BLOCKER: --idle-nudge-sec' <<<"$out" || fail "a non-numeric --idle-nudge-sec should be refused: $out"
pass "--idle-nudge-sec is validated, recorded and announced; --no-start starts no watchdog"

mkdir -p "$TMP/herdr-bin"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "$HERDR_LOG"\n' > "$TMP/herdr-bin/herdr"
chmod +x "$TMP/herdr-bin/herdr"
ids="$(jq -r '.agents[].id' "$sb/team.json" | tr '\n' ' ')"
a0="${ids%% *}"; a1="$(printf '%s' "$ids" | awk '{print $2}')"
mkdir -p "$sb/.pi-sessions/$a0" "$sb/.pi-sessions/$a1" "$sb/done/agents"
touch -t 202601010000 "$sb/.pi-sessions/$a0/s.jsonl" "$sb/.pi-sessions/$a1/s.jsonl"
: > "$sb/done/agents/$a1.done"
HERDR_LOG="$TMP/herdr.log" HERDR_BIN="$TMP/herdr-bin/herdr" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$sb" --idle-sec 60 --once >/dev/null 2>&1 || fail "idle-nudge.sh --once failed"
grep -q "^agent prompt $a0 " "$TMP/herdr.log" || fail "the idle agent was not prompted: $(cat "$TMP/herdr.log" 2>/dev/null)"
grep -q "^agent prompt $a1 " "$TMP/herdr.log" && fail "an agent with a done marker must be left alone"
# With no collector the line goes to the trace, or to the harness's spill
# when the trace is already chained (scripts/lib/trace.sh); either is kept.
{ cat "$sb/traces/events.jsonl" "$sb/traces/system-spill.jsonl" 2>/dev/null || true; } \
  | jq -e "select(.tool == \"idle_nudge\" and .args.agent == \"$a0\" and .result.ok == true)" >/dev/null || fail "no idle_nudge event on the trace or the harness's spill"
pass "the watchdog prompts an idle agent through herdr, skips a finished one, and logs idle_nudge"

# --- toolbox -------------------------------------------------------------------------
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label toolbox --toolbox dfir)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -f "$sb/toolbox.json" ]] || fail "no toolbox.json with --toolbox dfir: $out"
[[ "$(jq -r '.preset' "$sb/toolbox.json")" == "dfir" ]] || fail "toolbox preset"
[[ "$(jq -r '.present | type' "$sb/toolbox.json")" == "array" && "$(jq -r '.missing | type' "$sb/toolbox.json")" == "array" ]] || fail "toolbox.json needs present[] and missing[]"
jq -e '.present[] | select(.name == "python3")' "$sb/toolbox.json" >/dev/null || fail "python3 runs this very test, so the toolbox must list it as present"
grep -q '^## Toolbox' "$sb/SWARM.md" || fail "the contract has no Toolbox section"
grep -q '| `python3` |' "$sb/SWARM.md" || fail "the Toolbox table does not list python3"
[[ "$(reg toolbox '.toolbox')" == "dfir" ]] || fail "registry toolbox should be dfir"
grep -q '^Toolbox: *[0-9]* present, [0-9]* missing' <<<"$out" || fail "no Toolbox line in the kickoff output: $out"
pass "--toolbox dfir writes toolbox.json, renders the Toolbox table and reports the counts"

out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --toolbox bogus)"; rc=$?
[[ "$rc" -ne 0 ]] || fail "--toolbox bogus should fail: $out"
grep -q "BLOCKER: --toolbox must be auto, off, or sets from dfir,crypto,linux" <<<"$out" || fail "expected a BLOCKER for an unknown toolbox: $out"
pass "an unknown toolbox set is refused, and the message names the sets"

# A case about encryption asks for the crypto set as well; a Windows disk case
# should never be told it is missing dislocker.
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label toolboxsets --toolbox dfir,crypto)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -f "$sb/toolbox.json" ]] || fail "no toolbox.json for a set list: $out"
jq -e '[.present[], .missing[]] | map(.name) | index("aescrypt")' "$sb/toolbox.json" >/dev/null \
  || fail "the crypto set did not reach toolbox.json"
out2="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label toolboxdfir --toolbox dfir)"
sb2="$(sandbox_of "$out2")"
jq -e '[.present[], .missing[]] | map(.name) | index("dislocker") | not' "$sb2/toolbox.json" >/dev/null \
  || fail "dfir alone should not check for dislocker"
pass "an unknown toolbox preset is refused"

out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label tbauto --toolbox auto)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && ! -e "$sb/toolbox.json" ]] || fail "--toolbox auto without --catalog should check nothing: $out"
[[ "$(reg tbauto '.toolbox')" == "off" ]] || fail "registry toolbox should resolve auto to off without a catalog"
pass "--toolbox auto is off unless a catalog is built"

# --toolbox auto with a catalog reads the goal for the sets it needs. A library
# entry's metadata block is not the case (its inputs: and tags: lines name
# VHDX and encryption for every Windows entry), an explicit `toolbox:` key is
# taken as written, and a virtual disk under the inputs adds crypto whatever
# the goal says, because its readers (pyvhdi, qemu-img) are in that set.
mkgoal() { # <file> <metadata lines or empty> <extra body text>
  { if [[ -n "$2" ]]; then printf -- '---\ntitle: t\n%s\n---\n' "$2"; fi; cat "$HELLO"; printf '\n%s\n' "$3"; } > "$1"
}
autoset() { # <label> <goal file> [inputs dir]
  start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$2" --label "$1" --inputs "${3:-$TMP/src}" --catalog --toolbox auto >/dev/null
  reg "$1" '.toolbox'
}
mkgoal "$TMP/g-meta.md" $'inputs: one disk image (E01, raw or VHDX)\ntags: encryption, gpg, container' ""
[[ "$(autoset hintmeta "$TMP/g-meta.md")" == "dfir" ]] || fail "words in the metadata block asked for a toolbox set: $(reg hintmeta .toolbox)"
mkgoal "$TMP/g-key.md" "toolbox: dfir, crypto" ""
[[ "$(autoset hintkey "$TMP/g-key.md")" == "dfir,crypto" ]] || fail "an explicit toolbox: key was not honoured: $(reg hintkey .toolbox)"
mkgoal "$TMP/g-keyonly.md" "toolbox: dfir" "Read keys with gpg; the container store is under /var/lib."
[[ "$(autoset hintkeyonly "$TMP/g-keyonly.md")" == "dfir" ]] || fail "a toolbox: key should stop the body's words from adding sets: $(reg hintkeyonly .toolbox)"
mkgoal "$TMP/g-words.md" "" "The case turns on a BitLocker volume."
[[ "$(autoset hintwords "$TMP/g-words.md")" == "dfir,crypto" ]] || fail "a goal without a key should still be read for its words: $(reg hintwords .toolbox)"
mkdir -p "$TMP/src-vhdx"; cp "$TMP/src/readings.csv" "$TMP/src-vhdx/"; head -c 4096 /dev/zero > "$TMP/src-vhdx/disk.VHDX"
[[ "$(autoset hintvhdx "$TMP/g-keyonly.md" "$TMP/src-vhdx")" == "dfir,crypto" ]] || fail "a VHDX under the inputs should add the crypto set: $(reg hintvhdx .toolbox)"
mkgoal "$TMP/g-bad.md" "toolbox: dfir,everything" ""
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$TMP/g-bad.md" --label hintbad --inputs "$TMP/src" --catalog --toolbox auto)" && fail "an unknown set in toolbox: was accepted: $out"
grep -q 'BLOCKER: .*toolbox: dfir,everything' <<<"$out" || fail "expected a BLOCKER naming the bad toolbox key: $out"
pass "--toolbox auto reads a goal's toolbox: key, ignores its metadata words, and adds crypto for a VHDX input"

# --toolbox-required on a PATH that hides the forensic tools: a BLOCKER, exit 3.
mkdir -p "$TMP/bin" "$TMP/tb"
ln -s "$(command -v jq)" "$TMP/bin/jq"
ln -s "$(command -v python3)" "$TMP/bin/python3"
case "$(command -v mmls || true)" in
  /usr/bin/*|/bin/*) echo "skip - mmls lives on the system PATH here, the required-toolbox refusal cannot be staged" ;;
  *)
    out="$(PATH="$TMP/bin:/usr/bin:/bin:/usr/sbin:/sbin" bash "$ROOT/scripts/toolbox.sh" "$TMP/tb" dfir --required 2>&1)"; rc=$?
    [[ "$rc" -eq 3 ]] || fail "toolbox.sh --required with tools missing should exit 3, got $rc: $out"
    grep -q "BLOCKER: --toolbox-required and these tools are missing: .*mmls" <<<"$out" || fail "expected a BLOCKER naming mmls: $out"
    [[ -f "$TMP/tb/toolbox.json" ]] || fail "the refusal should still leave toolbox.json with the install commands"
    jq -e '.missing[] | select(.name == "mmls") | .install' "$TMP/tb/toolbox.json" >/dev/null || fail "toolbox.json should say how to install mmls"
    pass "--toolbox-required turns a missing tool into a BLOCKER (exit 3) and still writes the install commands"
    ;;
esac

# --- installing what the case needs -----------------------------------------------------
# BelkaCTF #6 met a BitLocker volume with the recovery key in hand and no
# reader on the host. The agents tried `brew install dislocker` and
# `pip3 install dislocker`; netguard denied pypi.org seventeen times and the
# run spent its last half hour on a door it could not open. Root was never
# the missing piece — a package index and somewhere to put the package were.
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label install --allow-install)"
sb="$(sandbox_of "$out")"
[[ "$(reg install '.allow_install')" == "true" ]] || fail "--allow-install should be in the registry"
# The allowlist itself is written when the sidecar starts, which --no-start
# skips; what it will contain is asserted in the netguard suite.
[[ -d "$sb/work/.toolchain" ]] || fail "--allow-install should make the in-sandbox prefix"
grep -q "pip install --user" "$sb/SWARM.md" || fail "the contract should say how to install: $(grep -c . "$sb/SWARM.md") lines"
grep -q "no root here and no \`sudo\`" "$sb/SWARM.md" || fail "the contract should still say there is no root"
grep -q '^Install: ' <<<"$out" || fail "the kickoff should announce the install setting: $out"
pass "--allow-install opens the package index and a prefix inside the sandbox, and says so in the contract"

out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label noinstall)"
sb="$(sandbox_of "$out")"
[[ "$(reg noinstall '.allow_install')" == "false" ]] || fail "install should be off by default"
[[ -d "$sb/work/.toolchain" ]] && fail "no prefix without --allow-install"
grep -q "pip install --user" "$sb/SWARM.md" && fail "the contract should not offer installing when it is off"
pass "installing is off by default: no index, no prefix, nothing in the contract"

# --- catalog --------------------------------------------------------------------------
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --catalog)"; rc=$?
[[ "$rc" -ne 0 ]] || fail "--catalog without --inputs should fail: $out"
grep -q "BLOCKER: --catalog needs --inputs" <<<"$out" || fail "expected a BLOCKER for --catalog without inputs: $out"
pass "--catalog without --inputs is refused"

out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label catalog --inputs "$TMP/src" --catalog)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -f "$sb/catalog/README.md" ]] || fail "no catalog/README.md with --catalog: $out"
grep -q '^Summary: 0 disk image(s), 0 memory image(s)' "$sb/catalog/README.md" || fail "a text-only inputs dir should catalog nothing: $(head -3 "$sb/catalog/README.md")"
has_write_bit "$sb/catalog/README.md" && fail "catalog/README.md still has a write bit"
has_write_bit "$sb/catalog" && fail "catalog/ still has a write bit"
[[ "$(reg catalog '.catalog')" == "true" ]] || fail "registry catalog should be true"
[[ "$(reg catalog '.quarantine')" == "true" ]] || fail "--catalog should imply quarantine in the registry"
[[ "$(reg catalog '.toolbox')" == "dfir" ]] || fail "--catalog should switch the toolbox on"
[[ -f "$sb/toolbox.json" ]] || fail "--catalog should have run the toolbox check"
grep -q '^## Evidence catalog (read-only)' "$sb/SWARM.md" || fail "the contract has no Evidence catalog section"
grep -q '^Summary: 0 disk image(s)' "$sb/SWARM.md" || fail "the contract does not carry the catalog index"
grep -q '{{CATALOG}}' "$sb/SWARM.md" && fail "the catalog placeholder leaked"
[[ -d "$sb/work/extracted" && -d "$sb/work/quarantine" ]] || fail "--catalog (quarantine implied) should create work/extracted and work/quarantine"
grep -q '^Catalog: *0 disk image(s)' <<<"$out" || fail "no Catalog line in the kickoff output: $out"
pass "--catalog builds a read-only catalog/, switches the toolbox and quarantine on, and renders the index into the contract"

if [[ -f "$sb/.fsguard/plan.txt" ]] && ! grep -q '^mode: none' "$sb/.fsguard/plan.txt"; then
  grep -q "^read-only: $sb/catalog\$" "$sb/.fsguard/plan.txt" || fail "the guard plan should hold catalog/ read-only: $(cat "$sb/.fsguard/plan.txt")"
  grep -q "^read-only: $sb/inputs\$" "$sb/.fsguard/plan.txt" || fail "the guard plan should hold inputs/ read-only"
  pass "with a kernel guard the catalog is read-only at the kernel too"
else
  echo "skip - kernel guard plan for the catalog (no guard on this host)"
fi

# --- quarantine ----------------------------------------------------------------------
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label quarantine --inputs "$TMP/src" --quarantine)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" && -d "$sb/work/extracted" && -d "$sb/work/quarantine" ]] || fail "--quarantine should create work/extracted and work/quarantine: $out"
[[ "$(reg quarantine '.quarantine')" == "true" ]] || fail "registry quarantine should be true"
[[ "$(reg quarantine '.catalog')" == "false" ]] || fail "--quarantine alone should not imply a catalog"
grep -q '^Quarantine: *work/extracted and work/quarantine are no-exec' <<<"$out" || fail "no Quarantine line in the kickoff output: $out"
pass "--quarantine creates the no-exec directories and says so"

# A goal's checks run in the sandbox and cannot read the registry, so the
# kickoff records the flag in inputs.json, which is harness-written and
# protected. The malware entries check it with exactly this line.
qcheck=$'grep -q \'"quarantine": true\' inputs.json'
# The record is whether the no-exec holds, so on a host with no kernel guard
# even --quarantine records false.
if [[ "$(jq -r '.guard' "$sb/inputs.json")" != "none" ]]; then
  (cd "$sb" && bash -c "$qcheck") || fail "--quarantine should be recorded in inputs.json: $(jq -c '{quarantine}' "$sb/inputs.json")"
  cat_sb="$(reg catalog '.sandbox')"
  [[ "$(jq -r '.quarantine' "$cat_sb/inputs.json")" == "true" ]] || fail "--catalog implies quarantine and inputs.json should say so"
fi
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label noquarantine --inputs "$TMP/src")"
sbq="$(sandbox_of "$out")"
[[ "$(jq -r '.quarantine' "$sbq/inputs.json")" == "false" ]] || fail "a kickoff without --quarantine should record quarantine: false: $(jq -c '{quarantine}' "$sbq/inputs.json")"
(cd "$sbq" && bash -c "$qcheck") && fail "the quarantine check passed for a kickoff without --quarantine"
# --inputs-enforce off drops the kernel guard, and the no-exec with it: the
# flag was given, the quarantine did not hold, and the record says so.
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label quarantine-noguard --inputs "$TMP/src" --inputs-enforce off --quarantine)"
sbq="$(sandbox_of "$out")"
[[ "$(jq -r '.quarantine' "$sbq/inputs.json")" == "false" ]] || fail "--quarantine without a guard should record quarantine: false: $(jq -c '{guard, quarantine}' "$sbq/inputs.json")"
(cd "$sbq" && bash -c "$qcheck") && fail "the quarantine check passed for a run whose no-exec did not hold"
pass "inputs.json records whether the quarantine held, and a goal check can read it"

if [[ -f "$sb/.fsguard/plan.txt" ]] && ! grep -q '^mode: none' "$sb/.fsguard/plan.txt"; then
  grep -q "^no-exec: $sb/work/extracted\$" "$sb/.fsguard/plan.txt" || fail "the guard plan should list work/extracted as no-exec: $(cat "$sb/.fsguard/plan.txt")"
  grep -q "^no-exec: $sb/work/quarantine\$" "$sb/.fsguard/plan.txt" || fail "the guard plan should list work/quarantine as no-exec"
  grep -q -- "--noexec $sb/work/extracted" "$sb/.zsh/.zshenv" || fail "the pane hook does not pass --noexec"
  pass "with a kernel guard both quarantine directories are no-exec in the plan and the pane hook"
else
  echo "skip - kernel no-exec plan (no guard on this host)"
fi

# --- per-agent cap ----------------------------------------------------------------------
out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$HELLO" --label percap --cap-per-agent 1.5)"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "no sandbox with --cap-per-agent: $out"
[[ "$(jq -r '.cap_per_agent_usd' "$sb/budget.json")" == "1.5" ]] || fail "budget.json cap_per_agent_usd should be 1.5, got $(jq -r '.cap_per_agent_usd' "$sb/budget.json")"
[[ "$(reg percap '.cap_per_agent_usd')" == "1.5" ]] || fail "registry cap_per_agent_usd should be 1.5"
grep -q '^Per-agent cap: \$1.5' <<<"$out" || fail "no Per-agent cap line in the kickoff output: $out"
pass "--cap-per-agent reaches budget.json, the registry and the kickoff output"

out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$HELLO" --label nocap)"
sb="$(sandbox_of "$out")"
[[ "$(jq -r 'has("cap_per_agent_usd")' "$sb/budget.json")" == "false" ]] || fail "budget.json should carry no per-agent cap unless asked"
[[ "$(reg nocap '.cap_per_agent_usd')" == "null" ]] || fail "registry cap_per_agent_usd should be null without the flag"
pass "without --cap-per-agent there is no per-agent cap anywhere"

out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$HELLO" --cap-per-agent abc)"; rc=$?
[[ "$rc" -ne 0 ]] || fail "--cap-per-agent abc should fail: $out"
grep -q "BLOCKER: --cap-per-agent must be a number of USD" <<<"$out" || fail "expected a BLOCKER for a non-numeric cap: $out"
pass "a per-agent cap that is not a number is refused"

# --- case id and examiner -----------------------------------------------------------------
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label custody --case-id CASE-42 --examiner "Jane Doe")"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "no sandbox with --case-id: $out"
[[ "$(reg custody '.case_id')" == "CASE-42" ]] || fail "registry case_id"
[[ "$(reg custody '.examiner')" == "Jane Doe" ]] || fail "registry examiner"
grep -q 'Case `CASE-42` · examiner Jane Doe' "$sb/SWARM.md" || fail "the contract does not name the case and the examiner: $(grep -n 'CASE-42\|Jane' "$sb/SWARM.md")"
grep -q '^Case: *CASE-42 · examiner Jane Doe' <<<"$out" || fail "no Case line in the kickoff output: $out"
pass "--case-id and --examiner reach the registry, the contract and the kickoff output"

grep -q 'CASE-42\|{{CASE}}' "$sb/../$(jq -r '.runs[] | select(.["label"] == "nocap") | .id' "$TMP/runs/registry.json")/SWARM.md" && fail "a run without a case carries a case line or the placeholder"
pass "a run without --case-id has no case line"

# --- stop records what happened ---------------------------------------------------------------
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label stopdone)"
sb="$(sandbox_of "$out")"; id="$(id_of "$out")"
[[ -n "$sb" && -n "$id" ]] || fail "no sandbox or id for the stop test: $out"
printf -- '---\nby: %s00\nreason: done\n---\n' "$id" > "$sb/done/SWARM_DONE"
out="$(swarm stop "$id")" || fail "stop failed: $out"
[[ "$(reg stopdone '.state')" == "done" ]] || fail "stop with the sentinel present should record done, got $(reg stopdone '.state')"
grep -q "recorded as done" <<<"$out" || fail "stop should say the sentinel was there: $out"
pass "stop after the sentinel records the run as done"

out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label stopplain)"
id="$(id_of "$out")"
out="$(swarm stop "$id")" || fail "stop failed: $out"
[[ "$(reg stopplain '.state')" == "stopped" ]] || fail "stop without the sentinel should record stopped, got $(reg stopplain '.state')"
pass "stop without the sentinel records the run as stopped"

# --- package ---------------------------------------------------------------------------------------
if [[ -f "$ROOT/scripts/summary.ts" ]]; then
  out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$HELLO" --label package --inputs "$TMP/src" --toolbox dfir)"
  sb="$(sandbox_of "$out")"; id="$(id_of "$out")"
  [[ -n "$sb" && -n "$id" ]] || fail "no sandbox or id for the package test: $out"
  printf '# Report\n\nnothing yet\n' > "$sb/work/report.md"
  # A run's deliverable is not only its Markdown: the package used to glob
  # work/*.md and silently drop a timeline, an export and everything in a
  # subdirectory. It also never kept the tools the run used, which B12 said
  # it did.
  printf 'ts,event\n1,start\n' > "$sb/work/timeline.csv"
  mkdir -p "$sb/work/exports" "$sb/work/extracted" "$sb/tools/demo_tool"
  printf '{"k":1}\n' > "$sb/work/exports/findings.json"
  printf 'live sample\n' > "$sb/work/extracted/sample.bin"
  printf '{"name":"demo_tool","entry":"run.py"}\n' > "$sb/tools/demo_tool/manifest.json"
  printf 'print("hi")\n' > "$sb/tools/demo_tool/run.py"
  # What a restarted collector keeps: the anchor it did not match, and a cut fragment.
  printf '{"lines":1}\n' > "$sb.trace-anchor.prev.json"
  printf 'cut sh' > "$sb/traces/events.fragment-2026-01-01T00-00-00-000Z.partial"
  out="$(swarm package "$id")" || fail "package failed: $out"
  for f in trace/trace-anchor.prev.json trace/events.fragment-2026-01-01T00-00-00-000Z.partial summary.md MANIFEST.txt trace/events.jsonl SWARM.md team.json budget.json inputs.json toolbox.json \
           work/report.md work/timeline.csv work/exports/findings.json \
           tools/demo_tool/manifest.json tools/demo_tool/run.py board/main.md; do
    [[ -f "$sb/package/$f" ]] || fail "package/ is missing $f: $(cd "$sb/package" && find . -type f | sort)"
  done
  [[ ! -e "$sb/package/work/extracted/sample.bin" ]] || fail "package must leave extracted evidence in the sandbox"
  grep -q "Left in the sandbox: 1 file" <<<"$out" || fail "package should say what it left behind: $out"
  grep -q 'work/timeline.csv' "$sb/package/MANIFEST.txt" || fail "MANIFEST.txt does not hash work/timeline.csv"
  grep -q 'tools/demo_tool/run.py' "$sb/package/MANIFEST.txt" || fail "MANIFEST.txt does not hash the run's tools"
  # The index hashes what the package carries AND what it deliberately leaves
  # behind, so a ledger entry citing an extracted file can still be checked.
  packaged="$(jq -r '[.files[] | select(.packaged)] | map(.path) | sort | join(",")' "$sb/package/artifacts.json")"
  [[ "$packaged" == "work/exports/findings.json,work/report.md,work/timeline.csv" ]] || fail "artifacts.json packaged set is wrong: $packaged"
  left="$(jq -r '[.files[] | select(.packaged | not) | .path] | join(",")' "$sb/package/artifacts.json")"
  [[ "$left" == "work/extracted/sample.bin" ]] || fail "artifacts.json must hash the extracted material: $left"
  jq -e '.files[] | select(.path == "work/extracted/sample.bin") | .sha256 | length == 64' "$sb/package/artifacts.json" >/dev/null \
    || fail "the extracted file has no sha256 in artifacts.json"
  n_files="$(find "$sb/package" -type f ! -name MANIFEST.txt | wc -l | tr -d ' ')"
  n_lines="$(wc -l < "$sb/package/MANIFEST.txt" | tr -d ' ')"
  [[ "$n_files" == "$n_lines" ]] || fail "MANIFEST.txt has $n_lines lines for $n_files files"
  grep -q 'summary.md' "$sb/package/MANIFEST.txt" || fail "MANIFEST.txt does not list summary.md"
  [[ -s "$sb/package/summary.md" ]] || fail "summary.md is empty"
  grep -q "^Packaged $id -> $sb/package" <<<"$out" || fail "package should report where it wrote: $out"
  pass "package ships the summary, the contract, the trace, the board, every work file and the run's tools, with one hash per file"
else
  echo "skip - package (scripts/summary.ts not present yet)"
fi

# --- unknown ids ---------------------------------------------------------------------------------------
out="$(swarm summary nope)"; rc=$?
[[ "$rc" -ne 0 ]] || fail "summary of an unknown id should fail: $out"
out="$(swarm package nope)"; rc=$?
[[ "$rc" -ne 0 ]] || fail "package of an unknown id should fail: $out"
pass "summary and package refuse an unknown swarm id"

# --- the pane hook survives a home with no .zshrc ------------------------------------------------------
# Ubuntu's zsh opens its new-user wizard in an interactive shell whose home has
# no .zshrc and reads the pi command line as the wizard's answer; the hook keeps
# the sandbox's own .zsh/ (with an empty .zshrc) in that case.
out="$(start --model solo/model --n 1 --cap-usd 1 --no-start --goal-file "$ROOT/prompts/goals/hello.md" --label hook)"
sb="$(sandbox_of "$out")"
[[ -f "$sb/.zsh/.zshrc" ]] || fail "the sandbox should carry a stand-in .zshrc for the pane"
grep -q 'if \[\[ -f "\$HOME/.zshrc" \]\]' "$sb/.zsh/.zshenv" || fail "the hook should hand ZDOTDIR back to the home only when it has a .zshrc"
grep -q "export ZDOTDIR=$sb/.zsh" "$sb/.zsh/.zshenv" || fail "the hook should otherwise keep the sandbox's .zsh"
pass "the pane hook keeps zsh's new-user wizard out of a pane whose home has no .zshrc"

echo "dfir-flags.test.sh: all checks passed"
