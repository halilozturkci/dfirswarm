#!/usr/bin/env bash
# What must not go wrong: an agent with something to read is woken quickly, an
# agent with an empty inbox is left alone until the long timer, the nudge says
# what is waiting, and the budget is per silence rather than per run. An agent
# that only waits is nudged too, later and as a steer, unless a job of its own
# is running; a seat whose compaction runs is not nudged, and one whose
# compaction never ends is reported on the board.
#
# The numbers this encodes were measured over seven forensic runs: 34 agents
# had to be woken, and in 32 of those a peer's post had landed a median of 26
# seconds into the silence and then sat unread until the 180-second timer.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/idle-nudge.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
# The run's trace as the harness keeps it: events.jsonl, and the system spill,
# where a harness line the collector did not take is kept (scripts/lib/trace.sh).
trace_of() { local f; for f in "$1/traces/events.jsonl" "$1/traces/system-spill.jsonl"; do [[ -f "$f" ]] && cat "$f"; done; return 0; }

SB="$TMP/sandbox"
mkdir -p "$SB"/{traces,done/agents,threads/main,inbox/a00,inbox/a01,.pi-sessions/a00,.pi-sessions/a01,locks}
cat > "$SB/team.json" <<'JSON'
{"swarm_id": "t", "n": 2, "agents": [{"id": "a00", "role": "worker"}, {"id": "a01", "role": "worker"}]}
JSON
: > "$SB/traces/events.jsonl"

post() { # post <id> <from>
  printf -- '---\nid: %s\nthread: main\nfrom: %s\nto: all\ntag: result\n---\n\nsomething happened\n' "$1" "$2" \
    > "$SB/threads/main/$(printf '%06d' "$1")-$2.md"
}

# a00 has two posts it has not read; a01 has read everything
post 1 a01
post 2 a01
printf '{"main": 0}\n' > "$SB/inbox/a00/cursors.json"
printf '{"main": 2}\n' > "$SB/inbox/a01/cursors.json"

# both have been quiet for about a minute: past the news threshold, short of
# the silence one
# touch -t reads local time, so the stamp has to be local too.
old="$(date -v-70S +%Y%m%d%H%M.%S 2>/dev/null || date -d '70 seconds ago' +%Y%m%d%H%M.%S)"
for id in a00 a01; do
  : > "$SB/.pi-sessions/$id/session.jsonl"
  touch -t "$old" "$SB/.pi-sessions/$id/session.jsonl"
done

# a herdr that always says the pane is idle and records what it was told
mkdir -p "$TMP/bin"
cat > "$TMP/bin/herdr" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
  "agent get") printf '{"result":{"agent":{"agent_status":"idle"}}}\n' ;;
  "agent prompt") printf '%s\t%s\n' "$3" "$4" >> "$PROMPT_LOG" ;;
  *) : ;;
esac
SH
chmod +x "$TMP/bin/herdr"
export PROMPT_LOG="$TMP/prompts.txt"
: > "$PROMPT_LOG"

run_once() { HERDR_BIN="$TMP/bin/herdr" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$SB" --once "$@" >/dev/null 2>&1; }

run_once --news-sec 45 --idle-sec 180
grep -q '^a00	' "$PROMPT_LOG" || fail "an agent with unread posts should be woken at the news threshold"
grep -q '^a01	' "$PROMPT_LOG" && fail "an agent with nothing to read should wait for the long timer"
pass "unread posts wake an agent early; an empty inbox does not"

grep '^a00	' "$PROMPT_LOG" | grep -q '2 post(s) you have not read' \
  || fail "the nudge should say how much is waiting: $(cat "$PROMPT_LOG")"
pass "the nudge says what is waiting"

# Same silence, run again: the budget counts up rather than starting over.
run_once --news-sec 45 --idle-sec 180
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 2 ]] || fail "a second pass in the same silence should nudge once more"
grep '^a00	' "$PROMPT_LOG" | tail -1 | grep -q 'Nudge 2 of 3' || fail "the second nudge should be numbered 2"
pass "the budget counts up within one silence"

# The agent works: its idle clock resets, and so does the budget.
run_once --news-sec 45 --idle-sec 180   # nudge 3 of 3
run_once --news-sec 45 --idle-sec 180   # budget spent, no fourth
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 3 ]] || fail "a spent budget should stop the nudges"
touch "$SB/.pi-sessions/a00/session.jsonl"
touch -t "$old" "$SB/.pi-sessions/a00/session.jsonl"
run_once --news-sec 45 --idle-sec 180
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 3 ]] || fail "same silence, still spent"
pass "a spent budget stops the nudges for that silence"

# An agent that has finished is left alone whatever its inbox says.
: > "$SB/done/agents/a00.done"
run_once --news-sec 45 --idle-sec 180
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 3 ]] || fail "a done agent must not be nudged"
pass "an agent with a done marker is left alone"

# Every nudge is on the trace.
[[ "$(trace_of "$SB" | grep -c '"tool":"idle_nudge"')" -ge 3 ]] || fail "the nudges are not on the trace"
pass "each nudge is written to the trace"

# --- a provider error is not a silence --------------------------------------
# Both DeepSeek agents on the BelkaCTF #6 run died on `402 Insufficient
# Balance` nine minutes in, and the watchdog spent all three nudges on each of
# them, as plain idle nudges back to back: every retry hit the same 402. A
# seat whose last turn is agent_error is tried again with words that say so,
# each wait twice the last, a bounded number of times under a cap policy
# (this run has no budget.json: not until solved). A retry refused again is
# also what tells a limit on every seat from a passing error, so it must be
# made under every stop policy.
rm -f "$SB/done/agents/a00.done"
: > "$PROMPT_LOG"
: > "$SB/traces/idle-nudge.state"
printf '{"ts":"2026-01-01T00:00:00.000Z","agent":"a00","tool":"agent_error","args":{"model":"deepseek/deepseek-v4-pro"},"result":{"ok":false,"reason":"402 Insufficient Balance"}}\n' \
  >> "$SB/traces/events.jsonl"
# The watchdog's own row about a00 is not a00's turn.
printf '{"ts":"2026-01-01T00:00:01.000Z","agent":"system","tool":"idle_nudge","args":{"agent":"a00","idle_seconds":1,"why":"idle"},"result":{"ok":true,"nudges":1}}\n' \
  >> "$SB/traces/events.jsonl"
run_once --news-sec 45 --idle-sec 180
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 1 ]] || fail "a seat whose turn ended in a provider error is tried again once: $(cat "$PROMPT_LOG")"
grep '^a00	' "$PROMPT_LOG" | grep -q 'Your last turn ended in a provider error. The harness tries you again up to 3 times' \
  || fail "the retry does not say what it is: $(cat "$PROMPT_LOG")"
grep '^a00	' "$PROMPT_LOG" | grep -q 'Try 1 of 3\.' || fail "the retry is not numbered: $(cat "$PROMPT_LOG")"
run_once --news-sec 45 --idle-sec 180
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 1 ]] || fail "a second retry came before its backoff"
# Past its backoff each time, it is tried up to the bound, and no more.
printf 'a00 2 0\n' > "$SB/traces/idle-nudge.errors"
run_once --news-sec 45 --idle-sec 180
grep '^a00	' "$PROMPT_LOG" | tail -1 | grep -q 'Try 3 of 3\.' || fail "the last retry is not the third: $(cat "$PROMPT_LOG")"
printf 'a00 3 0\n' > "$SB/traces/idle-nudge.errors"
run_once --news-sec 45 --idle-sec 180
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 2 ]] || fail "a seat past its retries was tried again: $(cat "$PROMPT_LOG")"
pass "a turn that ended in a provider error is retried with backoff, a bounded number of times, and says so"

# …and an agent that worked after the error is idle again like any other.
printf '{"ts":"2026-01-01T00:01:00.000Z","agent":"a00","tool":"bash","args":{},"result":{"ok":true}}\n' \
  >> "$SB/traces/events.jsonl"
touch -t "$old" "$SB/.pi-sessions/a00/session.jsonl"
: > "$PROMPT_LOG"
: > "$SB/traces/idle-nudge.state"
run_once --news-sec 45 --idle-sec 180
[[ "$(grep -c '^a00	' "$PROMPT_LOG")" -eq 1 ]] || fail "an agent that came back after an error is nudged normally"
grep '^a00	' "$PROMPT_LOG" | grep -q 'You ended your turn' || fail "a seat that worked is nudged as idle, not as a provider error: $(cat "$PROMPT_LOG")"
[[ "$(awk '$1 == "a00" { print $2 }' "$SB/traces/idle-nudge.errors")" == 0 ]] || fail "work did not start its retries over"
pass "an agent that works after a provider error is watched like any other"

# --- an agent that only waits ------------------------------------------------
# Run s6895a8: s6895a806 called nothing but wait and inbox for 33 minutes. Each
# wait returned with a post and wrote a trace row, and Herdr and the hub saw it
# working, so the watchdog never counted it idle.
ago() { # <seconds> -> an ISO time that long ago
  date -u -d "@$(( $(date +%s) - $1 ))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r $(( $(date +%s) - $1 )) +%Y-%m-%dT%H:%M:%SZ
}
row() { # <agent> <tool> <seconds ago> [args json]
  local args='{}'
  [[ $# -ge 4 ]] && args="$4"
  printf '{"ts":"%s","recv_ts":"%s","agent":"%s","tool":"%s","args":%s,"result":{"ok":true}}\n' "$(ago "$3")" "$(ago "$3")" "$1" "$2" "$args"
}
WS="$TMP/waiting"
mkdir -p "$WS"/{traces,done/agents,threads/main,inbox/w0,.pi-sessions/w0,locks,store/jobs}
printf '{"swarm_id":"w","n":1,"agents":[{"id":"w0","role":"worker"}]}\n' > "$WS/team.json"
printf '{"main": 0}\n' > "$WS/inbox/w0/cursors.json"
{ row w0 post 700 '{"tag":"result"}'; row w0 wait 600; row w0 context 599; row w0 wait 300; row w0 inbox 200; row w0 wait 30; row w0 thinking 29; } > "$WS/traces/events.jsonl"
: > "$WS/.pi-sessions/w0/session.jsonl"
# The pane is in a wait: Herdr says working, as it did on s6895a8.
cat > "$TMP/bin/herdr-working" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
  "agent get") printf '{"result":{"agent":{"agent_status":"working"}}}\n' ;;
  "agent prompt") printf '%s\t%s\n' "$3" "$4" >> "$PROMPT_LOG" ;;
  *) : ;;
esac
SH
chmod +x "$TMP/bin/herdr-working"
wait_once() { HERDR_BIN="$TMP/bin/herdr-working" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$WS" --once --idle-sec 180 "$@" >/dev/null 2>&1; }
: > "$PROMPT_LOG"
wait_once --wait-idle-sec 900
[[ "$(grep -c '^w0	' "$PROMPT_LOG")" -eq 0 ]] || fail "an agent waiting for less than --wait-idle-sec was nudged"
wait_once --wait-idle-sec 600
grep '^w0	' "$PROMPT_LOG" | grep -q 'For 11 minutes you have called only wait and inbox' || fail "an agent that only waited past --wait-idle-sec was not nudged: $(cat "$PROMPT_LOG")"
grep -q '"tool":"idle_nudge","args":{"agent":"w0","idle_seconds":7[0-9][0-9],"why":"waiting"}' <<<"$(trace_of "$WS")" \
  || fail "the nudge is not recorded as one for waiting: $(trace_of "$WS" | grep idle_nudge)"
pass "an agent that has only waited since its last post is nudged past --wait-idle-sec, though its pane is working"

# Waiting on its own job is what the job asked of it.
: > "$PROMPT_LOG"
: > "$WS/traces/idle-nudge.state"
mkdir -p "$WS/store/jobs/j000001"
printf '{"id":"j000001","requester":{"agent":"w0"},"state":"running"}\n' > "$WS/store/jobs/j000001/job.json"
wait_once --wait-idle-sec 600
[[ "$(grep -c '^w0	' "$PROMPT_LOG")" -eq 0 ]] || fail "an agent waiting on its own running job was nudged"
printf '{"id":"j000001","requester":{"agent":"w0"},"state":"committed"}\n' > "$WS/store/jobs/j000001/job.json"
wait_once --wait-idle-sec 600
[[ "$(grep -c '^w0	' "$PROMPT_LOG")" -eq 1 ]] || fail "once the job was done the waiting agent was not nudged"
pass "an agent waiting on a job of its own that is still running is left to wait"

# Its last wait long past: it is in some other long call, not waiting.
: > "$PROMPT_LOG"
: > "$WS/traces/idle-nudge.state"
{ row w0 post 1500 '{"tag":"result"}'; row w0 wait 1200; row w0 wait 600; } > "$WS/traces/events.jsonl"
wait_once --wait-idle-sec 600
[[ "$(grep -c '^w0	' "$PROMPT_LOG")" -eq 0 ]] || fail "an agent whose last wait was ten minutes ago was nudged as waiting"
pass "an agent whose last wait is long past is not counted as waiting"

# A prompt arriving is not the agent doing anything: the hub_prompt row is the
# echo of the watchdog's own nudge (s6895a803's four nudges each reset its clock).
: > "$PROMPT_LOG"
: > "$WS/traces/idle-nudge.state"
{ row w0 bash 400; row w0 hub_prompt 20 '{"kind":"idle_nudge"}'; } > "$WS/traces/events.jsonl"
touch -t "$(date -v-400S +%Y%m%d%H%M.%S 2>/dev/null || date -d '400 seconds ago' +%Y%m%d%H%M.%S)" "$WS/.pi-sessions/w0/session.jsonl"
HERDR_BIN="$TMP/bin/herdr" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$WS" --once --idle-sec 180 >/dev/null 2>&1
grep '^w0	' "$PROMPT_LOG" | grep -q 'You ended your turn 6 minutes ago' || fail "the echo of a prompt counted as the agent's activity: $(cat "$PROMPT_LOG")"
pass "the echo of a nudge (hub_prompt) does not count as the agent's activity"

# --- a seat silent in one long call --------------------------------------------
# Run s082123: a seat sat in one shell call for 178 minutes. Herdr said working,
# so it was never nudged, and nobody was told.
LS="$TMP/longcall"
mkdir -p "$LS"/{traces,done/agents,threads/main,inbox/l0,.pi-sessions/l0,locks}
printf '{"swarm_id":"l","n":1,"agents":[{"id":"l0","role":"worker"}]}\n' > "$LS/team.json"
printf '{"main": 0}\n' > "$LS/inbox/l0/cursors.json"
: > "$LS/.pi-sessions/l0/session.jsonl"
touch -t "$(date -v-3000S +%Y%m%d%H%M.%S 2>/dev/null || date -d '3000 seconds ago' +%Y%m%d%H%M.%S)" "$LS/.pi-sessions/l0/session.jsonl"
{ row l0 post 3100 '{"tag":"result"}'; row l0 read 3000; } > "$LS/traces/events.jsonl"
call_once() { HERDR_BIN="$TMP/bin/herdr-working" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$LS" --once --idle-sec 180 "$@" >/dev/null 2>&1; }
: > "$PROMPT_LOG"
call_once --call-stall-sec 3600
ls "$LS"/threads/main/*.md >/dev/null 2>&1 && fail "a call inside --call-stall-sec was reported"
call_once --call-stall-sec 2400
post="$(cat "$LS"/threads/main/*.md 2>/dev/null || true)"
grep -q "SEAT SILENT: l0 has been in one call for 50 minutes with nothing on its session or the trace" <<<"$post" || fail "a seat silent past --call-stall-sec was not said on the board: $post"
grep -q '^tag: hold' <<<"$post" || fail "the report is not a hold post: $post"
grep -q '"tool":"call_stalled","args":{"agent":"l0","by":"watchdog","limit_ms":2400000},"result":{"ok":true,"silent_seconds":' <<<"$(trace_of "$LS")" \
  || fail "the silent seat is not on the trace: $(trace_of "$LS" | grep call_stalled)"
call_once --call-stall-sec 2400
[[ "$(ls "$LS"/threads/main/*.md | wc -l | tr -d ' ')" == 1 ]] || fail "the silent seat was reported twice in one silence"
[[ "$(grep -c '^l0	' "$PROMPT_LOG")" -eq 0 ]] || fail "a working seat was prompted"
call_once --call-stall-sec 0
[[ "$(ls "$LS"/threads/main/*.md | wc -l | tr -d ' ')" == 1 ]] || fail "--call-stall-sec 0 should report nothing"
pass "a seat working with nothing on its session or trace past --call-stall-sec is said once, on the board and the trace, and not prompted"

# --- a seat whose compaction runs ---------------------------------------------
# Pi refuses every prompt while a hand-off's compaction runs. On s6895a8 the
# watchdog spent three nudges on s6895a803 there, and when the compaction never
# ended nobody was told the seat was gone.
CS="$TMP/compacting"
mkdir -p "$CS"/{traces,done/agents,threads/main,inbox/k0,.pi-sessions/k0,locks}
printf '{"swarm_id":"k","n":1,"agents":[{"id":"k0","role":"worker"}]}\n' > "$CS/team.json"
printf '{"main": 0}\n' > "$CS/inbox/k0/cursors.json"
: > "$CS/.pi-sessions/k0/session.jsonl"
touch -t "$(date -v-400S +%Y%m%d%H%M.%S 2>/dev/null || date -d '400 seconds ago' +%Y%m%d%H%M.%S)" "$CS/.pi-sessions/k0/session.jsonl"
{ row k0 bash 420; row k0 compact_start 400 '{"trigger":"agent idle"}'; row k0 compact_failed 300 '{"stage":"summary","attempt":1}'; } > "$CS/traces/events.jsonl"
comp_once() { HERDR_BIN="$TMP/bin/herdr" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$CS" --once --idle-sec 180 "$@" >/dev/null 2>&1; }
: > "$PROMPT_LOG"
comp_once --compact-stall-sec 1200
[[ "$(grep -c '^k0	' "$PROMPT_LOG")" -eq 0 ]] || fail "a seat whose compaction runs was nudged"
ls "$CS"/threads/main/*.md >/dev/null 2>&1 && fail "a compaction inside its bound was reported"
pass "a seat whose compaction runs is not nudged (a failed summary attempt is not the compaction's end)"
comp_once --compact-stall-sec 300
post="$(cat "$CS"/threads/main/*.md 2>/dev/null || true)"
grep -q "COMPACTION STALLED: k0's context compaction started 6 minutes ago and has not ended" <<<"$post" || fail "a compaction past its bound was not said on the board: $post"
grep -q '^tag: hold' <<<"$post" || fail "the report is not a hold post: $post"
grep -q '"tool":"compact_stalled","args":{"agent":"k0","by":"watchdog","limit_ms":300000},"result":{"ok":true,"open_seconds":' <<<"$(trace_of "$CS")" \
  || fail "the stalled compaction is not on the trace: $(trace_of "$CS" | grep compact_stalled)"
comp_once --compact-stall-sec 300
[[ "$(ls "$CS"/threads/main/*.md | wc -l | tr -d ' ')" == 1 ]] || fail "the stalled compaction was reported twice"
[[ "$(grep -c '^k0	' "$PROMPT_LOG")" -eq 0 ]] || fail "a seat with a stalled compaction was nudged"
pass "a compaction open past --compact-stall-sec is said once, on the board and the trace, and the seat is not nudged"
row k0 compact_done 100 '{"reason":"manual","via":"self"}' >> "$CS/traces/events.jsonl"
comp_once --compact-stall-sec 300
[[ "$(grep -c '^k0	' "$PROMPT_LOG")" -eq 0 ]] || fail "a seat 100 s out of its compaction was told it had ended its turn: $(cat "$PROMPT_LOG")"
pass "a seat just out of a compaction is not told it ended its turn: its hand-off is on its way (--compact-grace-sec, 300 by default)"
comp_once --compact-stall-sec 300 --compact-grace-sec 60
[[ "$(grep -c '^k0	' "$PROMPT_LOG")" -eq 1 ]] || fail "a seat whose compaction ended is not watched again"
pass "once the compaction ends and the grace is over the seat is watched like any other"

# --- a local model's first turn ---------------------------------------------
# The LM Studio seat on BelkaCTF #6 took about four minutes to answer its
# first turn on a 10 KB contract and was nudged twice before it had emitted a
# token. Nothing it has done yet, and a model served from this machine: that
# is loading, not stalling.
LOCAL_SB="$TMP/local"
mkdir -p "$LOCAL_SB"/{traces,done/agents,threads/main,inbox/L0,.pi-sessions/L0,locks}
cat > "$LOCAL_SB/team.json" <<'JSON'
{"swarm_id": "L", "n": 1, "agents": [{"id": "L0", "role": "worker", "model": "lmstudio/qwen3.8-27b-uncensored"}]}
JSON
: > "$LOCAL_SB/traces/events.jsonl"
printf '{"ts":"2026-01-01T00:00:00.000Z","agent":"L0","tool":"agent_start","args":{},"result":{"ok":true}}\n' \
  >> "$LOCAL_SB/traces/events.jsonl"
: > "$LOCAL_SB/.pi-sessions/L0/session.jsonl"
touch -t "$old" "$LOCAL_SB/.pi-sessions/L0/session.jsonl"
: > "$PROMPT_LOG"
PATH="$TMP/bin:$PATH" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$LOCAL_SB" --once --news-sec 45 --idle-sec 30 >/dev/null 2>&1 || true
[[ "$(grep -c '^L0	' "$PROMPT_LOG")" -eq 0 ]] || fail "a local seat on its first turn must not be nudged"
pass "a seat on a locally served model gets its first turn before the watchdog counts it idle"

# Once it has worked, the ordinary thresholds apply again.
printf '{"ts":"2026-01-01T00:00:10.000Z","agent":"L0","tool":"bash","args":{},"result":{"ok":true}}\n' \
  >> "$LOCAL_SB/traces/events.jsonl"
touch -t "$old" "$LOCAL_SB/.pi-sessions/L0/session.jsonl"
PATH="$TMP/bin:$PATH" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$LOCAL_SB" --once --news-sec 45 --idle-sec 30 >/dev/null 2>&1 || true
[[ "$(grep -c '^L0	' "$PROMPT_LOG")" -eq 1 ]] || fail "a local seat that has worked is nudged like any other"
pass "the first-turn grace is for the first turn only"

# --- agents in microVMs: the hub, not Herdr ----------------------------------
# A VM's pane runs `msb exec`: Herdr can neither read Pi's state off it nor
# type a prompt Pi takes. The watchdog asks the hub instead, which hears each
# agent's state up its link and puts the words down it.
VM_SB="$TMP/vm"
mkdir -p "$VM_SB"/{traces,done/agents,threads/main,inbox/v0,.pi-sessions/v0,locks}
printf '{"swarm_id": "v", "n": 1, "agents": [{"id": "v0", "role": "worker"}]}\n' > "$VM_SB/team.json"
: > "$VM_SB/traces/events.jsonl"
printf -- '---\nid: 1\nthread: main\nfrom: system\nto: all\ntag: result\n---\n\nnews\n' > "$VM_SB/threads/main/000001-system.md"
printf '{"main": 0}\n' > "$VM_SB/inbox/v0/cursors.json"
: > "$VM_SB/.pi-sessions/v0/session.jsonl"
touch -t "$old" "$VM_SB/.pi-sessions/v0/session.jsonl"
HUB_DIR="$(mktemp -d "/tmp/dfh.XXXXXX")"
printf '{"agents":["v0"],"tokens":{},"collector":"%s/none.sock"}' "$HUB_DIR" \
  | node --experimental-strip-types --no-warnings "$ROOT/scripts/vm-hub.ts" "$VM_SB" --dir "$HUB_DIR" --quiet >"$TMP/hub.log" 2>&1 &
HUB_PID=$!
trap 'kill "$HUB_PID" "${LINK_PID:-}" 2>/dev/null; rm -rf "$TMP" "$HUB_DIR"' EXIT
for _ in $(seq 50); do [[ -S "$HUB_DIR/admin.sock" ]] && break; sleep 0.1; done
[[ -S "$HUB_DIR/admin.sock" ]] || fail "the hub did not come up: $(cat "$TMP/hub.log")"
# v0's link: says it is idle, writes down every prompt it is given.
node -e '
const net = require("node:net"); const fs = require("node:fs");
const s = net.connect(process.argv[1]); let b = "";
s.on("connect", () => s.write(JSON.stringify({ t: "hello" }) + "\n" + JSON.stringify({ t: "state", state: "idle" }) + "\n"));
s.on("data", (d) => { b += d; let i; while ((i = b.indexOf("\n")) >= 0) { const m = JSON.parse(b.slice(0, i)); b = b.slice(i + 1); if (m.t === "prompt") fs.appendFileSync(process.argv[2], JSON.stringify({ deliver: m.deliver ?? null, text: m.text }) + "\n"); } });
' "$HUB_DIR/v0.sock" "$TMP/vm-prompts.txt" &
LINK_PID=$!
# Until the hub has the link, not a fixed half second.
for _ in $(seq 100); do jq -e '.agents.v0.connected == true' "$HUB_DIR/status.json" >/dev/null 2>&1 && break; sleep 0.05; done
jq -e '.agents.v0.connected == true' "$HUB_DIR/status.json" >/dev/null 2>&1 || fail "v0's link never reached the hub: $(cat "$HUB_DIR/status.json" 2>/dev/null)"
printf '#!/usr/bin/env bash\necho "$@" >> "%s"\nexit 1\n' "$TMP/herdr-used.txt" > "$TMP/bin/herdr-broken"
chmod +x "$TMP/bin/herdr-broken"
HERDR_BIN="$TMP/bin/herdr-broken" SWARM_HUB_ADMIN="$HUB_DIR/admin.sock" SWARM_HUB_STATUS="$HUB_DIR/status.json" \
  bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$VM_SB" --once --news-sec 45 --idle-sec 180 >"$TMP/nudge1.log" 2>&1 \
  || fail "the watchdog failed: $(cat "$TMP/nudge1.log")"
for _ in $(seq 100); do grep -q '1 post(s) you have not read' "$TMP/vm-prompts.txt" 2>/dev/null && break; sleep 0.05; done
grep -q '1 post(s) you have not read' "$TMP/vm-prompts.txt" 2>/dev/null || fail "a VM agent's nudge did not arrive through the hub: $(cat "$TMP/vm-prompts.txt" 2>/dev/null)"
[[ ! -s "$TMP/herdr-used.txt" ]] || fail "the watchdog asked Herdr about a VM agent: $(cat "$TMP/herdr-used.txt")"
{ cat "$VM_SB/traces/events.jsonl" "$VM_SB/traces/system-spill.jsonl" 2>/dev/null || true; } | grep -q '"tool":"idle_nudge"' || fail "the VM nudge is not recorded"
pass "an agent in a microVM is nudged through the hub, and Herdr is never asked"

printf '{"agents":{"v0":{"state":"working","connected":true}}}\n' > "$TMP/working.json"
: > "$TMP/vm-prompts.txt"
: > "$VM_SB/traces/idle-nudge.state"
# The watchdog's own verdict, not its silence: a watchdog that crashed would
# also nudge nobody.
nudges_before="$(cat "$VM_SB/traces/events.jsonl" "$VM_SB/traces/system-spill.jsonl" 2>/dev/null | grep -c '"tool":"idle_nudge"')"
HERDR_BIN="$TMP/bin/herdr-broken" SWARM_HUB_ADMIN="$HUB_DIR/admin.sock" SWARM_HUB_STATUS="$TMP/working.json" \
  bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$VM_SB" --once --news-sec 45 --idle-sec 180 >"$TMP/nudge2.log" 2>&1 \
  || fail "the watchdog failed: $(cat "$TMP/nudge2.log")"
sleep 0.3
[[ ! -s "$TMP/vm-prompts.txt" ]] || fail "a VM agent the hub says is working was nudged"
[[ "$(cat "$VM_SB/traces/events.jsonl" "$VM_SB/traces/system-spill.jsonl" 2>/dev/null | grep -c '"tool":"idle_nudge"')" == "$nudges_before" ]] || fail "a nudge was recorded for the working agent"
pass "an agent the hub says is working is left to work"

# The same agent, waiting: the hub still says working, and the words go down
# the link as a steer, since a waiting agent's turn does not end.
{ row v0 post 700; row v0 wait 5; } >> "$VM_SB/traces/events.jsonl"
: > "$TMP/vm-prompts.txt"
: > "$VM_SB/traces/idle-nudge.state"
HERDR_BIN="$TMP/bin/herdr-broken" SWARM_HUB_ADMIN="$HUB_DIR/admin.sock" SWARM_HUB_STATUS="$TMP/working.json" \
  bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$VM_SB" --once --news-sec 45 --idle-sec 180 --wait-idle-sec 600 >"$TMP/nudge3.log" 2>&1 \
  || fail "the watchdog failed: $(cat "$TMP/nudge3.log")"
for _ in $(seq 100); do [[ -s "$TMP/vm-prompts.txt" ]] && break; sleep 0.05; done
jq -e 'select(.deliver == "steer" and (.text | startswith("For 11 minutes you have called only wait and inbox")))' "$TMP/vm-prompts.txt" >/dev/null 2>&1 \
  || fail "a waiting VM agent was not steered through the hub: $(cat "$TMP/vm-prompts.txt" 2>/dev/null)"
pass "an agent in a microVM that only waits is steered through the hub though the hub says it is working"

# --- a hub that died is brought back by the watchdog, from what the hub kept ----
kill "$HUB_PID" 2>/dev/null; wait "$HUB_PID" 2>/dev/null || true
for _ in $(seq 30); do [[ ! -S "$HUB_DIR/admin.sock" ]] && break; sleep 0.1; done
echo "$HUB_PID" > "$VM_SB/hub.pid"
[[ -f "$HUB_DIR/hub-input.json" ]] || fail "the hub kept nothing to resume from"
HERDR_BIN="$TMP/bin/herdr-broken" SWARM_HUB_ADMIN="$HUB_DIR/admin.sock" SWARM_HUB_STATUS="$HUB_DIR/status.json" SWARM_HUB_DIR="$HUB_DIR" \
  bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$VM_SB" --once --news-sec 45 --idle-sec 180 >"$TMP/restart.log" 2>&1
HUB_PID="$(cat "$VM_SB/hub.pid")"
[[ -S "$HUB_DIR/admin.sock" ]] || fail "the watchdog did not bring the hub back: $(cat "$TMP/restart.log"; cat "$TMP/hub.log")"
kill -0 "$HUB_PID" 2>/dev/null || fail "hub.pid does not name the resumed hub"
answer="$(node "$ROOT/scripts/vm-hub-send.mjs" "$HUB_DIR/admin.sock" '{"op":"status"}')"
printf '%s' "$answer" | jq -e '.ok == true and (.agents | has("v0"))' >/dev/null || fail "the resumed hub does not know the run's agents: $answer"
{ cat "$VM_SB/traces/events.jsonl" "$HUB_DIR/hub-spill.jsonl" 2>/dev/null || true; } | grep -q 'hub_restarted' || fail "the restart is not on the record"
pass "a hub that died is brought back by the watchdog with the run's agents, and the restart is on the record"

# --- a host run's stop from outside the panes ---------------------------------
BS="$TMP/backstop"
mkdir -p "$BS"/{traces,done/agents,threads/main,inbox/b00,.pi-sessions/b00,locks}
printf '{"swarm_id":"bs","n":1,"agents":[{"id":"b00","role":"worker"}]}\n' > "$BS/team.json"
long_ago="$(date -u -d '@'$(( $(date +%s) - 1800 )) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r $(( $(date +%s) - 1800 )) +%Y-%m-%dT%H:%M:%SZ)"
printf '{"cap_usd":5,"spent_usd":0,"wall_clock_minutes":1,"started_at":"%s","agents":{}}\n' "$long_ago" > "$BS/budget.json"
HERDR_BIN="$TMP/bin/herdr-broken" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$BS" --once >"$TMP/bs1.log" 2>&1
[[ -n "$(jq -r '.stop_steer_at // empty' "$BS/budget.json")" ]] || fail "past the wall clock the watchdog did not start the stop clock: $(cat "$TMP/bs1.log")"
ls "$BS/threads/main"/*.md >/dev/null 2>&1 || fail "the steer was not said on the board"
[[ ! -f "$BS/done/SWARM_DONE" ]] || fail "the watchdog stopped the swarm before the grace period"
# The grace period passed with nobody stopping: the harness writes the sentinel.
jq --arg t "$long_ago" '.stop_steer_at = $t' "$BS/budget.json" > "$BS/b.tmp" && mv "$BS/b.tmp" "$BS/budget.json"
HERDR_BIN="$TMP/bin/herdr-broken" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$BS" --once >"$TMP/bs2.log" 2>&1
[[ -f "$BS/done/SWARM_DONE" ]] || fail "past the grace period the watchdog did not stop the swarm: $(cat "$TMP/bs2.log")"
grep -q '^by: harness' "$BS/done/SWARM_DONE" || fail "the sentinel is not the harness's"
{ cat "$BS/traces/events.jsonl" "$BS/traces/system-spill.jsonl" 2>/dev/null || true; } | grep -q '"tool":"harness_stop"' || fail "the stop is not on the record"
pass "a host run past its wall clock is steered from outside the panes, and stopped by the harness after the grace period"

# --- the operator hears the swarm's cap --------------------------------------------
CB="$TMP/nruns/scap1"
mkdir -p "$CB"/{traces,done/agents,threads/main,inbox/c00,.pi-sessions/c00,locks} "$TMP/nruns/notify"
printf '{"swarm_id":"scap1","n":1,"agents":[{"id":"c00","role":"worker"}]}\n' > "$CB/team.json"
printf '{"cap_usd":5,"spent_usd":6,"wall_clock_minutes":600,"started_at":"%s","agents":{}}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$CB/budget.json"
jq -n --arg sb "$CB" '{runs: [{id: "scap1", state: "running", sandbox: $sb, notify: true}]}' > "$TMP/nruns/registry.json"
printf 'cat >> %q\n' "$TMP/cap-events.jsonl" > "$TMP/nruns/notify/scap1.cmd"
chmod 600 "$TMP/nruns/notify/scap1.cmd"
SWARM_RUNS_DIR="$TMP/nruns" HERDR_BIN="$TMP/bin/herdr-broken" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$CB" --once >"$TMP/cap.log" 2>&1
for i in $(seq 1 50); do [[ -s "$TMP/cap-events.jsonl" ]] && break; sleep 0.1; done
jq -e 'select(.event == "budget_cap" and .run == "scap1" and .detail.spent_usd == 6 and .detail.cap_usd == 5)' "$TMP/cap-events.jsonl" >/dev/null \
  || fail "the cap was not notified: $(cat "$TMP/cap-events.jsonl" 2>/dev/null; cat "$TMP/cap.log")"
pass "a host run past its cap tells the operator's notify command (budget_cap)"

# --- where nobody has looked, at a quarter, a half and three quarters -------------
CV="$TMP/coverage"
mkdir -p "$CV"/{traces,done/agents,threads/main,inbox/d00,.pi-sessions/d00,locks,inputs}
printf '{"swarm_id":"cov","n":1,"agents":[{"id":"d00","role":"worker"}]}\n' > "$CV/team.json"
: > "$CV/done/agents/d00.done"
printf '{"files":[{"path":"inputs/named.bin","bytes":1,"sha256":"x"},{"path":"inputs/nobody.bin","bytes":1,"sha256":"y"}]}\n' > "$CV/inputs.json"
printf '%s\n' '{"ts":"2026-01-01T00:00:00Z","agent":"d00","tool":"bash","args":{"command":"xxd inputs/named.bin | head"},"result":{"ok":true}}' > "$CV/traces/events.jsonl"
started="$(date -u -d '@'$(( $(date +%s) - 3000 )) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r $(( $(date +%s) - 3000 )) +%Y-%m-%dT%H:%M:%SZ)"
printf '{"cap_usd":5,"spent_usd":0,"wall_clock_minutes":60,"started_at":"%s","agents":{}}\n' "$started" > "$CV/budget.json"
HERDR_BIN="$TMP/bin/herdr-broken" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$CV" --once >"$TMP/cov1.log" 2>&1
post="$(cat "$CV"/threads/main/*.md 2>/dev/null || true)"
grep -q 'no command has named these inputs yet' <<<"$post" || fail "the uncovered inputs were not posted: $(cat "$TMP/cov1.log")"
grep -q 'inputs/nobody.bin' <<<"$post" || fail "the input nobody named is not listed: $post"
grep -q 'inputs/named.bin' <<<"$post" && fail "an input a command named is listed as untouched"
grep -q 'At 75%' <<<"$post" || fail "the post does not say where in the run it is: $post"
[[ "$(tr '\n' ' ' < "$CV/traces/idle-nudge.coverage")" == "25 50 75 " ]] || fail "the marks passed are not spent: $(cat "$CV/traces/idle-nudge.coverage")"
HERDR_BIN="$TMP/bin/herdr-broken" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$CV" --once >"$TMP/cov2.log" 2>&1
[[ "$(ls "$CV"/threads/main/*.md | wc -l | tr -d ' ')" == 1 ]] || fail "the coverage was posted twice"
pass "past three quarters of the wall clock the inputs no command named are posted once, naming none that was named"

# --- no collector answering ---------------------------------------------------
# A harness line the collector does not take goes to the system spill, never
# into events.jsonl: not onto a trace that ends partway through a line (the
# fragment is usually a chained line cut short), and not onto one with no
# chain yet either, where nothing could say who wrote it.
TORN_SB="$TMP/torn"
mkdir -p "$TORN_SB/traces"
printf '{"ts":"t1","agent":"a0","tool":"bash","args":{},"result":{"ok":true},"prev":""}\n{"ts":"t2","agent":"a0","tool":"bash","args":{"cmd":"cut sh' \
  > "$TORN_SB/traces/events.jsonl"
before="$(cksum < "$TORN_SB/traces/events.jsonl")"
( source "$ROOT/scripts/lib/trace.sh"; trace_emit "$ROOT" "$TORN_SB" '{"ts":"t3","agent":"system","tool":"idle_nudge","args":{},"result":{"ok":true}}' )
[[ "$(cksum < "$TORN_SB/traces/events.jsonl")" == "$before" ]] || fail "a line was appended onto a torn trace tail"
[[ "$(grep -c idle_nudge "$TORN_SB/traces/system-spill.jsonl" 2>/dev/null)" -eq 1 ]] || fail "the line refused by a torn tail is not in the spill"
pass "a harness line spills rather than fusing onto a torn trace tail"

# A trace with no chain yet, whole lines: the spill all the same.
PLAIN_SB="$TMP/plain"
mkdir -p "$PLAIN_SB/traces"
printf '{"ts":"t1","agent":"a0","tool":"bash","args":{},"result":{"ok":true}}\n' > "$PLAIN_SB/traces/events.jsonl"
( source "$ROOT/scripts/lib/trace.sh"; trace_emit "$ROOT" "$PLAIN_SB" '{"ts":"t2","agent":"system","tool":"idle_nudge","args":{},"result":{"ok":true}}' )
[[ "$(wc -l < "$PLAIN_SB/traces/events.jsonl" | tr -d ' ')" -eq 1 ]] || fail "a line was appended to a trace with no chain: $(cat "$PLAIN_SB/traces/events.jsonl")"
[[ "$(grep -c idle_nudge "$PLAIN_SB/traces/system-spill.jsonl" 2>/dev/null)" -eq 1 ]] || fail "the line is not in the spill"
pass "a trace with no chain yet takes no appended line either: the harness's line is in the spill"

# --- the lead register in the nudge -------------------------------------------
# An idle agent is told what the register would have it take: the ready lead
# it ranks first, and the questions nobody holds a lead for.
LD="$TMP/leads"
mkdir -p "$LD"/{traces,done/agents,threads/main,inbox/a00,inbox/a01,.pi-sessions/a00,.pi-sessions/a01,locks}
cat > "$LD/team.json" <<'JSON'
{"swarm_id": "t", "n": 2, "agents": [{"id": "a00", "role": "worker"}, {"id": "a01", "role": "worker"}]}
JSON
: > "$LD/traces/events.jsonl"
printf '# Contract\n\n## Checks\n\n- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,summary,narrative`\n' > "$LD/SWARM.md"
for id in a00 a01; do
  : > "$LD/.pi-sessions/$id/session.jsonl"
  touch -t "$(date -v-300S +%Y%m%d%H%M.%S 2>/dev/null || date -d '300 seconds ago' +%Y%m%d%H%M.%S)" "$LD/.pi-sessions/$id/session.jsonl"
done
node --experimental-strip-types --no-warnings -e '
  const [leads, S] = process.argv.slice(1);
  import(leads).then(async (L) => {
    const r = await L.openLead({ sandboxRoot: S, agentId: "a01" }, { title: "Open the encrypted container", why: "question 2 rests on it", answers: ["2"] });
    if (!r.ok) { console.error(r.reason); process.exit(1); }
  });
' "$ROOT/extensions/leads.ts" "$LD" || fail "could not open a lead"
: > "$PROMPT_LOG"
SWARM_RUNS_DIR="$TMP/no-registry" HERDR_BIN="$TMP/bin/herdr" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$LD" --once --idle-sec 180 >/dev/null 2>&1
nudge="$(grep '^a00	' "$PROMPT_LOG" | tail -1)"
[[ -n "$nudge" ]] || fail "the idle agent was not nudged"
grep -q 'The ready lead the register ranks first is L-1 "Open the encrypted container"' <<<"$nudge" || fail "the nudge does not name the ready lead: $nudge"
grep -q 'Questions nobody holds a lead for: question:1, question:2 (open: L-1)' <<<"$nudge" || fail "the nudge does not name the uncovered questions: $nudge"
pass "an idle agent's nudge names the ready lead the register ranks first and the questions nobody holds"

# --- a stop in progress ------------------------------------------------------
# swarm.sh stop marks the hub directory first. On s17fdfe the watchdog went on
# for a quarter of an hour of the stop: 28 prompts and a regroup to seats whose
# VMs were gone.
STOP_HUB="$TMP/stophub"; mkdir -p "$STOP_HUB"; : > "$STOP_HUB/.stop"
: > "$PROMPT_LOG"
touch -t "$old" "$CS/.pi-sessions/k0/session.jsonl"
out="$(SWARM_HUB_DIR="$STOP_HUB" HERDR_BIN="$TMP/bin/herdr" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$CS" --once --idle-sec 30 --compact-grace-sec 1 2>&1)"; rc=$?
[[ "$rc" -eq 0 ]] || fail "the watchdog did not exit cleanly when a stop had begun (exit $rc): $out"
[[ "$(grep -c '^k0	' "$PROMPT_LOG")" -eq 0 ]] || fail "a seat was nudged while the run was being stopped"
pass "once a stop has begun the watchdog exits and nudges nobody"

# --- a seat whose process has ended --------------------------------------------
# On s5d814f every seat's link closed after a 76 MB message and nothing started
# them again. The watchdog says a seat is down, sets a session with a line too
# large to load aside, starts the seat again in its pane, and after the tries
# are spent records it dead; when all are, the run says so.
DS="$TMP/down"; DH="$TMP/downhub"
mkdir -p "$DS"/{traces,done/agents,threads/main,inbox/d0,inbox/d1,.pi-sessions/d0,.pi-sessions/d1,locks} "$DH"
printf '{"swarm_id":"d","n":2,"agents":[{"id":"d0","role":"worker"},{"id":"d1","role":"worker"}]}\n' > "$DS/team.json"
printf '{"n":2,"panes":["wD:p1","wD:p2"]}\n' > "$DS/layout.json"
printf '{"main": 0}\n' > "$DS/inbox/d0/cursors.json"; printf '{"main": 0}\n' > "$DS/inbox/d1/cursors.json"
: > "$DS/traces/events.jsonl"
printf '#!/bin/sh\n' > "$DH/launch-d0.sh"; printf '#!/bin/sh\n' > "$DH/launch-d1.sh"
printf '{"agents":{"d0":{"connected":false,"state":"gone"},"d1":{"connected":true,"state":"working"}}}\n' > "$DH/status.json"
printf '{"type":"message","message":{"role":"user"}}\n' > "$DS/.pi-sessions/d0/s.jsonl"
head -c 3000 /dev/zero | tr '\0' 'x' >> "$DS/.pi-sessions/d0/s.jsonl"; printf '\n' >> "$DS/.pi-sessions/d0/s.jsonl"
printf '{"type":"message"}\n' > "$DS/.pi-sessions/d1/s.jsonl"
PANE_LOG="$TMP/pane.log"; : > "$PANE_LOG"
cat > "$TMP/bin/herdr-down" <<SH
#!/bin/sh
if [ "\$1" = pane ] && [ "\$2" = run ]; then printf '%s\t%s\n' "\$3" "\$4" >> "$PANE_LOG"; exit 0; fi
exit 0
SH
chmod +x "$TMP/bin/herdr-down"
down_once() { SWARM_HUB_DIR="$DH" SWARM_HUB_STATUS="$DH/status.json" SWARM_SEAT_DOWN_SEC="${1:-0}" SWARM_SEAT_LINE_MAX_BYTES=2000 SWARM_SEAT_RELAUNCH_MAX=2 HERDR_BIN="$TMP/bin/herdr-down" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$DS" --once --idle-sec 100000 2>&1; }
out="$(down_once 100000)"
[[ ! -s "$PANE_LOG" ]] || fail "a seat whose link had just gone down was started again at once: $(cat "$PANE_LOG")"
grep -q '^d0 ' "$DS/traces/seat-down.state" || fail "the seat's link going down was not noted: $out"
out="$(down_once 0)"
grep -q "^wD:p1	sh $DH/launch-d0.sh$" "$PANE_LOG" || fail "the seat was not started again in its own pane: $(cat "$PANE_LOG") / $out"
grep -q 'wD:p2' "$PANE_LOG" && fail "a seat whose link is up was started again"
ls "$DS"/.pi-sessions/d0/retired-*/s.jsonl >/dev/null 2>&1 || fail "the session with a line too large to load was not set aside: $(ls -R "$DS/.pi-sessions/d0")"
[[ -z "$(ls "$DS"/.pi-sessions/d0/*.jsonl 2>/dev/null)" ]] || fail "the oversized session is still the seat's newest"
[[ -f "$DS/.pi-sessions/d1/s.jsonl" ]] || fail "another seat's session was touched"
grep -q 'started d0 again in wD:p1 (attempt 1 of 2, with a fresh session' <<<"$out" || fail "the relaunch was not said: $out"
pass "a seat whose link stays down is said and started again in its pane, with a fresh session when the old one cannot be loaded"
out="$(down_once 0)"; out="$(down_once 0)"
[[ -f "$DS/done/agents/d0.dead" ]] || fail "a seat that did not come back after its relaunches is not recorded dead: $out / $(cat "$DS/traces/seat-down.state")"
[[ "$(grep -c 'launch-d0.sh' "$PANE_LOG")" -eq 2 ]] || fail "the seat was started $(grep -c 'launch-d0.sh' "$PANE_LOG") times, not the 2 it is allowed"
[[ ! -e "$DS/done/ALL_AGENTS_DEAD" ]] || fail "the run was called dead while a seat is up"
printf '{"agents":{"d0":{"connected":false},"d1":{"connected":true}}}\n' > "$DH/status.json"
: > "$DS/done/agents/d1.done"
out="$(down_once 0)"
[[ -f "$DS/done/ALL_AGENTS_DEAD" ]] || fail "every seat is done or dead and the run does not say so: $out"
pass "after its relaunches a seat is recorded dead, and a run whose seats are all done or dead says so"
printf '{"agents":{"d0":{"connected":true},"d1":{"connected":true}}}\n' > "$DH/status.json"
rm -f "$DS/done/agents/d0.dead" "$DS/done/ALL_AGENTS_DEAD" "$DS/done/agents/d1.done"; printf 'd0 1 1 1\n' > "$DS/traces/seat-down.state"
out="$(down_once 0)"
grep -q '^d0 ' "$DS/traces/seat-down.state" && fail "a seat that came back is still counted down"
pass "a seat whose link came back is no longer counted"

# --- the log says when --------------------------------------------------------
: > "$PROMPT_LOG"
out="$(SWARM_LOG_TS=1 HERDR_BIN="$TMP/bin/herdr" bash "$ROOT/scripts/idle-nudge.sh" --sandbox "$CS" --once --idle-sec 30 --compact-grace-sec 1 2>&1)"
grep -Eq '^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z idle-nudge: ' <<<"$out" || fail "a log line carries no time with SWARM_LOG_TS=1: $out"
pass "each log line carries its time when the kickoff starts the watchdog (SWARM_LOG_TS=1)"

# --- the launcher reads its last command before it runs it --------------------
tail -1 "$ROOT/scripts/swarm.sh" | grep -qx 'main "\$@"; exit "\$?"' || fail "swarm.sh does not end with main and its exit on one line: $(tail -1 "$ROOT/scripts/swarm.sh")"
EDIT="$TMP/edit.sh"
printf '%s\n' 'main() { sleep 1; return 0; }' 'main "$@"; exit "$?"' > "$EDIT"
bash "$EDIT" & edit_pid=$!
sleep 0.3; printf '%s\n' ';; this is not shell' >> "$EDIT"; sed -i.bak '1s/^/# a line added while it runs\n/' "$EDIT" 2>/dev/null || true
wait "$edit_pid"; rc=$?
[[ "$rc" -eq 0 ]] || fail "a script edited while it ran ended with exit $rc"
pass "a launcher edited while a command runs still ends with that command's exit status"

echo "idle-nudge.test.sh: all checks passed"
