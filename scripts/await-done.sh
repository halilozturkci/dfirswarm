#!/usr/bin/env bash
# Block until the swarm is finished and its own checks pass.
#
# "Finished" is two things, and both have to hold:
#   1. done/SWARM_DONE exists. The file is the clock; chat saying "we're done"
#      is not.
#   2. Every `## Checks` line in the goal passes. Those come from the goal
#      document, so what counts as done is the goal's business — this script
#      used to hard-code work/hello.txt and would certify a swarm that had
#      done something else entirely.
#
# Where the checks come from matters. The copy in <sandbox>/SWARM.md is inside
# the agents' working directory: the write guard refuses it and a shell write
# is detected, but detection is not prevention, and a swarm that could rewrite
# its own checks could certify itself. So the goal is read from the run
# registry, which lives outside the sandbox, and SWARM.md is only a fallback
# (with a warning) for a sandbox that has no registry entry.
#
# A check is the code span on a `- ` line under `## Checks`:
#     - `test -f work/pelican.svg`
# Lines with no backticks are prose for the agents and are skipped. Checks run
# with the sandbox as their working directory, with stdin closed and a time
# limit, because they are shell commands that read agent-written files.
#
# --nudge: once the sentinel is there, every agent without a done or dead
# marker is prompted once through Herdr (`herdr agent prompt <id> ...`). An
# idle pane never makes another tool call, so it never sees the sentinel on
# its own; the prompt makes it act, and its next tool call is stopped.
#
# Exit 0 when the sentinel is present and every check passes, 1 otherwise.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX="${SWARM_SANDBOX:-$ROOT/sandbox}"
TIMEOUT="${SWARM_TIMEOUT:-480}"
INTERVAL="${WATCH_INTERVAL:-8}"
CHECK_TIMEOUT="${SWARM_CHECK_TIMEOUT:-30}"
QUIET=0
CHECKS_JSON=0
NUDGE=0
NUDGED=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sandbox) SANDBOX="$2"; shift 2 ;;
    --checks-json) CHECKS_JSON=1; shift ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --check-timeout) CHECK_TIMEOUT="$2"; shift 2 ;;
    --quiet) QUIET=1; shift ;;
    --nudge) NUDGE=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -d "$SANDBOX" ]] || { echo "No such sandbox: $SANDBOX" >&2; exit 2; }
SANDBOX="$(cd "$SANDBOX" && pwd -P)"
RUNS_DIR="${SWARM_RUNS_DIR:-$(dirname "$SANDBOX")}"

say() { [[ "$QUIET" -eq 1 ]] || echo "$@"; }

# The goal as the spawner recorded it, outside the agents' reach. Assigns
# GOAL_TEXT and GOAL_SOURCE directly rather than printing, so the caller can
# tell where the checks came from — a command substitution would lose it.
GOAL_TEXT=""
GOAL_SOURCE=""
load_goal() {
  GOAL_TEXT=""
  GOAL_SOURCE=""
  if [[ -f "$RUNS_DIR/registry.json" ]]; then
    # Compare resolved paths: a registry written before the sandbox was
    # resolved (or on a host where /var is a symlink) still has to match.
    GOAL_TEXT="$(python3 -c '
import json, os, sys
registry, sandbox = sys.argv[1], os.path.realpath(sys.argv[2])
try:
    runs = json.load(open(registry, encoding="utf-8")).get("runs", [])
except Exception:
    sys.exit(0)
for run in reversed(runs):
    recorded = run.get("sandbox") or ""
    if recorded and os.path.realpath(recorded) == sandbox:
        sys.stdout.write(run.get("goal") or "")
        break
' "$RUNS_DIR/registry.json" "$SANDBOX" 2>/dev/null || true)"
  fi
  if [[ -n "$GOAL_TEXT" ]]; then
    GOAL_SOURCE="registry"
    return 0
  fi
  if [[ -f "$SANDBOX/SWARM.md" ]]; then
    GOAL_SOURCE="sandbox contract"
    GOAL_TEXT="$(cat "$SANDBOX/SWARM.md")"
    [[ -n "$GOAL_TEXT" ]] && return 0
  fi
  return 1
}

# Agents in team.json with neither a done nor a dead marker, one per line.
unfinished_agents() {
  local sandbox="$1"
  [[ -f "$sandbox/team.json" ]] || return 0
  python3 -c '
import json, os, sys
sandbox = sys.argv[1]
try:
    team = json.load(open(os.path.join(sandbox, "team.json"), encoding="utf-8"))
except Exception:
    sys.exit(0)
for agent in team.get("agents", []):
    aid = agent.get("id") or ""
    if not aid:
        continue
    marks = os.path.join(sandbox, "done", "agents")
    if os.path.exists(os.path.join(marks, aid + ".done")) or os.path.exists(os.path.join(marks, aid + ".dead")):
        continue
    print(aid)
' "$sandbox"
}

# The sentinel is there; tell every agent that has not marked itself, once.
# Herdr missing or a pane already gone is not an error: the harness's own
# nudge and the sentinel hook still cover them.
nudge_unfinished() {
  local sandbox="$1" aid hub=""
  [[ "$NUDGE" -eq 1 ]] || return 0
  # Agents in microVMs are reached through the hub, which delivers the words
  # to Pi itself; Herdr can only type into a pane that runs `msb exec`.
  # Only a hub directory the harness made (under the hubs' parent, which no
  # pane can write) is a hub; a hub.dir that names anything else is ignored.
  local hd parent
  if [[ -f "$sandbox/hub.dir" ]]; then
    hd="$(cat "$sandbox/hub.dir" 2>/dev/null || true)"
    # The hubs' parent as swarm.sh keeps it (hubs_parent): one per user,
    # whatever this shell's TMPDIR, and only a directory of the user's own.
    parent="${SWARM_HUBS_DIR:-${DFIRSWARM_HOME:-$HOME/.dfirswarm}/hubs}"
    if [[ -d "$parent" && ! -L "$parent" && -O "$parent" ]]; then
      parent="$(cd "$parent" 2>/dev/null && pwd -P || true)"
    else
      parent=""
    fi
    [[ -n "$parent" && "$hd" == "$parent"/dfs-* && "$hd" != *..* && -S "$hd/admin.sock" \
      && "$(cat "$hd/sandbox" 2>/dev/null)" == "$(cd "$sandbox" 2>/dev/null && pwd -P)" ]] && hub="$hd/admin.sock"
  fi
  if [[ -z "$hub" ]]; then
    command -v "${HERDR_BIN:-herdr}" >/dev/null 2>&1 || { say "  nudge: herdr is not on PATH"; NUDGE=0; return 0; }
  fi
  local words="The swarm is finished: done/SWARM_DONE exists. Call done now and stop."
  while IFS= read -r aid; do
    [[ -n "$aid" ]] || continue
    case " $NUDGED " in *" $aid "*) continue ;; esac
    NUDGED="$NUDGED $aid"
    local reached=0
    if [[ -n "$hub" ]]; then
      node "$ROOT/scripts/vm-hub-send.mjs" "$hub" "$(jq -nc --arg a "$aid" --arg t "$words" '{op: "prompt", agent: $a, text: $t, deliver: "steer", kind: "swarm_done"}')" >/dev/null 2>&1 && reached=1
    else
      "${HERDR_BIN:-herdr}" agent prompt "$aid" "$words" >/dev/null 2>&1 && reached=1
    fi
    if [[ "$reached" -eq 1 ]]; then
      say "  nudged $aid"
    else
      say "  could not nudge $aid (pane gone?)"
    fi
  done < <(unfinished_agents "$sandbox")
}

# Code spans on bullet lines under every `## Checks` heading, one per line.
# The program is passed with -c, not on stdin: stdin is the goal document.
extract_checks() {
  python3 -c '
import re, sys
text = sys.stdin.read()
# A heading of any level ends the section: an appendix after the checks is
# not more checks.
sections = re.findall(r"^##[ \t]*Checks[ \t]*$(.*?)(?=^#{1,6}[ \t]|\Z)", text, re.M | re.S)
found = False
for body in sections:
    for line in body.splitlines():
        if not line.lstrip().startswith(("-", "*")):
            continue
        for span in re.findall(r"`+([^`]+)`+", line):
            span = span.strip()
            if span:
                found = True
                print(span)
sys.exit(0 if found else 3)
'
}

# Run one check with stdin closed and a wall-clock limit. A check is a shell
# command reading files agents wrote: it can block forever on a FIFO, and it
# would otherwise eat the remaining checks off this loop's stdin.
run_one_check() {
  local sandbox="$1" line="$2" limit="$3"
  # SWARM_HARNESS: where a check finds the harness's own check scripts
  # (scripts/check-answers.ts), whatever the sandbox.
  ( cd "$sandbox" && export SWARM_HARNESS="$ROOT" && eval "$line" ) >/dev/null 2>&1 </dev/null &
  local pid=$!
  local waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if (( waited >= limit * 10 )); then
      kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      echo "  check TIMED OUT after ${limit}s: $line"
      return 1
    fi
    sleep 0.1
    waited=$((waited + 1))
  done
  wait "$pid"
}

# 0 = all passed, 1 = a check failed, 2 = no checks defined, 3 = unreadable.
run_checks() {
  local sandbox="$1"
  local checks rc failed=0 total=0 line

  if ! load_goal; then
    say "  no goal document for $sandbox"
    return 3
  fi
  checks="$(printf '%s\n' "$GOAL_TEXT" | extract_checks)" && rc=0 || rc=$?
  if [[ "$rc" -eq 3 ]]; then
    return 2
  fi
  if [[ "$rc" -ne 0 ]]; then
    say "  could not read the checks out of the goal (exit $rc)"
    return 3
  fi

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    total=$((total + 1))
    if ! run_one_check "$sandbox" "$line" "$CHECK_TIMEOUT"; then
      failed=$((failed + 1))
      echo "  check FAILED: $line"
    fi
  done <<< "$checks"

  echo "  checks (${GOAL_SOURCE}): $((total - failed))/$total passed"
  [[ "$failed" -eq 0 ]]
}

# --checks-json: run the checks once, right now, and report each one as JSON.
# This is what the web app's finish-line panel reads. It never waits and never
# fails the process: a failing check is a row with ok=false, not an exit code,
# because the caller wants the list, not a verdict.
if [[ "$CHECKS_JSON" -eq 1 ]]; then
  sentinel=false
  [[ -f "$SANDBOX/done/SWARM_DONE" ]] && sentinel=true
  all_dead=false
  [[ "$sentinel" == false && -f "$SANDBOX/done/ALL_AGENTS_DEAD" ]] && all_dead=true
  rows=""
  source_name=""
  if load_goal; then
    source_name="$GOAL_SOURCE"
    checks="$(printf '%s\n' "$GOAL_TEXT" | extract_checks)" && rc=0 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        start_ms="$(python3 -c 'import time; print(int(time.time()*1000))')"
        out="$(run_one_check "$SANDBOX" "$line" "$CHECK_TIMEOUT")" && ok=1 || ok=0
        end_ms="$(python3 -c 'import time; print(int(time.time()*1000))')"
        timed_out=0
        [[ "$out" == *"TIMED OUT"* ]] && timed_out=1
        rows+="${ok}"$'\t'"$((end_ms - start_ms))"$'\t'"${timed_out}"$'\t'"${line}"$'\n'
      done <<< "$checks"
    fi
  fi
  printf '%s' "$rows" | CHECKS_SENTINEL="$sentinel" CHECKS_ALL_DEAD="$all_dead" CHECKS_SOURCE="$source_name" python3 -c '
import json, os, sys
checks = []
for raw in sys.stdin.read().splitlines():
    if not raw.strip():
        continue
    ok, ms, timed_out, cmd = raw.split("\t", 3)
    checks.append({"cmd": cmd, "ok": ok == "1", "ms": int(ms), "timed_out": timed_out == "1"})
print(json.dumps({
    "sentinel": os.environ.get("CHECKS_SENTINEL") == "true",
    "all_agents_dead": os.environ.get("CHECKS_ALL_DEAD") == "true",
    "source": os.environ.get("CHECKS_SOURCE") or None,
    "total": len(checks),
    "passed": sum(1 for c in checks if c["ok"]),
    "checks": checks,
}))
'
  exit 0
fi

deadline=$((SECONDS + TIMEOUT))
warned_source=0

while (( SECONDS < deadline )); do
  if [[ -x "$ROOT/scripts/reap.sh" ]]; then
    bash "$ROOT/scripts/reap.sh" --sandbox "$SANDBOX" --timeout "${REAP_TIMEOUT:-960}" --quiet --stop || true
  fi
  [[ "$QUIET" -eq 1 ]] || bash "$ROOT/scripts/watch.sh" --once --sandbox "$SANDBOX" || true

  # The reaper found every seat marked and no sentinel: nobody is left who
  # could finish, so waiting out the timeout would only delay the verdict.
  if [[ ! -f "$SANDBOX/done/SWARM_DONE" && -f "$SANDBOX/done/ALL_AGENTS_DEAD" ]]; then
    echo "FAILED: every agent died before the definition of done was met (done/ALL_AGENTS_DEAD, reason all_agents_dead)" >&2
    exit 1
  fi

  if [[ -f "$SANDBOX/done/SWARM_DONE" ]]; then
    nudge_unfinished "$SANDBOX"
    run_checks "$SANDBOX" && rc=0 || rc=$?
    if [[ "$GOAL_SOURCE" == "sandbox contract" && "$warned_source" -eq 0 ]]; then
      echo "WARN: no registry entry for this sandbox; checking against ${SANDBOX}/SWARM.md, which the agents can reach." >&2
      warned_source=1
    fi
    case "$rc" in
      0)
        echo "DoD met: SWARM_DONE and every check passed"
        exit 0
        ;;
      2)
        echo "SWARM_DONE present; the goal defines no checks, so the sentinel is the only signal"
        exit 0
        ;;
      3)
        echo "FAILED: SWARM_DONE is present but the goal's checks could not be read" >&2
        exit 1
        ;;
      *)
        say "SWARM_DONE present but the goal's checks do not pass yet; waiting"
        ;;
    esac
  fi
  sleep "$INTERVAL"
done

echo "TIMEOUT after ${TIMEOUT}s: no complete DoD in $SANDBOX" >&2
bash "$ROOT/scripts/watch.sh" --once --sandbox "$SANDBOX" || true
exit 1
