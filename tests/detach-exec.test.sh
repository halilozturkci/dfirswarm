#!/usr/bin/env bash
# How a run's daemons leave the kickoff behind (swarm.sh, detach_exec): setsid
# where there is one; else nohup; and where nohup refuses, as macOS's does
# under a LaunchDaemon ("nohup: can't detach from console"), the daemon still
# starts, ignores SIGHUP, and $! is its own pid. Stand-ins for setsid and
# nohup on a PATH that has nothing else of either, so every branch runs on
# any host.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/detach-exec.XXXXXX")"
PIDS=()
cleanup() {
  local p
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

eval "$(sed -n '/^detach_exec()/,/^}/p' "$ROOT/scripts/swarm.sh")"
[[ "$(type -t detach_exec)" == function ]] || fail "detach_exec missing from swarm.sh"

# A PATH with bash and sleep and, per case, a stand-in setsid or nohup.
mkpath() { # <dir>
  mkdir -p "$1"
  ln -s "$(command -v bash)" "$1/bash"
  ln -s "$(command -v sleep)" "$1/sleep"
}
# The daemon: says how SIGHUP stands in it, then lives until it is killed.
DAEMON='trap -p HUP > "$1/hup"; echo $$ > "$1/self"; exec sleep 60'

start() { # <path dir> <out dir>: runs the daemon through detach_exec, backgrounded
  mkdir -p "$2"
  ( PATH="$1"; detach_exec bash -c "$DAEMON" daemon "$2" ) >/dev/null 2>&1 &
  STARTED=$!
  PIDS+=("$STARTED")
  for _ in $(seq 1 50); do [[ -s "$2/self" ]] && break; sleep 0.1; done
  [[ -s "$2/self" ]] || fail "the daemon did not start ($2)"
}

echo "# nohup refuses, as macOS's does where there is no console to leave"
P="$TMP/path-refuses"; mkpath "$P"
printf '#!%s\necho "nohup: can'"'"'t detach from console: Inappropriate ioctl for device" >&2\nexit 1\n' "$(command -v bash)" > "$P/nohup"
chmod +x "$P/nohup"
start "$P" "$TMP/refuses"
[[ "$(cat "$TMP/refuses/self")" == "$STARTED" ]] || fail "\$! is not the daemon's pid: $STARTED vs $(cat "$TMP/refuses/self")"
grep -q "trap -- '' SIGHUP" "$TMP/refuses/hup" || fail "the daemon does not ignore SIGHUP: $(cat "$TMP/refuses/hup")"
kill -HUP "$STARTED"
sleep 0.3
kill -0 "$STARTED" 2>/dev/null || fail "a SIGHUP ended the daemon"
pass "where nohup cannot detach, the daemon still starts, ignores SIGHUP, and \$! is its pid"

echo "# nohup works: it is used, as before"
P="$TMP/path-nohup"; mkpath "$P"
printf '#!%s\n[ "$1" = true ] && exit 0\necho used >> %q\ntrap "" HUP\nexec "$@"\n' "$(command -v bash)" "$TMP/nohup-used" > "$P/nohup"
chmod +x "$P/nohup"
start "$P" "$TMP/nohup"
[[ -s "$TMP/nohup-used" ]] || fail "a nohup that works was not used"
[[ "$(cat "$TMP/nohup/self")" == "$STARTED" ]] || fail "\$! is not the daemon's pid through nohup"
pass "a nohup that works is used, and \$! is still the daemon's pid"

echo "# setsid first, wherever there is one"
P="$TMP/path-setsid"; mkpath "$P"
printf '#!%s\necho used >> %q\nexec "$@"\n' "$(command -v bash)" "$TMP/setsid-used" > "$P/setsid"
printf '#!%s\necho used >> %q\nexit 1\n' "$(command -v bash)" "$TMP/nohup-asked" > "$P/nohup"
chmod +x "$P/setsid" "$P/nohup"
start "$P" "$TMP/setsid"
[[ -s "$TMP/setsid-used" ]] || fail "setsid was there and not used"
[[ ! -e "$TMP/nohup-asked" ]] || fail "nohup was asked although setsid was there"
pass "setsid is used where there is one, and nohup is not asked"
