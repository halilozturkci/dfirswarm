#!/usr/bin/env bash
# Fixture for scripts/netguard.sh. No model, no third-party hosts: the only
# destination is a python http.server on the host loopback.
#
#   allowlist unit cases        -> netguard-proxy.mjs self-test
#   allowed host, plain HTTP    -> body arrives through the proxy
#   allowed host, CONNECT       -> same via curl -p (HTTPS code path)
#   denied host                 -> 403 from the proxy, nothing forwarded
#   bypass attempt (--noproxy)  -> connection fails (empty netns)  [netns only]
#   Node fetch ignoring proxy   -> fails, never reaches the server [netns only]
#   uid + exit code             -> real uid inside, child exit code propagates
#   proxy-only mode             -> still filters when the client cooperates
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NG="$ROOT/scripts/netguard.sh"
WWW="$(mktemp -d "${TMPDIR:-/tmp}/slice2-netguard.XXXXXX")"
# Both ports below 32768: above it lie the ranges a kernel hands out to the outgoing connections of every process on the host (Linux 32768-60999, macOS
# 49152-65535), which a port picked at random there can collide with. A port something already answers on is passed over.
port_in_use() { bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null; }
pick_port() { # pick_port <from> <count> [<taken>]
  local p i
  for i in $(seq 1 100); do
    p=$(( $1 + RANDOM % $2 ))
    if [[ "$p" != "${3:-}" ]] && ! port_in_use "$p"; then echo "$p"; return 0; fi
  done
  echo "no free port in $1..$(( $1 + $2 - 1 ))" >&2
  return 1
}
PORT="$(pick_port 20000 6000)"
PROXY_PORT="$(pick_port 27000 5000 "$PORT")"
SERVER_PID=""
# Reap the fixture server after killing it, or bash 3.2 reports the kill
# ("Terminated: 15") on the way out.
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WWW"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

command -v curl >/dev/null || fail "curl required for this test"
command -v python3 >/dev/null || fail "python3 required for this test"

echo "ok-from-host" > "$WWW/ok.txt"
( cd "$WWW" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 ) >/dev/null 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$PORT/ok.txt" >/dev/null 2>&1 && break; sleep 0.1; done
curl -sf "http://127.0.0.1:$PORT/ok.txt" >/dev/null || fail "fixture server did not start"

echo "# allowlist unit cases"
node "$ROOT/scripts/netguard-proxy.mjs" self-test || fail "allowlist self-test"
pass "allowlist matching"

echo "# dry run"
# The plan is on stdout; on a host without namespaces the script also warns
# on stderr that it fell back to proxy-only. The mode line below reports
# that, so the warning itself is not needed here.
plan="$(bash "$NG" --dry-run --allow Extra.Host,api.openai.com -- true 2>/dev/null)"
grep -q "^mode: " <<< "$plan" || fail "dry-run prints mode"
grep -q "extra.host" <<< "$plan" || fail "dry-run lowercases --allow entries"
[[ "$(grep -o 'api.openai.com' <<< "$plan" | wc -l)" -eq 1 ]] || fail "dry-run dedupes allowlist"
MODE="$(sed -n 's/^mode: *//p' <<< "$plan")"
echo "detected mode: $MODE"
pass "dry-run plan"

LOGF="$WWW/netguard.log"
run() { bash "$NG" --only "localhost:$PORT" --port "$PROXY_PORT" --log "$LOGF" -- "$@" 2>/dev/null; }

echo "# allowed host via plain HTTP"
body="$(run curl -sS "http://localhost:$PORT/ok.txt")" || fail "allowed request exited non-zero"
[[ "$body" == "ok-from-host" ]] || fail "allowed request body: $body"
grep -q "ALLOW http localhost:$PORT" "$LOGF" || fail "no ALLOW log line"
pass "allowed host (http)"

echo "# allowed host via CONNECT tunnel"
body="$(run curl -sS -p "http://localhost:$PORT/ok.txt")" || fail "CONNECT request exited non-zero"
[[ "$body" == "ok-from-host" ]] || fail "CONNECT body: $body"
grep -q "ALLOW connect localhost:$PORT" "$LOGF" || fail "no ALLOW connect log line"
pass "allowed host (CONNECT)"

echo "# denied host (same server, different name)"
code="$(run curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/ok.txt")" || true
[[ "$code" == "403" ]] || fail "denied host expected 403, got $code"
grep -q "DENY http 127.0.0.1:$PORT" "$LOGF" || fail "no DENY log line"
code="$(run curl -sS -p -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/ok.txt")" || true
[[ "$code" == "000" || "$code" == "403" ]] || fail "denied CONNECT expected failure, got $code"
grep -q "DENY connect 127.0.0.1:$PORT" "$LOGF" || fail "no DENY connect log line"
pass "denied host (http + CONNECT)"

echo "# a client that resets after a denied CONNECT must not take the proxy down"
# Run sfeb5: four DENYs for github.com, then an unhandled ECONNRESET on the
# denied client's socket, and the proxy process was gone; every agent's next
# model call failed with "Connection error". The client below sends a CONNECT
# the allowlist refuses and closes with a reset before reading the 403; the
# same guarded session then has to be served an allowed URL by the same
# proxy, with no restart in the log.
cat > "$WWW/reset.py" <<'PY'
import socket, struct, sys
from urllib.parse import urlparse
u = urlparse(sys.argv[1]); port = sys.argv[2]
for _ in range(4):
    s = socket.create_connection((u.hostname, u.port))
    s.sendall(("CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n" % (port, port)).encode())
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
PY
out="$(run bash -c "python3 '$WWW/reset.py' \"\$HTTPS_PROXY\" '$PORT'; sleep 0.5; curl -sS -p 'http://localhost:$PORT/ok.txt'")" \
  || fail "the proxy did not serve after a client reset on a denied CONNECT"
[[ "$out" == "ok-from-host" ]] || fail "after the reset the proxy should still serve, got: $out"
grep -q "RESTART" "$LOGF" && fail "the proxy died on the reset and had to be restarted; it must survive it"
pass "a client reset on a denied CONNECT leaves the proxy standing"

echo "# the same loopback server, allowed under its numeric address"
# A local model's base URL is http://127.0.0.1:PORT and Pi tunnels it as
# CONNECT through the proxy; --only with host:port is what --local-only
# produces, and it must admit exactly that and nothing else.
LOGF2="$WWW/netguard-twin.log"
body="$(bash "$NG" --only "127.0.0.1:$PORT" --port "$PROXY_PORT" --log "$LOGF2" -- curl -sS -p "http://127.0.0.1:$PORT/ok.txt" 2>/dev/null)" \
  || fail "allowed loopback CONNECT exited non-zero"
[[ "$body" == "ok-from-host" ]] || fail "allowed loopback CONNECT body: $body"
grep -q "ALLOW connect 127.0.0.1:$PORT" "$LOGF2" || fail "no ALLOW connect line for 127.0.0.1"
code="$(bash "$NG" --only "127.0.0.1:$PORT" --port "$PROXY_PORT" --log "$LOGF2" -- curl -sS -p -o /dev/null -w '%{http_code}' "http://localhost:$PORT/ok.txt" 2>/dev/null)" || true
[[ "$code" == "000" || "$code" == "403" ]] || fail "localhost should be denied when only 127.0.0.1:$PORT is allowed, got $code"
code="$(bash "$NG" --only "127.0.0.1:$PORT" --port "$PROXY_PORT" --log "$LOGF2" -- curl -sS -p -o /dev/null -w '%{http_code}' "https://api.openai.com/" 2>/dev/null)" || true
[[ "$code" == "000" || "$code" == "403" ]] || fail "a cloud host should be denied under --only 127.0.0.1:$PORT, got $code"
grep -q "DENY connect api.openai.com:443" "$LOGF2" || fail "no DENY line for the cloud host"
code="$(bash "$NG" --only 127.0.0.1 --port "$PROXY_PORT" --log "$LOGF2" -- curl -sS -p -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/ok.txt" 2>/dev/null)" || true
[[ "$code" == "000" || "$code" == "403" ]] || fail "a bare 127.0.0.1 must not open every port, got $code"
pass "--only with a loopback host:port admits it and nothing else: local model traffic stays inside netguard"

echo "# uid and exit code pass through"
out="$(bash "$NG" --port "$PROXY_PORT" -- bash -c 'echo "uid=$(id -u) mode=$NETGUARD_MODE proxy=$HTTPS_PROXY"; exit 7' 2>/dev/null)" && fail "exit code not propagated"
[[ "$out" == "uid=$(id -u) mode=$MODE proxy=http://127.0.0.1:$PROXY_PORT" ]] || fail "unexpected env inside guard: $out"
pass "uid, env and exit code"

if [[ "$MODE" == "netns" ]]; then
  echo "# bypass attempt: client ignores the proxy"
  if run curl -sS --noproxy '*' --max-time 3 "http://localhost:$PORT/ok.txt" >/dev/null; then
    fail "direct connection from inside the namespace succeeded"
  fi
  pass "direct egress blocked (fail-closed)"

  echo "# Node fetch without proxy support cannot reach the server either"
  if run node -e "fetch('http://localhost:$PORT/ok.txt').then(r=>r.text()).then(t=>{ if(t.trim()!=='ok-from-host') process.exit(3); process.exit(0)}).catch(()=>process.exit(9))"; then
    echo "  (node fetch went through the proxy: NODE_USE_ENV_PROXY honoured on $(node --version))"
  else
    echo "  (node fetch failed closed on $(node --version): no proxy support, no direct route)"
  fi
  pass "node fetch is either proxied or blocked, never direct"
else
  echo "skip - namespace checks (mode=$MODE on this host)"
fi

echo "# proxy-only mode still filters cooperating clients"
body="$(bash "$NG" --mode proxy-only --only "localhost:$PORT" --port "$PROXY_PORT" -- curl -sS "http://localhost:$PORT/ok.txt" 2>/dev/null)"
[[ "$body" == "ok-from-host" ]] || fail "proxy-only allowed body: $body"
code="$(bash "$NG" --mode proxy-only --only "localhost:$PORT" --port "$PROXY_PORT" -- curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/ok.txt" 2>/dev/null)" || true
[[ "$code" == "403" ]] || fail "proxy-only denied expected 403, got $code"
pass "proxy-only mode (advisory)"

echo "# PATH shim does not bind 3128 when netns is unavailable"
eval "$(sed -n '/^write_netguard_pi_wrapper()/,/^}/p' "$ROOT/scripts/swarm.sh")"
[[ "$(type -t write_netguard_pi_wrapper)" == function ]] || fail "write_netguard_pi_wrapper missing from swarm.sh"
WRAPDIR="$(mktemp -d "${TMPDIR:-/tmp}/netguard-wrap.XXXXXX")"
cleanup_wrap() {
  if [[ -n "${HOLD_PID:-}" ]]; then
    kill "$HOLD_PID" 2>/dev/null || true
    wait "$HOLD_PID" 2>/dev/null || true
  fi
  cleanup
  rm -rf "$WRAPDIR"
}
trap cleanup_wrap EXIT
mkdir -p "$WRAPDIR/bin" "$WRAPDIR/sb/traces"
cat > "$WRAPDIR/bin/pi" <<'EOF'
#!/usr/bin/env bash
printf 'pi proxy=%s args=%s\n' "${HTTPS_PROXY:-}" "$*"
EOF
chmod +x "$WRAPDIR/bin/pi"
cat > "$WRAPDIR/bin/unshare" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$WRAPDIR/bin/unshare"
PATH="$WRAPDIR/bin:$PATH"
write_netguard_pi_wrapper "$WRAPDIR/sb" "api.openai.com"
[[ -x "$WRAPDIR/sb/bin/pi" ]] || fail "kickoff wrote no PATH shim"
grep -q 'unshare -rn true' "$WRAPDIR/sb/bin/pi" || fail "the shim should skip the extra proxy when unshare cannot run"
# Something already listening on 3128 must survive two shim invocations.
HOLD_PID=""
( bash -c "exec 3<>/dev/tcp/127.0.0.1/3128" ) 2>/dev/null && fail "this test needs 3128 free to prove the shim does not bind it"
python3 - <<'PY' &
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# The backlog has to hold every probe this test makes. With listen(1) the
# wait-loop connection below fills the accept queue — nothing ever accepts it —
# and the final "is the holder still there" connect is refused, which read as
# "the shim stole the port". That was a flake, not a finding: 1 run in 3.
s.bind(("127.0.0.1", 3128)); s.listen(64)
time.sleep(30)
PY
HOLD_PID=$!
for _ in $(seq 1 50); do bash -c 'exec 3<>/dev/tcp/127.0.0.1/3128' 2>/dev/null && break; sleep 0.05; done
export HTTPS_PROXY="http://127.0.0.1:43178"
out1="$("$WRAPDIR/sb/bin/pi" --one 2>/dev/null)"
out2="$("$WRAPDIR/sb/bin/pi" --two 2>/dev/null)"
[[ "$out1" == "pi proxy=http://127.0.0.1:43178 args=--one" ]] || fail "proxy-only shim lost the sidecar URL: $out1"
[[ "$out2" == "pi proxy=http://127.0.0.1:43178 args=--two" ]] || fail "a second pane must keep the sidecar URL: $out2"
bash -c 'exec 3<>/dev/tcp/127.0.0.1/3128' 2>/dev/null || fail "the shim bound 3128 and knocked the holder off"
kill "$HOLD_PID" 2>/dev/null || true
wait "$HOLD_PID" 2>/dev/null || true
pass "proxy-only PATH shim keeps the sidecar URL and does not bind 3128"

echo "netguard.test.sh: all checks passed (mode=$MODE)"
