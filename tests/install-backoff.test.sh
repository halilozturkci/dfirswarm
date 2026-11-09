#!/usr/bin/env bash
# The image build's download backs off before a retry and does not retry a
# 4xx. A local HTTP server on 127.0.0.1 (a free port, stopped by its own pid)
# answers per path: 503 and then 200, 404 always, 500 always, 429 always, a
# first request that stalls past the read timeout and then 200. The waits are
# shortened through DFIRSWARM_FETCH_BACKOFF (the default is 10,30) and the
# read timeout through DFIRSWARM_FETCH_TIMEOUT.
#
# What must hold:
#   - a 503 and then a 200 is one retry after the first wait, then success;
#   - a 404 and a 429 (4xx) are one attempt and a named failure;
#   - a 500 three times waits the first and then the second wait, and fails
#     naming the status;
#   - a stalled first request is a timeout, is retried and succeeds;
#   - the build's message names each attempt's cause and wait.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/install-backoff.XXXXXX")"
SERVER_PID=""
cleanup() {
  [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

cat > "$TMP/server.py" <<'PY'
import json, os, socketserver, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"hello world\n"
LOG, PORTFILE = sys.argv[1], sys.argv[2]
seen = {}
lock = threading.Lock()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        with lock:
            n = seen[self.path] = seen.get(self.path, 0) + 1
            with open(LOG, "a") as f:
                f.write(json.dumps({"path": self.path, "n": n, "t": time.monotonic()}) + "\n")
        name = self.path.strip("/")
        status = 200
        if name == "flaky503" and n == 1:
            status = 503
        elif name == "missing":
            status = 404
        elif name == "toomany":
            status = 429
        elif name == "broken500":
            status = 500
        elif name == "stall" and n == 1:
            time.sleep(4)  # past the client's read timeout; the client has gone by then
            return
        if status != 200:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)


class S(ThreadingHTTPServer):
    # HTTPServer.server_bind asks socket.getfqdn for the server's name, a reverse DNS lookup that
    # can take many seconds on a CI host; nothing here uses the name.
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]


srv = S(("127.0.0.1", 0), H)
with open(PORTFILE + ".tmp", "w") as f:
    f.write(str(srv.server_address[1]))
os.rename(PORTFILE + ".tmp", PORTFILE)
srv.serve_forever()
PY
python3 "$TMP/server.py" "$TMP/hits.jsonl" "$TMP/port" >/dev/null 2>"$TMP/server.err" &
SERVER_PID=$!
for _ in $(seq 1 300); do [[ -s "$TMP/port" ]] && break; kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.1; done
[[ -s "$TMP/port" ]] || fail "the stand-in server did not start (alive: $(kill -0 "$SERVER_PID" 2>/dev/null && echo yes || echo no)): $(head -c 600 "$TMP/server.err")"
PORT="$(cat "$TMP/port")"
WANT="$(printf 'hello world\n' | sha256sum | cut -d' ' -f1)"

# One obtain() of a path: prints its result and the build's own lines.
get() { # <path>
  DFIRSWARM_FETCH_BACKOFF="1,2" DFIRSWARM_FETCH_TIMEOUT=1 DFIRSWARM_DATA_DIR="" python3 -I - "$ROOT/images/install.py" "http://127.0.0.1:$PORT$1" "$TMP/out$1" "$WANT" <<'PY'
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("install", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
dest = Path(sys.argv[3])
dest.parent.mkdir(parents=True, exist_ok=True)
why, how = m.obtain(sys.argv[2], dest, sys.argv[4], 12)
print(f"RESULT {why!r} {how}")
PY
}
hits() { grep -c "\"path\": \"$1\"" "$TMP/hits.jsonl" 2>/dev/null || true; }
gap() { # <path> <from n> <to n>: seconds between two requests of a path
  jq -s --arg p "$1" --argjson a "$2" --argjson b "$3" '[.[] | select(.path == $p)] | ((.[$b - 1].t) - (.[$a - 1].t))' "$TMP/hits.jsonl"
}
ge() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a >= b) }'; }

echo "# a 503 and then a 200: one retry after the first wait"
out="$(get /flaky503)" || fail "the flaky download crashed: $out"
grep -q "^RESULT None download" <<<"$out" || fail "a 503 and then a 200 did not succeed: $out"
[[ "$(hits /flaky503)" == 2 ]] || fail "the flaky path was asked $(hits /flaky503) times, not twice"
ge "$(gap /flaky503 1 2)" 0.95 || fail "the retry came after $(gap /flaky503 1 2) s, not after the 1 s wait"
grep -q "attempt 1 of 3 failed: HTTP 503.*server error.*waiting 1 s before attempt 2" <<<"$out" || fail "the build did not name the cause and the wait: $out"
pass "a 503 is retried once, after the shortened back-off, and the build names the cause and the wait"

echo "# a 404 and a 429 are the server's answer: one attempt, a named failure"
for p in missing toomany; do
  code=404; [[ "$p" == toomany ]] && code=429
  out="$(get "/$p")" || fail "the $p download crashed: $out"
  grep -q "^RESULT .download failed: HTTP $code" <<<"$out" || fail "a $code was not a named failure: $out"
  [[ "$(hits "/$p")" == 1 ]] || fail "a $code was asked $(hits "/$p") times"
  grep -q "waiting" <<<"$out" && fail "a $code waited for a retry: $out"
done
pass "a 4xx is asked once and fails naming its status"

echo "# a 500 three times: the first wait, then the second, then the failure"
out="$(get /broken500)" || fail "the broken download crashed: $out"
grep -q "^RESULT .download failed: HTTP 500" <<<"$out" || fail "three 500s did not end in a named failure: $out"
[[ "$(hits /broken500)" == 3 ]] || fail "three 500s were asked $(hits /broken500) times"
ge "$(gap /broken500 1 2)" 0.95 || fail "the second attempt came after $(gap /broken500 1 2) s, not the 1 s wait"
ge "$(gap /broken500 2 3)" 1.95 || fail "the third attempt came after $(gap /broken500 2 3) s, not the 2 s wait"
grep -q "waiting 2 s before attempt 3" <<<"$out" || fail "the second wait is not named: $out"
pass "a 5xx waits the first and then the second back-off, and the third failure is named"

echo "# a stalled server is a timeout and is retried"
out="$(get /stall)" || fail "the stalled download crashed: $out"
grep -q "^RESULT None download" <<<"$out" || fail "a stalled first request and then a 200 did not succeed: $out"
[[ "$(hits /stall)" == 2 ]] || fail "the stalled path was asked $(hits /stall) times, not twice"
grep -q "attempt 1 of 3 failed: timed out" <<<"$out" || fail "the timeout is not named: $out"
pass "a timeout is retried after the back-off"

echo "install-backoff: all checks passed"
