#!/usr/bin/env bash
# The base pack's own tests, run by tests/pack-local.test.sh: one regression test
# per fixed defect, each with a fixture built from the format's specification or
# a known-good sample, never from a parser's own output. A test that needs a
# program this host does not have builds a stand-in that records its arguments, or
# skips and says so. PACK_DIR points the same tests at another copy of the pack
# (the way a fix is shown to fail on the code before it).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PACK_DIR="${PACK_DIR:-$(cd "$HERE/.." && pwd)}"
export PYTHONDONTWRITEBYTECODE=1
fail() { echo "FAIL: $*" >&2; exit 1; }
command -v python3 >/dev/null || fail "python3 is required"

python3 -m py_compile "$PACK_DIR"/tools/*/run.py
echo "ok - every tool of the base pack compiles"

python3 "$HERE/run_tests.py" "$HERE"
