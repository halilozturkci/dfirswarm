#!/usr/bin/env bash
# scripts/image-acceptance.sh, the script the image-boot workflow runs inside a
# built image. On this host, with an image record and stand-in programs and
# tools made here:
#   - a program the record names that is not on PATH fails the run (the planted
#     missing program), unless the build was told it may lack it;
#   - a version that answers and does not contain the pinned one fails;
#   - a tool with no JSON answer, a crash or a hang past its timeout fails, and
#     one that answers "failed" on an empty file passes, its status recorded;
#   - the receipts are tables: program, version string, pin, tool, status.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/image-acceptance.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
S="$ROOT/scripts/image-acceptance.sh"

mkdir -p "$TMP/bin" "$TMP/etc" "$TMP/packs/p/tools"
printf '#!/bin/sh\necho "stand 2.3.4 (build 7)"\n' > "$TMP/bin/stand"
printf '#!/bin/sh\nexit 0\n' > "$TMP/bin/quiet"
chmod +x "$TMP/bin/stand" "$TMP/bin/quiet"
record() { # <binaries json> <extra json fields>
  printf '{"profile": "t", "arch": "amd64", "binaries": %s, "downloads": {"stand": {"version": "%s"}}%s}\n' "$1" "${PIN:-2.3.4}" "${2:-}" > "$TMP/etc/image.json"
}
accept() { DFIRSWARM_ETC_DIR="$TMP/etc" PATH="$TMP/bin:$PATH" sh "$S" "$@"; }
BIN='{"stand": "'"$TMP"'/bin/stand", "quiet": "'"$TMP"'/bin/quiet"}'

# --- programs -------------------------------------------------------------------
record "$BIN"
out="$(accept 2>&1)" || fail "an image whose programs are all there and at their pins failed: $out"
grep -q '^| stand | --version | stand 2.3.4 (build 7) | 2.3.4 | ok |$' <<<"$out" || fail "the receipt of a pinned program is not in the table: $out"
grep -q '^| quiet | - | - | - | on PATH, no version output |$' <<<"$out" || fail "a program with no version output is not said so: $out"

record '{"stand": "'"$TMP"'/bin/stand", "quiet": "'"$TMP"'/bin/quiet", "ghost": null}'
out="$(accept 2>&1)" && fail "an image whose record names ghost, which is not on PATH, passed: $out"
grep -q '^| ghost | - | - | - | MISSING |$' <<<"$out" && grep -q '^- ghost is named by this image and is not on PATH$' <<<"$out" || fail "the missing program is not named: $out"
# The planted one: a program the image does hold is removed from PATH.
record "$BIN"
out="$(DFIRSWARM_ETC_DIR="$TMP/etc" PATH="$TMP/nowhere:/usr/bin:/bin" sh "$S" 2>&1)" && fail "stand was removed from PATH and the run passed: $out"
grep -q '^- stand is named by this image and is not on PATH$' <<<"$out" || fail "the removed program is not named: $out"
record '{"stand": "'"$TMP"'/bin/stand", "ghost": null}' ', "missing_allowed": ["ghost"]'
out="$(accept 2>&1)" || fail "a program the build allowed to be missing failed the run: $out"
grep -q '^| ghost | - | - | - | missing, as the build allowed |$' <<<"$out" || fail "an allowed gap is not said: $out"

PIN=2.3.5 record "$BIN"
out="$(accept 2>&1)" && fail "a version that does not contain the pin passed: $out"
grep -q "^| stand | --version | stand 2.3.4 (build 7) | 2.3.5 | DIFFERS from the pin |$" <<<"$out" || fail "the differing receipt is not in the table: $out"
printf 'not json\n' > "$TMP/etc/image.json"
accept >/dev/null 2>&1 && fail "an unreadable record passed"
pass "a program missing from PATH or at another version than its pin fails the run, an allowed gap does not, and each program has its receipt"

# --- tools ----------------------------------------------------------------------
mk_tool() { # <name> <timeout> <script> [use names json]
  mkdir -p "$TMP/packs/p/tools/$1"
  printf '{"name": "%s", "params": {"path": {"type": "string", "description": "Path to the input"}}, "runtime": "python3", "entry": "run.py", "timeout_seconds": %s, "use": {"names": %s}}\n' \
    "$1" "$2" "${4:-[]}" > "$TMP/packs/p/tools/$1/manifest.json"
  printf '%s\n' "$3" > "$TMP/packs/p/tools/$1/run.py"
}
mk_tool answers 10 $'import json, sys, os\nargs = json.load(sys.stdin)\nsize = os.path.getsize(args["path"])\nprint(json.dumps({"status": "failed" if size == 0 else "complete", "size": size}))' '["x.pcap"]'
record "$BIN"
out="$(accept --packs "$TMP/packs/p" 2>&1)" || fail "a tool that answers JSON on an empty file failed the run: $out"
grep -q '^| p | answers | empty file | 0 | failed | ' <<<"$out" || fail "the empty-file receipt (status failed) is missing: $out"
grep -q '^| p | answers | pcap with no packet | 0 | complete | ' <<<"$out" || fail "the receipt on the smallest valid pcap is missing: $out"
mk_tool crashes 10 $'raise RuntimeError("boom")'
out="$(accept --packs "$TMP/packs/p" 2>&1)" && fail "a tool that crashed without JSON passed: $out"
grep -q '^- p/crashes (empty file) gave no JSON answer (exit 1)$' <<<"$out" || fail "the crashing tool is not named: $out"
rm -rf "$TMP/packs/p/tools/crashes"
mk_tool hangs 2 $'import time\ntime.sleep(60)'
out="$(timeout 60 bash -c 'DFIRSWARM_ETC_DIR="$1" PATH="$2:$PATH" sh "$3" --packs "$4"' _ "$TMP/etc" "$TMP/bin" "$S" "$TMP/packs/p" 2>&1)" && fail "a tool that ran past its timeout passed: $out"
grep -q '^- p/hangs (empty file) ran past its 2 s$' <<<"$out" || fail "the hanging tool is not named: $out"
rm -rf "$TMP/packs/p/tools/hangs"
pass "a tool run as a job runs it on an empty file and on the smallest valid one, its status recorded; no JSON, a crash or a hang fails the run"

echo "image-acceptance: all checks passed"
