#!/usr/bin/env bash
# The local gate: what a change needs, run here as fast as this machine allows,
# with every result said.
#
#   scripts/test-gate.sh [--all] [--base REF] [--shards N] [--tier fast|deep|all]
#
# 1. the typecheck;
# 2. the node suites the change needs (scripts/test-select.ts against REF,
#    origin/main by default; --all for every suite), at this machine's own
#    concurrency, each file that fails run again alone (scripts/test-node.ts
#    --retry-alone);
# 3. the shell suites it needs, in N groups side by side (default: the cores
#    over four, at least one and at most four), each group a test-bash.sh of
#    its own with its own msb home and hub directory.
#
# Exit 0: all passed. Exit 3: all passed, but some node file only when run
# alone (named: a suite that fails under load is a finding, not a pass). Exit
# 1: something failed; its log is named. The logs stay in a directory it names.
# Every group it starts is waited for, and stopped if the gate is interrupted.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
ALL=0 BASE="origin/main" SHARDS="" TIER="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --all) ALL=1; shift ;;
    --base) BASE="${2:?--base needs a ref}"; shift 2 ;;
    --shards) SHARDS="${2:?--shards needs a number}"; shift 2 ;;
    --tier) TIER="${2:?--tier needs fast, deep or all}"; shift 2 ;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "test-gate: unknown option: $1" >&2; exit 2 ;;
  esac
done
cores="$( (getconf _NPROCESSORS_ONLN || sysctl -n hw.ncpu) 2>/dev/null || echo 4)"
if [[ -z "$SHARDS" ]]; then SHARDS=$(( cores / 4 )); (( SHARDS < 1 )) && SHARDS=1; (( SHARDS > 4 )) && SHARDS=4; fi
[[ "$SHARDS" =~ ^[1-9][0-9]*$ ]] || { echo "test-gate: --shards wants a number, got '$SHARDS'" >&2; exit 2; }

LOGS="$(mktemp -d "${TMPDIR:-/tmp}/test-gate.XXXXXX")"
PIDS=()
# Job control gives each background group a process group of its own, so an
# interrupted gate stops the suites a group started, not only its test-bash.
set -m
stop_groups() {
  local p
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill -TERM -- "-$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap 'stop_groups; echo "test-gate: interrupted; logs in $LOGS" >&2; exit 130' INT TERM
started=$SECONDS
echo "test-gate: $cores cores, $SHARDS shell group(s), logs in $LOGS"

echo "== typecheck"
if ! npm run --silent typecheck > "$LOGS/typecheck.log" 2>&1; then
  tail -20 "$LOGS/typecheck.log"; echo "test-gate: the typecheck failed ($LOGS/typecheck.log)" >&2; exit 1
fi

node_args=(--retry-alone "--tier=$TIER")
shell_all=1
if [[ $ALL -eq 0 ]]; then
  echo "== what the change against $BASE needs"
  if ! node --experimental-strip-types --no-warnings scripts/test-select.ts --base "$BASE" --node-out "$LOGS/node.list" --shell-out "$LOGS/shell.list" | tee "$LOGS/select.log"; then
    echo "test-gate: the selection failed" >&2; exit 2
  fi
  if ! grep -q 'everything$' <(head -1 "$LOGS/select.log"); then
    node_args+=("--files-from=$LOGS/node.list")
    shell_all=0
  fi
fi

echo "== node suites"
at=$SECONDS
node --experimental-strip-types --no-warnings scripts/test-node.ts "${node_args[@]}" --timings="$LOGS/node-timings.json" > "$LOGS/node.log" 2>&1
node_rc=$?
grep -aE '^# (tests|pass|fail|cancelled)|^test-node: |^  (passed alone|failed alone)' "$LOGS/node.log" | head -40
echo "node suites: exit $node_rc ($((SECONDS - at))s)"

echo "== shell suites"
at=$SECONDS
group_rc=()
if [[ $shell_all -eq 1 ]]; then
  for ((i = 1; i <= SHARDS; i++)); do
    bash scripts/test-bash.sh --shard "$i/$SHARDS" > "$LOGS/shell-$i.log" 2>&1 &
    PIDS+=($!)
  done
else
  mapfile_lines=()
  while IFS= read -r s; do [[ -n "$s" ]] && mapfile_lines+=("$s"); done < "$LOGS/shell.list"
  n=${#mapfile_lines[@]}
  (( n < SHARDS )) && SHARDS=$n
  for ((i = 1; i <= SHARDS; i++)); do
    group=()
    for ((k = i - 1; k < n; k += SHARDS)); do group+=("${mapfile_lines[$k]}"); done
    bash scripts/test-bash.sh "${group[@]}" > "$LOGS/shell-$i.log" 2>&1 &
    PIDS+=($!)
  done
fi
for p in ${PIDS[@]+"${PIDS[@]}"}; do wait "$p"; group_rc+=($?); done
PIDS=()
shell_failed=0
for ((i = 1; i <= ${#group_rc[@]}; i++)); do
  grep -aE '^=== FAIL |^shell suites: ' "$LOGS/shell-$i.log"
  [[ "${group_rc[$((i - 1))]}" -eq 0 ]] || shell_failed=1
done
[[ ${#group_rc[@]} -gt 0 ]] || echo "no shell suite to run"
echo "shell suites: $([[ $shell_failed -eq 0 ]] && echo passed || echo FAILED) ($((SECONDS - at))s)"

echo
echo "test-gate: $((SECONDS - started))s; logs in $LOGS"
if [[ $node_rc -ne 0 && $node_rc -ne 3 ]] || [[ $shell_failed -ne 0 ]]; then
  echo "test-gate: FAILED" >&2; exit 1
fi
if [[ $node_rc -eq 3 ]]; then
  echo "test-gate: passed, but only alone for the node files named above (load-sensitive)" >&2; exit 3
fi
echo "test-gate: passed"
