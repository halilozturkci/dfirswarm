# Sourced by scripts/reap.sh and scripts/idle-nudge.sh. Functions only.

# trace_emit <root> <sandbox> <json-line>: append one harness line to the run's
# trace, through the collector when it answers.
trace_emit() {
  local root="$1" sandbox="$2" line="$3"
  if ! printf '%s' "$line" | node "$root/scripts/trace-emit.mjs" "$sandbox" 2>/dev/null; then
    # Where the line goes depends on whether there is a chain to protect,
    # which is a property of the file and not of the collector's liveness: a
    # socket can exist and still be unreachable.
    #
    # An unchained record — no collector ran, and the kickoff and the report
    # both say so — takes the append, consistent with every other line in it.
    #
    # A chained one must not. Appending there puts an unchained line into a
    # chained record, and the verifier reports the file as "added by
    # something other than the harness": a corruption alarm the harness
    # raises against itself. The line is kept in the spill file instead,
    # which the report reads, so nothing is lost and nothing is falsified.
    if tail -n 1 "$sandbox/traces/events.jsonl" 2>/dev/null | grep -q '"prev":'; then
      mkdir -p "$sandbox/work"
      printf '%s\n' "$line" >> "$sandbox/work/.trace-spill.jsonl"
    else
      printf '%s\n' "$line" >> "$sandbox/traces/events.jsonl"
    fi
  fi
}
