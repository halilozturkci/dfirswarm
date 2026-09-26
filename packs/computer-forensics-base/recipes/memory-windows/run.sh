#!/usr/bin/env bash
# memory-windows: Volatility 3's first pass over one Windows memory image.
#
#   run.sh detect --target TARGET          exit 0 applies, 1 does not, 2 error
#   run.sh run --target TARGET --out DIR
#
# TARGET is JSON, inline or a file: {"paths": [...], "name": "inputs/x.mem"}.
# detect gates on the name (and file(1) when the name says nothing) before it
# asks Volatility, so a PDF or a pcap never costs a windows.info run, and
# gives offline windows.info RECIPE_PROBE_SECONDS (default 30). run writes
# windows.info.txt and one file per plugin, each step time-boxed
# (RECIPE_STEP_SECONDS, default 900) with its stderr kept whole beside it,
# plus index.tsv and coverage.json.
set -uo pipefail

have() { command -v "$1" >/dev/null 2>&1; }

target_field() {
  python3 - "$1" "$2" <<'PY'
import json, os, sys
arg, field = sys.argv[1], sys.argv[2]
t = json.load(open(arg, encoding="utf-8")) if os.path.isfile(arg) else json.loads(arg)
paths = t.get("paths") or []
print((paths[0] if paths else "") if field == "paths0" else (t.get("name") or (paths[0] if paths else "")))
PY
}

looks_like_memory() {
  local img="$1" name magic
  name="$(basename "$img" | tr 'A-Z' 'a-z')"
  case "$name" in
    *.pdf|*.pcap|*.pcapng|*.evtx|*.txt|*.json|*.csv|*.md|*.html|*.htm|*.xml|\
    *.jpg|*.jpeg|*.png|*.gif|*.zip|*.gz|*.xz|*.7z|*.tar|*.doc|*.docx|*.xls|*.xlsx|\
    *.ppt|*.pptx|*.mp3|*.mp4|*.wav|*.log|*.js|*.css|*.e01|*.ex01|*.vmdk|*.vhd|*.vhdx)
      return 1 ;;
    *.mem|*.dmp|*.vmem|*.raw|*.lime|*.crash|*.dump|*.core|hiberfil.sys|pagefile.sys)
      return 0 ;;
  esac
  if have file; then
    magic="$(file -b "$img" 2>/dev/null | tr 'A-Z' 'a-z')"
    case "$magic" in
      *crash*dump*|*hibernation*file*|*memory*dump*) return 0 ;;
    esac
  fi
  return 1
}

STEP_TIMEOUT="${RECIPE_STEP_SECONDS:-900}"
PROBE_TIMEOUT="${RECIPE_PROBE_SECONDS:-30}"
out=""
notes=()

run_step() { # run_step <limit> <outfile> <cmd...>
  local limit="$1" file="$2"; shift 2
  local rc=0
  perl -e 'alarm shift; exec @ARGV' "$limit" "$@" > "$file" 2> "$file.stderr" || rc=$?
  [[ -s "$file.stderr" ]] || rm -f "$file.stderr"
  if [[ "$rc" -eq 0 ]]; then echo ok; return 0; fi
  [[ -s "$file" ]] || rm -f "$file"
  local err=""
  if [[ -f "$file.stderr" ]]; then
    err="$(head -c 200 "$file.stderr" | tr '\n' ' ')"
    err="$err; all of stderr: ${file#"$out/"}.stderr"
  fi
  echo "failed (exit $rc${err:+: $err})"
}

index_row() { [[ -f "$out/$1" ]] && printf '%s\t%s\n' "$1" "$2" >> "$out/index.tsv"; return 0; }

coverage() {
  python3 - "$out/coverage.json" "$1" "$2" "${notes[@]+"${notes[@]}"}" <<'PY'
import json, sys
path, status, covered, *notes = sys.argv[1:]
json.dump({"recipe": "memory-windows", "status": status, "covered": covered,
           "not_covered": "every other Volatility plugin; YARA without supplied rules; non-Windows images; unsupported hibernation or crash-dump variants",
           "limits_hit": [note for note in notes if "exit 142" in note],
           "errors": notes}, open(path, "w"), indent=2)
PY
}

cmd="${1:-}"; shift || true
target=""
probe_out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) target="${2:-}"; shift 2 ;;
    --out) out="${2:-}"; shift 2 ;;
    --probe-out) probe_out="${2:-}"; shift 2 ;;
    *) echo '{"ok": false, "error": "unknown argument"}'; exit 2 ;;
  esac
done
[[ -n "$target" ]] || { echo '{"ok": false, "error": "--target is required"}'; exit 2; }
img="$(target_field "$target" paths0)"
shown="$(target_field "$target" name)"
[[ -n "$img" && -f "$img" ]] || { echo '{"ok": false, "error": "the target is not a readable file"}'; exit 2; }

case "$cmd" in
  detect)
    looks_like_memory "$img" || { echo '{"applies": false, "why": "not memory by its name or file(1)"}'; exit 1; }
    have vol || { echo '{"applies": false, "why": "looks like memory, but vol is not in this image"}'; exit 1; }
    # What vol says about a file it does not recognise is kept, when the
    # caller gives a place for it (--probe-out), not thrown away.
    if [[ -n "$probe_out" ]]; then mkdir -p "$probe_out"; probe="$probe_out/windows.info.txt"; else probe="$(mktemp)"; fi
    rc=0
    perl -e 'alarm shift; exec @ARGV' "$PROBE_TIMEOUT" vol --offline -vv -q -f "$img" windows.info > "$probe" 2> "$probe.stderr" || rc=$?
    [[ -s "$probe.stderr" ]] || rm -f "$probe.stderr"
    if [[ "$rc" -eq 0 ]] && grep -qi "NTBuildLab\|Kernel Base\|SystemTime" "$probe"; then
      rm -f "$probe" "$probe.stderr"; echo '{"applies": true, "why": "Volatility windows.info names a Windows image"}'; exit 0
    fi
    # Volatility can identify and stack a Windows layer before discovering
    # that the exact offline symbol table is absent. That is applicable-but-
    # blocked, not "not Windows"; keep both probe files for diagnosis.
    if [[ -f "$probe.stderr" ]] && grep -qi "DTB was found" "$probe.stderr" && \
       grep -qi "symbol_table_name" "$probe" "$probe.stderr" 2>/dev/null; then
      [[ -n "$probe_out" ]] || rm -f "$probe" "$probe.stderr"
      echo '{"applies": true, "why": "Volatility recognized Windows memory, but the matching offline symbol table is absent; run will fail until the image supplies it"}'; exit 0
    fi
    [[ -s "$probe" ]] || rm -f "$probe"
    [[ -n "$probe_out" ]] || rm -f "$probe" "$probe.stderr"
    if [[ "$rc" -eq 142 ]]; then
      echo "{\"applies\": false, \"why\": \"offered to Volatility as memory; windows.info did not answer within ${PROBE_TIMEOUT}s\"}"; exit 1
    fi
    echo '{"applies": false, "why": "offered to Volatility as memory; windows.info named no Windows memory image"}'; exit 1
    ;;
  run)
    [[ -n "$out" ]] || { echo '{"ok": false, "error": "run needs --out DIR"}'; exit 2; }
    mkdir -p "$out"; : > "$out/index.tsv"
    r="$(run_step "$STEP_TIMEOUT" "$out/windows.info.txt" vol --offline -q -f "$img" windows.info)"
    if [[ "$r" != ok ]] || ! grep -qi "NTBuildLab\|Kernel Base\|SystemTime" "$out/windows.info.txt" 2>/dev/null; then
      notes+=("vol windows.info on $shown: ${r/ok/ran but named no Windows image}")
      coverage failed "nothing"
      echo '{"ok": false, "status": "failed"}'
      exit 2
    fi
    index_row "windows.info.txt" "OS, build, capture time of $shown (vol windows.info)"
    for plugin in pslist psscan pstree cmdline netscan malfind vadinfo handles modules svcscan dlllist; do
      r="$(run_step "$STEP_TIMEOUT" "$out/$plugin.txt" vol --offline -q -f "$img" "windows.$plugin")"
      [[ "$r" == ok ]] || notes+=("vol windows.$plugin on $shown: $r")
      index_row "$plugin.txt" "vol windows.$plugin over $shown"
    done
    while IFS= read -r f; do
      rel="${f#"$out/"}"; index_row "$rel" "what the step writing ${rel%.stderr} said on stderr"
    done < <(find "$out" -type f -name '*.stderr' | sort)
    if [[ ${#notes[@]} -gt 0 ]]; then coverage partial "windows.info and the plugins that finished"; else coverage complete "windows.info and eleven plugins"; fi
    python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(json.dumps({"ok": True, "status": c["status"]}))' "$out/coverage.json"
    ;;
  *) echo '{"ok": false, "error": "usage: run.sh detect --target T | run --target T --out DIR"}'; exit 2 ;;
esac
