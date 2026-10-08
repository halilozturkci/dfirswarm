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
# plus index.tsv, steps.jsonl (one record per step: the command, its exit, how
# long it took and what it wrote) and coverage.json, which a run writes as
# partial before its first step and again after each outcome.
#
# Volatility always runs with --offline: the symbol tables are the ones the
# image holds, and nothing is fetched. An image with no table for the
# kernel stops the run after windows.info, whose output is kept, with the
# kernel named as missing and coverage partial; no plugin that needs symbols
# is run.
#
# When the image holds no symbol table for the kernel, detect and run say so
# with a `missing` entry naming the kernel (PDB, GUID, age, as Volatility's
# automagic asked for it): the census writes it to catalog/missing.json and a
# kickoff stops on it unless --allow-missing-symbols; a generation's post
# says it. A probe that does not answer in time says that whether the image
# holds the table is unknown, the same way: the start does not go on blind.
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

# step_record <outfile> <exit> <seconds> <limit> <cmd...>: one line of
# steps.jsonl per step, written whatever the step's outcome was.
step_record() {
  python3 - "$out" "$@" <<'PY'
import json, os, sys
out, file, rc, seconds, limit, *argv = sys.argv[1:]
rel = os.path.relpath(file, out)
rec = {"step": rel, "argv": argv, "exit": int(rc), "seconds": int(seconds), "limit_seconds": int(limit),
       "timed_out": int(rc) == 142}
for key, path in (("output", file), ("stderr", file + ".stderr")):
    if os.path.isfile(path):
        rec[key] = {"file": os.path.relpath(path, out), "bytes": os.path.getsize(path)}
with open(os.path.join(out, "steps.jsonl"), "a", encoding="utf-8") as fh:
    fh.write(json.dumps(rec) + "\n")
PY
}

run_step() { # run_step <limit> <outfile> <cmd...>
  local limit="$1" file="$2"; shift 2
  local rc=0 began="$SECONDS"
  perl -e 'alarm shift; exec @ARGV' "$limit" "$@" > "$file" 2> "$file.stderr" || rc=$?
  [[ -s "$file.stderr" ]] || rm -f "$file.stderr"
  if [[ "$rc" -ne 0 ]]; then [[ -s "$file" ]] || rm -f "$file"; fi
  step_record "$file" "$rc" "$((SECONDS - began))" "$limit" "$@"
  if [[ "$rc" -eq 0 ]]; then echo ok; return 0; fi
  local err=""
  if [[ -f "$file.stderr" ]]; then
    err="$(head -c 200 "$file.stderr" | tr '\n' ' ')"
    err="$err; all of stderr: ${file#"$out/"}.stderr"
  fi
  echo "failed (exit $rc${err:+: $err})"
}

index_row() { [[ -f "$out/$1" ]] && printf '%s\t%s\n' "$1" "$2" >> "$out/index.tsv"; return 0; }

# kernel_missing <stdout> <stderr> <shown> [timeout seconds]: the `missing`
# list (JSON) for an image whose kernel table this image lacks, the kernel
# named from the symbol-server address Volatility asked for offline; with a
# timeout, that it is unknown whether the image holds it.
kernel_missing() {
  python3 - "$@" <<'PY'
import json, re, sys
out, err, shown = sys.argv[1:4]
timeout = sys.argv[4] if len(sys.argv) > 4 else ""
# What Volatility's automagic asked for is in its log. A log can be large, so it
# is read in blocks, up to a budget, with a carry so a name cut by a block's end
# is still found; the first match ends the search.
BUDGET = 16 * 1024 * 1024
BLOCK = 1 << 20
CARRY = 512
rx = re.compile(r"/download/symbols/([A-Za-z0-9_.-]+\.pdb)/([0-9A-Fa-f]{32})([0-9A-Fa-f]{1,8})/")
m, spent = None, 0
for f in (err, out):
    tail = ""
    try:
        with open(f, encoding="utf-8", errors="replace") as fh:
            while not m and spent <= BUDGET:
                block = fh.read(BLOCK)
                if not block:
                    break
                spent += len(block)
                text = tail + block
                m = rx.search(text)
                tail = text[-CARRY:]
    except OSError:
        pass
    if m or spent > BUDGET:
        break
if timeout:
    print(json.dumps([{"kind": "symbols", "what": f"vol --offline windows.info did not answer within {timeout}s on {shown}: whether this image holds the symbol table of its kernel is unknown, so what reads it may find nothing (raise RECIPE_PROBE_SECONDS, or SWARM_CATALOG_MEMORY_PROBE_TIMEOUT)"}]))
elif m:
    pdb, guid, age = m.group(1), m.group(2).upper(), int(m.group(3), 16)
    print(json.dumps([{"kind": "symbols", "identity": {"pdb": pdb, "guid": guid, "age": age},
                       "what": f"the symbol table of the Windows kernel {pdb} {guid} age {age}, which {shown} runs: this image does not hold it, so its Windows plugins cannot read it offline (what needs no kernel table still works: strings, YARA, carving)"}]))
else:
    print(json.dumps([{"kind": "symbols", "what": f"the symbol table of the Windows kernel {shown} runs: this image does not hold it, and the kernel's identity was not named" + (" (the log was read up to a budget of %d bytes)" % BUDGET if spent > BUDGET else "")}]))
PY
}

coverage() {
  python3 - "$out/coverage.json" "$1" "$2" "${missing_json:-[]}" "${notes[@]+"${notes[@]}"}" <<'PY'
import json, os, sys
path, status, covered, missing, *notes = sys.argv[1:]
steps = []
try:
    with open(os.path.join(os.path.dirname(path), "steps.jsonl"), encoding="utf-8") as fh:
        steps = [json.loads(line) for line in fh if line.strip()]
except OSError:
    pass
json.dump({"recipe": "memory-windows", "status": status, "covered": covered,
           "not_covered": "every other Volatility plugin; YARA without supplied rules; non-Windows images; unsupported hibernation or crash-dump variants",
           "missing": json.loads(missing),
           "limits_hit": [note for note in notes if "exit 142" in note],
           "errors": notes,
           "steps": steps}, open(path, "w"), indent=2)
PY
}

cmd="${1:-}"; shift || true
target=""
probe_out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target|--out|--probe-out)
      # A flag with no value is an error, not a loop: `shift 2` with one word left shifts nothing.
      [[ $# -ge 2 ]] || { echo "{\"ok\": false, \"error\": \"$1 needs a value\"}"; exit 2; }
      case "$1" in --target) target="$2" ;; --out) out="$2" ;; --probe-out) probe_out="$2" ;; esac
      shift 2 ;;
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
    if { [[ -f "$probe.stderr" ]] && grep -qi "DTB was found" "$probe.stderr" && grep -qi "symbol_table_name" "$probe" "$probe.stderr" 2>/dev/null; } || \
       grep -qs '/download/symbols/.*\.pdb/' "$probe.stderr"; then
      miss="$(kernel_missing "$probe" "$probe.stderr" "$shown")"
      [[ -n "$probe_out" ]] || rm -f "$probe" "$probe.stderr"
      python3 -c 'import json, sys; print(json.dumps({"applies": True, "why": "Volatility recognized Windows memory, but the matching offline symbol table is absent; run will fail until the image supplies it", "missing": json.loads(sys.argv[1])}))' "$miss"
      exit 0
    fi
    if [[ "$rc" -eq 142 ]]; then
      # Not a pass: whether the image holds the kernel's table is unknown,
      # and the start says so rather than going on blind.
      miss="$(kernel_missing "$probe" "$probe.stderr" "$shown" "$PROBE_TIMEOUT")"
      [[ -s "$probe" ]] || rm -f "$probe"
      [[ -n "$probe_out" ]] || rm -f "$probe" "$probe.stderr"
      python3 -c 'import json, sys; print(json.dumps({"applies": False, "why": "offered to Volatility as memory; windows.info did not answer within %ss" % sys.argv[2], "missing": json.loads(sys.argv[1])}))' "$miss" "$PROBE_TIMEOUT"
      exit 1
    fi
    [[ -s "$probe" ]] || rm -f "$probe"
    [[ -n "$probe_out" ]] || rm -f "$probe" "$probe.stderr"
    echo '{"applies": false, "why": "offered to Volatility as memory; windows.info named no Windows memory image"}'; exit 1
    ;;
  run)
    [[ -n "$out" ]] || { echo '{"ok": false, "error": "run needs --out DIR"}'; exit 2; }
    mkdir -p "$out"; : > "$out/index.tsv"; : > "$out/steps.jsonl"
    # Said before the first step, so a run stopped anywhere leaves a coverage
    # file that says it did not finish.
    coverage partial "started; no step has finished (the run stopped before its end)"
    # Volatility reads the symbol tables the image holds, and fetches nothing:
    # every step runs with --offline. An image with no table for its kernel stops
    # the run after windows.info, whose output is kept, with the kernel named.
    symbols="held in the image"
    VOLNET=(--offline)
    r="$(run_step "$STEP_TIMEOUT" "$out/windows.info.txt" vol --offline -q -f "$img" windows.info)"
    index_row "windows.info.txt" "OS, build, capture time of $shown (vol --offline windows.info)"
    index_row "windows.info.txt.stderr" "what vol --offline windows.info said on stderr"
    index_row "steps.jsonl" "one record per step: the command, its exit, how long it took and what it wrote"
    if [[ "$r" != ok ]] || ! grep -qi "NTBuildLab\|Kernel Base\|SystemTime" "$out/windows.info.txt" 2>/dev/null; then
      if grep -qi "symbol" "$out/windows.info.txt" "$out/windows.info.txt.stderr" 2>/dev/null; then
        # The image lacks the table: said in coverage (missing), and no plugin that
        # reads kernel structures is run, since none would find them.
        missing_json="$(kernel_missing "$out/windows.info.txt" "$out/windows.info.txt.stderr" "$shown")"
        notes+=("vol --offline windows.info on $shown: no symbol table for this kernel in the image; it was not fetched, and the plugins that need it were not run")
        coverage partial "windows.info was attempted offline; no symbol table for this kernel in the image, so no Windows plugin was run"
        python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(json.dumps({"ok": True, "status": c["status"], "missing": c["missing"]}))' "$out/coverage.json"
        exit 0
      fi
      if [[ "$r" == ok ]]; then why="ran but named no Windows image"; else why="$r"; fi
      notes+=("vol windows.info on $shown: $why")
      coverage failed "nothing"
      echo '{"ok": false, "status": "failed"}'
      exit 2
    fi
    finished=0
    coverage partial "windows.info finished; no plugin has yet (this file is rewritten after each step, so a run stopped part way says how far it got)"
    for plugin in pslist psscan pstree cmdline netscan malfind vadinfo handles modules svcscan dlllist; do
      r="$(run_step "$STEP_TIMEOUT" "$out/$plugin.txt" vol ${VOLNET[@]+"${VOLNET[@]}"} -q -f "$img" "windows.$plugin")"
      [[ "$r" == ok ]] || notes+=("vol windows.$plugin on $shown: $r")
      index_row "$plugin.txt" "vol windows.$plugin over $shown"
      finished=$((finished + 1))
      coverage partial "windows.info and $finished of eleven plugins have finished; the run did not reach its end (this file is rewritten after each step)"
    done
    while IFS= read -r f; do
      rel="${f#"$out/"}"; [[ "$rel" == windows.info.txt.stderr ]] || index_row "$rel" "what the step writing ${rel%.stderr} said on stderr"
    done < <(find "$out" -type f -name '*.stderr' | sort)
    if [[ ${#notes[@]} -gt 0 ]]; then coverage partial "windows.info and the plugins that finished; symbols $symbols"; else coverage complete "windows.info and eleven plugins; symbols $symbols"; fi
    python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(json.dumps({"ok": True, "status": c["status"]}))' "$out/coverage.json"
    ;;
  *) echo '{"ok": false, "error": "usage: run.sh detect --target T | run --target T --out DIR"}'; exit 2 ;;
esac
