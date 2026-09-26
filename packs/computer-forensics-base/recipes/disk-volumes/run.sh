#!/usr/bin/env bash
# disk-volumes: The Sleuth Kit's first pass over one disk image.
#
#   run.sh detect --target TARGET          exit 0 applies, 1 does not, 2 error
#   run.sh run --target TARGET --out DIR
#
# TARGET is JSON, inline or a file: {"paths": [...], "name": "inputs/x.E01"};
# the image is paths[0] (a segment set's first segment: libewf reads the rest).
# With a partition table (`mmls`): partitions.txt and, per filesystem
# partition, p<start>/{fsstat.txt, bodyfile.txt, filelist.txt, timeline.csv}.
# With none but a filesystem at sector 0 (`fsstat`): the same under p0. Each
# step is time-boxed (RECIPE_STEP_SECONDS, default 900) and keeps what it wrote
# to stderr whole beside its output as <file>.stderr. index.tsv lists what was
# written (file, what) and coverage.json what was and was not covered.
set -uo pipefail

have() { command -v "$1" >/dev/null 2>&1; }

target_field() { # target_field <json or file> <paths0|name>
  python3 - "$1" "$2" <<'PY'
import json, os, sys
arg, field = sys.argv[1], sys.argv[2]
t = json.load(open(arg, encoding="utf-8")) if os.path.isfile(arg) else json.loads(arg)
paths = t.get("paths") or []
if field == "paths0":
    print(paths[0] if paths else "")
else:
    print(t.get("name") or (paths[0] if paths else ""))
PY
}

# mmls prints start sectors zero-padded; sector 0 must stay 0.
mmls_start_sector() {
  local n
  n="$(printf '%s' "$1" | awk '{print $3}' | sed 's/^0*//')"
  printf '%s\n' "${n:-0}"
}

STEP_TIMEOUT="${RECIPE_STEP_SECONDS:-900}"
out=""
notes=()

# Run a command with a deadline; stdout to a file, stderr whole beside it as
# <file>.stderr when there is any. Prints "ok" or a reason naming that file.
run_step() { # run_step <outfile> <cmd...>
  local file="$1"; shift
  local rc=0
  perl -e 'alarm shift; exec @ARGV' "$STEP_TIMEOUT" "$@" > "$file" 2> "$file.stderr" || rc=$?
  [[ -s "$file.stderr" ]] || rm -f "$file.stderr"
  if [[ "$rc" -eq 0 ]]; then
    echo ok
    return 0
  fi
  [[ -s "$file" ]] || rm -f "$file"
  local err=""
  if [[ -f "$file.stderr" ]]; then
    err="$(head -c 200 "$file.stderr" | tr '\n' ' ')"
    err="$err; all of stderr: ${file#"$out/"}.stderr"
  fi
  echo "failed (exit $rc${err:+: $err})"
}

index_row() { # index_row <file relative to out> <what>
  [[ -f "$out/$1" ]] || return 0
  printf '%s\t%s\n' "$1" "$2" >> "$out/index.tsv"
}

volume() { # volume <img> <shown name> <start> <description>
  local img="$1" shown="$2" start="$3" desc="$4" pdir r
  pdir="$out/p$start"
  mkdir -p "$pdir"
  candidate_volumes=$((candidate_volumes + 1))
  if ! have fsstat; then
    notes+=("fsstat missing: cannot establish whether the candidate at sector $start is a readable filesystem")
    return
  fi
  r="$(run_step "$pdir/fsstat.txt" fsstat -o "$start" "$img")"
  if [[ "$r" != ok ]]; then
    notes+=("candidate partition at sector $start is not a readable filesystem: $r")
    index_row "p$start/fsstat.txt" "fsstat output for unreadable candidate at sector $start ($desc)"
    # Keep the historical best-effort fls probes as diagnostics. They do not
    # make the candidate a readable volume, even if they leave partial output.
    if have fls; then
      r="$(run_step "$pdir/bodyfile.txt" fls -m / -r -o "$start" "$img")"
      [[ "$r" == ok ]] || notes+=("fls body file at sector $start: $r")
      index_row "p$start/bodyfile.txt" "diagnostic body-file probe for unreadable candidate at sector $start"
      r="$(run_step "$pdir/filelist.txt" fls -r -p -o "$start" "$img")"
      [[ "$r" == ok ]] || notes+=("fls path list at sector $start: $r")
      index_row "p$start/filelist.txt" "diagnostic path-list probe for unreadable candidate at sector $start"
    fi
    return
  fi
  volumes=$((volumes + 1))
  index_row "p$start/fsstat.txt" "filesystem header at sector $start ($desc)"
  if have fls; then
    r="$(run_step "$pdir/bodyfile.txt" fls -m / -r -o "$start" "$img")"
    [[ "$r" == ok ]] || notes+=("fls body file at sector $start: $r")
    index_row "p$start/bodyfile.txt" "body file (fls -m -r), every file with MAC times, for mactime/grep"
    r="$(run_step "$pdir/filelist.txt" fls -r -p -o "$start" "$img")"
    [[ "$r" == ok ]] || notes+=("fls path list at sector $start: $r")
    index_row "p$start/filelist.txt" "path list (fls -r -p): inode, type and full path per line; icat -o $start $shown <inode>"
  else
    notes+=("fls missing: no body file or path list for $shown")
  fi
  if have mactime && [[ -s "$pdir/bodyfile.txt" ]]; then
    r="$(run_step "$pdir/timeline.csv" mactime -b "$pdir/bodyfile.txt" -d -y)"
    [[ "$r" == ok ]] || notes+=("mactime at sector $start: $r")
    index_row "p$start/timeline.csv" "MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC"
  fi
}

coverage() { # coverage <status> <covered> — notes become errors
  python3 - "$out/coverage.json" "$1" "$2" "${notes[@]+"${notes[@]}"}" <<'PY'
import json, sys
path, status, covered, *notes = sys.argv[1:]
json.dump({"recipe": "disk-volumes", "status": status, "covered": covered,
           "not_covered": "file contents, carving, encrypted volumes, volume shadow copies",
           "limits_hit": [], "errors": notes}, open(path, "w"), indent=2)
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
    if have mmls && mmls "$img" >/dev/null 2>&1; then
      echo '{"applies": true, "why": "a partition table (mmls)"}'; exit 0
    fi
    if have fsstat && fsstat "$img" 2>/dev/null | grep -q '^File System Type:'; then
      echo '{"applies": true, "why": "a filesystem at sector 0 (fsstat)"}'; exit 0
    fi
    # A volume carved or copied out of a disk can keep the disk's offset
    # with no table before it (Ali Hadi #10's recovered Kali prefix: ext4
    # at sector 2048). The two usual starts are tried.
    for o in 63 2048; do
      if have fsstat && fsstat -o "$o" "$img" 2>/dev/null | grep -q '^File System Type:'; then
        echo "{\"applies\": true, \"why\": \"a filesystem at sector $o with no partition table (fsstat -o $o)\"}"; exit 0
      fi
    done
    if ! have mmls && ! have fsstat; then
      echo '{"applies": false, "why": "mmls and fsstat are not in this image"}'; exit 1
    fi
    echo '{"applies": false, "why": "no partition table and no filesystem at sector 0, 63 or 2048"}'; exit 1
    ;;
  run)
    [[ -n "$out" ]] || { echo '{"ok": false, "error": "run needs --out DIR"}'; exit 2; }
    mkdir -p "$out"
    : > "$out/index.tsv"
    volumes=0
    candidate_volumes=0
    if have mmls && mmls "$img" > "$out/partitions.txt" 2> "$out/partitions.txt.stderr"; then
      [[ -s "$out/partitions.txt.stderr" ]] || rm -f "$out/partitions.txt.stderr"
      index_row "partitions.txt" "partition table of $shown (mmls)"
      while IFS= read -r line; do
        start="$(mmls_start_sector "$line")"
        desc="$(printf '%s' "$line" | awk '{ $1=$2=$3=$4=$5=""; print }' | sed 's/^ *//')"
        case "$desc" in *NTFS*|*FAT*|*exFAT*|*Ext*|*HFS*|*APFS*|*Linux*|*Basic*data*) ;; *) continue ;; esac
        volume "$img" "$shown" "$start" "$desc"
      done < <(grep -E '^[0-9]+:' "$out/partitions.txt")
      if [[ "$volumes" -eq 0 ]]; then
        coverage partial "a partition table and $candidate_volumes candidate partition(s), but no readable filesystem"
      elif [[ ${#notes[@]} -gt 0 ]]; then
        coverage partial "partition table and $volumes readable filesystem(s) from $candidate_volumes candidate partition(s), with steps that did not finish"
      else
        coverage complete "partition table and $volumes readable filesystem(s) from $candidate_volumes candidate partition(s)"
      fi
    else
      rm -f "$out/partitions.txt" "$out/partitions.txt.stderr"
      if have fsstat && fsstat "$img" > "$out/.fsstat.tmp" 2>/dev/null && grep -q '^File System Type:' "$out/.fsstat.tmp"; then
        fstype="$(sed -n 's/^File System Type: *//p' "$out/.fsstat.tmp" | head -1)"
        rm -f "$out/.fsstat.tmp"
        printf 'No partition table: %s is one %s volume starting at sector 0 (use the tools without -o).\n' "$shown" "$fstype" > "$out/partitions.txt"
        index_row "partitions.txt" "no partition table: $shown is a single $fstype volume"
        volume "$img" "$shown" 0 "$fstype (logical volume, no partition table)"
        if [[ ${#notes[@]} -gt 0 ]]; then
          coverage partial "single $fstype volume, with steps that did not finish"
        else
          coverage complete "single $fstype volume"
        fi
      else
        rm -f "$out/.fsstat.tmp"
        at=""
        for o in 63 2048; do
          if have fsstat && fsstat -o "$o" "$img" > "$out/.fsstat.tmp" 2>/dev/null && grep -q '^File System Type:' "$out/.fsstat.tmp"; then at="$o"; break; fi
        done
        if [[ -n "$at" ]]; then
          fstype="$(sed -n 's/^File System Type: *//p' "$out/.fsstat.tmp" | head -1)"
          rm -f "$out/.fsstat.tmp"
          printf 'No partition table: %s holds one %s volume starting at sector %s (use the tools with -o %s).\n' "$shown" "$fstype" "$at" "$at" > "$out/partitions.txt"
          index_row "partitions.txt" "no partition table: $shown holds one $fstype volume at sector $at"
          volume "$img" "$shown" "$at" "$fstype (no partition table, at sector $at)"
          if [[ ${#notes[@]} -gt 0 ]]; then
            coverage partial "one $fstype volume at sector $at, with steps that did not finish"
          else
            coverage complete "one $fstype volume at sector $at"
          fi
        else
          rm -f "$out/.fsstat.tmp"
          notes+=("no partition table (mmls), and no filesystem at sector 0, 63 or 2048 (fsstat)")
          coverage unsupported "nothing"
          echo '{"ok": false, "status": "unsupported"}'
          exit 2
        fi
      fi
    fi
    # What every step wrote to stderr, listed beside its output.
    while IFS= read -r f; do
      rel="${f#"$out/"}"
      index_row "$rel" "what the step writing ${rel%.stderr} said on stderr"
    done < <(find "$out" -type f -name '*.stderr' | sort)
    python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(json.dumps({"ok": True, "status": c["status"], "volumes": int(sys.argv[2]), "candidate_volumes": int(sys.argv[3])}))' "$out/coverage.json" "$volumes" "$candidate_volumes"
    ;;
  *)
    echo '{"ok": false, "error": "usage: run.sh detect --target T | run --target T --out DIR"}'
    exit 2
    ;;
esac
