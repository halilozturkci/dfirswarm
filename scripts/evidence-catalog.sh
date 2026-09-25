#!/usr/bin/env bash
# evidence-catalog: the standard first pass over forensic inputs, once, before
# the agents start, into <sandbox>/catalog/ (harness-owned, read-only).
#
#   scripts/evidence-catalog.sh <sandbox>
#
# For every file under inputs/ that looks like a disk image: with a partition
# table (`mmls`) partitions.txt and, per filesystem partition, the filesystem
# header, a body file (`fls -m -r`), a path list (`fls -r -p`) and a mactime
# timeline (CSV); a logical volume image with no partition table (`fsstat`
# reads it at sector 0: FTK "logical" E01s, many course images) gets the same
# under p0. For every file that looks like a memory image
# (Volatility's windows.info succeeds): info, pslist, psscan, cmdline, netscan,
# malfind, dlllist. Each step is time-boxed; a tool that is missing or fails
# leaves a note in the index instead of stopping the kickoff, and what it wrote
# to stderr stays whole beside its output as <file>.stderr. Every input gets a
# row in catalog/coverage.tsv — catalogued, partial, a segment of a set, not
# catalogued, or not probed — with the reason, so an input this pass could not
# read is named rather than missing. The index, catalog/README.md, lists every
# catalog file with its row count and size and what was not catalogued, and
# swarm.sh copies it into SWARM.md.
set -uo pipefail

sandbox="${1:-}"
# The files the catalog considers: every regular file under inputs/, in one
# order. -L matters: under --inputs-bind, inputs/ is a symlink to the operator's
# directory, and find without it stops at the link and catalogs nothing (run
# s3091: 0 images over a 25 GB disk and a 1 GB dump). The copy dereferences
# symlinks too (cp -RL), so following them here reads the same tree either way.
catalog_candidates() { find -L "$1/inputs" -type f | sort; }
# `--candidates <sandbox>` prints that list and stops: what a test can hold still.
if [[ "${1:-}" == "--candidates" ]]; then
  [[ -n "${2:-}" && -d "$2/inputs" ]] || { echo "evidence-catalog: --candidates needs a sandbox with inputs/" >&2; exit 2; }
  catalog_candidates "$2"
  exit 0
fi
[[ -n "$sandbox" && -d "$sandbox/inputs" ]] || { echo "evidence-catalog: usage: evidence-catalog.sh <sandbox> (needs inputs/)" >&2; exit 2; }
out="$sandbox/catalog"
# Emptied, not removed: in a VM catalog/ is a mount of its own, the one
# writable place in an otherwise read-only run, and a mount point cannot
# be removed from inside.
mkdir -p "$out"
find "$out" -mindepth 1 -delete 2>/dev/null || true
STEP_TIMEOUT="${SWARM_CATALOG_STEP_TIMEOUT:-900}"
index=()
notes=()
coverage=()

# Run a command with a deadline; stdout to a file, and stderr, when there is
# any, whole beside it as <file>.stderr. Prints "ok" or a reason: a failure
# quotes the start of stderr and names the file that holds all of it.
run_step() { # run_step <outfile> <cmd...>
  local file="$1"; shift
  local limit="${RUN_STEP_TIMEOUT:-$STEP_TIMEOUT}"
  local rc=0
  perl -e 'alarm shift; exec @ARGV' "$limit" "$@" > "$file" 2> "$file.stderr" || rc=$?
  [[ -s "$file.stderr" ]] || rm -f "$file.stderr"
  if [[ "$rc" -eq 0 ]]; then
    echo ok
    return 0
  fi
  [[ -s "$file" ]] || rm -f "$file"
  local err=""
  if [[ -f "$file.stderr" ]]; then
    err="$(head -c 200 "$file.stderr" | tr '\n' ' ')"
    err="$err; all of stderr: catalog/${file#"$out/"}.stderr"
  fi
  echo "failed (exit $rc${err:+: $err})"
}

# One field of coverage.tsv: a tab, newline or backslash in a file name is
# written escaped (\t, \n, \\), so every input stays one row of four fields.
tsv_field() {
  local s="${1//\\/\\\\}"
  s="${s//$'\t'/\\t}"
  printf '%s' "${s//$'\n'/\\n}"
}

cover() { # cover <rel> <bytes> <status> <why>
  coverage+=("$(tsv_field "$1")"$'\t'"$2"$'\t'"$3"$'\t'"$(tsv_field "$4")")
}

human() { # bytes -> human
  awk -v b="$1" 'BEGIN {
    if (b >= 1073741824) printf "%.1f GB", b / 1073741824;
    else if (b >= 1048576) printf "%.1f MB", b / 1048576;
    else if (b >= 1024) printf "%.1f KB", b / 1024;
    else printf "%d B", b }'
}

add_index() { # add_index <relpath> <what>
  local rel="$1" what="$2" abs="$out/$1"
  [[ -f "$abs" ]] || return 0
  local rows bytes
  rows="$(wc -l < "$abs" | tr -d ' ')"
  bytes="$(stat -c %s "$abs" 2>/dev/null || stat -f %z "$abs")"
  index+=("| \`catalog/$rel\` | $what | $rows | $(human "$bytes") |")
}

have() { command -v "$1" >/dev/null 2>&1; }

# mmls prints start sectors zero-padded. Stripping the zeros of sector 0
# used to leave an empty string, and that partition was skipped.
mmls_start_sector() {
  local n
  n="$(printf '%s' "$1" | awk '{print $3}' | sed 's/^0*//')"
  printf '%s\n' "${n:-0}"
}

# Two inputs can share a basename (node1/sda.E01 and node2/sda.E01). A slug
# from basename alone would write both into the same catalog/ tree.
catalog_slug() { # path relative to inputs/
  printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'
}

# A segmented image is one image. libewf, and The Sleuth Kit through it,
# resolve a whole set from any one segment, so cataloguing `.E02` produces the
# same partition table, body file and timeline as `.E01` — on the BelkaCTF #6
# case that was six identical catalogues of one 8.7 GB disk, and six times the
# minutes. Only the first segment is catalogued; the rest are counted and
# named in the index, so nobody reads the gap as a skipped file.
#
# EWF counts `.E01 .E02 … .E99 .EAA .EAB …` (and `.Ex01` for EnCase 7, and
# lower case for both); split raw counts `.001 .002 …`. The first segment of
# each is the one that is *not* a continuation.
is_continuation_segment() { # <absolute path>
  local path="$1" dir base stem ext first
  dir="$(dirname "$path")"
  base="$(basename "$path")"
  case "$base" in
    *.[Ee][0-9][0-9]|*.[Ee][A-Za-z][A-Za-z]|*.[Ee][Xx][0-9][0-9]|*.[Ss][0-9][0-9]|*.[0-9][0-9][0-9])
      stem="${base%.*}"
      ext="${base##*.}"
      ;;
    *) return 1 ;;
  esac
  # The first segment of a set never counts as a continuation of it.
  case "$ext" in
    E01|e01|Ex01|ex01|EX01|S01|s01|001) return 1 ;;
  esac
  # A continuation only when the set's first segment is actually there; a lone
  # `.002` with no `.001` beside it is a file in its own right.
  for first in "$stem.E01" "$stem.e01" "$stem.Ex01" "$stem.ex01" "$stem.EX01" "$stem.S01" "$stem.s01" "$stem.001"; do
    [[ -f "$dir/$first" ]] && { printf '%s\n' "$first"; return 0; }
  done
  return 1
}

# Leftovers after mmls/fsstat are not all memory images. A PDF, pcap or EVTX
# used to take SWARM_CATALOG_STEP_TIMEOUT (default 900s) of vol windows.info
# each, or a "vol missing" note per file. Gate on name (and file(1) when the
# name is silent) before starting that loop.
is_memory_image() {
  local img="$1" name magic
  name="$(basename "$img" | tr 'A-Z' 'a-z')"
  case "$name" in
    *.pdf|*.pcap|*.pcapng|*.evtx|*.txt|*.json|*.csv|*.md|*.html|*.htm|*.xml|\
    *.jpg|*.jpeg|*.png|*.gif|*.zip|*.gz|*.xz|*.7z|*.doc|*.docx|*.xls|*.xlsx|\
    *.ppt|*.pptx|*.mp3|*.mp4|*.wav|*.log|*.js|*.css)
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

# One filesystem: its header, the body file, the path list, the MAC timeline.
catalog_volume() { # catalog_volume <img> <rel> <slug> <start sector> <description>
  local img="$1" rel="$2" slug="$3" start="$4" desc="$5"
  local pdir="$out/$slug/p$start" r
  mkdir -p "$pdir"
  volumes=$((volumes + 1))
  have fsstat && run_step "$pdir/fsstat.txt" fsstat -o "$start" "$img" >/dev/null
  add_index "$slug/p$start/fsstat.txt" "filesystem header at sector $start ($desc)"
  if have fls; then
    r="$(run_step "$pdir/bodyfile.txt" fls -m / -r -o "$start" "$img")"
    [[ "$r" == ok ]] || notes+=("fls body file at sector $start: $r")
    add_index "$slug/p$start/bodyfile.txt" "body file (fls -m -r), every file with MAC times, for mactime/grep"
    r="$(run_step "$pdir/filelist.txt" fls -r -p -o "$start" "$img")"
    [[ "$r" == ok ]] || notes+=("fls path list at sector $start: $r")
    add_index "$slug/p$start/filelist.txt" "path list (fls -r -p): inode, type and full path per line; icat -o $start $rel <inode>"
  else
    notes+=("fls missing: no body file or path list for $rel")
  fi
  if have mactime && [[ -s "$pdir/bodyfile.txt" ]]; then
    r="$(run_step "$pdir/timeline.csv" mactime -b "$pdir/bodyfile.txt" -d -y)"
    [[ "$r" == ok ]] || notes+=("mactime at sector $start: $r")
    add_index "$slug/p$start/timeline.csv" "MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC"
  fi
}

disk_images=0
memory_images=0
segments_skipped=0
segment_sets=""
while IFS= read -r img; do
  rel_under="${img#"$sandbox/inputs/"}"
  rel="inputs/$rel_under"
  size="$(stat -c %s "$img" 2>/dev/null || stat -f %z "$img")"
  if [[ "$size" -lt 65536 ]]; then   # nothing under 64 KB is an image (a logical E01 can be small)
    cover "$rel" "$size" "not probed" "under 64 KB: not tried as a disk or memory image"
    continue
  fi
  if first_segment="$(is_continuation_segment "$img")"; then
    segments_skipped=$((segments_skipped + 1))
    case "$segment_sets" in
      *"|$first_segment|"*) ;;
      *) segment_sets="$segment_sets|$first_segment|" ;;
    esac
    cover "$rel" "$size" "segment" "a further segment of $first_segment: the set is read, and catalogued, from that one"
    continue
  fi
  slug="$(catalog_slug "$rel_under")"
  volumes=0
  notes_before=${#notes[@]}

  # --- a disk image? ---------------------------------------------------------
  if have mmls && mmls "$img" > "$out/.mmls.tmp" 2>/dev/null; then
    disk_images=$((disk_images + 1))
    mkdir -p "$out/$slug"
    mv "$out/.mmls.tmp" "$out/$slug/partitions.txt"
    add_index "$slug/partitions.txt" "partition table of $rel (mmls)"
    # every partition with a filesystem
    while IFS= read -r line; do
      start="$(mmls_start_sector "$line")"
      desc="$(printf '%s' "$line" | awk '{ $1=$2=$3=$4=$5=""; print }' | sed 's/^ *//')"
      case "$desc" in *NTFS*|*FAT*|*exFAT*|*Ext*|*HFS*|*APFS*|*Linux*|*Basic*data*) ;; *) continue ;; esac
      catalog_volume "$img" "$rel" "$slug" "$start" "$desc"
    done < <(grep -E '^[0-9]+:' "$out/$slug/partitions.txt")
    if [[ "$volumes" -eq 0 ]]; then
      cover "$rel" "$size" "partial" "a partition table only (catalog/$slug/partitions.txt): no partition held a filesystem this pass lists"
    elif [[ ${#notes[@]} -gt "$notes_before" ]]; then
      cover "$rel" "$size" "partial" "disk image, $volumes filesystem(s) under catalog/$slug/, with steps that did not finish (Not built, in the index)"
    else
      cover "$rel" "$size" "catalogued" "disk image: partition table and $volumes filesystem(s) under catalog/$slug/"
    fi
    continue
  fi
  rm -f "$out/.mmls.tmp"

  # --- a logical volume image (a filesystem with no partition table)? ---------
  # FTK's "logical" E01s and many course images start straight at the boot
  # sector: mmls has nothing to say, fsstat does.
  if have fsstat && fsstat "$img" > "$out/.fsstat.tmp" 2>/dev/null && grep -q '^File System Type:' "$out/.fsstat.tmp"; then
    fstype="$(sed -n 's/^File System Type: *//p' "$out/.fsstat.tmp" | head -1)"
    rm -f "$out/.fsstat.tmp"
    disk_images=$((disk_images + 1))
    mkdir -p "$out/$slug"
    printf 'No partition table: %s is one %s volume starting at sector 0 (use the tools without -o).\n' "$rel" "$fstype" > "$out/$slug/partitions.txt"
    add_index "$slug/partitions.txt" "no partition table: $rel is a single $fstype volume"
    catalog_volume "$img" "$rel" "$slug" 0 "$fstype (logical volume, no partition table)"
    if [[ ${#notes[@]} -gt "$notes_before" ]]; then
      cover "$rel" "$size" "partial" "single $fstype volume under catalog/$slug/p0/, with steps that did not finish (Not built, in the index)"
    else
      cover "$rel" "$size" "catalogued" "single $fstype volume: catalog/$slug/p0/"
    fi
    continue
  fi
  rm -f "$out/.fsstat.tmp"

  # --- a memory image? ---------------------------------------------------------
  if ! is_memory_image "$img"; then
    if have mmls || have fsstat; then
      cover "$rel" "$size" "not catalogued" "no recipe in this pass read it: not a disk image to mmls or fsstat, and not memory by its name or file(1)"
    else
      cover "$rel" "$size" "not catalogued" "mmls and fsstat are not in this image, so it was not tried as a disk; not memory by its name or file(1)"
    fi
    continue
  fi
  if have vol; then
    # The probe writes under probes/ and moves into the catalogue only when
    # Volatility names a Windows memory image: a file that is not one keeps
    # no catalogue tree, and what vol said about it is still on disk.
    probe="$out/probes/$slug"
    mkdir -p "$probe"
    r="$(RUN_STEP_TIMEOUT="${SWARM_CATALOG_MEMORY_PROBE_TIMEOUT:-30}" run_step "$probe/windows.info.txt" vol -q -f "$img" windows.info)"
    if [[ "$r" == ok ]] && grep -qi "NTBuildLab\|Kernel Base\|SystemTime" "$probe/windows.info.txt"; then
      memory_images=$((memory_images + 1))
      mkdir -p "$out/$slug"
      find "$probe" -mindepth 1 -maxdepth 1 -exec mv {} "$out/$slug/" \;
      rmdir "$probe" "$out/probes" 2>/dev/null || true
      add_index "$slug/windows.info.txt" "OS, build, capture time of $rel (vol windows.info)"
      for plugin in pslist psscan cmdline netscan malfind dlllist; do
        r="$(run_step "$out/$slug/$plugin.txt" vol -q -f "$img" "windows.$plugin")"
        [[ "$r" == ok ]] || notes+=("vol windows.$plugin on $rel: $r")
        add_index "$slug/$plugin.txt" "vol windows.$plugin over $rel"
      done
      if [[ ${#notes[@]} -gt "$notes_before" ]]; then
        cover "$rel" "$size" "partial" "memory image under catalog/$slug/, with plugins that did not finish (Not built, in the index)"
      else
        cover "$rel" "$size" "catalogued" "memory image: catalog/$slug/"
      fi
    else
      why="offered to Volatility as memory; windows.info named no Windows memory image"
      [[ "$r" == ok ]] || why="$why ($r)"
      if rmdir "$probe" 2>/dev/null; then
        rmdir "$out/probes" 2>/dev/null || true
      else
        why="$why; what it wrote: catalog/probes/$slug/"
      fi
      cover "$rel" "$size" "not catalogued" "$why"
    fi
  else
    notes+=("vol missing: no memory catalog for $rel")
    cover "$rel" "$size" "not catalogued" "looks like memory, but vol is not in this image"
  fi
done < <(catalog_candidates "$sandbox")

# The whole of what every step wrote to stderr, in the index beside its output.
while IFS= read -r f; do
  rel_err="${f#"$out/"}"
  add_index "$rel_err" "what the step writing catalog/${rel_err%.stderr} said on stderr"
done < <(find "$out" -type f -name '*.stderr' | sort)

{
  printf 'input\tbytes\tstatus\twhy\n'
  printf '%s\n' "${coverage[@]+"${coverage[@]}"}"
} > "$out/coverage.tsv"
add_index "coverage.tsv" "every input, one row each: path, bytes, status (catalogued, partial, segment, not catalogued, not probed) and why"

# How many inputs have <status>.
count_status() { printf '%s\n' "${coverage[@]+"${coverage[@]}"}" | awk -F'\t' -v s="$1" '$3 == s' | wc -l | tr -d ' '; }

# The inputs with <status>, one line each, twenty at most: the rest are named
# by count and are all in coverage.tsv.
list_status() { # list_status <status> <heading>
  local n
  n="$(count_status "$1")"
  [[ "$n" -gt 0 ]] || return 0
  echo
  echo "$2:"
  printf '%s\n' "${coverage[@]}" | awk -F'\t' -v s="$1" '
    function human(b) {
      if (b >= 1073741824) return sprintf("%.1f GB", b / 1073741824)
      if (b >= 1048576) return sprintf("%.1f MB", b / 1048576)
      if (b >= 1024) return sprintf("%.1f KB", b / 1024)
      return b " B"
    }
    $3 == s { if (++k <= 20) printf "- `%s` (%s): %s\n", $1, human($2), $4 }
    END { if (k > 20) printf "- and %d more, every one in `catalog/coverage.tsv`\n", k - 20 }'
}

{
  echo "Summary: $disk_images disk image(s), $memory_images memory image(s), $(( ${#index[@]} )) catalog file(s); ${#coverage[@]} input file(s): $(count_status catalogued) catalogued, $(count_status partial) partial, $(count_status segment) segment(s) of a set, $(count_status "not catalogued") not catalogued, $(count_status "not probed") not probed"
  if [[ "$segments_skipped" -gt 0 ]]; then
    echo
    printf 'Segmented images: %d further segment(s) belong to the set(s) catalogued above (%s) and were not catalogued separately — libewf and The Sleuth Kit read the whole set from the first segment, so pass that one to every tool.\n' \
      "$segments_skipped" "$(printf '%s' "$segment_sets" | tr '|' ' ' | tr -s ' ' | sed 's/^ //; s/ $//; s/ /, /g')"
  fi
  echo
  echo "Coverage: every input has a row in \`catalog/coverage.tsv\` with its status and why. An input that is not catalogued has no file list or timeline here: open it with other tools. Missing from the catalog is not missing from the evidence."
  list_status "not catalogued" "Not catalogued"
  list_status "partial" "Catalogued in part"
  list_status "not probed" "Not probed (under 64 KB)"
  echo
  echo "| File | What | Rows | Size |"
  echo "| --- | --- | --- | --- |"
  printf '%s\n' "${index[@]+"${index[@]}"}"
  if [[ "${#notes[@]}" -gt 0 ]]; then
    echo
    echo "Not built:"
    printf -- '- %s\n' "${notes[@]}"
  fi
} > "$out/README.md"
echo "evidence-catalog: $(sed -n 1p "$out/README.md")"
