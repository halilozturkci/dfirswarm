#!/usr/bin/env bash
# Sector 0 must remain 0 after mmls's zero-padded start column is stripped.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
# One input's row of coverage.tsv as "bytes|status|why", or nothing.
cov_row() { awk -F'\t' -v p="$2" '$1 == p { print $2 "|" $3 "|" $4 }' "$1"; }

# The catalog script exits if argv is missing, so extract the helper and
# run it — that is the transform kickoff actually uses on each mmls line.
eval "$(sed -n '/^mmls_start_sector()/,/^}/p' "$ROOT/scripts/evidence-catalog.sh")"
[[ "$(type -t mmls_start_sector)" == function ]] || fail "mmls_start_sector missing from evidence-catalog.sh"

[[ "$(mmls_start_sector $'00:  000  0000000000  0001028095   001028096   Linux')" == 0 ]] \
  || fail "sector 0 became empty and would be skipped"
[[ "$(mmls_start_sector $'01:  000  0000002048  0001028095   001026048   NTFS')" == 2048 ]] \
  || fail "a non-zero start sector should keep its value"
pass "mmls start sector 0 is 0, not skipped"

eval "$(sed -n '/^catalog_slug()/,/^}/p' "$ROOT/scripts/evidence-catalog.sh")"
[[ "$(type -t catalog_slug)" == function ]] || fail "catalog_slug missing from evidence-catalog.sh"
[[ "$(catalog_slug "node1/sda.E01")" == "node1_sda.E01" ]] \
  || fail "a nested input should keep its directory in the slug"
[[ "$(catalog_slug "node2/sda.E01")" == "node2_sda.E01" ]] \
  || fail "two inputs with the same basename must not share a slug"
[[ "$(catalog_slug "sda.E01")" == "sda.E01" ]] \
  || fail "a top-level input should keep its basename"
[[ "$(catalog_slug "node1/sda.E01")" != "$(catalog_slug "node2/sda.E01")" ]] \
  || fail "node1/sda.E01 and node2/sda.E01 collided"
pass "catalog slug is the path under inputs/, not the basename"

# Two same-basename images must land in different catalog trees.
TMP="$(mktemp -d "${TMPDIR:-/tmp}/catalog-slug.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/sandbox/inputs/node1" "$TMP/sandbox/inputs/node2"
# mmls is enough for the script to claim a disk image and write partitions.txt
# under $slug/; fsstat/fls may be missing and that only leaves notes.
cat > "$TMP/bin/mmls" <<'EOF'
#!/usr/bin/env bash
cat <<'TABLE'
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
002:  000:000   0000002048   0001028095   001026048    NTFS (0x07)
TABLE
EOF
chmod +x "$TMP/bin/mmls"
dd if=/dev/zero of="$TMP/sandbox/inputs/node1/sda.E01" bs=1024 count=64 status=none
dd if=/dev/zero of="$TMP/sandbox/inputs/node2/sda.E01" bs=1024 count=64 status=none
PATH="$TMP/bin:$PATH" bash "$ROOT/scripts/evidence-catalog.sh" "$TMP/sandbox" >/dev/null
[[ -f "$TMP/sandbox/catalog/node1_sda.E01/partitions.txt" ]] \
  || fail "node1/sda.E01 should catalog under catalog/node1_sda.E01/"
[[ -f "$TMP/sandbox/catalog/node2_sda.E01/partitions.txt" ]] \
  || fail "node2/sda.E01 should catalog under catalog/node2_sda.E01/"
[[ ! -d "$TMP/sandbox/catalog/sda.E01" ]] \
  || fail "a basename-only slug would have overwritten catalog/sda.E01/"
grep -q 'node1/sda.E01' "$TMP/sandbox/catalog/README.md" \
  || fail "the index should name the first nested input"
grep -q 'node2/sda.E01' "$TMP/sandbox/catalog/README.md" \
  || fail "the index should name the second nested input"
pass "two inputs named sda.E01 keep separate catalog trees"

eval "$(sed -n '/^have()/,/^}/p' "$ROOT/scripts/evidence-catalog.sh")"
eval "$(sed -n '/^is_memory_image()/,/^}/p' "$ROOT/scripts/evidence-catalog.sh")"
[[ "$(type -t is_memory_image)" == function ]] || fail "is_memory_image missing from evidence-catalog.sh"
touch "$TMP/sample.pdf" "$TMP/sample.pcap" "$TMP/sample.evtx" "$TMP/sample.mem" "$TMP/sample.dmp" "$TMP/sample.e01"
is_memory_image "$TMP/sample.pdf" && fail "a PDF is not a memory image"
is_memory_image "$TMP/sample.pcap" && fail "a pcap is not a memory image"
is_memory_image "$TMP/sample.evtx" && fail "an EVTX is not a memory image"
is_memory_image "$TMP/sample.e01" && fail "a leftover E01 is a disk image, not memory"
is_memory_image "$TMP/sample.mem" || fail ".mem should be offered to Volatility"
is_memory_image "$TMP/sample.dmp" || fail ".dmp should be offered to Volatility"
pass "memory catalog is gated on the filename, not every leftover ≥64 KB"

# A PDF leftover must not invoke vol; a .mem leftover must, and a missing vol
# is noted only for the memory file.
mkdir -p "$TMP/mem/bin" "$TMP/mem/sandbox/inputs"
dd if=/dev/zero of="$TMP/mem/sandbox/inputs/report.pdf" bs=1024 count=64 status=none
dd if=/dev/zero of="$TMP/mem/sandbox/inputs/dump.mem" bs=1024 count=64 status=none
cat > "$TMP/mem/bin/mmls" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
cp "$TMP/mem/bin/mmls" "$TMP/mem/bin/fsstat"
cat > "$TMP/mem/bin/vol" <<'EOF'
#!/usr/bin/env bash
printf 'vol %s\n' "$*" >> "${VOL_LOG:?}"
echo "not a windows dump"
exit 1
EOF
chmod +x "$TMP/mem/bin/vol" "$TMP/mem/bin/mmls" "$TMP/mem/bin/fsstat"
VOL_LOG="$TMP/mem/vol.log"
# Hide host mmls/fsstat/vol so leftovers reach the memory gate.
hide="$TMP/mem/bin"
PATH="$hide:/usr/bin:/bin" VOL_LOG="$VOL_LOG" \
  bash "$ROOT/scripts/evidence-catalog.sh" "$TMP/mem/sandbox" >/dev/null
[[ -f "$VOL_LOG" ]] || : > "$VOL_LOG"
grep -q 'report.pdf' "$VOL_LOG" && fail "vol ran on a PDF leftover: $(cat "$VOL_LOG")"
grep -q 'dump.mem' "$VOL_LOG" || fail "vol should probe a .mem leftover: $(cat "$VOL_LOG")"
readme="$TMP/mem/sandbox/catalog/README.md"
grep -q '^| `catalog/report' "$readme" && fail "the PDF should have no catalog row"
grep -q '^| `catalog/dump.mem' "$readme" && fail "a failed probe should not leave a dump.mem catalog row"
[[ ! -d "$TMP/mem/sandbox/catalog/dump.mem" ]] || fail "a failed probe should not keep a catalogue tree"
# Neither is silently gone: both are named as not catalogued, with why, and
# what vol printed about dump.mem is kept whole under probes/.
[[ "$(cov_row "$TMP/mem/sandbox/catalog/coverage.tsv" inputs/report.pdf)" == "65536|not catalogued|"* ]] \
  || fail "coverage.tsv should list the PDF as not catalogued: $(cat "$TMP/mem/sandbox/catalog/coverage.tsv")"
[[ "$(cov_row "$TMP/mem/sandbox/catalog/coverage.tsv" inputs/dump.mem)" == "65536|not catalogued|offered to Volatility as memory; windows.info named no Windows memory image"* ]] \
  || fail "coverage.tsv should say vol did not recognise dump.mem: $(cat "$TMP/mem/sandbox/catalog/coverage.tsv")"
grep -q 'not a windows dump' "$TMP/mem/sandbox/catalog/probes/dump.mem/windows.info.txt" \
  || fail "what vol printed about dump.mem should be kept under catalog/probes/"
grep -q '^- `inputs/report.pdf` (64.0 KB): ' "$readme" || fail "the index should name the PDF under Not catalogued: $(cat "$readme")"
pass "vol is not started on a PDF leftover; a failed .mem probe keeps no catalogue tree, and both are named as not catalogued"

# vol missing: note the memory file, not the PDF.
rm -f "$TMP/mem/bin/vol" "$TMP/mem/sandbox/catalog/README.md"
PATH="$hide:/usr/bin:/bin" bash "$ROOT/scripts/evidence-catalog.sh" "$TMP/mem/sandbox" >/dev/null
grep -q 'vol missing: no memory catalog for inputs/dump.mem' "$TMP/mem/sandbox/catalog/README.md" \
  || fail "missing vol should be noted for a .mem file: $(cat "$TMP/mem/sandbox/catalog/README.md")"
grep -q 'vol missing: no memory catalog for inputs/report.pdf' "$TMP/mem/sandbox/catalog/README.md" && fail "missing vol should not be noted for a PDF"
[[ "$(cov_row "$TMP/mem/sandbox/catalog/coverage.tsv" inputs/dump.mem)" == "65536|not catalogued|looks like memory, but vol is not in this image" ]] \
  || fail "coverage.tsv should say vol is missing for dump.mem: $(cat "$TMP/mem/sandbox/catalog/coverage.tsv")"
pass "vol missing is noted only for files that look like memory"

# The probe timeout, not the 900s step timeout, bounds windows.info.
mkdir -p "$TMP/slow/bin" "$TMP/slow/sandbox/inputs"
dd if=/dev/zero of="$TMP/slow/sandbox/inputs/dump.mem" bs=1024 count=64 status=none
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' > "$TMP/slow/bin/mmls"
cp "$TMP/slow/bin/mmls" "$TMP/slow/bin/fsstat"
cat > "$TMP/slow/bin/vol" <<'EOF'
#!/usr/bin/env bash
sleep 30
echo NTBuildLab
exit 0
EOF
chmod +x "$TMP/slow/bin/vol" "$TMP/slow/bin/mmls" "$TMP/slow/bin/fsstat"
start=$(date +%s)
PATH="$TMP/slow/bin:/usr/bin:/bin" SWARM_CATALOG_MEMORY_PROBE_TIMEOUT=1 \
  bash "$ROOT/scripts/evidence-catalog.sh" "$TMP/slow/sandbox" >/dev/null
elapsed=$(( $(date +%s) - start ))
[[ "$elapsed" -lt 15 ]] || fail "memory probe should give up in ~1s, took ${elapsed}s"
[[ ! -d "$TMP/slow/sandbox/catalog/dump.mem" ]] \
  || fail "a timed-out probe should not keep a catalog tree"
pass "windows.info is time-boxed by the memory probe, not the 900s step timeout"

# --- segmented images are one image ------------------------------------------
# libewf resolves a whole set from any segment, so cataloguing .E02 repeats
# .E01's work exactly. The BelkaCTF #6 run catalogued one 8.7 GB disk six
# times before this rule existed.
eval "$(sed -n '/^is_continuation_segment()/,/^}/p' "$ROOT/scripts/evidence-catalog.sh")"
[[ "$(type -t is_continuation_segment)" == function ]] || fail "is_continuation_segment missing"

SEG="$(mktemp -d)"
trap 'rm -rf "$SEG"' EXIT
: > "$SEG/disk.E01"; : > "$SEG/disk.E02"; : > "$SEG/disk.E10"; : > "$SEG/disk.EAA"
: > "$SEG/raw.001"; : > "$SEG/raw.002"
: > "$SEG/orphan.002"
: > "$SEG/mem.raw"
: > "$SEG/case.Ex01"; : > "$SEG/case.Ex02"

is_continuation_segment "$SEG/disk.E01" >/dev/null && fail "the first segment is not a continuation"
is_continuation_segment "$SEG/raw.001" >/dev/null && fail "the first split-raw segment is not a continuation"
is_continuation_segment "$SEG/case.Ex01" >/dev/null && fail "EnCase 7's first segment is not a continuation"
is_continuation_segment "$SEG/mem.raw" >/dev/null && fail "a plain image is not a continuation"
is_continuation_segment "$SEG/orphan.002" >/dev/null && fail "a .002 with no .001 beside it stands on its own"
for f in disk.E02 disk.E10 disk.EAA raw.002 case.Ex02; do
  is_continuation_segment "$SEG/$f" >/dev/null || fail "$f should be a continuation of its set"
done
[[ "$(is_continuation_segment "$SEG/disk.EAA")" == "disk.E01" ]] \
  || fail "a continuation names the set's first segment"
pass "a segment set is catalogued once: continuations are named, not walked"

# And end to end: two segments in, one catalogue out, with the skip on the record.
SEGSB="$(mktemp -d)"
mkdir -p "$SEGSB/inputs"
head -c 200000 /dev/zero > "$SEGSB/inputs/disk.E01"
head -c 200000 /dev/zero > "$SEGSB/inputs/disk.E02"
bash "$ROOT/scripts/evidence-catalog.sh" "$SEGSB" >/dev/null
grep -q "1 further segment(s)" "$SEGSB/catalog/README.md" \
  || fail "the index should say a segment was skipped: $(cat "$SEGSB/catalog/README.md")"
grep -q "disk.E01" "$SEGSB/catalog/README.md" \
  || fail "the index should name the set's first segment"
[[ ! -d "$SEGSB/catalog/disk.E02" ]] || fail "disk.E02 should not have its own catalog tree"
rm -rf "$SEGSB"
pass "the catalog index names the segments it did not walk, and why"

# --- every input is accounted for ---------------------------------------------
# BelkaCTF #6: a 5.1 GB iPhone tar sat beside the laptop E01, the catalogue
# neither read it nor named it, and ten agents listed it with `tar -t` 59
# times. Every input now has a row in coverage.tsv, and the index names what
# was not catalogued.
COV="$(mktemp -d)"
trap 'rm -rf "$COV"' EXIT
mkdir -p "$COV/bin" "$COV/sb/inputs/notes"
cat > "$COV/bin/mmls" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  *disk.E01) printf '%s\n' 'DOS Partition Table' '      Slot      Start        End          Length       Description' \
    '002:  000:000   0000002048   0001028095   001026048    NTFS (0x07)' ;;
  *) exit 1 ;;
esac
STUB
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' > "$COV/bin/fsstat"
# fls fails with more to say than an excerpt holds.
cat > "$COV/bin/fls" <<'STUB'
#!/usr/bin/env bash
for i in $(seq 1 40); do echo "fls: Error reading MFT entry $i: attribute list is corrupt" >&2; done
exit 1
STUB
chmod +x "$COV/bin/"*
head -c 200000 /dev/zero > "$COV/sb/inputs/disk.E01"
head -c 200000 /dev/zero > "$COV/sb/inputs/disk.E02"
head -c 100000 /dev/zero > "$COV/sb/inputs/phone.tar"
echo "the brief" > "$COV/sb/inputs/CASE.md"
echo x > "$COV/sb/inputs/notes/odd"$'\t'"name.txt"
for i in $(seq -w 1 20); do echo "$i" > "$COV/sb/inputs/notes/n$i.txt"; done
PATH="$COV/bin:/usr/bin:/bin" bash "$ROOT/scripts/evidence-catalog.sh" "$COV/sb" >/dev/null
tsv="$COV/sb/catalog/coverage.tsv"
readme="$COV/sb/catalog/README.md"
[[ "$(head -1 "$tsv")" == $'input\tbytes\tstatus\twhy' ]] || fail "coverage.tsv should open with its header: $(head -1 "$tsv")"
[[ "$(($(wc -l < "$tsv") - 1))" -eq 25 ]] || fail "coverage.tsv should have one row per input (25): $(cat "$tsv")"
awk -F'\t' 'NF != 4 { bad = 1 } END { exit bad }' "$tsv" || fail "every coverage row should have four fields: $(cat "$tsv")"
[[ "$(cov_row "$tsv" inputs/disk.E01)" == "200000|partial|disk image, 1 filesystem(s) under catalog/disk.E01/, with steps that did not finish"* ]] \
  || fail "a disk whose fls failed is catalogued in part: $(cov_row "$tsv" inputs/disk.E01)"
[[ "$(cov_row "$tsv" inputs/disk.E02)" == "200000|segment|a further segment of disk.E01"* ]] \
  || fail "a further segment is named as one: $(cov_row "$tsv" inputs/disk.E02)"
[[ "$(cov_row "$tsv" inputs/phone.tar)" == "100000|not catalogued|no recipe in this pass read it"* ]] \
  || fail "an input no recipe read is named as not catalogued: $(cov_row "$tsv" inputs/phone.tar)"
[[ "$(cov_row "$tsv" inputs/CASE.md)" == "10|not probed|under 64 KB"* ]] \
  || fail "a small input is named as not probed: $(cov_row "$tsv" inputs/CASE.md)"
# (awk -v reads escapes, so the literal backslash-t is written \\t here.)
[[ "$(cov_row "$tsv" 'inputs/notes/odd\\tname.txt')" == "2|not probed|"* ]] \
  || fail "a tab in a file name is written escaped, on one row: $(grep odd "$tsv")"
grep -q '^Summary: 1 disk image(s), 0 memory image(s), [0-9]* catalog file(s); 25 input file(s): 0 catalogued, 1 partial, 1 segment(s) of a set, 1 not catalogued, 22 not probed$' "$readme" \
  || fail "the summary line should count the inputs by status: $(head -1 "$readme")"
grep -q '^- `inputs/phone.tar` (97.7 KB): no recipe in this pass read it' "$readme" \
  || fail "the index should name the tar under Not catalogued: $(cat "$readme")"
grep -q '^- and 2 more, every one in `catalog/coverage.tsv`$' "$readme" \
  || fail "past twenty, the index names how many more and where they all are: $(cat "$readme")"
pass "every input has a coverage row, and the index names what was not catalogued"

# A failed step's stderr is kept whole and named; the index quotes its start.
err="$COV/sb/catalog/disk.E01/p2048/bodyfile.txt.stderr"
[[ -f "$err" ]] || fail "fls's stderr should be kept beside its output"
[[ "$(wc -l < "$err" | tr -d ' ')" -eq 40 ]] || fail "all forty lines of fls's stderr should be kept: $(wc -l < "$err")"
grep -q 'fls body file at sector 2048: failed (exit 1: fls: Error reading MFT entry 1: .*; all of stderr: catalog/disk.E01/p2048/bodyfile.txt.stderr)' "$readme" \
  || fail "the Not built note should name the file with all of stderr: $(cat "$readme")"
grep -q '^| `catalog/disk.E01/p2048/bodyfile.txt.stderr` | what the step writing catalog/disk.E01/p2048/bodyfile.txt said on stderr | 40 |' "$readme" \
  || fail "the index should list the stderr file: $(cat "$readme")"
pass "a failed step's stderr is kept whole beside its output and named in the index"

# A newline in an input's name: one input, one coverage row, one index line.
NL="$(mktemp -d)"
trap 'rm -rf "$NL"' EXIT
mkdir -p "$NL/sb/inputs"
head -c 70000 /dev/zero > "$NL/sb/inputs/two"$'\n'"lines.bin"
PATH="/usr/bin:/bin" bash "$ROOT/scripts/evidence-catalog.sh" "$NL/sb" >/dev/null
[[ "$(($(wc -l < "$NL/sb/catalog/coverage.tsv") - 1))" -eq 1 ]] \
  || fail "a name with a newline is one input, one row: $(cat "$NL/sb/catalog/coverage.tsv")"
[[ "$(cov_row "$NL/sb/catalog/coverage.tsv" 'inputs/two\\nlines.bin')" == "70000|not catalogued|"* ]] \
  || fail "the newline is written escaped: $(cat "$NL/sb/catalog/coverage.tsv")"
grep -q '^- `inputs/two\\nlines.bin` (68.4 KB): ' "$NL/sb/catalog/README.md" \
  || fail "the index shows the name escaped, on one line: $(cat "$NL/sb/catalog/README.md")"
pass "an input whose name holds a newline is one input, named escaped"
