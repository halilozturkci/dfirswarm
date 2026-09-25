#!/usr/bin/env bash
# The kickoff's evidence catalog: the harness's census (a coverage row for
# every input) and the computer-forensics-base recipes it runs (disk volumes,
# Windows memory, archive members), with The Sleuth Kit and Volatility
# stubbed on PATH.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RECIPES="$ROOT/packs/computer-forensics-base/recipes"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
# One input's row of coverage.tsv as "bytes|status|why", or nothing.
cov_row() { awk -F'\t' -v p="$2" '$1 == p { print $2 "|" $3 "|" $4 }' "$1"; }
py() { python3 -c "import sys; sys.path.insert(0, '$ROOT/scripts'); import evidence_catalog as e; $1"; }

# The disk recipe strips mmls's zero-padded start column; sector 0 must stay 0.
eval "$(sed -n '/^mmls_start_sector()/,/^}/p' "$RECIPES/disk-volumes/run.sh")"
[[ "$(type -t mmls_start_sector)" == function ]] || fail "mmls_start_sector missing from the disk-volumes recipe"
[[ "$(mmls_start_sector $'00:  000  0000000000  0001028095   001028096   Linux')" == 0 ]] \
  || fail "sector 0 became empty and would be skipped"
[[ "$(mmls_start_sector $'01:  000  0000002048  0001028095   001026048   NTFS')" == 2048 ]] \
  || fail "a non-zero start sector should keep its value"
pass "mmls start sector 0 is 0, not skipped"

[[ "$(py 'print(e.catalog_slug("node1/sda.E01"))')" == "node1_sda.E01" ]] || fail "a nested input should keep its directory in the slug"
[[ "$(py 'print(e.catalog_slug("node2/sda.E01"))')" == "node2_sda.E01" ]] || fail "two inputs with the same basename must not share a slug"
[[ "$(py 'print(e.catalog_slug("sda.E01"))')" == "sda.E01" ]] || fail "a top-level input should keep its basename"
pass "catalog slug is the path under inputs/, not the basename"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/catalog.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Two same-basename images land in different catalog trees. mmls is enough
# for the disk recipe to take an image and write partitions.txt under $slug/.
mkdir -p "$TMP/bin" "$TMP/sandbox/inputs/node1" "$TMP/sandbox/inputs/node2"
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
PATH="$TMP/bin:/usr/bin:/bin" bash "$ROOT/scripts/evidence-catalog.sh" "$TMP/sandbox" >/dev/null
[[ -f "$TMP/sandbox/catalog/node1_sda.E01/partitions.txt" ]] || fail "node1/sda.E01 should catalog under catalog/node1_sda.E01/"
[[ -f "$TMP/sandbox/catalog/node2_sda.E01/partitions.txt" ]] || fail "node2/sda.E01 should catalog under catalog/node2_sda.E01/"
[[ ! -d "$TMP/sandbox/catalog/sda.E01" ]] || fail "a basename-only slug would have overwritten catalog/sda.E01/"
grep -q 'node1/sda.E01' "$TMP/sandbox/catalog/README.md" || fail "the index should name the first nested input"
grep -q 'node2/sda.E01' "$TMP/sandbox/catalog/README.md" || fail "the index should name the second nested input"
pass "two inputs named sda.E01 keep separate catalog trees"

# The memory recipe gates on the name (and file(1)) before it asks Volatility.
eval "$(sed -n '/^have()/,/^}/p' "$RECIPES/memory-windows/run.sh")"
eval "$(sed -n '/^looks_like_memory()/,/^}/p' "$RECIPES/memory-windows/run.sh")"
[[ "$(type -t looks_like_memory)" == function ]] || fail "looks_like_memory missing from the memory-windows recipe"
touch "$TMP/sample.pdf" "$TMP/sample.pcap" "$TMP/sample.evtx" "$TMP/sample.mem" "$TMP/sample.dmp" "$TMP/sample.e01"
looks_like_memory "$TMP/sample.pdf" && fail "a PDF is not a memory image"
looks_like_memory "$TMP/sample.pcap" && fail "a pcap is not a memory image"
looks_like_memory "$TMP/sample.evtx" && fail "an EVTX is not a memory image"
looks_like_memory "$TMP/sample.e01" && fail "an E01 is a disk image, not memory"
looks_like_memory "$TMP/sample.mem" || fail ".mem should be offered to Volatility"
looks_like_memory "$TMP/sample.dmp" || fail ".dmp should be offered to Volatility"
pass "the memory recipe is gated on the name, not every leftover of 64 KB or more"

# A PDF must not start vol; a .mem must, and what vol said about a file it
# did not recognise is kept, not dropped.
mkdir -p "$TMP/mem/bin" "$TMP/mem/sandbox/inputs"
dd if=/dev/zero of="$TMP/mem/sandbox/inputs/report.pdf" bs=1024 count=64 status=none
dd if=/dev/zero of="$TMP/mem/sandbox/inputs/dump.mem" bs=1024 count=64 status=none
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' > "$TMP/mem/bin/mmls"
cp "$TMP/mem/bin/mmls" "$TMP/mem/bin/fsstat"
cat > "$TMP/mem/bin/vol" <<'EOF'
#!/usr/bin/env bash
printf 'vol %s\n' "$*" >> "${VOL_LOG:?}"
echo "not a windows dump"
exit 1
EOF
chmod +x "$TMP/mem/bin/vol" "$TMP/mem/bin/mmls" "$TMP/mem/bin/fsstat"
VOL_LOG="$TMP/mem/vol.log"
PATH="$TMP/mem/bin:/usr/bin:/bin" VOL_LOG="$VOL_LOG" bash "$ROOT/scripts/evidence-catalog.sh" "$TMP/mem/sandbox" >/dev/null
[[ -f "$VOL_LOG" ]] || : > "$VOL_LOG"
grep -q 'report.pdf' "$VOL_LOG" && fail "vol ran on a PDF leftover: $(cat "$VOL_LOG")"
grep -q 'dump.mem' "$VOL_LOG" || fail "vol should probe a .mem leftover: $(cat "$VOL_LOG")"
readme="$TMP/mem/sandbox/catalog/README.md"
tsv="$TMP/mem/sandbox/catalog/coverage.tsv"
grep -q '^| `catalog/report' "$readme" && fail "the PDF should have no catalog row"
grep -q '^| `catalog/dump.mem' "$readme" && fail "a failed probe should not leave a dump.mem catalog row"
[[ ! -d "$TMP/mem/sandbox/catalog/dump.mem" ]] || fail "a failed probe should not keep a catalogue tree"
[[ "$(cov_row "$tsv" inputs/report.pdf)" == "65536|not catalogued|no recipe of this run applies: "* ]] \
  || fail "coverage.tsv should list the PDF as not catalogued: $(cat "$tsv")"
cov_row "$tsv" inputs/dump.mem | grep -q 'computer-forensics-base/memory-windows: offered to Volatility as memory; windows.info named no Windows memory image (what it wrote: catalog/probes/dump.mem/memory-windows/)' \
  || fail "coverage.tsv should say vol did not recognise dump.mem, and where what it said is: $(cat "$tsv")"
grep -q 'not a windows dump' "$TMP/mem/sandbox/catalog/probes/dump.mem/memory-windows/windows.info.txt" \
  || fail "what vol printed about dump.mem should be kept under catalog/probes/"
grep -q '^- `inputs/report.pdf` (64.0 KB): no recipe of this run applies' "$readme" || fail "the index should name the PDF under Not catalogued: $(cat "$readme")"
pass "vol is not started on a PDF; a failed .mem probe keeps no catalogue tree, what vol said is kept, and both are named as not catalogued"

# vol missing: noted for the memory file, not the PDF.
rm -f "$TMP/mem/bin/vol"
PATH="$TMP/mem/bin:/usr/bin:/bin" bash "$ROOT/scripts/evidence-catalog.sh" "$TMP/mem/sandbox" >/dev/null
grep -q 'looks like memory, but vol is not in this image — no catalogue of inputs/dump.mem by computer-forensics-base/memory-windows' "$TMP/mem/sandbox/catalog/README.md" \
  || fail "missing vol should be noted for a .mem file: $(cat "$TMP/mem/sandbox/catalog/README.md")"
grep -q 'no catalogue of inputs/report.pdf' "$TMP/mem/sandbox/catalog/README.md" && fail "missing vol should not be noted for a PDF"
pass "vol missing is noted only for files that look like memory"

# The probe's own box (SWARM_CATALOG_MEMORY_PROBE_TIMEOUT, as before), not the
# 900 s step, bounds windows.info.
mkdir -p "$TMP/slow/bin" "$TMP/slow/sandbox/inputs"
dd if=/dev/zero of="$TMP/slow/sandbox/inputs/dump.mem" bs=1024 count=64 status=none
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' > "$TMP/slow/bin/mmls"
cp "$TMP/slow/bin/mmls" "$TMP/slow/bin/fsstat"
printf '%s\n' '#!/usr/bin/env bash' 'sleep 30' 'echo NTBuildLab' > "$TMP/slow/bin/vol"
chmod +x "$TMP/slow/bin/vol" "$TMP/slow/bin/mmls" "$TMP/slow/bin/fsstat"
start=$(date +%s)
PATH="$TMP/slow/bin:/usr/bin:/bin" SWARM_CATALOG_MEMORY_PROBE_TIMEOUT=1 bash "$ROOT/scripts/evidence-catalog.sh" "$TMP/slow/sandbox" >/dev/null
elapsed=$(( $(date +%s) - start ))
[[ "$elapsed" -lt 15 ]] || fail "memory probe should give up in ~1s, took ${elapsed}s"
[[ ! -d "$TMP/slow/sandbox/catalog/dump.mem" ]] || fail "a timed-out probe should not keep a catalogue tree"
cov_row "$TMP/slow/sandbox/catalog/coverage.tsv" inputs/dump.mem | grep -q 'did not answer within 1s' \
  || fail "a probe that timed out says so: $(cat "$TMP/slow/sandbox/catalog/coverage.tsv")"
pass "windows.info is time-boxed by the memory probe, not the 900s step timeout"

# --- segmented images are one image ------------------------------------------
SEG="$TMP/seg"; mkdir -p "$SEG"
: > "$SEG/disk.E01"; : > "$SEG/disk.E02"; : > "$SEG/disk.E10"; : > "$SEG/disk.EAA"
: > "$SEG/raw.001"; : > "$SEG/raw.002"; : > "$SEG/orphan.002"; : > "$SEG/mem.raw"
: > "$SEG/case.Ex01"; : > "$SEG/case.Ex02"
cont() { py "print(e.continuation_of('$SEG/$1') or '')"; }
[[ -z "$(cont disk.E01)" ]] || fail "the first segment is not a continuation"
[[ -z "$(cont raw.001)" ]] || fail "the first split-raw segment is not a continuation"
[[ -z "$(cont case.Ex01)" ]] || fail "EnCase 7's first segment is not a continuation"
[[ -z "$(cont mem.raw)" ]] || fail "a plain image is not a continuation"
[[ -z "$(cont orphan.002)" ]] || fail "a .002 with no .001 beside it stands on its own"
for f in disk.E02 disk.E10 disk.EAA raw.002 case.Ex02; do [[ -n "$(cont "$f")" ]] || fail "$f should be a continuation of its set"; done
[[ "$(cont disk.EAA)" == "disk.E01" ]] || fail "a continuation names the set's first segment"
pass "a segment set is catalogued once: continuations are named, not walked"

# End to end: two segments in, one catalogue out, the skip on the record, and
# the recipe given the whole set in order.
SEGSB="$TMP/segsb"; mkdir -p "$SEGSB/inputs" "$TMP/segbin"
head -c 200000 /dev/zero > "$SEGSB/inputs/disk.E01"
head -c 200000 /dev/zero > "$SEGSB/inputs/disk.E02"
head -c 200000 /dev/zero > "$SEGSB/inputs/disk.E03"
cat > "$TMP/segbin/mmls" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >> "${MMLS_LOG:?}"
exit 1
EOF
chmod +x "$TMP/segbin/mmls"
MMLS_LOG="$TMP/mmls.log" PATH="$TMP/segbin:/usr/bin:/bin" bash "$ROOT/scripts/evidence-catalog.sh" "$SEGSB" >/dev/null
grep -q "2 further segment(s)" "$SEGSB/catalog/README.md" || fail "the index should say two segments were skipped: $(cat "$SEGSB/catalog/README.md")"
grep -q "disk.E01" "$SEGSB/catalog/README.md" || fail "the index should name the set's first segment"
[[ ! -d "$SEGSB/catalog/disk.E02" ]] || fail "disk.E02 should not have its own catalog tree"
grep -q 'disk.E02' "$TMP/mmls.log" && fail "a recipe was run on a further segment: $(cat "$TMP/mmls.log")"
pass "the catalog index names the segments it did not walk, and why"

# The plan: with --plan-only nothing runs, every applicable recipe is listed
# with its target (the set in order) for the job service, and the rows say so.
PLAN="$TMP/plan"; mkdir -p "$PLAN/inputs" "$TMP/planbin"
head -c 200000 /dev/zero > "$PLAN/inputs/disk.E01"
head -c 200000 /dev/zero > "$PLAN/inputs/disk.E02"
cp "$TMP/bin/mmls" "$TMP/planbin/mmls"
printf '%s\n' '#!/usr/bin/env bash' 'echo "fls ran" >> "${FLS_LOG:?}"' > "$TMP/planbin/fls"; chmod +x "$TMP/planbin/fls"
FLS_LOG="$TMP/fls.log" PATH="$TMP/planbin:/usr/bin:/bin" bash "$ROOT/scripts/evidence-catalog.sh" "$PLAN" --plan-only >/dev/null
[[ ! -f "$TMP/fls.log" ]] || fail "--plan-only ran a recipe"
[[ "$(cov_row "$PLAN/catalog/coverage.tsv" inputs/disk.E01)" == "200000|planned|to be catalogued once the run is up by computer-forensics-base/disk-volumes" ]] \
  || fail "a planned input says by what: $(cat "$PLAN/catalog/coverage.tsv")"
python3 - "$PLAN" <<'PY' || fail "plan.json does not hold the recipe and its target: $(cat "$PLAN/catalog/plan.json")"
import json, os, sys
plan = json.load(open(os.path.join(sys.argv[1], "catalog", "plan.json")))["recipes"]
assert len(plan) == 1, plan
r = plan[0]
assert r["recipe"] == "computer-forensics-base/disk-volumes" and r["input"] == "inputs/disk.E01", r
assert [os.path.basename(p) for p in r["target"]["paths"]] == ["disk.E01", "disk.E02"], r["target"]
assert r["target"]["ref"] == "input:disk.E01" and r["alias"] == "catalog/disk.E01", r
assert len(r["recipe_sha256"]) == 64 and r["seconds"] == 14400, r
PY
grep -q '^Being built: ' "$PLAN/catalog/README.md" || fail "the index should say the catalogue is being built"
pass "--plan-only lists every applicable recipe with its target for the job service, and runs none"

# --- every input is accounted for ---------------------------------------------
# BelkaCTF #6: a 5.1 GB iPhone tar sat beside the laptop E01, the catalogue
# neither read it nor named it, and ten agents listed it with `tar -t` 59
# times. Every input has a row, and a tar is now inventoried by a recipe.
COV="$TMP/cov"
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
cat > "$COV/bin/fls" <<'STUB'
#!/usr/bin/env bash
for i in $(seq 1 40); do echo "fls: Error reading MFT entry $i: attribute list is corrupt" >&2; done
exit 1
STUB
chmod +x "$COV/bin/"*
head -c 200000 /dev/zero > "$COV/sb/inputs/disk.E01"
head -c 200000 /dev/zero > "$COV/sb/inputs/disk.E02"
python3 - "$COV/sb/inputs/phone.tar" <<'PY'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w") as tf:
    for name, data in (("private/var/mobile/Library/SMS/sms.db", b"SQLite format 3\0" + b"x" * 70000), ("a\nb", b"n")):
        ti = tarfile.TarInfo(name); ti.size = len(data); ti.mtime = 1700000000
        tf.addfile(ti, io.BytesIO(data))
PY
head -c 100000 /dev/zero > "$COV/sb/inputs/blob.bin"
echo "the brief" > "$COV/sb/inputs/CASE.md"
echo x > "$COV/sb/inputs/notes/odd"$'\t'"name.txt"
for i in $(seq -w 1 20); do echo "$i" > "$COV/sb/inputs/notes/n$i.txt"; done
PATH="$COV/bin:/usr/bin:/bin" bash "$ROOT/scripts/evidence-catalog.sh" "$COV/sb" >/dev/null
tsv="$COV/sb/catalog/coverage.tsv"
readme="$COV/sb/catalog/README.md"
[[ "$(head -1 "$tsv")" == $'input\tbytes\tstatus\twhy' ]] || fail "coverage.tsv should open with its header: $(head -1 "$tsv")"
[[ "$(($(wc -l < "$tsv") - 1))" -eq 26 ]] || fail "coverage.tsv should have one row per input (26): $(cat "$tsv")"
awk -F'\t' 'NF != 4 { bad = 1 } END { exit bad }' "$tsv" || fail "every coverage row should have four fields: $(cat "$tsv")"
[[ "$(cov_row "$tsv" inputs/disk.E01)" == "200000|partial|catalogued in part under catalog/disk.E01/ by computer-forensics-base/disk-volumes:partial"* ]] \
  || fail "a disk whose fls failed is catalogued in part: $(cov_row "$tsv" inputs/disk.E01)"
[[ "$(cov_row "$tsv" inputs/disk.E02)" == "200000|segment|a further segment of disk.E01"* ]] || fail "a further segment is named as one"
[[ "$(cov_row "$tsv" inputs/phone.tar)" == *"|catalogued|under catalog/phone.tar/ by computer-forensics-base/archive-members:complete" ]] \
  || fail "a tar is inventoried by the archive recipe: $(cov_row "$tsv" inputs/phone.tar)"
grep -q $'^0\tfile\tprivate/var/mobile/Library/SMS/sms.db\t' "$COV/sb/catalog/phone.tar/members.tsv" || fail "the tar's member list names sms.db"
grep -q $'^1\tfile\ta\\\\nb\t' "$COV/sb/catalog/phone.tar/members.tsv" || fail "a member name with a newline is one escaped row: $(cat "$COV/sb/catalog/phone.tar/members.tsv")"
[[ "$(cov_row "$tsv" inputs/blob.bin)" == "100000|not catalogued|no recipe of this run applies: "*"archive-members: no tar, zip or 7z structure"* ]] \
  || fail "an input no recipe reads is named as not catalogued, with each recipe's why: $(cov_row "$tsv" inputs/blob.bin)"
[[ "$(cov_row "$tsv" inputs/CASE.md)" == "10|not probed|under 64 KB"* ]] || fail "a small input is named as not probed"
# (awk -v reads escapes, so the literal backslash-t is written \\t here.)
[[ "$(cov_row "$tsv" 'inputs/notes/odd\\tname.txt')" == "2|not probed|"* ]] || fail "a tab in a file name is written escaped, on one row: $(grep odd "$tsv")"
grep -q '^Summary: 1 disk image(s), 0 memory image(s), 1 archive(s), [0-9]* catalog file(s); 26 input file(s): 1 catalogued, 1 partial, 0 planned, 1 segment(s) of a set, 1 not catalogued, 22 not probed$' "$readme" \
  || fail "the summary line should count by what the recipes catalogue and the inputs by status: $(head -1 "$readme")"
grep -q '^- `inputs/blob.bin` (97.7 KB): no recipe of this run applies' "$readme" || fail "the index should name blob.bin under Not catalogued"
grep -q '^- and 2 more, every one in `catalog/coverage.tsv`$' "$readme" || fail "past twenty, the index names how many more and where they all are"
grep -q '^| `catalog/phone.tar/members.tsv` | ' "$readme" || fail "the index lists the tar's member list: $(cat "$readme")"
pass "every input has a coverage row, a tar is inventoried, and the index names what was not catalogued"

# A failed step's stderr is kept whole and named; the index quotes its start.
err="$COV/sb/catalog/disk.E01/p2048/bodyfile.txt.stderr"
[[ -f "$err" ]] || fail "fls's stderr should be kept beside its output"
[[ "$(wc -l < "$err" | tr -d ' ')" -eq 40 ]] || fail "all forty lines of fls's stderr should be kept: $(wc -l < "$err")"
grep -q 'computer-forensics-base/disk-volumes on inputs/disk.E01 (catalog/disk.E01/): fls body file at sector 2048: failed (exit 1: fls: Error reading MFT entry 1: .*; all of stderr: p2048/bodyfile.txt.stderr)' "$readme" \
  || fail "the Not built note should say which recipe, which input and which file holds all of stderr: $(cat "$readme")"
grep -q '^| `catalog/disk.E01/p2048/bodyfile.txt.stderr` | what the step writing p2048/bodyfile.txt said on stderr | 40 |' "$readme" \
  || fail "the index should list the stderr file: $(cat "$readme")"
pass "a failed step's stderr is kept whole beside its output and named in the index"

# A newline in an input's name: one input, one coverage row, one index line.
NL="$TMP/nl"
mkdir -p "$NL/sb/inputs"
head -c 70000 /dev/zero > "$NL/sb/inputs/two"$'\n'"lines.bin"
PATH="/usr/bin:/bin" bash "$ROOT/scripts/evidence-catalog.sh" "$NL/sb" >/dev/null
[[ "$(($(wc -l < "$NL/sb/catalog/coverage.tsv") - 1))" -eq 1 ]] || fail "a name with a newline is one input, one row: $(cat "$NL/sb/catalog/coverage.tsv")"
[[ "$(cov_row "$NL/sb/catalog/coverage.tsv" 'inputs/two\\nlines.bin')" == "70000|not catalogued|"* ]] || fail "the newline is written escaped: $(cat "$NL/sb/catalog/coverage.tsv")"
grep -q '^- `inputs/two\\nlines.bin` (68.4 KB): ' "$NL/sb/catalog/README.md" || fail "the index shows the name escaped, on one line: $(cat "$NL/sb/catalog/README.md")"
pass "an input whose name holds a newline is one input, named escaped"
