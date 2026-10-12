#!/usr/bin/env bash
# Pack recipes: the catalogue procedures a pack ships under recipes/<name>/.
# A pack with one seals it (its entry's sha256 in recipe.json, its id in
# pack.json as <pack>/<name>) and installs; a recipe that is malformed, whose
# entry leaves its directory, or whose auto names a trigger that does not
# exist, keeps the pack from sealing. The shipped computer-forensics-base
# recipes answer the entry protocol.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK="$ROOT/scripts/pack.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
export DFIRSWARM_HOME="$WORK/home"

mk_pack() { # <dir> <id>
  local d="$1/$2"
  mkdir -p "$d/recipes/list-things" "$d/requires"
  echo "Test pack." > "$d/LICENCE"
  echo '{ "binaries": [] }' > "$d/requires/host.json"
  cat > "$d/recipes/list-things/recipe.json" <<'EOF'
{
  "id": "list-things",
  "version": "1.0.0",
  "description": "List things.",
  "object": "thing",
  "runtime": "python3",
  "entry": "run.py",
  "auto": ["derived"],
  "limits": {"seconds": 60},
  "outputs": ["things.tsv"],
  "covers": "The things; not what is inside them."
}
EOF
  printf 'print("{}")\n' > "$d/recipes/list-things/run.py"
  python3 - "$d/pack.json" "$2" <<'EOF'
import json, sys
json.dump({"id": sys.argv[2], "name": sys.argv[2], "version": "1.0.0", "description": "A pack for the suite.",
           "licence": "AGPL-3.0-or-later", "depends": [], "requires": {"host": "requires/host.json"}, "secrets": []},
          open(sys.argv[1], "w"), indent=2)
EOF
}

mkdir -p "$WORK/src"
mk_pack "$WORK/src" rpack
"$PACK" seal "$WORK/src/rpack" >/dev/null || fail "a pack with a well-formed recipe should seal"
[[ "$(jq -c '.recipes' "$WORK/src/rpack/pack.json")" == '["rpack/list-things"]' ]] || fail "pack.json should name the recipe as <pack>/<name>: $(jq -c . "$WORK/src/rpack/pack.json")"
[[ "$(jq -r '.sha256' "$WORK/src/rpack/recipes/list-things/recipe.json")" == "$(shasum -a 256 "$WORK/src/rpack/recipes/list-things/run.py" | cut -d' ' -f1)" ]] \
  || fail "recipe.json should carry its entry's sha256"
"$PACK" install "$WORK/src/rpack" --no-secrets >/dev/null || fail "a sealed pack with a recipe should install"
"$PACK" verify rpack >/dev/null || fail "the installed pack should verify"
pass "a recipe is sealed with its entry's sha256, named <pack>/<name>, and installs"

# A changed entry after sealing is caught by the checksums.
echo '# changed' >> "$WORK/home/packs/rpack/recipes/list-things/run.py"
"$PACK" verify rpack >/dev/null 2>&1 && fail "a recipe changed after sealing should not verify"
pass "a recipe changed after sealing does not verify"

refuse() { # <what> <python that edits recipe.json r in place> <expected error text>
  local d="$WORK/bad-$RANDOM"
  mkdir -p "$d"
  mk_pack "$d" bad
  python3 - "$d/bad/recipes/list-things/recipe.json" "$2" <<'EOF'
import json, sys
p, code = sys.argv[1], sys.argv[2]
r = json.load(open(p))
exec(code)
json.dump(r, open(p, "w"), indent=2)
EOF
  out="$("$PACK" seal "$d/bad" 2>&1)" && fail "$1 should keep the pack from sealing: $out"
  grep -q -- "$3" <<<"$out" || fail "$1: the refusal should say \"$3\": $out"
}
refuse "an entry outside the recipe's directory" 'r["entry"] = "../../pack.json"' "must be a file inside the recipe's directory"
refuse "an absolute entry" 'r["entry"] = "/etc/passwd"' "must be a file inside the recipe's directory"
refuse "a trigger that does not exist" 'r["auto"] = ["always"]' "auto is a list of derived, kickoff"
refuse "a missing covers" 'del r["covers"]' "missing covers"
refuse "a runtime the harness does not run" 'r["runtime"] = "perl"' "runtime must be python3 or bash"
refuse "no time limit" 'r["limits"] = {}' "limits.seconds is a whole number"
refuse "a recipe whose id is not its directory" 'r["id"] = "other"' "declares the id"
refuse "a magic that is not hex bytes" 'r["magic"] = [{"offset": 0, "hex": "zz"}]' "magic is a list of {offset, hex}"
refuse "suffixes that are not a list of names" 'r["suffixes"] = ".tar"' "suffixes is a list of name endings"
# What it prepares (docs/adr/0013): an inventory, or a broad extraction that
# says what it does not hold; one the images cannot run says why, and has no
# trigger.
refuse "a purpose that is neither" 'r["purpose"] = "everything"' "purpose is inventory"
refuse "a broad extraction that lists no exclusions" 'r["purpose"] = "broad_extraction"' "lists its exclusions"
refuse "exclusions on an inventory" 'r["exclusions"] = ["the contents"]' "exclusions belong to a broad extraction"
refuse "a capability that is not a name" 'r.update(purpose="broad_extraction", exclusions=["the contents"], capability="Two Words")' "capability names what a broad extraction prepares"
refuse "an unavailable recipe with a trigger" 'r.update(purpose="broad_extraction", exclusions=["the contents"], unavailable="no program in the images reads it")' "has no auto trigger"
refuse "an unavailable inventory" 'r.update(unavailable="no program in the images reads it", auto=[])' "unavailable is a broad extraction's"
refuse "an unavailable with no why" 'r.update(purpose="broad_extraction", exclusions=["the contents"], unavailable=" ", auto=[])' "unavailable says why"
pass "a malformed recipe keeps the pack from sealing, with the reason"

d="$WORK/broad"; mkdir -p "$d"; mk_pack "$d" bpack
python3 - "$d/bpack/recipes/list-things/recipe.json" <<'EOF2'
import json, sys
r = json.load(open(sys.argv[1]))
r.update(purpose="broad_extraction", capability="thing-records", exclusions=["what no parser reads"], auto=[])
json.dump(r, open(sys.argv[1], "w"), indent=2)
EOF2
"$PACK" seal "$d/bpack" >/dev/null || fail "a broad extraction with its capability and exclusions should seal"
pass "a broad extraction with its capability and exclusions seals"

# The shipped recipes answer the protocol: detect exits 0 or 1 with a why,
# run writes coverage.json and index.tsv.
CFB="$ROOT/packs/computer-forensics-base"
"$PACK" verify "$CFB" >/dev/null 2>&1 || "$PACK" install "$CFB" --no-secrets >/dev/null 2>&1 || true
T="$WORK/proto"; mkdir -p "$T"
python3 - "$T/a.zip" <<'EOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("x.txt", "x")
EOF
for r in archive-members disk-volumes memory-windows; do
  rj="$CFB/recipes/$r/recipe.json"
  [[ -f "$rj" ]] || fail "computer-forensics-base should ship the $r recipe"
  entry="$CFB/recipes/$r/$(jq -r .entry "$rj")"
  rt="$(jq -r .runtime "$rj")"
  v="$("$rt" "$entry" detect --target "{\"paths\": [\"$T/a.zip\"], \"name\": \"inputs/a.zip\"}" 2>/dev/null)"; rc=$?
  [[ "$rc" -eq 0 || "$rc" -eq 1 ]] || fail "$r detect should exit 0 or 1, not $rc: $v"
  jq -e 'has("why")' <<<"$v" >/dev/null || fail "$r detect should say why: $v"
done
python3 "$CFB/recipes/archive-members/run.py" run --target "{\"paths\": [\"$T/a.zip\"]}" --out "$T/out" >/dev/null || fail "archive-members should catalogue a zip"
[[ "$(jq -r .status "$T/out/coverage.json")" == complete && -s "$T/out/index.tsv" && -s "$T/out/members.tsv" ]] || fail "archive-members should write coverage.json, index.tsv and members.tsv"
pass "the shipped recipes answer detect and run as the runner expects"

# disk-timeline, the base pack's broad extraction of a disk image: detect by
# signature alone (an EWF container, a partition table with a partition, a
# filesystem's boot sector), run with stand-ins for log2timeline and psort
# that write what the real ones do, and without them, failed and why. The
# stand-ins keep Plaso's way with its log: where --logfile says, else
# <tool>-<time>.log.gz in the working directory, and a log that cannot be
# written fails the step. On the Belka run the job started in the run's
# directory, read-only in its worker, and both steps failed there; here the
# recipe runs from a read-only directory too.
DT="$CFB/recipes/disk-timeline/run.py"
python3 - "$T" <<'EOF2'
import os, struct, sys
t = sys.argv[1]
open(os.path.join(t, "x.E01"), "wb").write(b"EVF\x09\x0d\x0a\xff\x00" + b"\0" * 70000)
mbr = bytearray(70000)
mbr[446 + 4] = 0x07
struct.pack_into("<I", mbr, 446 + 8, 2048)
struct.pack_into("<I", mbr, 446 + 12, 4096)
mbr[510:512] = b"\x55\xaa"
open(os.path.join(t, "mbr.img"), "wb").write(bytes(mbr))
empty = bytearray(70000)
empty[510:512] = b"\x55\xaa"
open(os.path.join(t, "no-parts.img"), "wb").write(bytes(empty))
EOF2
for f in x.E01 mbr.img; do
  python3 "$DT" detect --target "{\"paths\": [\"$T/$f\"]}" | jq -e '.applies' >/dev/null || fail "disk-timeline should take $f"
done
for f in a.zip no-parts.img zeros.img; do
  [[ -f "$T/$f" ]] || dd if=/dev/zero of="$T/$f" bs=1024 count=0 seek=65536 status=none
  python3 "$DT" detect --target "{\"paths\": [\"$T/$f\"]}" >/dev/null && fail "disk-timeline should turn down $f"
done
mkdir -p "$T/bin"
cat > "$T/bin/log2timeline" <<'L2T'
#!/usr/bin/env bash
log="log2timeline-$(date +%Y%m%dT%H%M%S).log.gz"
while [[ $# -gt 0 ]]; do case "$1" in --storage-file) s="$2"; shift 2;; --logfile) log="$2"; shift 2;; *) shift;; esac; done
echo log 2>/dev/null > "$log" || { echo "OSError: [Errno 30] Read-only file system: '$log'" >&2; exit 1; }
echo plaso > "$s"
L2T
cat > "$T/bin/psort" <<'PSORT'
#!/usr/bin/env bash
log="psort-$(date +%Y%m%dT%H%M%S).log.gz"
while [[ $# -gt 1 ]]; do case "$1" in -w) w="$2"; shift 2;; --logfile) log="$2"; shift 2;; *) shift;; esac; done
echo log 2>/dev/null > "$log" || { echo "OSError: [Errno 30] Read-only file system: '$log'" >&2; exit 1; }
printf "datetime,message\n2024-04-01T00:00:00,x\n" > "$w"
PSORT
chmod +x "$T/bin/log2timeline" "$T/bin/psort"
mkdir -p "$T/ro"; chmod a-w "$T/ro"
(cd "$T/ro" && PATH="$T/bin:$PATH" python3 "$DT" run --target "{\"paths\": [\"$T/x.E01\"]}" --out "$T/dt" >/dev/null); rc=$?
chmod u+w "$T/ro"
[[ "$rc" -eq 0 ]] || fail "disk-timeline should run with log2timeline and psort from a read-only directory: $(cat "$T/dt/coverage.json" 2>/dev/null; cat "$T/dt/"*.stderr 2>/dev/null)"
jq -e '.status == "complete"' "$T/dt/coverage.json" >/dev/null || fail "disk-timeline should say complete: $(cat "$T/dt/coverage.json")"
[[ "$(cut -f1 "$T/dt/index.tsv" | tr '\n' ' ')" == "timeline.plaso timeline.csv " ]] || fail "disk-timeline should index the storage file and the timeline: $(cat "$T/dt/index.tsv")"
[[ -s "$T/dt/log2timeline.log.gz" && -s "$T/dt/psort.log.gz" ]] || fail "disk-timeline should give each Plaso step its log in --out (--logfile): $(ls "$T/dt")"
[[ -z "$(ls -A "$T/ro")" ]] || fail "disk-timeline wrote in the directory it was run from: $(ls -A "$T/ro")"
PY3="$(command -v python3)"
env PATH=/usr/bin:/bin "$PY3" "$DT" run --target "{\"paths\": [\"$T/x.E01\"]}" --out "$T/dt-none" >/dev/null && fail "disk-timeline with no Plaso should fail"
jq -e '.status == "failed" and (.errors[0] | test("log2timeline and psort not on PATH"))' "$T/dt-none/coverage.json" >/dev/null || fail "disk-timeline with no Plaso should say which program is missing: $(cat "$T/dt-none/coverage.json")"
pass "disk-timeline takes a disk image by its signature, writes the timeline and each step's log under --out from a read-only directory, and says failed and why with no Plaso"

# disk-timeline: the evidence's timezone reaches log2timeline when given, an output directory that holds a
# timeline from an earlier run is refused and its files are not taken for this run's, Plaso's own
# processing report is kept when pinfo is there, and `complete` says the pipeline finished.
mkdir -p "$T/bin2"
cp "$T/bin/log2timeline" "$T/bin2/log2timeline"
sed -i.bak 's|^while \[\[ \$# -gt 0 \]\]; do case "\$1" in --storage-file|echo "$*" > "$CALLS_L2T"\nwhile [[ $# -gt 0 ]]; do case "$1" in --storage-file|' "$T/bin2/log2timeline" && rm -f "$T/bin2/log2timeline.bak"
cp "$T/bin/psort" "$T/bin2/psort"
cat > "$T/bin2/pinfo" <<'PINFO'
#!/usr/bin/env bash
echo "Plaso Storage Information"
echo "Warnings generated: 3"
PINFO
chmod +x "$T/bin2/"*
CALLS_L2T="$T/l2t-args.txt" PATH="$T/bin2:$PATH" python3 "$DT" run --target "{\"paths\": [\"$T/x.E01\"], \"timezone\": \"Europe/Istanbul\"}" --out "$T/dt-zone" >/dev/null || fail "disk-timeline with a timezone should run: $(cat "$T/dt-zone/coverage.json" 2>/dev/null)"
grep -q -- '--timezone Europe/Istanbul' "$T/l2t-args.txt" || fail "the evidence's timezone reaches log2timeline: $(cat "$T/l2t-args.txt")"
jq -e '.status == "complete" and .timezone == "Europe/Istanbul" and (.coverage_note | test("does not say every parser read every source"))' "$T/dt-zone/coverage.json" >/dev/null || fail "complete says the pipeline finished, and the zone is stated: $(cat "$T/dt-zone/coverage.json")"
grep -q 'Warnings generated: 3' "$T/dt-zone/pinfo.txt" && cut -f1 "$T/dt-zone/index.tsv" | grep -qx 'pinfo.txt' || fail "Plaso's processing report is kept and indexed"
CALLS_L2T="$T/l2t-args2.txt" PATH="$T/bin2:$PATH" python3 "$DT" run --target "{\"paths\": [\"$T/x.E01\"]}" --out "$T/dt-nozone" >/dev/null
jq -e '.timezone == "not given" and (.timezone_note | test("none given"))' "$T/dt-nozone/coverage.json" >/dev/null || fail "no zone given is said, not assumed to be UTC: $(cat "$T/dt-nozone/coverage.json")"
grep -q -- '--timezone' "$T/l2t-args2.txt" && fail "a zone nobody gave was passed to log2timeline"
# A timeline already in the output directory is not this run's.
mkdir -p "$T/dt-stale" && printf 'old storage' > "$T/dt-stale/timeline.plaso" && printf '{"status": "complete", "earlier": true}' > "$T/dt-stale/coverage.json"
CALLS_L2T="$T/l2t-args3.txt" PATH="$T/bin2:$PATH" python3 "$DT" run --target "{\"paths\": [\"$T/x.E01\"]}" --out "$T/dt-stale" >/dev/null && fail "disk-timeline should refuse an output directory that holds an earlier timeline"
jq -e '.status == "failed" and (.errors[0] | test("already in the output directory"))' "$T/dt-stale/coverage.refused.json" >/dev/null || fail "a stale output directory is refused and said: $(cat "$T/dt-stale/coverage.refused.json")"
jq -e '.earlier == true' "$T/dt-stale/coverage.json" >/dev/null || fail "the earlier run's coverage.json was overwritten by the refusal: $(cat "$T/dt-stale/coverage.json")"
[[ ! -e "$T/l2t-args3.txt" ]] || fail "log2timeline ran over a stale output directory"
[[ "$(cat "$T/dt-stale/timeline.plaso")" == "old storage" ]] || fail "the earlier storage file was touched"
# A log2timeline that exits 0 and writes no storage file leaves no timeline to be taken for the run's.
cat > "$T/bin2/log2timeline" <<'L2T'
#!/usr/bin/env bash
exit 0
L2T
PATH="$T/bin2:$PATH" python3 "$DT" run --target "{\"paths\": [\"$T/x.E01\"]}" --out "$T/dt-nostore" >/dev/null && fail "disk-timeline with no storage file should not be complete"
jq -e '.status == "failed"' "$T/dt-nostore/coverage.json" >/dev/null || fail "no storage file is failed: $(cat "$T/dt-nostore/coverage.json")"
# Two zero exits and two files are not a finished job: a worker Plaso reported killed, an error line in what a step printed or logged,
# and a timeline of no events each make it partial, whatever the exit codes say.
mkdir -p "$T/bin3"
cat > "$T/bin3/log2timeline" <<'L2T'
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do case "$1" in --storage-file) s="$2"; shift 2;; --logfile) log="$2"; shift 2;; *) shift;; esac; done
if [[ -n "$L2T_LOG_LINE" ]]; then printf '%s\n' "$L2T_LOG_LINE" | gzip > "$log"; else echo log > "$log"; fi
echo plaso > "$s"
L2T
cat > "$T/bin3/psort" <<'PSORT'
#!/usr/bin/env bash
while [[ $# -gt 1 ]]; do case "$1" in -w) w="$2"; shift 2;; --logfile) log="$2"; shift 2;; *) shift;; esac; done
echo log > "$log"
[[ -n "$PSORT_STDERR" ]] && printf '%s\n' "$PSORT_STDERR" >&2
[[ -n "$PSORT_STDOUT" ]] && printf '%s\n' "$PSORT_STDOUT"
if [[ -n "$PSORT_EMPTY" ]]; then printf "datetime,message\n" > "$w"; else printf "datetime,message\n2024-04-01T00:00:00,x\n" > "$w"; fi
PSORT
chmod +x "$T/bin3/log2timeline" "$T/bin3/psort"
dt3() { # dt3 <out> : run with the bin3 stubs and whatever environment is set
  PATH="$T/bin3:$PATH" python3 "$DT" run --target "{\"paths\": [\"$T/x.E01\"]}" --out "$1" >/dev/null
}
dt3 "$T/dt-clean" || fail "disk-timeline with Plaso saying nothing wrong should be complete: $(cat "$T/dt-clean/coverage.json")"
jq -e '.status == "complete" and (has("plaso_signals") | not)' "$T/dt-clean/coverage.json" >/dev/null || fail "a clean run is complete: $(cat "$T/dt-clean/coverage.json")"
PSORT_STDERR="[ERROR] Worker killed" dt3 "$T/dt-killed" && fail "a worker Plaso reported killed should not be complete"
jq -e '.status == "partial" and ([.errors[] | select(test("psort.stderr: 1 line.*error.*Worker killed"))] | length == 1) and .plaso_signals[0].file == "psort.stderr"' "$T/dt-killed/coverage.json" >/dev/null || fail "the killed worker is named, with where it was said: $(cat "$T/dt-killed/coverage.json")"
PSORT_STDOUT="Events extracted: 0" PSORT_EMPTY=1 dt3 "$T/dt-zero" && fail "a timeline of no events should not be complete"
jq -e '.status == "partial" and ([.errors[] | select(test("no events were extracted"))] | length == 1) and ([.errors[] | select(test("holds no event"))] | length == 1)' "$T/dt-zero/coverage.json" >/dev/null || fail "zero events is said twice over, by Plaso and by the file: $(cat "$T/dt-zero/coverage.json")"
L2T_LOG_LINE="2024-04-01 [ERROR] Worker 3 killed by the kernel" dt3 "$T/dt-logged" && fail "an error line in the log2timeline log should not be complete"
jq -e '.status == "partial" and .plaso_signals[0].file == "log2timeline.log.gz"' "$T/dt-logged/coverage.json" >/dev/null || fail "an error in the gzip log is found: $(cat "$T/dt-logged/coverage.json")"
pass "disk-timeline passes the evidence's timezone, says when none was given, keeps Plaso's processing report, refuses a stale output directory, and says complete only for a pipeline that finished and said nothing wrong"

# Every recipe of every pack answers detect the two ways the harness asks: the
# kickoff's census gives the target as JSON with a --probe-out directory
# (scripts/evidence_catalog.py), a detect job gives it as a file
# (scripts/job-service.ts). The mobile recipes refused --probe-out with a usage
# error, so at kickoff a phone's tar was never asked about by them.
printf '{"paths": ["%s"], "name": "inputs/a.zip"}' "$T/a.zip" > "$T/target.json"
n=0
for rj in "$ROOT"/packs/*/recipes/*/recipe.json; do
  d="$(dirname "$rj")"
  id="$(basename "$(dirname "$(dirname "$d")")")/$(basename "$d")"
  entry="$d/$(jq -r .entry "$rj")"
  rt="$(jq -r .runtime "$rj")"
  mkdir -p "$T/probe/$n"
  v="$("$rt" "$entry" detect --target "$(cat "$T/target.json")" --probe-out "$T/probe/$n" 2>"$T/probe/$n.err")"; rc=$?
  # Exit 2 is the protocol's "error", and a recipe may use it, with "applies": "unknown", for a probe that could not tell
  # (its reader is not in the image, it timed out): that is not a "does not apply", and the route stays open.
  [[ "$rc" -eq 0 || "$rc" -eq 1 || ( "$rc" -eq 2 && "$(jq -r '.applies' <<<"$v" 2>/dev/null)" == unknown ) ]] || fail "$id detect, asked as the census asks (--probe-out), should exit 0 or 1 (or 2 with applies unknown), not $rc: $v $(cat "$T/probe/$n.err")"
  jq -e 'has("why")' <<<"$v" >/dev/null || fail "$id detect, asked as the census asks, should say why: $v"
  v="$("$rt" "$entry" detect --target "$T/target.json" 2>"$T/probe/$n.err")"; rc=$?
  [[ "$rc" -eq 0 || "$rc" -eq 1 || ( "$rc" -eq 2 && "$(jq -r '.applies' <<<"$v" 2>/dev/null)" == unknown ) ]] || fail "$id detect, asked as a detect job asks (the target in a file), should exit 0 or 1 (or 2 with applies unknown), not $rc: $v $(cat "$T/probe/$n.err")"
  jq -e 'has("why")' <<<"$v" >/dev/null || fail "$id detect, asked as a detect job asks, should say why: $v"
  n=$((n + 1))
done
[[ "$n" -ge 8 ]] || fail "expected every shipped recipe to be asked, asked $n"
pass "every shipped recipe ($n) answers detect as the census asks it, with --probe-out, and as a detect job asks it"

# A tar is opened by its magic, never by trying every decompressor: the LZMA
# one read 64 MiB of zeros as a stream for half a minute, and a disk or memory
# image that starts with zeros is asked about by every tar recipe at kickoff.
# A compressed tar is still read, as a stream.
dd if=/dev/zero of="$T/zeros.img" bs=1024 count=0 seek=65536 status=none
python3 - "$T/one.tar.gz" <<'EOF'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w:gz") as tf:
    info = tarfile.TarInfo("private/var/mobile/Library/SMS/sms.db"); info.size = 3
    tf.addfile(info, io.BytesIO(b"sql"))
EOF
for r in computer-forensics-base/recipes/archive-members mobile-forensics/recipes/ios-filesystem; do
  start=$(date +%s)
  v="$(python3 "$ROOT/packs/$r/run.py" detect --target "{\"paths\": [\"$T/zeros.img\"]}")"; rc=$?
  elapsed=$(( $(date +%s) - start ))
  [[ "$rc" -eq 1 && "$elapsed" -lt 10 ]] || fail "$r should turn down 64 MiB of zeros at once, not in ${elapsed}s (exit $rc): $v"
  python3 "$ROOT/packs/$r/run.py" detect --target "{\"paths\": [\"$T/one.tar.gz\"]}" | jq -e '.applies' >/dev/null \
    || fail "$r should still take a gzip-compressed tar"
done
python3 "$ROOT/packs/mobile-forensics/recipes/ios-filesystem/run.py" run --target "{\"paths\": [\"$T/one.tar.gz\"]}" --out "$T/ios-gz" >/dev/null \
  && jq -e '.status == "complete" and .categories.communications == 1' "$T/ios-gz/coverage.json" >/dev/null \
  || fail "ios-filesystem should catalogue a gzip-compressed tar: $(cat "$T/ios-gz/coverage.json" 2>/dev/null)"
pass "archive-members and ios-filesystem turn down a file of zeros at once and still read a compressed tar"

# Hostile archives: names that climb out, absolute names, duplicates, links,
# a zip bomb's ratio, an encrypted member, a truncated tar and a central
# directory that declares more members than the limit.
H="$WORK/hostile"; mkdir -p "$H"
python3 - "$H" <<'PY'
import io, os, struct, sys, tarfile, zipfile
d = sys.argv[1]
def add(tf, name, data=b"x", typ=tarfile.REGTYPE, link=""):
    ti = tarfile.TarInfo(name); ti.type = typ; ti.linkname = link; ti.mtime = 1700000000
    ti.size = len(data) if typ == tarfile.REGTYPE else 0
    tf.addfile(ti, io.BytesIO(data) if typ == tarfile.REGTYPE else None)
with tarfile.open(os.path.join(d, "evil.tar"), "w", encoding="utf-8", errors="surrogateescape") as tf:
    add(tf, "../../etc/cron.d/x"); add(tf, "/abs/path"); add(tf, "dup"); add(tf, "dup", b"yy")
    add(tf, b"caf\xe9.txt".decode("utf-8", "surrogateescape"))
    add(tf, "ln", typ=tarfile.SYMTYPE, link="/etc/shadow")
open(os.path.join(d, "cut.tar"), "wb").write(open(os.path.join(d, "evil.tar"), "rb").read()[:2000])
with zipfile.ZipFile(os.path.join(d, "bomb.zip"), "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.writestr("zeros.bin", b"\0" * 20_000_000)
    z.writestr("..\\windows\\evil.dll", b"MZ")
# An encrypted member: the flag bit set by hand on a stored entry.
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("secret.txt", b"hidden")
raw = bytearray(buf.getvalue())
for sig in (b"PK\x03\x04", b"PK\x01\x02"):
    i = raw.find(sig)
    off = 6 if sig == b"PK\x03\x04" else 8
    flags = struct.unpack_from("<H", raw, i + off)[0] | 1
    struct.pack_into("<H", raw, i + off, flags)
open(os.path.join(d, "enc.zip"), "wb").write(bytes(raw))
with zipfile.ZipFile(os.path.join(d, "many.zip"), "w") as z:
    for i in range(30):
        z.writestr("f%02d" % i, b"")
PY
AM="$ROOT/packs/computer-forensics-base/recipes/archive-members/run.py"
run_am() { python3 "$AM" run --target "{\"paths\": [\"$H/$1\"]}" --out "$H/out-$1" >/dev/null; }
run_am evil.tar
flags_of() { awk -F'\t' -v p="$2" '$3 == p { print $14 }' "$H/out-$1/members.tsv"; }
[[ "$(flags_of evil.tar '../../etc/cron.d/x')" == escapes-root ]] || fail "a name that climbs out should be flagged: $(cat "$H/out-evil.tar/members.tsv")"
[[ "$(flags_of evil.tar '/abs/path')" == escapes-root ]] || fail "an absolute name should be flagged"
[[ "$(awk -F'\t' '$3 == "dup"' "$H/out-evil.tar/members.tsv" | wc -l | tr -d ' ')" -eq 2 ]] || fail "duplicate names are two rows"
[[ "$(awk -F'\t' '$3 == "ln" { print $2 "|" $12 }' "$H/out-evil.tar/members.tsv")" == "symlink|/etc/shadow" ]] || fail "a link is listed as one, with its target, never followed"
[[ "$(awk -F'\t' '$4 == "Y2Fm6S50eHQ=" { print $14 }' "$H/out-evil.tar/members.tsv")" == name-not-utf8 ]] || fail "a member name that is not UTF-8 is flagged: $(cat "$H/out-evil.tar/members.tsv")"
run_am cut.tar || true
[[ "$(jq -r .status "$H/out-cut.tar/coverage.json")" == partial ]] || fail "a truncated tar is partial: $(cat "$H/out-cut.tar/coverage.json")"
run_am bomb.zip
[[ "$(flags_of bomb.zip zeros.bin)" == 'ratio>1000' ]] || fail "a zip bomb's ratio is flagged: $(cat "$H/out-bomb.zip/members.tsv")"
# (the shown name escapes each backslash, and awk -v reads escapes once more)
[[ "$(flags_of bomb.zip '..\\\\windows\\\\evil.dll')" == escapes-root ]] || fail "a backslash path that climbs out is flagged: $(cat "$H/out-bomb.zip/members.tsv")"
[[ ! -e "$H/out-bomb.zip/zeros.bin" ]] || fail "nothing is extracted"
run_am enc.zip
[[ "$(flags_of enc.zip secret.txt)" == encrypted ]] || fail "an encrypted member is flagged: $(cat "$H/out-enc.zip/members.tsv")"
RECIPE_MEMBERS=10 python3 "$AM" run --target "{\"paths\": [\"$H/many.zip\"]}" --out "$H/out-many" >/dev/null || true
jq -e '.limits_hit[0] | test("declares 30, more than the limit of 10")' "$H/out-many/coverage.json" >/dev/null || fail "a directory past the limit is not loaded, and says so: $(cat "$H/out-many/coverage.json")"
RECIPE_ZIP_DIRECTORY_BYTES=100 python3 "$AM" run --target "{\"paths\": [\"$H/many.zip\"]}" --out "$H/out-many-bytes" >/dev/null || true
jq -e '.limits_hit[0] | test("the central directory is [0-9]+ bytes, more than the limit of 100")' "$H/out-many-bytes/coverage.json" >/dev/null || fail "a directory past the byte limit is not loaded, and says so: $(cat "$H/out-many-bytes/coverage.json")"
pass "hostile archives are listed as data: escapes, duplicates, links, bombs, encryption, truncation, a name that is not UTF-8 and limits by count and by bytes, each named"

# A volume with no partition table in front of it, at sector 2048 (as a
# volume carved out of a disk keeps its offset): detected and catalogued there.
if command -v fsstat >/dev/null && command -v fls >/dev/null; then
  python3 - "$H/off2048.img" <<'PY'
import struct, sys
bs = bytearray(512)
bs[0:3] = b"\xeb\x3c\x90"; bs[3:11] = b"MSDOS5.0"
struct.pack_into("<HBHBHHBHHHII", bs, 11, 512, 1, 1, 2, 224, 2880, 0xF0, 9, 18, 2, 0, 0)
bs[38] = 0x29; bs[43:54] = b"NO NAME    "; bs[54:62] = b"FAT12   "; bs[510:512] = b"\x55\xaa"
img = bytearray(2880 * 512); img[0:512] = bs
for f in (1, 10): img[f * 512:f * 512 + 3] = b"\xf0\xff\xff"
open(sys.argv[1], "wb").write(b"\0" * (2048 * 512) + img)
PY
  DV="$ROOT/packs/computer-forensics-base/recipes/disk-volumes/run.sh"
  bash "$DV" detect --target "{\"paths\": [\"$H/off2048.img\"], \"name\": \"off.img\"}" | jq -e '.applies and (.why | test("sector 2048"))' >/dev/null || fail "a volume at sector 2048 with no table should be detected"
  bash "$DV" run --target "{\"paths\": [\"$H/off2048.img\"], \"name\": \"off.img\"}" --out "$H/out-off" >/dev/null || fail "and catalogued"
  [[ "$(jq -r .status "$H/out-off/coverage.json")" == complete && -f "$H/out-off/p2048/filelist.txt" ]] || fail "the volume at 2048 is listed: $(cat "$H/out-off/coverage.json")"
  pass "a volume at sector 2048 with no partition table is detected and catalogued there"
fi

# disk-volumes reads the rows of a partition table as mmls prints them: an
# extended partition is a container and swap holds no filesystem, so neither
# is a candidate ("DOS Extended" used to match `*Ext*`), an LVM physical volume
# is named as a layer, and only a row fsstat reads is a volume. Stub TSK
# programs, so this runs on any host.
mkdir -p "$H/tsk-shim"
cat > "$H/tsk-shim/mmls" <<'SH'
#!/bin/sh
cat <<'T'
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0001050623   0001048576   Linux (0x83)
003:  000:001   0001050624   0020969471   0019918848   DOS Extended (0x05)
004:  Meta      0001050624   0001050624   0000000001   Extended Table (#1)
005:  001:000   0001052672   0001060000   0000007329   Linux Swap / Solaris x86 (0x82)
006:  002:000   0001062912   0020969471   0019906560   Linux Logical Volume Manager (0x8e)
T
SH
cat > "$H/tsk-shim/fsstat" <<'SH'
#!/bin/sh
[ "$2" = 2048 ] || { echo "Cannot determine file system type" >&2; exit 1; }
echo "File System Type: Ext4"
SH
cat > "$H/tsk-shim/fls" <<'SH'
#!/bin/sh
case "$1" in -m) echo "0|/etc/hostname|12|r/rrw-r--r--|0|0|9|0|0|0|0" ;; *) echo "r/r 12:	etc/hostname" ;; esac
SH
chmod +x "$H/tsk-shim/"*
: > "$H/lvm.img"
PATH="$H/tsk-shim:$PATH" bash "$ROOT/packs/computer-forensics-base/recipes/disk-volumes/run.sh" run --target "{\"paths\": [\"$H/lvm.img\"], \"name\": \"lvm.img\"}" --out "$H/out-lvm" > "$H/out-lvm.json" || true
jq -e '.volumes == 1 and .candidate_volumes == 1' "$H/out-lvm.json" >/dev/null || fail "one Linux row is the one candidate and the one volume; the extended container, swap and LVM are not: $(cat "$H/out-lvm.json")"
[[ ! -d "$H/out-lvm/p1050624" && ! -d "$H/out-lvm/p1052672" ]] || fail "the extended container and swap were read as filesystems"
jq -e '.status == "partial" and ([.errors[] | select(test("LVM physical volume at sector 1062912"))] | length == 1) and ([.errors[] | select(test("1050624|1052672"))] | length == 0)' "$H/out-lvm/coverage.json" >/dev/null || fail "the LVM layer is named and nothing else: $(cat "$H/out-lvm/coverage.json")"
pass "disk-volumes takes no extended container or swap for a filesystem, names an LVM volume as a layer, and counts the row fsstat reads"

# disk-volumes inventories every allocated partition entry and what became of it. A description that
# was on no list used to be skipped without a word and the run said complete; it is tried now, and
# fsstat says whether a file system is there. What holds no file system by definition (an extended
# partition, swap, a Microsoft reserved or BIOS boot partition) is named and not counted against
# coverage. mactime gets the zone the timeline says (UTC), and coverage is partial before any step ends.
mkdir -p "$H/tsk-shim2" "$H/mt-shim"
cat > "$H/tsk-shim2/mmls" <<'SH'
#!/bin/sh
cat <<'T'
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000       0000002048   0001050623   0001048576   Basic data partition
003:  001       0001050624   0001083391   0000032768   Microsoft reserved partition
004:  002       0001083392   0001100000   0000016609   Unknown Type (0x99)
005:  003       0001100001   0001200000   0000100000   BIOS Boot Partition
T
SH
cat > "$H/tsk-shim2/fsstat" <<'SH'
#!/bin/sh
echo "fsstat $*" >> "$TSK_CALLS"
[ -f "$OUT_COVERAGE" ] && [ ! -f "$FIRST_COVERAGE" ] && cp "$OUT_COVERAGE" "$FIRST_COVERAGE"
[ "$2" = 2048 ] || { echo "Cannot determine file system type" >&2; exit 1; }
echo "File System Type: NTFS"
SH
cat > "$H/tsk-shim2/fls" <<'SH'
#!/bin/sh
case "$1" in -m) echo "0|/a.txt|12|r/rrw-r--r--|0|0|9|1700000000|1700000000|1700000000|1700000000" ;; *) printf 'r/r 12:\ta.txt\n' ;; esac
SH
cat > "$H/mt-shim/mactime" <<'SH'
#!/bin/sh
echo "mactime TZ=$TZ $*" >> "$TSK_CALLS"
echo "Date,Size,Type,Mode,UID,GID,Meta,File Name"
SH
chmod +x "$H/tsk-shim2/"* "$H/mt-shim/"*
: > "$H/gpt.img"
DVR="$ROOT/packs/computer-forensics-base/recipes/disk-volumes/run.sh"
TSK_CALLS="$H/tsk-calls.log" OUT_COVERAGE="$H/out-gpt/coverage.json" FIRST_COVERAGE="$H/first-coverage.json" PATH="$H/tsk-shim2:$H/mt-shim:$PATH" \
  bash "$DVR" run --target "{\"paths\": [\"$H/gpt.img\"], \"name\": \"gpt.img\"}" --out "$H/out-gpt" > "$H/out-gpt.json" || true
jq -e '.status == "partial" and ([.inventory[] | {(.description): .outcome}] | add) == {"Basic data partition": "read", "Microsoft reserved partition": "structural", "Unknown Type (0x99)": "failed", "BIOS Boot Partition": "structural"}' "$H/out-gpt/coverage.json" >/dev/null \
  || fail "every allocated entry is in the inventory with what became of it, an unlisted description is tried (and fails here), and what holds no file system is structural: $(cat "$H/out-gpt/coverage.json")"
jq -e '[.errors[] | select(test("1083392"))] | length == 1' "$H/out-gpt/coverage.json" >/dev/null || fail "the entry that could not be read is named once in the errors: $(cat "$H/out-gpt/coverage.json")"
[[ "$(grep -c '^fsstat -o 1083392 ' "$H/tsk-calls.log")" -ge 1 ]] || fail "an unlisted description is tried with fsstat, not skipped: $(cat "$H/tsk-calls.log")"
[[ ! -d "$H/out-gpt/p1050624" && ! -d "$H/out-gpt/p1100001" ]] || fail "a structural entry was catalogued as a file system"
jq -e '.status == "partial" and (.covered | test("started"))' "$H/first-coverage.json" >/dev/null || fail "coverage says partial before the first step finishes: $(cat "$H/first-coverage.json")"
grep -q 'mactime TZ=UTC .* -z UTC' "$H/tsk-calls.log" || fail "mactime is given the zone its timeline says: $(cat "$H/tsk-calls.log")"
# With nothing left unread the same table is complete, and a missing mactime is said, not skipped.
sed -i.bak '/Unknown Type/d' "$H/tsk-shim2/mmls" && rm -f "$H/tsk-shim2/mmls.bak"
TSK_CALLS="$H/tsk-calls2.log" OUT_COVERAGE=/nonexistent FIRST_COVERAGE=/nonexistent PATH="$H/tsk-shim2:$H/mt-shim:$PATH" \
  bash "$DVR" run --target "{\"paths\": [\"$H/gpt.img\"], \"name\": \"gpt.img\"}" --out "$H/out-gpt2" >/dev/null || fail "disk-volumes with nothing unread should run"
[[ "$(jq -r .status "$H/out-gpt2/coverage.json")" == complete ]] || fail "a table whose every entry was read or is structural is complete: $(cat "$H/out-gpt2/coverage.json")"
rm -f "$H/mt-shim/mactime"
TSK_CALLS="$H/tsk-calls3.log" OUT_COVERAGE=/nonexistent FIRST_COVERAGE=/nonexistent PATH="$H/tsk-shim2:$H/mt-shim:/usr/bin:/bin" \
  bash "$DVR" run --target "{\"paths\": [\"$H/gpt.img\"], \"name\": \"gpt.img\"}" --out "$H/out-gpt3" >/dev/null || true
if ! PATH="$H/mt-shim:/usr/bin:/bin" command -v mactime >/dev/null; then
  jq -e '.status == "partial" and ([.errors[] | select(test("mactime missing"))] | length == 1)' "$H/out-gpt3/coverage.json" >/dev/null || fail "a missing mactime is said: $(cat "$H/out-gpt3/coverage.json")"
fi
pass "disk-volumes inventories every allocated entry, tries what no list names, names what holds no file system, sets the zone its timeline says, and writes coverage before its first step"

# A description is the table's word, not what is in the partition: an entry the table calls swap, a reserved
# area, LVM or RAID is first asked of fsstat, and is classed by its name only when fsstat reads nothing there.
mkdir -p "$H/tsk-shim3"
cat > "$H/tsk-shim3/mmls" <<'SH'
#!/bin/sh
cat <<'T'
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  000:000   0000002048   0001050623   0001048576   Linux Swap / Solaris x86 (0x82)
002:  000:001   0001050624   0002099199   0001048576   Linux Logical Volume Manager (0x8e)
003:  000:002   0002099200   0003147775   0001048576   Linux Logical Volume Manager (0x8e)
T
SH
cat > "$H/tsk-shim3/fsstat" <<'SH'
#!/bin/sh
case "$2" in 2048|1050624) echo "File System Type: Ext4" ;; *) echo "Cannot determine file system type" >&2; exit 1 ;; esac
SH
cp "$H/tsk-shim/fls" "$H/tsk-shim3/fls"
chmod +x "$H/tsk-shim3/"*
: > "$H/mislabel.img"
PATH="$H/tsk-shim3:$PATH" bash "$DVR" run --target "{\"paths\": [\"$H/mislabel.img\"], \"name\": \"mislabel.img\"}" --out "$H/out-mislabel" > "$H/out-mislabel.json" || true
jq -e '.volumes == 2' "$H/out-mislabel.json" >/dev/null || fail "a swap-labelled and an LVM-labelled entry that fsstat reads are volumes: $(cat "$H/out-mislabel.json")"
jq -e '([.inventory[] | {(.description): .outcome}] | add) as $o | ($o["Linux Swap / Solaris x86 (0x82)"] == "read") and (.inventory | map(select(.start_sector == 2099200))[0].outcome == "unsupported")' "$H/out-mislabel/coverage.json" >/dev/null \
  || fail "the name decides only where fsstat read nothing: $(cat "$H/out-mislabel/coverage.json")"
pass "disk-volumes asks fsstat before it believes a partition's description"

# Without its value a flag ends the run with an error; it used to loop for ever (`shift 2` shifts nothing with one word left).
for rc in disk-volumes memory-windows; do
  R="$ROOT/packs/computer-forensics-base/recipes/$rc/run.sh"
  for flag in --target --out --probe-out; do
    code=0; perl -e 'alarm 20; exec @ARGV' bash "$R" run "$flag" > "$H/noval.json" 2>&1 || code=$?
    [[ "$code" -eq 2 ]] || fail "$rc $flag with no value should exit 2, not $code (142 is the loop): $(cat "$H/noval.json")"
    jq -e '.ok == false and (.error | test("needs a value"))' "$H/noval.json" >/dev/null || fail "$rc $flag says it needs a value: $(cat "$H/noval.json")"
  done
done
pass "disk-volumes and memory-windows end with an error when a flag has no value"

# With no partition table, the fsstat tries are time-boxed like every other step, a mmls that does not finish is said,
# and what mmls said on stderr is kept.
mkdir -p "$H/tsk-hang" "$H/tsk-notable"
cat > "$H/tsk-hang/mmls" <<'SH'
#!/bin/sh
exec sleep 30
SH
cat > "$H/tsk-hang/fsstat" <<'SH'
#!/bin/sh
exec sleep 30
SH
cat > "$H/tsk-notable/mmls" <<'SH'
#!/bin/sh
echo "Cannot determine partition type" >&2
exit 1
SH
cat > "$H/tsk-notable/fsstat" <<'SH'
#!/bin/sh
[ "$1" = "-o" ] && [ "$2" != 0 ] && { echo "Cannot determine file system type" >&2; exit 1; }
echo "File System Type: Ext4"
SH
cp "$H/tsk-shim/fls" "$H/tsk-hang/fls"; cp "$H/tsk-shim/fls" "$H/tsk-notable/fls"
# mactime too: the recipe runs it over the body file, and a host without The Sleuth Kit (CI) has none to run.
for d in tsk-hang tsk-notable; do
  printf '#!/bin/sh\necho "Date,Size,Type,Mode,UID,GID,Meta,File Name"\n' > "$H/$d/mactime"
done
chmod +x "$H/tsk-hang/"* "$H/tsk-notable/"*
: > "$H/hang.img"
began=$SECONDS
RECIPE_STEP_SECONDS=1 PATH="$H/tsk-hang:$PATH" perl -e 'alarm 60; exec @ARGV' bash "$DVR" run --target "{\"paths\": [\"$H/hang.img\"], \"name\": \"hang.img\"}" --out "$H/out-hang" > "$H/out-hang.json" 2>&1 || true
[[ $((SECONDS - began)) -lt 30 ]] || fail "a fsstat that does not answer was not time-boxed in the no-table branch ($((SECONDS - began)) seconds)"
jq -e '.status == "unsupported" and ([.errors[] | select(test("mmls did not finish"))] | length == 1)' "$H/out-hang/coverage.json" >/dev/null || fail "a mmls that did not finish is said: $(cat "$H/out-hang/coverage.json")"
PATH="$H/tsk-notable:$PATH" bash "$DVR" run --target "{\"paths\": [\"$H/hang.img\"], \"name\": \"notable.img\"}" --out "$H/out-notable" > "$H/out-notable.json" || fail "a raw volume with no table should run: $(cat "$H/out-notable.json")"
grep -q "Cannot determine partition type" "$H/out-notable/mmls.stderr" || fail "what mmls said is kept: $(ls "$H/out-notable")"
grep -q "^mmls.stderr" "$H/out-notable/index.tsv" || fail "and is in the index: $(cat "$H/out-notable/index.tsv")"
[[ "$(jq -r .status "$H/out-notable/coverage.json")" == complete ]] || fail "no table is not a failure for a volume that is one: $(cat "$H/out-notable/coverage.json")"
pass "disk-volumes time-boxes the no-table fsstat tries, says a mmls that did not finish, and keeps what mmls said"

# A 7z that exits nonzero is an error whether or not it said anything on stderr (it was recorded only when it had),
# and the recipe no longer advertises .tar.zst, which it cannot read. A stub 7z, so this runs on any host.
mkdir -p "$H/seven-stub"
cat > "$H/seven-stub/7z" <<'SH'
#!/bin/sh
printf 'Path = a.txt\nSize = 1\nPacked Size = 1\n\n'
exit 2
SH
chmod +x "$H/seven-stub/7z"
printf '7z\274\257\047\034' > "$H/silent.7z"; head -c 4096 /dev/zero >> "$H/silent.7z"
PATH="$H/seven-stub:$PATH" python3 "$AM" run --target "{\"paths\": [\"$H/silent.7z\"]}" --out "$H/out-7z-silent" >/dev/null || true
jq -e '.status == "partial" and (.errors | length == 1) and (.errors[0] | test("^7z exited 2 with nothing on stderr"))' "$H/out-7z-silent/coverage.json" >/dev/null || fail "a 7z that exits nonzero with nothing on stderr is an error: $(cat "$H/out-7z-silent/coverage.json")"
jq -e '(.suffixes | index(".tar.zst")) == null' "$CFB/recipes/archive-members/recipe.json" >/dev/null || fail "archive-members advertises .tar.zst, which it cannot read"
grep -rn "archive_extract takes\|is extracted with archive_extract" "$CFB/recipes/archive-members" >/dev/null && fail "archive-members still promises an extractor the pack does not ship"
pass "archive-members records a silent nonzero 7z exit, advertises no .tar.zst and promises no extractor the pack does not ship"

# memory-windows reads the symbol tables the image holds and fetches nothing:
# every Volatility call carries --offline. An image with no table for its
# kernel stops the run after one windows.info call, with the kernel named as
# missing and coverage partial, and no plugin is run. A stub vol that logs every
# call, so this runs on any host. The stub answers a call WITHOUT --offline as
# a reachable symbol server would (success), so a recipe that retried online
# would show as a second call and as a complete run.
mkdir -p "$H/vol-shim"
cat > "$H/vol-shim/vol" <<'SH'
#!/bin/sh
[ -n "$VOL_STUB_LOG" ] && printf '%s\n' "$*" >> "$VOL_STUB_LOG"
offline=0; for a in "$@"; do [ "$a" = --offline ] && offline=1; last="$a"; done
if [ "$offline" = 1 ] && [ -n "$VOL_STUB_NO_SYMBOLS" ]; then
  # What Volatility prints offline for a kernel whose table the image lacks (the
  # PDB, GUID and age are the ones in its automagic message).
  echo "WARNING  volatility3.framework.plugins: Automagic exception occurred: volatility3.framework.exceptions.OfflineException: Volatility 3 is offline: unable to access http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/0123456789ABCDEF0123456789ABCDEFA/ntkrnlmp.pdb" >&2
  echo "Unsatisfied requirement plugins.Info.kernel.symbol_table_name" >&2; exit 1
fi
[ -n "$VOL_STUB_FAIL_INFO" ] && [ "$last" = windows.info ] && { echo "the token was not ok, look" >&2; exit 1; }
[ -n "$VOL_STUB_SNAPSHOT" ] && [ "$last" = windows.cmdline ] && cp "$VOL_STUB_SNAPSHOT/coverage.json" "$VOL_STUB_SNAPSHOT/at-cmdline.json"
case "$last" in windows.info) printf 'Variable\tValue\nKernel Base\t0xf80000000000\n' ;; *) printf 'PID\tImageFileName\n4\tSystem\n' ;; esac
SH
chmod +x "$H/vol-shim/vol"
: > "$H/win.mem"
MW="$ROOT/packs/computer-forensics-base/recipes/memory-windows/run.sh"
VOL_STUB_LOG="$H/vol-calls-1.log" PATH="$H/vol-shim:$PATH" bash "$MW" run --target "{\"paths\": [\"$H/win.mem\"], \"name\": \"win.mem\"}" --out "$H/out-mw" >/dev/null || fail "memory-windows with the image's symbols should run"
jq -e '.status == "complete" and (.covered | test("symbols held in the image")) and (.steps | length == 12) and ([.steps[].exit] | all(. == 0))' "$H/out-mw/coverage.json" >/dev/null || fail "with the image's symbols, coverage says so and has one record per step: $(cat "$H/out-mw/coverage.json")"
[[ "$(wc -l < "$H/vol-calls-1.log")" -eq 12 ]] && ! grep -v -- '--offline' "$H/vol-calls-1.log" | grep -q . || fail "every Volatility call carries --offline: $(cat "$H/vol-calls-1.log")"
jq -e '(.steps[0].step == "windows.info.txt") and (.steps[0].argv | index("--offline")) and (.steps[0] | has("seconds") and has("limit_seconds") and has("output"))' "$H/out-mw/coverage.json" >/dev/null || fail "a step's record names its command, duration and output: $(cat "$H/out-mw/coverage.json")"
VOL_STUB_NO_SYMBOLS=1 VOL_STUB_LOG="$H/vol-calls-2.log" PATH="$H/vol-shim:$PATH" bash "$MW" run --target "{\"paths\": [\"$H/win.mem\"], \"name\": \"win.mem\"}" --out "$H/out-mw2" > "$H/out-mw2.json" || fail "memory-windows without the image's symbols should end partial, not fail: $(cat "$H/out-mw2.json")"
[[ "$(wc -l < "$H/vol-calls-2.log")" -eq 1 ]] || fail "without the image's symbols there is exactly one Volatility call, the offline windows.info; a second one is an online retry: $(cat "$H/vol-calls-2.log")"
grep -q -- '--offline' "$H/vol-calls-2.log" && grep -q 'windows.info' "$H/vol-calls-2.log" || fail "the one call is the offline windows.info: $(cat "$H/vol-calls-2.log")"
jq -e '.status == "partial" and (.covered | test("no symbol table for this kernel in the image")) and .missing[0].kind == "symbols" and .missing[0].identity == {"pdb": "ntkrnlmp.pdb", "guid": "0123456789ABCDEF0123456789ABCDEF", "age": 10} and (.errors | length >= 1) and (.steps | length == 1) and .steps[0].exit == 1' "$H/out-mw2/coverage.json" >/dev/null || fail "an image with no table is partial and names the kernel's PDB, GUID and age: $(cat "$H/out-mw2/coverage.json")"
jq -e '.ok == true and .status == "partial" and .missing[0].identity.pdb == "ntkrnlmp.pdb"' "$H/out-mw2.json" >/dev/null || fail "the run says partial and names what is missing: $(cat "$H/out-mw2.json")"
grep -q symbol_table_name "$H/out-mw2/windows.info.txt.stderr" && grep -q '^windows.info.txt.stderr' "$H/out-mw2/index.tsv" || fail "the offline attempt is kept and indexed"
[[ ! -e "$H/out-mw2/pslist.txt" && ! -e "$H/out-mw2/offline.windows.info.txt.stderr" ]] || fail "no plugin ran and nothing was fetched into the output"
# What windows.info said when it failed is in the note whole (a substring replace once mangled any "ok" in it), and a run stopped
# part way leaves a coverage file that says how far it got, not that nothing had finished.
VOL_STUB_FAIL_INFO=1 PATH="$H/vol-shim:$PATH" bash "$MW" run --target "{\"paths\": [\"$H/win.mem\"], \"name\": \"win.mem\"}" --out "$H/out-mw3" > "$H/out-mw3.json" || true
jq -e '.status == "failed" and ([.errors[] | select(test("the token was not ok, look"))] | length == 1)' "$H/out-mw3/coverage.json" >/dev/null || fail "the failure's words come back whole: $(cat "$H/out-mw3/coverage.json")"
mkdir -p "$H/out-mw4"
VOL_STUB_SNAPSHOT="$H/out-mw4" PATH="$H/vol-shim:$PATH" bash "$MW" run --target "{\"paths\": [\"$H/win.mem\"], \"name\": \"win.mem\"}" --out "$H/out-mw4" >/dev/null || fail "memory-windows with a snapshot stub should run"
jq -e '.status == "partial" and (.covered | test("windows.info and 3 of eleven plugins have finished")) and (.steps | length == 4)' "$H/out-mw4/at-cmdline.json" >/dev/null || fail "coverage is rewritten after each step: $(cat "$H/out-mw4/at-cmdline.json")"
pass "memory-windows reads the image's symbol tables offline at every step, never retries online, ends partial with the kernel named as missing when the image has none, and keeps one record per step"

# 7z, read as its listing streams, with the member limit applied as it goes.
SEVEN="$(command -v 7z || command -v 7zz || true)"
if [[ -n "$SEVEN" ]]; then
  mkdir -p "$H/shim" "$H/s7"
  ln -sf "$SEVEN" "$H/shim/7z"
  for i in 1 2 3; do printf 'member %s\n' "$i" > "$H/s7/m$i.txt"; done
  ( cd "$H/s7" && "$SEVEN" a -bd -y ../three.7z m1.txt m2.txt m3.txt >/dev/null )
  PATH="$H/shim:$PATH" python3 "$AM" run --target "{\"paths\": [\"$H/three.7z\"]}" --out "$H/out-7z" >/dev/null || fail "a 7z should be listed"
  [[ "$(jq -r '.status + " " + (.members|tostring)' "$H/out-7z/coverage.json")" == "complete 3" ]] || fail "a 7z's three members are listed: $(cat "$H/out-7z/coverage.json")"
  [[ "$(awk -F'\t' 'NR > 1 { print $3 }' "$H/out-7z/members.tsv" | sort | tr '\n' ' ')" == "m1.txt m2.txt m3.txt " ]] || fail "the 7z's member names: $(cat "$H/out-7z/members.tsv")"
  RECIPE_MEMBERS=2 PATH="$H/shim:$PATH" python3 "$AM" run --target "{\"paths\": [\"$H/three.7z\"]}" --out "$H/out-7z-2" >/dev/null || true
  jq -e '.status == "partial" and .members == 2 and (.limits_hit[0] == "members: stopped at 2")' "$H/out-7z-2/coverage.json" >/dev/null || fail "a 7z past the member limit stops there and says so: $(cat "$H/out-7z-2/coverage.json")"
  pass "a 7z is listed as its listing streams, and stops at the member limit, saying so"
else
  echo "skip - no 7z or 7zz on this host"
fi
