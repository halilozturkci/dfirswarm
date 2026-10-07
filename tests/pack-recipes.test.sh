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

# memory-windows reads with the image's symbols first, and asks the symbol
# server only when the image has none for the kernel: coverage says which, and
# the offline attempt is kept. A stub vol, so this runs on any host.
mkdir -p "$H/vol-shim"
cat > "$H/vol-shim/vol" <<'SH'
#!/bin/sh
offline=0; for a in "$@"; do [ "$a" = --offline ] && offline=1; last="$a"; done
if [ "$offline" = 1 ] && [ -n "$VOL_STUB_NO_SYMBOLS" ]; then
  echo "Unsatisfied requirement plugins.Info.kernel.symbol_table_name" >&2; exit 1
fi
case "$last" in windows.info) printf 'Variable\tValue\nKernel Base\t0xf80000000000\n' ;; *) printf 'PID\tImageFileName\n4\tSystem\n' ;; esac
SH
chmod +x "$H/vol-shim/vol"
: > "$H/win.mem"
MW="$ROOT/packs/computer-forensics-base/recipes/memory-windows/run.sh"
PATH="$H/vol-shim:$PATH" bash "$MW" run --target "{\"paths\": [\"$H/win.mem\"], \"name\": \"win.mem\"}" --out "$H/out-mw" >/dev/null || fail "memory-windows with the image's symbols should run"
jq -e '.status == "complete" and (.covered | test("symbols held in the image"))' "$H/out-mw/coverage.json" >/dev/null || fail "with the image's symbols, coverage says so: $(cat "$H/out-mw/coverage.json")"
VOL_STUB_NO_SYMBOLS=1 PATH="$H/vol-shim:$PATH" bash "$MW" run --target "{\"paths\": [\"$H/win.mem\"], \"name\": \"win.mem\"}" --out "$H/out-mw2" >/dev/null || fail "memory-windows without the image's symbols should fall back to the symbol server"
jq -e '.status == "complete" and (.covered | test("fetched from the symbol server"))' "$H/out-mw2/coverage.json" >/dev/null || fail "a fetched symbol table is said: $(cat "$H/out-mw2/coverage.json")"
grep -q symbol_table_name "$H/out-mw2/offline.windows.info.txt.stderr" && grep -q '^offline.windows.info.txt.stderr' "$H/out-mw2/index.tsv" || fail "the offline attempt is kept and indexed"
grep -q 'System' "$H/out-mw2/pslist.txt" || fail "the plugins ran with the fetched symbols"
pass "memory-windows uses the image's symbols first, falls back to the symbol server when it has none, and says which"

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
