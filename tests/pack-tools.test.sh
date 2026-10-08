#!/usr/bin/env bash
# The shipped packs' own tools, and the references between their skills.
#
# A pack's promise is that an agent which fetches a skill can carry out what the
# skill tells it to do. Two things break that promise quietly: a parser that
# returns a plausible wrong answer, and a skill naming a tool or a peer skill
# that nothing in the resolved set carries. Both are checked here.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="$ROOT/packs/computer-forensics-base"
WIN="$ROOT/packs/windows-forensics"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
skip() { echo "skip - $*"; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || { echo "skip - no python3"; exit 0; }

run_tool() { # <tool dir> <json on stdin>
  "$PY" "$1/run.py"
}

# --- every skill resolves against its own pack's dependency closure -------------
# The real contract: a run loads a pack and its dependencies, so a reference has to
# resolve inside THAT set, not merely somewhere in the repository.
"$PY" - "$ROOT/packs" <<'EOF' || fail "a skill points at something its pack's dependencies do not carry"
import json, os, re, sys

FM = re.compile(r"\A---\n(.*?)\n---\n", re.S)
root = sys.argv[1]
packs = {}
for pid in sorted(os.listdir(root)):
    manifest = os.path.join(root, pid, "pack.json")
    if not os.path.isfile(manifest):
        continue
    meta = json.load(open(manifest))
    tools, skills, refs = set(), set(), []
    tdir = os.path.join(root, pid, "tools")
    if os.path.isdir(tdir):
        tools = {n for n in os.listdir(tdir) if os.path.isdir(os.path.join(tdir, n))}
    for dirpath, _dirs, files in os.walk(os.path.join(root, pid, "skills")):
        for f in sorted(files):
            if not f.endswith(".md") or f == "INDEX.md":
                continue
            text = open(os.path.join(dirpath, f), encoding="utf-8").read()
            m = FM.match(text)
            if not m:
                print("%s/%s has no front matter" % (pid, f)); raise SystemExit(1)
            fields = {}
            for line in m.group(1).splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                fields[k] = [x.strip() for x in v[1:-1].split(",") if x.strip()] \
                    if v.startswith("[") and v.endswith("]") else v
            skills.add(fields["id"])
            refs.append((fields["id"], fields.get("tools", []), fields.get("needs", [])))
    packs[pid] = {"depends": [d.split(">=")[0].strip() for d in (meta.get("depends") or [])],
                  "tools": tools, "skills": skills, "refs": refs}

bad = []
for pid, pack in packs.items():
    seen, queue = set(), list(pack["depends"])
    while queue:
        dep = queue.pop()
        if dep in seen:
            continue
        seen.add(dep)
        if dep not in packs:
            bad.append("%s depends on %r, which is not in packs/" % (pid, dep))
            continue
        queue += packs[dep]["depends"]
    tools = set(pack["tools"])
    skills = set(pack["skills"])
    for dep in seen:
        if dep in packs:
            tools |= packs[dep]["tools"]
            skills |= packs[dep]["skills"]
    for sid, uses, needs in pack["refs"]:
        bad += ["%s: %s names the tool %r" % (pid, sid, t) for t in uses if t not in tools]
        bad += ["%s: %s needs the skill %r" % (pid, sid, n) for n in needs if n not in skills]

# No two packs may carry a tool of the same name: a run that loads both would collide.
owners = {}
for pid, pack in packs.items():
    for tool in pack["tools"]:
        owners.setdefault(tool, []).append(pid)
for tool, where in sorted(owners.items()):
    if len(where) > 1:
        bad.append("the tool %r is carried by %s" % (tool, " and ".join(sorted(where))))

for line in bad:
    print("  " + line)
print("checked %d packs" % len(packs))
raise SystemExit(1 if bad else 0)
EOF
pass "every skill resolves inside its own pack's dependency closure, and no tool name is carried twice"

# --- every seeded tool must carry the hash of its own entry script -------------
# A manifest with no 64-hex sha256 is SILENTLY LEFT OUT when the run seeds the
# pack's tools, so the tool exists, verifies, and never reaches an agent. seal
# stamps it; this is the check that it did.
"$PY" - "$ROOT/packs" <<'EOF' || fail "a shipped tool manifest has no matching sha256 and would be left out of a run"
import hashlib, json, os, sys

root, bad, total = sys.argv[1], [], 0
for pid in sorted(os.listdir(root)):
    tdir = os.path.join(root, pid, "tools")
    if not os.path.isdir(tdir):
        continue
    for name in sorted(os.listdir(tdir)):
        manifest = os.path.join(tdir, name, "manifest.json")
        if not os.path.isfile(manifest):
            continue
        total += 1
        meta = json.load(open(manifest))
        entry = os.path.join(tdir, name, meta.get("entry", ""))
        if not meta.get("entry") or not os.path.isfile(entry):
            bad.append("%s/%s has no readable entry" % (pid, name)); continue
        want = hashlib.sha256(open(entry, "rb").read()).hexdigest()
        if meta.get("sha256") != want:
            bad.append("%s/%s: manifest says %r, %s hashes to %s"
                       % (pid, name, meta.get("sha256"), meta["entry"], want[:16]))
for line in bad:
    print("  " + line)
print("checked %d tool manifests" % total)
raise SystemExit(1 if bad else 0)
EOF
pass "every shipped tool manifest carries the hash of its entry script, so none is silently left out"

# --- every shipped pack seals clean, and is checked in sealed --------------------
# A skill that calls a program no pack of its dependency set declares is a
# warning at seal: the mobile pack's iOS unified-log method still named the
# retired UnifiedLogReader.py after the macOS pack replaced it with
# unifiedlog_iterator. Sealed again from a copy (its dependencies beside it),
# each pack says nothing, and its pack.json is the one checked in.
cp -R "$ROOT/packs" "$WORK/sealed"
for d in "$WORK/sealed"/*/; do
  id="$(basename "$d")"
  said="$(bash "$ROOT/scripts/pack.sh" seal "$d" 2>&1 >/dev/null)" || fail "packs/$id does not seal: $said"
  [[ -z "$said" ]] || fail "packs/$id seals with a warning: $said"
  [[ "$(jq -S . "$d/pack.json")" == "$(jq -S . "$ROOT/packs/$id/pack.json")" ]] || fail "packs/$id is not checked in as sealed: seal it"
done
pass "every shipped pack seals without a warning, and is checked in as sealed"

# --- mft_records: a synthetic $MFT built from the documented layout ----------
"$PY" - "$WORK/MFT" <<'EOF' || fail "could not build the synthetic \$MFT"
import struct, sys, datetime
EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
def ft(iso):
    dt = datetime.datetime.fromisoformat(iso).replace(tzinfo=datetime.timezone.utc)
    return int((dt - EPOCH).total_seconds()) * 10_000_000
def attr(atype, content, name="", aid=0):
    nb = name.encode("utf-16-le"); noff = 0x18
    coff = noff + len(nb); coff += (-coff) % 8
    total = coff + len(content); total += (-total) % 8
    b = bytearray(total)
    struct.pack_into("<IIBBHHH", b, 0, atype, total, 0, len(name), noff if nb else 0, 0, aid)
    struct.pack_into("<IH", b, 0x10, len(content), coff)
    b[noff:noff+len(nb)] = nb
    b[coff:coff+len(content)] = content
    return bytes(b)
def si(c, m, r, a):  return struct.pack("<QQQQI", c, m, r, a, 0x20) + b"\x00" * 0x24
def fn(parent, c, m, r, a, name):
    return (struct.pack("<Q", parent | (1 << 48)) + struct.pack("<QQQQ", c, m, r, a)
            + struct.pack("<QQ", 4096, 154) + struct.pack("<II", 0x20, 0)
            + struct.pack("<BB", len(name), 1) + name.encode("utf-16-le"))
def record(number, seq, in_use, attrs, size=1024):
    b = bytearray(size); b[0:4] = b"FILE"
    usa_off, usa_count = 0x30, size // 512 + 1
    struct.pack_into("<HH", b, 0x04, usa_off, usa_count)
    struct.pack_into("<H", b, 0x10, seq)
    first = usa_off + usa_count * 2; first += (-first) % 8
    struct.pack_into("<HH", b, 0x14, first, 1 if in_use else 0)
    struct.pack_into("<I", b, 0x2C, number)
    off = first
    for a in attrs:
        b[off:off+len(a)] = a; off += len(a)
    struct.pack_into("<I", b, off, 0xFFFFFFFF)
    struct.pack_into("<II", b, 0x18, off + 8, size)
    sig = b"\x0b\x00"; b[usa_off:usa_off+2] = sig
    for i in range(1, usa_count):
        end = i * 512 - 2
        b[usa_off + i*2: usa_off + i*2 + 2] = bytes(b[end:end+2])
        b[end:end+2] = sig
    return bytes(b)
out = record(40, 1, True, [
    attr(0x10, si(ft("2026-03-01T10:00:00"), ft("2026-03-02T11:00:00"), ft("2026-03-02T11:00:00"), ft("2026-03-03T09:00:00"))),
    attr(0x30, fn(5, ft("2026-03-01T10:00:00"), ft("2026-03-02T11:00:00"), ft("2026-03-02T11:00:00"), ft("2026-03-03T09:00:00"), "notes.txt")),
    attr(0x80, b"a resident note, 30 bytes ok!\n"),
]) + record(41, 2, False, [
    attr(0x10, si(*(4 * [ft("2019-01-01T00:00:00")]))),
    attr(0x30, fn(5, *(4 * [ft("2026-03-05T12:00:00")]), "LPT1.txt")),
    attr(0x80, b""),
    attr(0x80, b"MZ\x90\x00 payload bytes", name="payload.exe", aid=4),
])
open(sys.argv[1], "wb").write(out)
EOF

got="$(echo "{\"path\":\"$WORK/MFT\",\"with_resident\":true}" | run_tool "$WIN/tools/mft_records")"
echo "$got" | "$PY" -c '
import json, sys
d = json.load(sys.stdin)
a, b = d["entries"]
assert d["record_size"] == 1024, d["record_size"]
assert a["entry"] == 40 and a["in_use"], a
assert a["primary_name"] == "notes.txt", a["primary_name"]
assert a["standard_information"]["modified"] == "2026-03-02T11:00:00.0000000Z", a["standard_information"]
import base64
assert base64.b64decode(a["data_streams"][0]["content_base64"]).startswith(b"a resident note"), a["data_streams"]
assert b["entry"] == 41 and not b["in_use"], b
assert b["ads"] == ["payload.exe"], b["ads"]
assert "si_created_before_fn_created" in b["flags"], b["flags"]
' || fail "mft_records did not read the synthetic \$MFT correctly"
pass "mft_records applies the fixup and reads both time sets, resident data and a named stream"

echo "{\"path\":\"$WORK/MFT\",\"timestomp_only\":true}" | run_tool "$WIN/tools/mft_records" | "$PY" -c '
import json, sys
d = json.load(sys.stdin)
assert [e["primary_name"] for e in d["entries"]] == ["LPT1.txt"], d["entries"]
' || fail "timestomp_only did not narrow to the record whose time sets disagree"
pass "timestomp_only returns the record whose two time sets disagree, and not the ordinary one"

printf 'not an MFT at all' > "$WORK/notmft"
if echo "{\"path\":\"$WORK/notmft\"}" | run_tool "$WIN/tools/mft_records" >/dev/null 2>&1; then
  fail "mft_records accepted a file with no FILE record"
fi
pass "a file with no FILE record is refused rather than parsed into nonsense"

# --- evtx_carve: a chunk with no file header around it ----------------------
SAMPLE="$ROOT/docs/use-cases/belkactf/belkactf6-bogus-bill/run-2/work/s83fd05/BitLocker_Management.evtx"
if ! "$PY" -c 'import Evtx' 2>/dev/null; then
  skip "evtx_carve (python-evtx is not installed)"
elif [[ ! -f "$SAMPLE" ]]; then
  skip "evtx_carve (no event log in the repository to carve a chunk out of)"
else
  "$PY" - "$SAMPLE" "$WORK/unallocated.bin" <<'EOF'
import sys, random
src = open(sys.argv[1], "rb").read()
random.seed(7)
noise = bytes(random.getrandbits(8) for _ in range(1000))
# One chunk, no file header, not aligned, rubbish on both sides: unallocated space.
open(sys.argv[2], "wb").write(noise + src[4096:4096 + 65536] + noise)
EOF
  # In the scratch directory: past its page it writes every record under the
  # work/ of the directory it runs in.
  echo "{\"path\":\"$WORK/unallocated.bin\",\"limit\":5}" | (cd "$WORK" && run_tool "$WIN/tools/evtx_carve") | "$PY" -c '
import json, sys
d = json.load(sys.stdin)
assert d["chunks_found"] == 1, d["chunks_found"]
assert d["chunks_checksum_ok"] == 1, d
assert d["record_count"] >= 1, d["record_count"]
r = d["records"][0]
assert r["chunk_offset"] == 1000, r["chunk_offset"]
assert r["channel"], r
assert r["chunk_verified"] is True, r
' || fail "evtx_carve did not recover records from a chunk with no file header"
  pass "evtx_carve recovers records from a lone chunk in unallocated space, checksums verified"
fi

# --- jumplist: the DestList layout, by version -------------------------------
# The fixtures are written from the jump list format notes, not from the parser:
# a 32-byte header; an entry's fixed part is 114 bytes in version 1 (path length at
# 0x70, path from 0x72) and 130 bytes in versions 3 and 4 (path length at 0x80, path
# from 0x82, then a 4-byte trailer); in all of them the NetBIOS name is at 0x48, the
# entry number at 0x58, the last-access FILETIME at 0x64 and the pin state at 0x6C
# (-1 is not pinned). The same fixtures once shared the parser's single 118-byte
# layout, which put the path length at 0x74 for every version.
"$PY" - "$WIN/tools/jumplist/run.py" <<'EOF' || fail "jumplist did not read a DestList"
import struct, datetime, importlib.util, sys
spec = importlib.util.spec_from_file_location("jl", sys.argv[1])
jl = importlib.util.module_from_spec(spec); spec.loader.exec_module(jl)
EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
def ft(iso, extra_ticks=0):
    dt = datetime.datetime.fromisoformat(iso).replace(tzinfo=datetime.timezone.utc)
    return int((dt - EPOCH).total_seconds()) * 10_000_000 + extra_ticks
def entry(version, number, host, when, path, pin):
    fixed, chars_at, trailer = (114, 0x70, 0) if version == 1 else (130, 0x80, 4)
    b = bytearray(fixed + len(path) * 2 + trailer)
    b[0x48:0x48 + len(host)] = host.encode("ascii")
    struct.pack_into("<I", b, 0x58, number)
    struct.pack_into("<I", b, 0x5C, 0x11223344)            # counters the tool must not call an access count
    struct.pack_into("<I", b, 0x60, 0x55667788)
    struct.pack_into("<Q", b, 0x64, when)
    struct.pack_into("<i", b, 0x6C, pin)
    if version != 1:
        struct.pack_into("<IIII", b, 0x70, 0xA1, 0xA2, 0xA3, 0xA4)
    struct.pack_into("<H", b, chars_at, len(path))
    b[fixed:fixed + len(path) * 2] = path.encode("utf-16-le")
    return bytes(b)
UNC = r"\\fileserver\finance\Q4.xlsx"
LOCAL = r"C:\case\report.txt"
when = ft("2026-02-03T08:15:00", 1234567)
for version in (1, 3, 4):
    e = [entry(version, 1, "WIN-DC01", when, UNC, -1), entry(version, 10, "WIN-DC01", when + 10_000_000, LOCAL, 2)]
    data = struct.pack("<IIIIIIII", version, len(e), 1, 0, 2, 0, 0, 0) + b"".join(e)
    got = jl.parse_destlist(data)
    assert not got["problems"], (version, got["problems"])
    assert got["destlist_version"] == version and len(got["entries"]) == 2, got
    one, two = got["entries"]
    assert one["path"] == UNC, (version, one)
    assert one["hostname"] == "WIN-DC01" and one["entry_number"] == 1 and one["stream"] == "1", one
    assert one["last_access"] == "2026-02-03T08:15:00.1234567Z", (version, one)
    assert one["last_access_filetime"] == str(when), one
    assert one["pinned"] is False and one["pin_status"] == -1, one
    assert two["path"] == LOCAL and two["stream"] == "a" and two["pinned"] is True and two["pin_status"] == 2, (version, two)
    assert two["last_access"] == "2026-02-03T08:15:01.1234567Z", two
    assert "access_count" not in one, "no access count is claimed: its position is not established"
    assert one["undecoded_0x5c_0x64_hex"] == "4433221188776655", one
    if version != 1:
        assert one["undecoded_0x70_0x80_hex"] == "a1000000a2000000a3000000a4000000", one
# a version this parser does not read is a problem and no entries, never a guess
odd = struct.pack("<IIIIIIII", 2, 1, 0, 0, 0, 0, 0, 0) + entry(3, 1, "H", when, LOCAL, -1)
got = jl.parse_destlist(odd)
assert got["entries"] == [] and got["problems"] and "version 2" in got["problems"][0], got
# an entry whose path length runs past the stream stops the read and says so
cut = struct.pack("<IIIIIIII", 3, 1, 0, 0, 0, 0, 0, 0) + entry(3, 1, "H", when, LOCAL, -1)[:-20]
got = jl.parse_destlist(cut)
assert got["entries"] == [] and any("does not fit" in p for p in got["problems"]), got
# and the link structures inside a customDestinations-ms are found by their own header
blob = b"\x02\x00\x00\x00" + jl.LNK_MAGIC + b"A" * 40 + jl.LNK_MAGIC + b"B" * 30
assert [o for o, _ in jl.split_lnks(blob)] == [4, 64], jl.split_lnks(blob)
EOF
pass "jumplist reads a DestList by its version's layout (1, 3 and 4), refuses another version, and splits a customDestinations by link header"

# --- shellbags: shell items, and the honest fallback ------------------------
"$PY" - "$WIN/tools/shellbags/run.py" <<'EOF' || fail "shellbags did not decode a shell item"
import struct, importlib.util, sys
spec = importlib.util.spec_from_file_location("sb", sys.argv[1])
sb = importlib.util.module_from_spec(spec); spec.loader.exec_module(sb)
def dos(y, mo, d, h, mi, s):
    return ((((y - 1980) << 9) | (mo << 5) | d) | ((((h << 11) | (mi << 5) | (s // 2))) << 16))
vol = b"\x2fC:\\\x00"
vol = struct.pack("<H", len(vol) + 2) + vol
got = sb.decode_item(vol)
assert got["type"] == "volume" and got["name"] == "C:\\", got
def dir_item(short, long_name, version):
    b = bytearray(b"\x00\x00" + bytes([0x31, 0x00]))
    b += struct.pack("<I", 0) + struct.pack("<I", dos(2026, 2, 14, 9, 30, 12)) + struct.pack("<H", 0x10)
    b += short.encode("ascii") + b"\x00"
    if len(b) % 2:
        b += b"\x00"
    # The 0xBEEF0004 block as the libfwsi notes lay it out: size, version, signature, the FAT creation and access
    # times, the 2-byte offset of the long name at 0x10, the fields of the version up to the name (0x14 in version 3,
    # 0x26 in 7, 0x2A in 8, 0x2E in 9), the NUL-terminated UTF-16 long name, and the 2-byte offset of the block in the item.
    name_at = {3: 0x14, 7: 0x26, 8: 0x2A, 9: 0x2E}[version]
    ext = bytearray(struct.pack("<HH", 0, version) + struct.pack("<I", 0xBEEF0004))
    ext += struct.pack("<I", dos(2026, 1, 3, 8, 0, 0)) + struct.pack("<I", dos(2026, 2, 14, 9, 31, 0))
    ext += struct.pack("<H", name_at)
    ext += b"\x00" * (name_at - len(ext))
    ext += long_name.encode("utf-16-le") + b"\x00\x00" + struct.pack("<H", 0x14)
    struct.pack_into("<H", ext, 0, len(ext))
    b += ext
    struct.pack_into("<H", b, 0, len(b))
    return bytes(b)
for version in (3, 7, 8, 9):
    got = sb.decode_item(dir_item("HOLIDA~1", "holiday photos 2026", version))
    assert got["type"] == "directory", (version, got)
    assert got["name"] == "holiday photos 2026", (version, got)
    assert got["short_name"] == "HOLIDA~1", (version, got)
    assert got["modified"].endswith("(local)"), got["modified"]
    assert got["long_name_from"] == "layout", (version, got)
# an item type this parser does not know still yields a name, labelled as a guess
unknown = sb.decode_item(b"\x20\x00\x99" + "Some Share".encode("utf-16-le"))
assert unknown["name"] == "Some Share" and unknown["decoded"] == "strings", unknown
EOF
pass "shellbags decodes volume and directory items, and labels a name it had to search for"

# --- image_layout: mmls output, in sectors ----------------------------------
"$PY" - "$BASE/tools/image_layout/run.py" <<'EOF' || fail "image_layout misread an mmls table"
import importlib.util, sys
spec = importlib.util.spec_from_file_location("il", sys.argv[1])
il = importlib.util.module_from_spec(spec); spec.loader.exec_module(il)
sample = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
003:  000:001   0000206848   0062912511   0062705664   NTFS / exFAT (0x07)
"""
sector, slots = il.parse_mmls(sample)
assert sector == 512, sector
allocated = [s for s in slots if s["allocated"]]
assert [s["start_sector"] for s in allocated] == [2048, 206848], allocated
assert all("NTFS" in s["description"] for s in allocated), allocated
# the meta row and the gap are both present and both marked not allocated
assert len(slots) == 4, slots
EOF
pass "image_layout reads an mmls table in sectors and marks the meta row and the gap"

printf 'not an image' > "$WORK/plain"
# mmls and fsstat as they answer a file that is no image: exit 1, and fsstat says it
# cannot determine the type. Stand-ins, so the answer does not depend on the host's Sleuth Kit.
mkdir -p "$WORK/tsk-none"
printf '#!/bin/sh\nexit 1\n' > "$WORK/tsk-none/mmls"
printf '#!/bin/sh\necho "Cannot determine file system type" >&2\nexit 1\n' > "$WORK/tsk-none/fsstat"
printf '#!/bin/sh\necho "IMAGE FILE INFORMATION"\n' > "$WORK/tsk-none/img_stat"      # a silent mmls failure counts as "no table" only when img_stat opens the image
chmod +x "$WORK/tsk-none/mmls" "$WORK/tsk-none/fsstat" "$WORK/tsk-none/img_stat"
(cd "$WORK" && echo "{\"image\":\"$WORK/plain\"}" | PATH="$WORK/tsk-none:$PATH" run_tool "$BASE/tools/image_layout") | "$PY" -c '
import json, sys
d = json.load(sys.stdin)
assert d["partition_table"] is False, d
assert d["volumes_readable"] == 0, d
assert d["container"] == "raw", d["container"]
assert any("filesystem/encrypted" in n for n in d["notes"]), d["notes"]
' || fail "image_layout did not report a file that is neither a table nor a volume"
pass "a file with no table and no file system is reported, with where to take it next"

# --- vss_stores: the missing binary is a result, not a crash ----------------
if command -v vshadowinfo >/dev/null; then
  skip "vss_stores refusal (vshadowinfo is installed on this host)"
else
  out="$(echo "{\"image\":\"$WORK/plain\"}" | run_tool "$WIN/tools/vss_stores" 2>&1 || true)"
  echo "$out" | "$PY" -c '
import json, sys
d = json.loads(sys.stdin.read())
assert "vshadowinfo" in d["error"], d
assert "install" in d, d
' || fail "vss_stores did not say plainly that vshadowinfo is missing"
  pass "vss_stores names the missing binary and how to install it, rather than failing silently"
fi

# --- carving and timeline output stays in the run directory -------------------
# icat_extract has always refused an output outside the run directory or under
# inputs/; file_carver, mem_carve and timeline_super wrote wherever the path
# pointed, so a mistyped `../` or `inputs/` landed a carving beside the
# evidence and the integrity check then reported the evidence modified.
OUT="$WORK/outpaths"; mkdir -p "$OUT/run/work" "$OUT/run/inputs" "$OUT/bin"
{ printf 'PK\003\004zip'; head -c 2048 /dev/zero; printf 'regf'; head -c 8192 /dev/zero; } > "$OUT/run/inputs/blob.bin"
# file_carver takes only a signature whose size it can read whole: a PNG ends
# at its IEND chunk.
printf '\211PNG\r\n\032\n\000\000\000\000IEND\256B`\202' > "$OUT/run/inputs/pic.png"
# The Plaso stand-ins keep its way with its log: where --logfile says, else
# <tool>-<time>.log.gz in the working directory, and a log that cannot be
# written fails the run.
for t in log2timeline psort; do
  cat > "$OUT/bin/$t.py" <<'PLASO'
#!/usr/bin/env bash
log="$(basename "$0" .py)-$(date +%Y%m%dT%H%M%S).log.gz"
while [[ $# -gt 0 ]]; do
  case "$1" in --logfile) log="$2"; shift ;; --storage_file) echo s > "$2"; shift ;; -w) echo "{}" > "$2"; shift ;; esac
  shift
done
echo log 2>/dev/null > "$log" || { echo "OSError: [Errno 30] Read-only file system: '$log'" >&2; exit 1; }
PLASO
done
chmod +x "$OUT/bin/"*
carve() { (cd "$OUT/run" && printf '{"path":"inputs/pic.png","offset":0,"sig_type":"PNG","max_size":64,"output":"%s"}' "$1" | "$PY" "$BASE/tools/file_carver/run.py"); }
memc() { (cd "$OUT/run" && printf '{"path":"inputs/blob.bin","extract_to":"%s","max_extract":1}' "$1" | "$PY" "$ROOT/packs/memory-forensics/tools/mem_carve/run.py"); }
plaso() { (cd "$OUT/run" && printf '{"source":"inputs/blob.bin","out_dir":"%s"}' "$1" | PATH="$OUT/bin:$PATH" "$PY" "$BASE/tools/timeline_super/run.py"); }
for bad in ../escaped inputs/planted work/../inputs/planted "$OUT/abs"; do
  carve "$bad.bin" >/dev/null 2>&1 && fail "file_carver wrote output=$bad.bin"
  memc "$bad-mem" >/dev/null 2>&1 && fail "mem_carve wrote extract_to=$bad-mem"
  plaso "$bad-plaso" >/dev/null 2>&1 && fail "timeline_super wrote out_dir=$bad-plaso"
done
leaked="$(find "$OUT" -path "$OUT/run/work" -prune -o \( -name 'escaped*' -o -name 'planted*' -o -name 'abs*' \) -print)"
[[ -z "$leaked" ]] || fail "a refused output was still written: $leaked"
carve work/c.bin >/dev/null || fail "file_carver refused an output under work/"
# mem_carve writes only inside an agent's own directory, the one its VM may write.
memc work/m >/dev/null 2>&1 && fail "mem_carve wrote into work/ itself rather than an agent's directory"
memc work/a1/m >/dev/null || fail "mem_carve refused an extract_to under work/<agent>/"
plaso work/p >/dev/null || fail "timeline_super refused an out_dir under work/"
[[ -s "$OUT/run/work/c.bin" && -n "$(ls "$OUT/run/work/a1/m")" && -f "$OUT/run/work/p/timeline.plaso" ]] || fail "outputs under work/ were not written"
cmp -s "$BASE/tools/file_carver/run.py" "$ROOT/tool-library/file_carver/run.py" || fail "the tool-library copy of file_carver has drifted from the pack's"
pass "file_carver, mem_carve and timeline_super write under the run directory and never under inputs/"

# In an agent's VM and in a job's worker the run's directory is read-only
# (only work/<agent>/ or $OUT is writable), and it is the working directory:
# Plaso's default log there failed log2timeline on the Belka run.
# timeline_super gives each step its log in out_dir.
chmod a-w "$OUT/run"
got="$(plaso work/ro 2>&1)"; rc=$?
chmod u+w "$OUT/run"
[[ "$rc" -eq 0 ]] || fail "timeline_super should run with the run directory read-only: $got"
[[ -s "$OUT/run/work/ro/log2timeline.log.gz" && -s "$OUT/run/work/ro/psort.log.gz" ]] || fail "timeline_super should keep each step's log in out_dir (--logfile): $(ls "$OUT/run/work/ro")"
[[ -z "$(find "$OUT/run" -maxdepth 1 -name '*.log.gz')" ]] || fail "timeline_super let Plaso write its log in the run directory"
jq -e '.logs | length == 2' <<<"$got" >/dev/null || fail "timeline_super should name the logs it kept: $got"
pass "timeline_super keeps log2timeline's and psort's logs in out_dir, and runs with the run directory read-only"

# feature_scan, zeek_run, sigma_hunt, unified_log and doc_probe wrote wherever
# out_dir (extract_to) pointed too. Each refuses a place outside the run, the
# run itself or under inputs/ before it looks for its program, and follows a
# link to where it really lands. Only python3 on PATH, so no program is found
# and a path the check lets through ends at "not on PATH", never at the check.
mkdir -p "$OUT/pyonly"; ln -sf "$(command -v "$PY")" "$OUT/pyonly/python3"
ln -s "$OUT" "$OUT/run/work/out-link"
guarded() { # <run.py> <key> <path>
  (cd "$OUT/run" && printf '{"path":"inputs/blob.bin","%s":"%s"}' "$2" "$3" | PATH="$OUT/pyonly" "$OUT/pyonly/python3" "$1")
}
refuses='must stay inside the run directory|cannot be under inputs/'
for t in "$BASE/tools/feature_scan:out_dir" "$ROOT/packs/network-forensics/tools/zeek_run:out_dir" \
         "$WIN/tools/sigma_hunt:out_dir" "$ROOT/packs/macos-forensics/tools/unified_log:out_dir" \
         "$ROOT/packs/reverse-engineering/tools/doc_probe:extract_to"; do
  tool="${t%%:*}/run.py"; key="${t##*:}"; name="$(basename "${t%%:*}")"
  for bad in "../escaped-$name" "inputs/planted-$name" "work/../inputs/planted-$name" "$OUT/abs-$name" \
             "work/out-link/escaped-$name" . inputs; do
    got="$(guarded "$tool" "$key" "$bad" 2>&1)" && fail "$name wrote $key=$bad: $got"
    grep -Eq "$refuses" <<<"$got" || fail "$name should refuse $key=$bad with the reason, not: $got"
  done
  got="$(guarded "$tool" "$key" "work/$name" 2>&1)"
  grep -Eq "$refuses" <<<"$got" && fail "$name refused $key=work/$name: $got"
done
leaked="$(find "$OUT" -path "$OUT/run/work" -prune -o \( -name 'escaped*' -o -name 'planted*' -o -name 'abs*' \) -print)"
[[ -z "$leaked" ]] || fail "a refused output was still written: $leaked"
# doc_probe checks each part it extracts as well: a link left in extract_to,
# named as the macro project would be, is not written through.
"$PY" - "$OUT/run/work/macro.docm" <<'EOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("word/document.xml", "<w:document/>")
    z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0 macro project")
EOF
docp() { (cd "$OUT/run" && printf '{"path":"work/macro.docm","extract_to":"%s"}' "$1" | "$PY" "$ROOT/packs/reverse-engineering/tools/doc_probe/run.py"); }
docp work/doc > "$OUT/doc.json" || fail "doc_probe did not extract into work/: $(cat "$OUT/doc.json")"
[[ "$(jq -r '.parts[] | select(.carries_code) | .extracted_to' "$OUT/doc.json")" == work/doc/000001-word_vbaProject.bin && -s "$OUT/run/work/doc/000001-word_vbaProject.bin" ]] \
  || fail "doc_probe should extract the macro project under extract_to: $(cat "$OUT/doc.json")"
mkdir -p "$OUT/run/work/doc2"; ln -s ../../inputs/planted-part "$OUT/run/work/doc2/000001-word_vbaProject.bin"
docp work/doc2 > "$OUT/doc2.json" 2>&1 && fail "doc_probe wrote through a link in extract_to: $(cat "$OUT/doc2.json")"
grep -q 'cannot be under inputs/' "$OUT/doc2.json" && [[ ! -e "$OUT/run/inputs/planted-part" ]] || fail "doc_probe should refuse the part a link sends under inputs/: $(cat "$OUT/doc2.json")"
pass "feature_scan, zeek_run, sigma_hunt, unified_log and doc_probe write under the run directory, never under inputs/ or through a link out of it"

# The tools that keep their whole result in an out_file or an out_dir of the
# caller's naming wrote there unchecked as well: cloud, macOS, triage, network
# and Linux. The same refusals, before anything is read or run.
more() { # <run.py> <key> <path>
  # The cloud tools refuse an argument they do not take (a typo would otherwise return an unfiltered answer that looks filtered),
  # so they get only the path and the output key; the others take the one bag of every name.
  if [[ "$1" == */cloud-forensics/* ]]; then
    (cd "$OUT/run" && printf '{"path":"inputs/blob.bin","%s":"%s"}' "$2" "$3" | PATH="$OUT/pyonly" "$OUT/pyonly/python3" "$1")
    return
  fi
  (cd "$OUT/run" && printf '{"path":"inputs/blob.bin","source":"inputs/blob.bin","db":"inputs/blob.bin","rules":"inputs/blob.bin","root":"inputs","%s":"%s"}' "$2" "$3" \
    | PATH="$OUT/pyonly" "$OUT/pyonly/python3" "$1")
}
n=0
for t in cloud-forensics/cloudtrail_parse:out_file cloud-forensics/signin_analyse:out_file cloud-forensics/ual_parse:out_file \
         macos-forensics/fsevents_parse:out_file macos-forensics/knowledgec_query:out_file macos-forensics/plist_read:out_file \
         triage-collection/collection_index:out_file network-forensics/network_log_summary:out_dir \
         network-forensics/pcap_extract:out_dir network-forensics/pcap_summary:out_dir network-forensics/suricata_run:out_dir \
         linux-forensics/linux_triage:out_dir; do
  tool="$ROOT/packs/${t%%/*}/tools/$(basename "${t%%:*}")/run.py"; key="${t##*:}"; name="$(basename "${t%%:*}")"
  for bad in "../escaped-$name" "inputs/planted-$name" "work/../inputs/planted-$name" "$OUT/abs-$name" \
             "work/out-link/escaped-$name" . inputs; do
    got="$(more "$tool" "$key" "$bad" 2>&1)" && fail "$name wrote $key=$bad: $got"
    grep -Eq "$refuses" <<<"$got" || fail "$name should refuse $key=$bad with the reason, not: $got"
  done
  got="$(more "$tool" "$key" "work/more-$name" 2>&1)"
  grep -Eq "$refuses" <<<"$got" && fail "$name refused $key=work/more-$name: $got"
  n=$((n + 1))
done
leaked="$(find "$OUT" -path "$OUT/run/work" -prune -o \( -name 'escaped*' -o -name 'planted*' -o -name 'abs*' \) -print)"
[[ -z "$leaked" ]] || fail "a refused output was still written: $leaked"
pass "the $n tools that keep a whole result in an out_file or out_dir write it under the run directory, never under inputs/ or through a link out of it"

# --- sigma_hunt speaks the Zircolite the images carry ----------------------------
# Zircolite 3 dropped --noexternal and refuses it, as argparse does any flag
# it does not know; sigma_hunt passed it, so with Zircolite in the disk image
# its auto engine stopped finding anything. This stand-in refuses what
# Zircolite 4 does not take and writes its result shape: a list of rules, each
# with the events it matched.
SH="$WORK/sigma"; mkdir -p "$SH/bin" "$SH/run/work"
printf 'evtx' > "$SH/run/Security.evtx"
cat > "$SH/bin/zircolite" <<'ZC'
#!/usr/bin/env python3
import argparse, json
ap = argparse.ArgumentParser()
ap.add_argument("-e", "--evtx", "--events")
ap.add_argument("-o", "--outfile")
ap.add_argument("-r", "--ruleset", action="append", nargs="+")
ap.add_argument("-l", "--logfile", default="zircolite.log")
a = ap.parse_args()
import os, sys
# Its log where --logfile says, else zircolite.log in the working directory;
# a log it cannot open stops it, as logging's FileHandler does.
open(a.logfile, "w").write("log\n")
# SIGMA_STUB_MANY: that many rules fire, each on a record of 15 fields, and the
# engine talks at length on both streams. SIGMA_STUB_FAIL: it writes no result.
many = int(os.environ.get("SIGMA_STUB_MANY") or 0)
if many or os.environ.get("SIGMA_STUB_FAIL"):
    sys.stdout.write("o" * 3000 + "\n")
    sys.stderr.write("e" * 5000 + "\n")
if os.environ.get("SIGMA_STUB_FAIL"):
    sys.exit(1)
rules = [{"title": "Bitsadmin Download", "id": "r1", "rule_level": "high", "matches": [
    {"SystemTime": "2026-09-01T10:00:00Z", "EventID": 59, "Channel": "Microsoft-Windows-Bits-Client/Operational",
     "Computer": "WS01", "EventRecordID": 7}]}]
for i in range(many):
    match = {"SystemTime": "2026-09-01T11:%02d:00Z" % (i % 60), "EventID": 4688, "Channel": "Security",
             "Computer": "WS01", "EventRecordID": 100 + i}
    match.update({"Field%02d" % k: "v%d" % k for k in range(10)})
    rules.append({"title": "Rule %02d" % i, "id": "m%d" % i, "rule_level": "medium", "matches": [match]})
json.dump(rules, open(a.outfile, "w"))
ZC
chmod +x "$SH/bin/zircolite"
out="$(cd "$SH/run" && printf '{"path": "Security.evtx", "out_dir": "work/hunt", "engine": "zircolite"}' | PATH="$SH/bin:$PATH" "$PY" "$WIN/tools/sigma_hunt/run.py" 2>&1)" \
  || fail "sigma_hunt could not run the Zircolite the images carry: $out"
"$PY" -c '
import json, sys
d = json.loads(sys.argv[1])
assert d["engine"] == "zircolite", d
assert "--noexternal" not in d.get("command", ""), d
det = d["detections"][0]
assert det["rule"] == "Bitsadmin Download" and det["record_id"] == 7 and det["level"] == "high", det
' "$out" || fail "sigma_hunt did not read what Zircolite matched: $out"
# Each run writes into a directory of its own inside out_dir, so a link left in
# out_dir under the result's old name is never written through (the engine writes
# beside it, in a name nobody could plant), and an out_dir that is itself a link
# to a place under inputs/ is refused.
mkdir -p "$SH/run/inputs" "$SH/run/work/hunt2"; ln -s ../../inputs/planted.json "$SH/run/work/hunt2/zircolite.json"
out="$(cd "$SH/run" && printf '{"path": "Security.evtx", "out_dir": "work/hunt2", "engine": "zircolite"}' | PATH="$SH/bin:$PATH" "$PY" "$WIN/tools/sigma_hunt/run.py" 2>&1)" \
  || fail "sigma_hunt should run in a directory of its own beside a planted link: $out"
[[ ! -e "$SH/run/inputs/planted.json" ]] || fail "sigma_hunt let its engine write through a link in out_dir: $out"
ln -s ../inputs "$SH/run/work/hunt3"
out="$(cd "$SH/run" && printf '{"path": "Security.evtx", "out_dir": "work/hunt3", "engine": "zircolite"}' | PATH="$SH/bin:$PATH" "$PY" "$WIN/tools/sigma_hunt/run.py" 2>&1)" \
  && fail "sigma_hunt accepted an out_dir that is a link under inputs/: $out"
grep -q 'cannot be under inputs/' <<<"$out" || fail "sigma_hunt should refuse an out_dir a link sends under inputs/: $out"
pass "sigma_hunt runs Zircolite without --noexternal, which Zircolite 3 and later refuse, and reads its detections, in a directory of its own, and never through a link out of out_dir"

# Nothing cut: every field of a matched record (it kept the first 12), every
# rule that fired (it kept 25), and the engine's own stdout and stderr whole
# in files it names (they were dropped on success and cut to their last 400
# and 800 characters on failure). Past limit the detections are a page, and
# all of them are in detections.jsonl.
out="$(cd "$SH/run" && printf '{"path": "Security.evtx", "out_dir": "work/many", "engine": "zircolite", "limit": 5}' \
  | SIGMA_STUB_MANY=40 PATH="$SH/bin:$PATH" "$PY" "$WIN/tools/sigma_hunt/run.py" 2>&1)" || fail "sigma_hunt over forty rules: $out"
"$PY" - "$out" "$SH/run" <<'EOF' || fail "sigma_hunt cut what the engine gave it: $out"
import hashlib, json, os, sys
d, run = json.loads(sys.argv[1]), sys.argv[2]
# forty rules and the one the stand-in always fires
assert d["detection_count"] == 41 and d["returned"] == 5 and d["truncated"], d
assert len(d["rules_that_fired"]) == 41 and d["rules_fired"] == 41, d["rules_that_fired"]
wide = [x for x in d["detections"] if x["rule"].startswith("Rule ")]
assert wide and all(len(x["detail"]) == 15 for x in wide), d["detections"]
def named(ref):
    data = open(os.path.join(run, ref["path"]), "rb").read()
    assert ref["bytes"] == len(data) and ref["sha256"] == hashlib.sha256(data).hexdigest(), ref
    return data
rows = [json.loads(l) for l in named(d["all_detections"]).decode().splitlines()]
assert len(rows) == 41 == d["all_detections"]["rows"], len(rows)
assert sum(1 for r in rows if len(r["detail"]) == 15) == 40, rows
assert named(d["engine_stdout"]).count(b"o") == 3000 and named(d["engine_stderr"]).count(b"e") == 5000
EOF
out="$(cd "$SH/run" && printf '{"path": "Security.evtx", "out_dir": "work/failed", "engine": "zircolite"}' \
  | SIGMA_STUB_FAIL=1 PATH="$SH/bin:$PATH" "$PY" "$WIN/tools/sigma_hunt/run.py" 2>&1)" && fail "an engine that wrote no result should fail the tool: $out"
"$PY" - "$out" "$SH/run" <<'EOF' || fail "sigma_hunt cut the failed engine's words: $out"
import json, os, sys
d, run = json.loads(sys.argv[1]), sys.argv[2]
assert "wrote no result file" in d["error"], d
assert os.path.getsize(os.path.join(run, d["stderr"]["path"])) == d["stderr"]["bytes"] == 5001, d["stderr"]
assert os.path.getsize(os.path.join(run, d["stdout"]["path"])) == d["stdout"]["bytes"] == 3001, d["stdout"]
EOF
pass "sigma_hunt keeps every field, every rule and every detection, and the engine's stdout and stderr whole in files it names"

# Neither engine writes beside the run: in a VM or a job the run's directory
# is read-only and it is the working directory. Zircolite is given its log in
# out_dir (--logfile); Hayabusa saves its error log as ./logs/errorlog-<time>.log
# with no option to move it, so it runs in out_dir with every path absolute.
cat > "$SH/bin/hayabusa" <<'HB'
#!/usr/bin/env python3
import argparse, json, os, sys
ap = argparse.ArgumentParser()
ap.add_argument("command")
ap.add_argument("-f", "--file")
ap.add_argument("-d", "--directory")
ap.add_argument("-o", "--output")
ap.add_argument("-r", "--rules")
ap.add_argument("-w", "--no-wizard", action="store_true")
ap.add_argument("-q", "--quiet", action="store_true")
a = ap.parse_args()
source = a.file or a.directory
if not os.path.exists(source):
    sys.exit("no such file: %s (from %s)" % (source, os.getcwd()))
json.dump([{"RuleTitle": "Hayabusa rule", "Level": "high", "Timestamp": "2026-09-01T10:00:00Z", "EventID": 4688,
            "Channel": "Security", "Computer": "WS01", "RecordID": 9, "Details": {"Cmd": "x"}}], open(a.output, "w"))
os.makedirs("logs", exist_ok=True)
open("logs/errorlog-20260929_120000.log", "w").write("user input: %s\n" % " ".join(sys.argv))
HB
chmod +x "$SH/bin/hayabusa"
chmod a-w "$SH/run"
zc="$(cd "$SH/run" && printf '{"path": "Security.evtx", "out_dir": "work/ro-z", "engine": "zircolite"}' | PATH="$SH/bin:$PATH" "$PY" "$WIN/tools/sigma_hunt/run.py" 2>&1)"; zrc=$?
hb="$(cd "$SH/run" && printf '{"path": "Security.evtx", "out_dir": "work/ro-h", "engine": "hayabusa"}' | PATH="$SH/bin:$PATH" "$PY" "$WIN/tools/sigma_hunt/run.py" 2>&1)"; hrc=$?
chmod u+w "$SH/run"
[[ "$zrc" -eq 0 ]] || fail "sigma_hunt should run Zircolite with the run directory read-only: $zc"
[[ "$hrc" -eq 0 ]] || fail "sigma_hunt should run Hayabusa with the run directory read-only: $hb"
[[ -z "$(find "$SH/run" -maxdepth 1 \( -name zircolite.log -o -name logs \))" ]] || fail "an engine wrote its log in the run directory"
"$PY" - "$zc" "$hb" "$SH/run" <<'EOF' || fail "sigma_hunt should keep each engine's log in out_dir and name it: $zc $hb"
import json, os, sys
z, h, run = json.loads(sys.argv[1]), json.loads(sys.argv[2]), sys.argv[3]
# Each run has a directory of its own under out_dir, and its logs are in it.
assert z["run_dir"].startswith("work/ro-z/hunt-"), z["run_dir"]
assert z["engine_logs"] == [z["run_dir"] + "/zircolite.log"] and os.path.isfile(os.path.join(run, z["engine_logs"][0])), z
assert h["engine_logs"] == [h["run_dir"] + "/logs/errorlog-20260929_120000.log"], h
assert h["detections"][0]["rule"] == "Hayabusa rule" and h["detections"][0]["record_id"] == 9, h
EOF
pass "sigma_hunt keeps Zircolite's log (--logfile) and Hayabusa's error log (run in out_dir) in out_dir, and runs with the run directory read-only"

# --- unified_log hands the reader one archive and keeps its whole output --------
# The 2020 UnifiedLogReader crashed on modern archives and the wrapper still
# said it succeeded; Mandiant's unifiedlog_iterator reads one logarchive
# layout. A .logarchive goes as it is; a /private/var/db copy is staged as one
# (uuidtext and diagnostics merged) and the staging removed. A reader that
# fails fails the tool, with its stderr kept whole.
UL="$WORK/ulog"; mkdir -p "$UL/bin" "$UL/run/x.logarchive/timesync" "$UL/run/db/diagnostics/timesync" "$UL/run/db/uuidtext/0A"
: > "$UL/run/db/diagnostics/timesync/0000.timesync"; : > "$UL/run/db/uuidtext/0A/B"
cat > "$UL/bin/unifiedlog_iterator" <<'ULR'
#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
arg = lambda f: a[a.index(f) + 1]
inp, out = arg("--input"), arg("--output")
layout = sorted(os.path.relpath(os.path.join(d, f), inp) for d, _, fs in os.walk(inp) for f in fs)
with open(out, "w") as fh:
    for i in range(3):
        fh.write(json.dumps({"timestamp": "2026-02-14T09:30:0%d+0000" % i, "message": "m%d" % i, "n": i, "input": inp, "layout": layout, "argv": a}) + "\n")
if os.environ.get("ULI_FAIL"):
    sys.stderr.write("thread panicked: " + "x" * 5000 + "\n")
    sys.exit(101)
ULR
chmod +x "$UL/bin/unifiedlog_iterator"
# Only this bin on PATH: a Mac's own /usr/bin/log would be chosen first.
ln -s "$(command -v "$PY")" "$UL/bin/python3"
ulog() { (cd "$UL/run" && printf '{"path": "%s", "out_dir": "work/%s"}' "$1" "$2" | PATH="$UL/bin" "$UL/bin/python3" "$ROOT/packs/macos-forensics/tools/unified_log/run.py"); }
ulog x.logarchive a > "$UL/a.json" || fail "unified_log could not run unifiedlog_iterator on a .logarchive: $(cat "$UL/a.json")"
"$PY" -c '
import json, sys
r = json.load(open(sys.argv[1]))
assert r["engine"] == "unifiedlog_iterator" and r["status"] == "complete" and r["entry_count"] == 3, r
first = json.loads(open(sys.argv[2] + "/" + r["output"]).readline())
assert first["input"] == "x.logarchive" and first["argv"][first["argv"].index("--format") + 1] == "jsonl", first
' "$UL/a.json" "$UL/run" || fail "unified_log did not give unifiedlog_iterator the .logarchive and keep its JSONL"
ulog db b > "$UL/b.json" || fail "unified_log could not run unifiedlog_iterator on a copy of /private/var/db: $(cat "$UL/b.json")"
"$PY" -c '
import json, os, sys
r = json.load(open(sys.argv[1]))
first = json.loads(open(sys.argv[2] + "/" + r["output"]).readline())
assert first["layout"] == ["0A/B", "timesync/0000.timesync"], first["layout"]
assert not os.path.exists(sys.argv[2] + "/work/b/.logarchive-input"), "the staged archive was left behind"
' "$UL/b.json" "$UL/run" || fail "unified_log did not stage a /private/var/db copy as one logarchive"
ULI_FAIL=1 ulog x.logarchive c > "$UL/c.json" && fail "a reader that exits non-zero must fail the tool"
"$PY" -c '
import json, os, sys
r = json.load(open(sys.argv[1]))
assert r["status"] == "partial" and r["exit_code"] == 101 and r["entry_count"] == 3, r
assert os.path.getsize(sys.argv[2] + "/" + r["stderr"]) == r["stderr_bytes"] > 5000, r
' "$UL/c.json" "$UL/run" || fail "a failed reader is partial, with its whole stderr kept"
# A link left in out_dir under the name of the reader's output is followed to
# where it lands, and refused under inputs/.
mkdir -p "$UL/run/inputs" "$UL/run/work/d"; ln -s ../../inputs/planted.jsonl "$UL/run/work/d/unifiedlogs.jsonl"
ulog x.logarchive d > "$UL/d.json" && fail "unified_log wrote through a link in out_dir: $(cat "$UL/d.json")"
grep -q 'cannot be under inputs/' "$UL/d.json" && [[ ! -e "$UL/run/inputs/planted.jsonl" ]] || fail "unified_log should refuse an output a link sends under inputs/: $(cat "$UL/d.json")"
pass "unified_log hands unifiedlog_iterator one archive (a /private/var/db copy staged as one), keeps the whole JSONL, fails when the reader does, and never writes through a link out of out_dir"

echo "pack-tools: all checks passed"
