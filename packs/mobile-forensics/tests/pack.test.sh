#!/usr/bin/env bash
set -euo pipefail
PACK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/mobile-pack.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

python3 - "$WORK" <<'PY'
import io, os, plistlib, sqlite3, sys, tarfile, zlib

work = sys.argv[1]
ios = os.path.join(work, "ios.tar")
members = {
    "private/var/mobile/Library/SMS/sms.db": b"SQLite format 3\0",
    "private/var/mobile/Library/SMS/sms.db-wal": b"wal",
    "private/var/mobile/Library/Biome/streams/test/1": b"SEGB",
    "private/var/db/diagnostics/Persist/0000000000000001.tracev3": b"trace",
    "private/var/Keychains/keychain-2.db": b"SQLite format 3\0",
    "private/var/mobile/Media/PhotoData/Photos.sqlite": b"SQLite format 3\0",
    "private/var/mobile/Containers/Data/Application/X/.com.apple.mobile_container_manager.metadata.plist": b"bplist00",
}
with tarfile.open(ios, "w") as archive:
    for name, data in members.items():
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mtime = 1700000000
        archive.addfile(info, io.BytesIO(data))

payload = io.BytesIO()
with tarfile.open(fileobj=payload, mode="w") as archive:
    for name, data in {
        "apps/com.example/_manifest": b"manifest",
        "apps/com.example/db/messages.db": b"SQLite format 3\0",
        "shared/0/DCIM/photo.jpg": b"jpeg",
    }.items():
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mtime = 1700000000
        archive.addfile(info, io.BytesIO(data))
with open(os.path.join(work, "android.ab"), "wb") as handle:
    handle.write(b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(payload.getvalue()))

backup = os.path.join(work, "backup")
os.makedirs(backup)
with open(os.path.join(backup, "Manifest.plist"), "wb") as handle:
    plistlib.dump({"IsEncrypted": False, "Version": "test"}, handle)
db = sqlite3.connect(os.path.join(backup, "Manifest.db"))
db.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
for n in range(750):
    db.execute("INSERT INTO Files VALUES (?,?,?,?,?)", ("%040x" % n, "Domain-%03d" % (n % 30), "p/%04d" % n, 1, None))
db.commit(); db.close()

free = os.path.join(work, "free.db")
db = sqlite3.connect(free)
db.execute("PRAGMA secure_delete=OFF")
db.execute("CREATE TABLE messages (body TEXT)")
text = "recover-" + "x" * 1800
db.execute("INSERT INTO messages VALUES (?)", (text,))
db.commit(); db.execute("DELETE FROM messages"); db.commit(); db.close()
PY

IOS_TARGET="$(python3 -c 'import json,sys; print(json.dumps({"paths":[sys.argv[1]]}))' "$WORK/ios.tar")"
python3 "$PACK/recipes/ios-filesystem/run.py" detect --target "$IOS_TARGET" | grep -q '"applies": true'
# As the kickoff's census asks: with a directory for what the probe keeps.
python3 "$PACK/recipes/ios-filesystem/run.py" detect --target "$IOS_TARGET" --probe-out "$WORK/ios-probe" | grep -q '"applies": true'
python3 "$PACK/recipes/ios-filesystem/run.py" run --target "$IOS_TARGET" --out "$WORK/ios-out" >/dev/null
jq -e '.status == "complete" and .categories["biome-segb"] == 1 and .categories["unified-log"] == 1' "$WORK/ios-out/coverage.json" >/dev/null
grep -q $'private/var/mobile/Library/SMS/sms.db\t16\t3\t' "$WORK/ios-out/sqlite.tsv"

AB_TARGET="$(python3 -c 'import json,sys; print(json.dumps({"paths":[sys.argv[1]]}))' "$WORK/android.ab")"
python3 "$PACK/recipes/android-backup/run.py" detect --target "$AB_TARGET" | grep -q '"applies": true'
python3 "$PACK/recipes/android-backup/run.py" detect --target "$AB_TARGET" --probe-out "$WORK/ab-probe" | grep -q '"applies": true'
python3 "$PACK/recipes/android-backup/run.py" run --target "$AB_TARGET" --out "$WORK/ab-out" >/dev/null
jq -e '.status == "complete" and .covered == "3 embedded tar members"' "$WORK/ab-out/coverage.json" >/dev/null
[[ "$(($(wc -l < "$WORK/ab-out/members.tsv") - 1))" -eq 3 ]]

# The broad extractions (purpose broad_extraction): iLEAPP and ALEAPP over a
# whole acquisition, each with a stand-in on PATH that writes one report the
# way the real one does (a report folder of its own, a TSV per artefact, a
# timeline database); and the adb backup's, declared and never run.
PY3="$(command -v python3)"
python3 - "$WORK" <<'PY'
import io, os, sys, tarfile, zipfile
work = sys.argv[1]
with tarfile.open(os.path.join(work, "android.tar"), "w") as archive:
    for name in ("data/system/packages.xml", "data/data/com.example/databases/messages.db"):
        info = tarfile.TarInfo(name); info.size = 1; info.mtime = 1700000000
        archive.addfile(info, io.BytesIO(b"x"))
with zipfile.ZipFile(os.path.join(work, "ios.zip"), "w") as z:
    z.writestr("private/var/mobile/Library/SMS/sms.db", b"SQLite format 3\0")
PY
mkdir -p "$WORK/bin"
for tool in ileapp aleapp; do
  up="$(printf '%s' "$tool" | sed 's/^i/iL/; s/^a/AL/' | tr '[:lower:]' '[:upper:]' | sed 's/^IL/iL/')"
  cat > "$WORK/bin/$tool" <<SH
#!/usr/bin/env bash
while [[ \$# -gt 0 ]]; do case "\$1" in -o) out="\$2"; shift 2;; -t) kind="\$2"; shift 2;; *) shift;; esac; done
[[ -n "\${STANDIN_SLEEP:-}" ]] && sleep "\$STANDIN_SLEEP"
d="\$out/${up}_Reports_2026-09-29"; mkdir -p "\$d/_TSV Exports" "\$d/_Timeline" "\$d/_HTML"
echo "Artifact to parse: 2"
echo "[1/2] Messages [messages] artifact started at 09:29:44 UTC"
printf 'time\tfrom\n1\t2\n' > "\$d/_TSV Exports/Messages (\$kind).tsv"
echo "Found 1 record for Messages"
echo "Messages [messages] artifact completed in 0.0s"
echo "[2/2] Notes [notes] artifact started at 09:29:44 UTC"
echo "No file found"
echo "Notes [notes] artifact completed in 0.0s"
echo "Processes completed."
: > "\$d/_Timeline/tl.db"; : > "\$d/_HTML/index.html"
SH
  chmod +x "$WORK/bin/$tool"
done
ILEAPP="$PACK/recipes/ios-ileapp/run.py"
ALEAPP="$PACK/recipes/android-aleapp/run.py"
target() { python3 -c 'import json,sys; print(json.dumps({"paths":[sys.argv[1]]}))' "$1"; }
# `! cmd` never stops a set -e script: a refusal is checked by hand.
refuses() { if "$@" >/dev/null 2>&1; then echo "FAIL: should have refused: $*" >&2; exit 1; fi; }
python3 "$ILEAPP" detect --target "$IOS_TARGET" --probe-out "$WORK/p1" | grep -q '"applies": true'
python3 "$ILEAPP" detect --target "$(target "$WORK/ios.zip")" | grep -q '"applies": true'
refuses python3 "$ILEAPP" detect --target "$(target "$WORK/android.tar")"
refuses python3 "$ILEAPP" detect --target "$AB_TARGET"
PATH="$WORK/bin:$PATH" python3 "$ILEAPP" run --target "$IOS_TARGET" --out "$WORK/ileapp-out" >/dev/null
jq -e '.status == "complete" and (.errors | length) == 0' "$WORK/ileapp-out/coverage.json" >/dev/null
grep -q $'^ileapp/_TSV Exports/Messages (tar).tsv\tiLEAPP artefact report' "$WORK/ileapp-out/index.tsv"
grep -q $'^ileapp/_Timeline/tl.db\t' "$WORK/ileapp-out/index.tsv"
[[ -f "$WORK/ileapp-out/ileapp/_HTML/index.html" && ! -e "$WORK/ileapp-out/ileapp-run" ]]
PATH="$WORK/bin:$PATH" python3 "$ILEAPP" run --target "$(target "$WORK/ios.zip")" --out "$WORK/ileapp-zip" >/dev/null
[[ -f "$WORK/ileapp-zip/ileapp/_TSV Exports/Messages (zip).tsv" ]]
# No iLEAPP in the image: failed, and why.
refuses env PATH=/usr/bin:/bin "$PY3" "$ILEAPP" run --target "$IOS_TARGET" --out "$WORK/ileapp-none"
jq -e '.status == "failed" and (.errors[0] | test("not on PATH"))' "$WORK/ileapp-none/coverage.json" >/dev/null
# Stopped before its end: what it leaves says partial, never complete.
STANDIN_SLEEP=30 PATH="$WORK/bin:$PATH" python3 - "$ILEAPP" "$IOS_TARGET" "$WORK/ileapp-cut" <<'PY'
import subprocess, sys
try:
    subprocess.run([sys.executable, sys.argv[1], "run", "--target", sys.argv[2], "--out", sys.argv[3]], timeout=2, capture_output=True)
except subprocess.TimeoutExpired:
    pass
PY
jq -e '.status == "partial"' "$WORK/ileapp-cut/coverage.json" >/dev/null
python3 "$ALEAPP" detect --target "$(target "$WORK/android.tar")" | grep -q '"applies": true'
refuses python3 "$ALEAPP" detect --target "$IOS_TARGET"
PATH="$WORK/bin:$PATH" python3 "$ALEAPP" run --target "$(target "$WORK/android.tar")" --out "$WORK/aleapp-out" >/dev/null
jq -e '.status == "complete"' "$WORK/aleapp-out/coverage.json" >/dev/null
grep -q $'^aleapp/_TSV Exports/Messages (tar).tsv\tALEAPP artefact report' "$WORK/aleapp-out/index.tsv"
BAA="$PACK/recipes/android-backup-apps/run.py"
python3 "$BAA" detect --target "$AB_TARGET" | grep -q '"applies": true'
refuses python3 "$BAA" detect --target "$IOS_TARGET"
out="$(python3 "$BAA" run --target "$AB_TARGET" --out "$WORK/baa-out")" && exit 1
jq -e '.status == "unsupported" and (.why | test("app tree"))' <<<"$out" >/dev/null
jq -e '.status == "failed"' "$WORK/baa-out/coverage.json" >/dev/null
[[ "$(jq -r .unavailable "$PACK/recipes/android-backup-apps/recipe.json")" == *"app tree"* && "$(jq -c .auto "$PACK/recipes/android-backup-apps/recipe.json")" == "[]" ]]

(cd "$WORK" && AGENT_ID=t1 python3 "$PACK/tools/manifest_db/run.py" <<<"{\"path\":\"$WORK/backup\"}" > "$WORK/manifest.json")
jq -e '.encrypted == false and .encryption.state == "not_encrypted" and .entry_count == 750 and (.domains | length) == 30 and .truncated == true and .pages.entries.matched == 750' "$WORK/manifest.json" >/dev/null
# nothing is cut: the whole listing is in the file the answer names
[[ "$(wc -l < "$WORK/$(jq -r .pages.entries.all_results "$WORK/manifest.json")")" -eq 750 ]]

python3 - "$PACK" "$WORK" <<'PY'
import json, os, subprocess, sys
pack, work = sys.argv[1:]

def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)

def job(tool, args, name):
    """The tool as a job runs it: JOB_ID and OUT set, OUT inside the working directory."""
    out = os.path.join(work, name)
    os.makedirs(out, exist_ok=True)
    env = dict(os.environ, JOB_ID="j-" + name, OUT=out)
    proc = subprocess.run([sys.executable, os.path.join(pack, "tools", tool, "run.py")], input=json.dumps(args),
                          text=True, capture_output=True, check=True, env=env, cwd=work)
    return json.loads(proc.stdout), out

def values(out, name):
    return [json.loads(line) for line in open(os.path.join(out, name), encoding="utf-8")]

text = b"z" * 3000
field = varint(10) + varint(len(text)) + text
blob = field + b"".join(varint(16) + varint(n) for n in range(700))
result, out = job("protobuf_peek", {"hex": blob.hex(), "write_values": True}, "pb")
assert result["field_count"] == 701 and result["structure"]["status"] == "valid", result["structure"]
# The text is in the values file, whole, and not in the answer.
assert values(out, "protobuf-values.jsonl")[0]["value"] == text.decode()
assert text.decode() not in json.dumps(result)

result, out = job("sqlite_freespace", {"db": os.path.join(work, "free.db"), "contains": "recover-", "write_values": True}, "fs")
found = values(out, "sqlite-freespace-values.jsonl")
assert any(len(item["value"]) > 1000 for item in found), result
assert result["fragment_count"] == len(found) and result["fragments"][0]["offset_verified"] is True
assert all("text" not in item for item in result["fragments"])

# Not in a job: the values are refused, and nothing is written.
proc = subprocess.run([sys.executable, os.path.join(pack, "tools/sqlite_freespace/run.py")],
                      input=json.dumps({"db": os.path.join(work, "free.db"), "write_values": True}),
                      text=True, capture_output=True, cwd=work)
assert proc.returncode != 0 and "outside a job" in json.loads(proc.stdout)["error"], proc.stdout
PY

echo "mobile-forensics pack tests passed"
