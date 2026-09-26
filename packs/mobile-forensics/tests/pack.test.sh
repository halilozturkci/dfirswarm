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
python3 "$PACK/recipes/ios-filesystem/run.py" run --target "$IOS_TARGET" --out "$WORK/ios-out" >/dev/null
jq -e '.status == "complete" and .categories["biome-segb"] == 1 and .categories["unified-log"] == 1' "$WORK/ios-out/coverage.json" >/dev/null
grep -q $'private/var/mobile/Library/SMS/sms.db\t16\t3\t' "$WORK/ios-out/sqlite.tsv"

AB_TARGET="$(python3 -c 'import json,sys; print(json.dumps({"paths":[sys.argv[1]]}))' "$WORK/android.ab")"
python3 "$PACK/recipes/android-backup/run.py" detect --target "$AB_TARGET" | grep -q '"applies": true'
python3 "$PACK/recipes/android-backup/run.py" run --target "$AB_TARGET" --out "$WORK/ab-out" >/dev/null
jq -e '.status == "complete" and .covered == "3 embedded tar members"' "$WORK/ab-out/coverage.json" >/dev/null
[[ "$(($(wc -l < "$WORK/ab-out/members.tsv") - 1))" -eq 3 ]]

printf '%s' "{\"path\":\"$WORK/backup\"}" | python3 "$PACK/tools/manifest_db/run.py" > "$WORK/manifest.json"
jq -e '.encrypted == false and .entry_count == 750 and (.domains | length) == 30 and .truncated == null' "$WORK/manifest.json" >/dev/null

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

text = b"z" * 3000
field = varint(10) + varint(len(text)) + text
blob = field + b"".join(varint(16) + varint(n) for n in range(700))
proc = subprocess.run([sys.executable, os.path.join(pack, "tools/protobuf_peek/run.py")],
                      input=json.dumps({"hex": blob.hex()}), text=True, capture_output=True, check=True)
result = json.loads(proc.stdout)
assert len(result["fields"]) == 701
assert result["fields"][0]["text"] == text.decode()

proc = subprocess.run([sys.executable, os.path.join(pack, "tools/sqlite_freespace/run.py")],
                      input=json.dumps({"db": os.path.join(work, "free.db"), "contains": "recover-"}),
                      text=True, capture_output=True, check=True)
result = json.loads(proc.stdout)
assert any(len(item["text"]) > 1000 for item in result["fragments"]), result
assert "truncated" not in result
PY

echo "mobile-forensics pack tests passed"
