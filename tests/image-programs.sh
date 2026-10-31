#!/bin/sh
# Run INSIDE a built image (a container, or a microVM booted from it), not on
# the host: the images workflow mounts tests/ and runs it in every profile
# image, and it is how a locally built image is checked before it is loaded
# into msb. Each check is for a program the packs put in an image because a
# run asked for it and none had it:
#
#   gcc             compiles and runs a C program
#   aeskeyfind      finds an AES-128 and an AES-256 key schedule planted in
#                   random bytes (a key finder is relied on only after its own
#                   planted-key test)
#   steghide, PIL   embeds a short message in a JPEG made here and extracts it
#
# A program the image does not hold is skipped when its packs do not name it:
# the profiles differ (the base and web hold none of these). One its packs
# name (a key of `binaries` in /etc/dfirswarm/image.json) and that is not on
# PATH fails: a build that lost it (apt out of disk space did) is caught here
# too, not only by install.py at the end of the build. One the build was told
# it may lack (`missing_allowed`, recipe.py build --allow-missing-optional) is
# skipped, and says so; a record that cannot be read fails, since it cannot
# say which. Nothing here is evidence, a secret or a challenge: the
# keys and the message are made up and thrown away.
set -u
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
failed=0
ok() { echo "ok - $*"; }
no() { echo "FAIL: $*" >&2; failed=1; }
skip() { echo "skip - $*"; }
# Read the record even when every program is present: otherwise none of the
# absent() calls below checks it, and an unreadable record can pass.
if ! python3 - <<'PY' >/dev/null 2>&1
import json, os
r = json.load(open(os.environ.get("DFIRSWARM_ETC_DIR", "/etc/dfirswarm") + "/image.json"))
if not isinstance(r, dict):
    raise ValueError("image.json is not an object")
if not isinstance(r.get("binaries"), dict) or not isinstance(r.get("missing_allowed", []), list):
    raise ValueError("image.json has an invalid program list")
PY
then
  no "the image's record (image.json) could not be read to check its programs"
  exit "$failed"
fi
absent() { # <program>: not on PATH; fail when the image's record says it should be
  case "$(python3 - "$1" <<'PY' 2>/dev/null
import json, os, sys
try:
    r = json.load(open(os.environ.get("DFIRSWARM_ETC_DIR", "/etc/dfirswarm") + "/image.json"))
except (OSError, ValueError):
    print("unreadable")
    sys.exit(0)
name = sys.argv[1]
print("allowed" if name in (r.get("missing_allowed") or []) else "named" if name in (r.get("binaries") or {}) else "not-named")
PY
)" in
    named) no "$1 is named by this image's packs (image.json binaries) and is not on PATH" ;;
    allowed) skip "$1 is missing, as its build allowed (image.json missing_allowed)" ;;
    not-named) skip "$1 is not in this image" ;;
    # Every image has python3 and its record: one without either cannot say
    # whether the program should be here, and is not passed as if it did.
    *) no "$1 is not on PATH, and the image's record (image.json) could not be read to say whether it should be" ;;
  esac
}

if command -v gcc >/dev/null 2>&1; then
  printf '#include <stdio.h>\nint main(void) { puts("compiled"); return 42; }\n' > "$T/t.c"
  if gcc -O2 -Wall -o "$T/t" "$T/t.c"; then
    "$T/t" > "$T/t.out"; rc=$?
    if [ "$rc" -eq 42 ] && [ "$(cat "$T/t.out")" = compiled ]; then
      ok "gcc compiles and runs a C program ($(gcc -dumpversion))"
    else
      no "gcc built a program that does not run as written (exit $rc)"
    fi
  else
    no "gcc could not compile a C program"
  fi
  if command -v make >/dev/null 2>&1; then ok "make is there ($(make --version | head -1))"; else no "make is not there beside gcc"; fi
else
  absent gcc
fi

if command -v aeskeyfind >/dev/null 2>&1; then
  python3 - "$T/planted.bin" "$T/big.bin" > "$T/planted.txt" <<'PY'
import os, sys

def make_sbox():
    sbox = [0] * 256
    p = q = 1
    rotl = lambda x, s: ((x << s) | (x >> (8 - s))) & 0xFF
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        q &= 0xFF
        sbox[p] = q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox

SBOX = make_sbox()

def expand(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
            rcon = ((rcon << 1) ^ (0x11B if rcon & 0x80 else 0)) & 0xFF
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return bytes(b for word in w for b in word)

# FIPS-197 appendix A.1: the last round key of this key's schedule.
assert expand(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))[-16:].hex() == "d014f9a8c9ee2589e13f0cc8b6630ca6"
small, big = sys.argv[1], sys.argv[2]
size = 3000000
k128, k256, kbig = os.urandom(16), os.urandom(32), os.urandom(32)
buf = bytearray(os.urandom(size))
buf[size // 3:size // 3 + 176] = expand(k128)
buf[2 * size // 3:2 * size // 3 + 240] = expand(k256)
open(small, "wb").write(buf)
# A sparse file past 4 GiB: Debian's patch for files that large is what lets a
# key there be found, and reported at the right offset.
obig = 4 * 1024 ** 3 + 123456
with open(big, "wb") as f:
    f.truncate(5 * 1024 ** 3)
    f.seek(obig)
    f.write(expand(kbig))
print("aes128", k128.hex(), size // 3)
print("aes256", k256.hex(), 2 * size // 3)
print("beyond4GiB", kbig.hex(), obig)
PY
  # -v prints where each was found (AT BYTE, in hexadecimal) beside the key.
  aeskeyfind -q -v "$T/planted.bin" > "$T/found.txt" 2> "$T/found.err"
  aeskeyfind -q -v "$T/big.bin" > "$T/found-big.txt" 2> "$T/found-big.err"
  while read -r name key off; do
    case "$name" in beyond4GiB) f="$T/found-big.txt" ;; *) f="$T/found.txt" ;; esac
    hex="$(printf '%x' "$off")"
    # The key, and the offset it was found at, which is a line before it.
    if grep -qix "KEY: $key" "$f" && grep -qi "AT BYTE $hex *$" "$f"; then
      ok "aeskeyfind finds the planted $name key schedule at byte 0x$hex"
    else
      no "aeskeyfind did not report the planted $name key at 0x$hex: $(grep -E 'FOUND|^KEY' "$f" | head -6 | tr '\n' ' ') $(head -c 300 "${f%.txt}.err")"
    fi
  done < "$T/planted.txt"
  rm -f "$T/big.bin"
else
  absent aeskeyfind
fi

if command -v steghide >/dev/null 2>&1; then
  if python3 -c 'import PIL' 2>/dev/null; then
    python3 - "$T/cover.jpg" <<'PY'
import os, sys
from PIL import Image
Image.frombytes("RGB", (320, 240), os.urandom(320 * 240 * 3)).save(sys.argv[1], "JPEG", quality=90)
PY
    printf 'a short message made up for this check\n' > "$T/msg.txt"
    if steghide embed -q -cf "$T/cover.jpg" -ef "$T/msg.txt" -p "image-check" -sf "$T/stego.jpg" \
       && steghide extract -q -sf "$T/stego.jpg" -p "image-check" -xf "$T/back.txt" && cmp -s "$T/msg.txt" "$T/back.txt"; then
      ok "steghide embeds a message in a JPEG Pillow made and extracts it unchanged"
    else
      no "steghide could not embed and extract a message"
    fi
    # The tool's own limit, said by the image: another passphrase opens nothing.
    if steghide extract -q -sf "$T/stego.jpg" -p "another" -xf "$T/other.txt" 2>/dev/null; then
      no "steghide extracted with a passphrase that was not the one used"
    else
      ok "steghide opens nothing under another passphrase"
    fi
  else
    no "steghide is in this image and Pillow is not"
  fi
else
  absent steghide
fi

# The isolated venv of ccl_indexeddb_dump decodes Brotli content taken from the
# evidence, and Brotli before 1.2.1 has an out-of-bounds write in its decoder
# (GHSA-9v8h-qqgm-4m35): the venv must hold 1.2.1 or newer.
CCL_PY="${DFIRSWARM_SRC_DIR:-/opt/dfir/src}/ccl_indexeddb_dump/.venv/bin/python"
if [ -x "$CCL_PY" ]; then
  if v="$("$CCL_PY" -c 'import brotli; print(brotli.__version__)' 2>/dev/null)" && [ -n "$v" ] \
     && python3 -c 'import sys; v = tuple(int(p) for p in sys.argv[1].split(".")[:3]); sys.exit(0 if v >= (1, 2, 1) else 1)' "$v" 2>/dev/null; then
    ok "the ccl_indexeddb_dump venv holds Brotli $v (at least 1.2.1)"
  else
    no "the ccl_indexeddb_dump venv does not hold Brotli 1.2.1 or newer (${v:-no brotli module}); before 1.2.1 its decoder has an out-of-bounds write (GHSA-9v8h-qqgm-4m35)"
  fi
else
  absent ccl_indexeddb_dump
fi

# Pi (the agent runtime, /opt/pi) must not carry an undici older than 8.12.2:
# its own release pins 8.10.2, which has GHSA-xjj6-f33q-929c, GHSA-4qv8-2p9j-2685
# and GHSA-f72v-6w45-q472, so base.Dockerfile overrides it.
PI_DIR="${DFIRSWARM_PI_DIR:-/opt/pi}"
if [ -d "$PI_DIR/node_modules" ] && command -v node >/dev/null 2>&1; then
  old="$(node - "$PI_DIR/node_modules" <<'JS'
const fs = require("fs"), path = require("path");
const floor = [8, 12, 2], bad = [];
let found = 0;
function walk(dir) {
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (!e.isDirectory() || e.name === ".bin") continue;
    const full = path.join(dir, e.name);
    if (e.name === "undici" && fs.existsSync(path.join(full, "package.json"))) {
      found++;
      let v = "";
      try { v = String(JSON.parse(fs.readFileSync(path.join(full, "package.json"), "utf8")).version || ""); } catch {}
      const m = /^(\d+)\.(\d+)\.(\d+)/.exec(v);
      const n = m ? [+m[1], +m[2], +m[3]] : null;
      const older = !n || n[0] < floor[0] || (n[0] === floor[0] && (n[1] < floor[1] || (n[1] === floor[1] && n[2] < floor[2])));
      if (older) bad.push(path.relative(process.argv[2], full) + " " + (v || "(no version)"));
    }
    walk(full);
  }
}
walk(process.argv[2]);
process.stdout.write(bad.join("\n"));
process.exit(bad.length ? 1 : 0);
JS
)" && ok "every undici under Pi is 8.12.2 or later" \
    || no "Pi carries an undici older than 8.12.2 (GHSA-xjj6-f33q-929c, GHSA-4qv8-2p9j-2685, GHSA-f72v-6w45-q472): $old"
elif [ -d "$PI_DIR/node_modules" ]; then
  no "Pi is installed in $PI_DIR and node is not there to check its undici"
else
  skip "Pi is not installed in $PI_DIR in this image"
fi
exit $failed
