#!/usr/bin/env bash
# pip hash-checking mode in the image build (images/install.py pip_locked and
# lock_problem, images/recipe.py lock_entry, scripts/pack.sh's lock check).
#
# No network: a wheel is built here, from the wheel format (a zip with a
# dist-info directory), into a local --find-links directory, and every install
# is `--no-index --find-links` into a --target directory.
#   - a lock with the wheel's right hash installs it, and the install is recorded;
#   - a wrong hash fails, naming the program, and records nothing;
#   - a lock line without `==`, without a hash, or with an option is refused by
#     lock_problem, by the build (pip_locked) and by the seal (pack.sh);
#   - a lock changed after the build recorded its sha256 is refused;
#   - recipe.read_pack carries a pack's python.lock, a program's pip_lock and a
#     pinned source's pip_lock into the spec and the context's locks/;
#   - a set without a lock installs as it did.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || fail "$PY is required"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/wheels" "$WORK/locks"
# pip comes from a venv (ensurepip's bundled wheel: no network), whatever the host's python3 has.
if ! "$PY" -m venv "$WORK/venv" >/dev/null 2>&1 || ! "$WORK/venv/bin/python" -m pip --version >/dev/null 2>&1; then
  echo "skip - $PY cannot make a venv with pip offline"; exit 0
fi
PY="$WORK/venv/bin/python"

"$PY" - "$WORK/wheels" <<'EOF' || fail "could not build the test wheel"
import base64, hashlib, sys, zipfile
dest = sys.argv[1]
name = "hashdemo-1.0-py3-none-any.whl"
files = {
    "hashdemo/__init__.py": b"VALUE = 42\n",
    "hashdemo-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: hashdemo\nVersion: 1.0\n",
    "hashdemo-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
}
rec = []
for p, data in files.items():
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    rec.append("%s,sha256=%s,%d" % (p, digest, len(data)))
rec.append("hashdemo-1.0.dist-info/RECORD,,")
with zipfile.ZipFile(dest + "/" + name, "w") as z:
    for p, data in files.items():
        z.writestr(p, data)
    z.writestr("hashdemo-1.0.dist-info/RECORD", "\n".join(rec) + "\n")
EOF
WHEEL_SHA="$(sha256sum "$WORK/wheels/hashdemo-1.0-py3-none-any.whl" | cut -d' ' -f1)"
WRONG_SHA="$(printf 'not the wheel' | sha256sum | cut -d' ' -f1)"

# The driver: runs install.py's own functions, as the build calls them.
cat > "$WORK/drive.py" <<'EOF'
import hashlib, json, os, subprocess, sys
sys.path.insert(0, os.path.join(os.environ["ROOT"], "images"))
import install

work = os.environ["WORK"]
install.LOCK_DIR = install.Path(work + "/locks")

def pip_cmd(target):
    return [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--no-index", "--find-links", work + "/wheels",
            "--target", target, "--disable-pip-version-check", "-q"]

def ref(name):
    return {"name": name, "sha256": hashlib.sha256(open(work + "/locks/" + name, "rb").read()).hexdigest()}

mode, lockname, target = sys.argv[1], sys.argv[2], sys.argv[3]
if mode == "locked":
    why = install.pip_locked(pip_cmd(target), ref(lockname), "hashdemo-program")
    print(json.dumps({"why": why, "locked": install.LOCKED}))
elif mode == "stale":
    r = ref(lockname)
    r["sha256"] = "0" * 64
    print(json.dumps({"why": install.pip_locked(pip_cmd(target), r, "hashdemo-program"), "locked": install.LOCKED}))
elif mode == "plain":
    ok = install.run(pip_cmd(target) + ["hashdemo"])
    print(json.dumps({"ok": ok, "locked": install.LOCKED}))
elif mode == "problem":
    print(json.dumps({"why": install.lock_problem(open(work + "/locks/" + lockname).read())}))
EOF
export ROOT WORK
# install.run echoes the command it runs ("+ ...") on stdout; the result is the last line.
drive() { "$PY" "$WORK/drive.py" "$@" 2>"$WORK/drive.err" | tail -n 1; }
jqpy() { "$PY" -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1]) if sys.argv[1] in d else "")' "$1"; }

printf 'hashdemo==1.0 \\\n    --hash=sha256:%s\n' "$WHEEL_SHA" > "$WORK/locks/good.lock"
printf 'hashdemo==1.0 \\\n    --hash=sha256:%s\n' "$WRONG_SHA" > "$WORK/locks/wrong.lock"
printf 'hashdemo \\\n    --hash=sha256:%s\n' "$WHEEL_SHA" > "$WORK/locks/noeq.lock"
printf 'hashdemo==1.0\n' > "$WORK/locks/nohash.lock"
printf -- '--find-links /elsewhere\nhashdemo==1.0 --hash=sha256:%s\n' "$WHEEL_SHA" > "$WORK/locks/option.lock"
printf '# only a comment\n' > "$WORK/locks/empty.lock"

# 1. The right hash installs, and the set is recorded as locked.
out="$(drive locked good.lock "$WORK/t1")" || fail "the driver failed on the good lock: $(cat "$WORK/drive.err")"
[[ "$(jqpy why <<<"$out")" == None ]] || fail "a lock with the wheel's right hash did not install: $out $(cat "$WORK/drive.err")"
[[ -f "$WORK/t1/hashdemo/__init__.py" ]] || fail "the wheel was not installed"
grep -q '"lock": "good.lock"' <<<"$out" || fail "the install was not recorded as locked: $out"
pass "a lock with the wheel's right hash installs it, and the record says locked"

# 2. A wrong hash fails the build, names the program, and records nothing.
out="$(drive locked wrong.lock "$WORK/t2")" || fail "the driver failed on the wrong lock"
grep -q 'hashdemo-program' <<<"$out" && grep -q 'failed' <<<"$out" || fail "a wrong hash did not fail, naming the program: $out"
[[ ! -e "$WORK/t2/hashdemo" ]] || fail "a wheel whose hash is not in the lock was installed"
grep -q '"locked": \[\]' <<<"$out" || fail "a failed lock was recorded as locked: $out"
pass "a wrong hash fails the build, names the program, installs nothing and records nothing"

# 3. A lock that is not one is refused by the check and by the build, naming the program.
for case in "noeq:is not pinned with ==" "nohash:has no --hash=sha256" "option:is an option, not a requirement" "empty:holds no requirement"; do
  lock="${case%%:*}.lock"; want="${case#*:}"
  out="$(drive problem "$lock" x)"
  grep -qF "$want" <<<"$out" || fail "lock_problem on $lock did not say '$want': $out"
  out="$(drive locked "$lock" "$WORK/t3")"
  grep -q 'hashdemo-program' <<<"$out" && grep -qF "$want" <<<"$out" || fail "the build did not refuse $lock, naming the program and why: $out"
  [[ ! -e "$WORK/t3/hashdemo" ]] || fail "$lock installed something"
done
pass "a lock line without ==, without a hash, with an option, or an empty lock is refused, and the build names the program"

# 4. A lock changed after the build recorded its sha256 is refused.
out="$(drive stale good.lock "$WORK/t4")"
grep -q 'does not match the sha256 the build recorded' <<<"$out" || fail "a changed lock was not refused: $out"
[[ ! -e "$WORK/t4/hashdemo" ]] || fail "a changed lock installed something"
pass "a lock that no longer matches the sha256 the build recorded is refused"

# 5. A set without a lock installs as before, and is not recorded as locked.
out="$(drive plain good.lock "$WORK/t5")"
grep -q '"ok": true' <<<"$out" && [[ -f "$WORK/t5/hashdemo/__init__.py" ]] || fail "a set without a lock did not install: $out $(cat "$WORK/drive.err")"
grep -q '"locked": \[\]' <<<"$out" || fail "an unlocked set was recorded as locked: $out"
pass "a set without a lock installs as today"

# 6. The seal checks a pack's locks; the recipe carries them into the spec.
PK="$WORK/packs/lockpack"
mkdir -p "$PK/skills/a" "$PK/requires/locks"
printf 'Test pack.\n' > "$PK/LICENCE"
printf -- '---\nid: a/first\ntitle: First\nwhen: When asked.\nneeds: []\ntools: []\nrequires_host: []\n---\n\nBody.\n' > "$PK/skills/a/first.md"
printf 'hashdemo>=1.0\n' > "$PK/requires/python.txt"
cp "$WORK/locks/good.lock" "$PK/requires/python.lock"
cp "$WORK/locks/good.lock" "$PK/requires/locks/demo.txt"
cat > "$PK/requires/host.json" <<'EOF'
{ "binaries": [
  { "name": "demoprog", "package": "demoprog", "optional": true, "why": "A program installed from a lock.",
    "install": { "apt": "python3 -m pip install hashdemo", "pip_lock": "requires/locks/demo.txt" }, "licence": "MIT", "redistributable": true },
  { "name": "demosrc", "package": "demosrc", "optional": true, "why": "A pinned source with a locked set.",
    "install": { "apt": "pinned source 1.0", "source": { "version": "1.0", "url": "https://example.invalid/demosrc-1.0.tar.gz",
      "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "entry": "run.py", "run": "python",
      "pip_lock": "requires/locks/demo.txt", "pip": ["--no-deps", "."] } }, "licence": "MIT", "redistributable": true }
] }
EOF
printf '{ "id": "lockpack", "name": "lockpack", "version": "1.0.0", "description": "x", "licence": "AGPL-3.0-or-later", "depends": [], "requires": {"host": "requires/host.json"}, "secrets": [] }\n' > "$PK/pack.json"
got="$(bash "$ROOT/scripts/pack.sh" seal "$PK" 2>&1)" || fail "a pack with good locks did not seal: $got"
pass "the seal accepts a pack whose python.lock, pip_lock and source pip_lock are hash locks"

"$PY" - "$ROOT" "$WORK/packs" <<'EOF' || fail "recipe.read_pack did not carry the locks"
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1] + "/images")
import recipe
spec = recipe.read_pack(Path(sys.argv[2]), "lockpack")
assert spec["requirements"] == [], spec["requirements"]            # python.txt's lines are the lock's now
assert [l["pack"] for l in spec["python_locks"]] == ["lockpack"], spec["python_locks"]
assert spec["pip_locks"][0]["program"] == "demoprog" and spec["pip_locks"][0]["packages"] == ["hashdemo"], spec["pip_locks"]
assert "hashdemo" not in spec["pip"], spec["pip"]                  # not installed from the bare name as well
src = spec["sources"][0]
assert src["pip_lock"]["name"] == "lockpack-demo.txt" and len(src["pip_lock"]["sha256"]) == 64, src
assert src["pip"] == ["--no-deps", "."], src                       # the source itself still installs after its lock
names = sorted(f["name"] for f in spec["lock_files"])
assert names == ["lockpack-demo.txt", "lockpack-python.lock"], names
EOF
pass "the recipe carries python.lock, a program's pip_lock and a source's pip_lock into the spec, and the lock files into the context"

for bad in noeq nohash option; do
  cp "$WORK/locks/$bad.lock" "$PK/requires/locks/demo.txt"
  got="$(bash "$ROOT/scripts/pack.sh" seal "$PK" 2>&1)" && fail "the seal accepted a $bad lock: $got"
  grep -q 'not a hash lock' <<<"$got" || fail "the seal's refusal of a $bad lock does not say it is not a hash lock: $got"
done
pass "the seal refuses a lock line without ==, without a hash, or with an option"

cp "$WORK/locks/good.lock" "$PK/requires/locks/demo.txt"
"$PY" - "$PK/requires/host.json" <<'EOF'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
d["binaries"][0]["install"]["pip_lock"] = "../outside.txt"
json.dump(d, open(p, "w"))
EOF
got="$(bash "$ROOT/scripts/pack.sh" seal "$PK" 2>&1)" && fail "the seal accepted a lock outside requires/: $got"
grep -q 'inside requires/' <<<"$got" || fail "the refusal does not say the lock must be inside requires/: $got"
pass "the seal refuses a lock outside requires/"
