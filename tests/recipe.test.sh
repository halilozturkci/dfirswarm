#!/usr/bin/env bash
# Images from packs: which profile a run gets, what a build context holds, and
# how a pinned download is fetched. No container is built here; CI's images
# workflow builds and boots them.
#
# What must not go wrong: a run must get the smallest image that serves its
# packs, never an unbuilt `full` when a smaller one covers them; a build must
# not bake programs their packs mark not redistributable without being told
# to; an image must record which pack versions it was built from; a pinned
# download must be refused when its bytes are not the pinned ones, or when its
# archive reaches outside its directory; a pack must not declare a download
# that could not be checked; an installed pack the repository does not carry
# must be matched by what it names, not sent to `full`; a lock entry must be
# pinned by digest; every image, the base included, must record the package
# lists a VM's inventory is diffed against, a NOTICE and an SBOM.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/recipe.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
R="$ROOT/images/recipe.py"
# profile-for reads installed packs from here; the operator's own must not
# change what this suite sees.
export DFIRSWARM_HOME="$TMP/home"

# --- which profile ------------------------------------------------------------
[[ "$(python3 "$R" profile-for)" == base ]] || fail "no packs should be the base image"
[[ "$(python3 "$R" profile-for windows-forensics)" == disk ]] || fail "windows-forensics should be disk"
[[ "$(python3 "$R" profile-for memory-forensics)" == memory ]] || fail "memory-forensics should be memory"
got="$(python3 "$R" profile-for ransomware-response)"
[[ "$got" == re ]] || fail "ransomware-response is held by re, which beats memory, a smaller image that covers it only by chance; got $got"
[[ "$(python3 "$R" profile-for macos-forensics)" == mobile ]] || fail "macos-forensics is held by mobile, as mobile-forensics' dependency"
[[ "$(python3 "$R" profile-for triage-collection)" == full ]] || fail "triage-collection is held by full alone and covered by nothing smaller"
[[ "$(python3 "$R" profile-for no-such-pack)" == full ]] || fail "an unknown pack cannot be covered by anything smaller than full"
# A run's job images: each pack in its own profile, and a dependency every
# profile holds with its dependents, not in the smallest image that holds it.
jp="$(python3 "$R" job-profiles computer-forensics-base windows-forensics mobile-forensics encrypted-containers macos-forensics)"
jq -e '. == {"computer-forensics-base": "disk", "windows-forensics": "disk", "mobile-forensics": "mobile", "encrypted-containers": "disk", "macos-forensics": "mobile"}' <<<"$jp" >/dev/null \
  || fail "the base pack of a disk and mobile run should run in disk, not in memory: $jp"
jp="$(python3 "$R" job-profiles computer-forensics-base windows-forensics encrypted-containers linux-forensics)"
[[ "$(jq -r '."computer-forensics-base"' <<<"$jp")" == disk ]] || fail "the base pack goes where most of the run's packs are (disk, two), not linux (one): $jp"
[[ "$(python3 "$R" job-profiles computer-forensics-base memory-forensics | jq -r '."computer-forensics-base"')" == memory ]] || fail "with memory-forensics alone, the base pack runs in memory"
pass "the smallest profile that holds or covers the packs is chosen, and full only when nothing smaller serves"

# An installed pack this repository does not carry (a pro or third-party one):
# found where pack.sh installs it, or at the path given, and matched by what it
# names. This one names memory programs only, so memory covers it.
pro="$DFIRSWARM_HOME/packs/pro-memory"
mkdir -p "$pro/requires"
printf '{"id": "pro-memory", "name": "p", "version": "1.0.0", "description": "p", "licence": "MIT", "depends": ["computer-forensics-base>=1.2.0"]}\n' > "$pro/pack.json"
printf '{"binaries": [{"name": "vol", "why": "t", "licence": "t", "redistributable": false}, {"name": "memprocfs", "optional": true, "why": "t", "licence": "t", "redistributable": false}]}\n' > "$pro/requires/host.json"
got="$(python3 "$R" profile-for pro-memory)"
[[ "$got" == memory ]] || fail "an installed pack naming only memory programs should get memory, got $got"
got="$(DFIRSWARM_HOME="$TMP/elsewhere" python3 "$R" profile-for "$pro")"
[[ "$got" == memory ]] || fail "a pack given as a directory should be read there, got $got"
got="$(DFIRSWARM_HOME="$TMP/elsewhere" python3 "$R" profile-for --installed "$DFIRSWARM_HOME/packs" pro-memory)"
[[ "$got" == memory ]] || fail "--installed should name where the packs are, got $got"
[[ "$(DFIRSWARM_HOME="$TMP/elsewhere" python3 "$R" profile-for pro-memory)" == full ]] || fail "a pack found nowhere should still be full"
# One that imports a library no profile installs is covered by none.
printf 'somelib>=1\n' > "$pro/requires/python.txt"
[[ "$(python3 "$R" profile-for pro-memory)" == full ]] || fail "an installed pack importing what no profile installs should be full"
rm "$pro/requires/python.txt"
pass "an installed pack the repository does not carry is found where it is installed and matched by what it names"

# Library tools say which programs they call (manifest `requires`): a profile
# smaller than full that has them all is preferred, and one that lacks some
# never pushes a run to full.
got="$(python3 "$R" profile-for --tools-from "$ROOT/tool-library")"
[[ "$got" == disk ]] || fail "the tool library calls TSK, esedbexport, yara and vol, which disk has; got $got"
got="$(python3 "$R" profile-for --tools-from "$ROOT/tool-library" memory-forensics)"
[[ "$got" == memory ]] || fail "the packs decide when no smaller image serves both; got $got"
mkdir -p "$TMP/tl/only_sql" "$TMP/tl2/odd_one"
printf '{"name": "only_sql", "requires": ["sqlite3"]}\n' > "$TMP/tl/only_sql/manifest.json"
printf '{"name": "odd_one", "requires": ["no-such-program"]}\n' > "$TMP/tl2/odd_one/manifest.json"
[[ "$(python3 "$R" profile-for --tools-from "$TMP/tl")" == base ]] || fail "a program the base image has needs no profile"
[[ "$(python3 "$R" profile-for --tools-from "$TMP/tl2")" == base ]] || fail "a program no image has must not push a run to full"
missing_req="$(python3 - "$ROOT" <<'EOF'
import json, re, sys, pathlib
# A library tool that runs one of these must say so in its manifest. (No
# quote characters in this heredoc: bash 3.2 miscounts them inside $(...).)
progs = "fls|icat|img_stat|img_cat|mmls|istat|esedbexport|yara|vol|ewfexport"
# Python: an argv element or a which(); a shell script: a command at the start of a line or after a pipe.
py_call = re.compile(r"[\x22\x27](" + progs + r")[\x22\x27]\s*[,\])]")
sh_call = re.compile(r"(?:^|\|)\s*(" + progs + r")\s", re.M)
out = []
for mf in sorted(pathlib.Path(sys.argv[1]).glob("tool-library/*/manifest.json")):
    m = json.loads(mf.read_text())
    body = (mf.parent / m["entry"]).read_text()
    used = set((sh_call if m["entry"].endswith(".sh") else py_call).findall(body))
    lacking = used - set(m.get("requires") or [])
    if lacking:
        out.append(f"{mf.parent.name}: {', '.join(sorted(lacking))}")
print("\n".join(out))
EOF
)"
[[ -z "$missing_req" ]] || fail "a library tool runs a program its manifest does not name in requires: $missing_req"
pass "library tools name the programs they call, and those pick an image only when one smaller than full has them"

# --- the images lock ------------------------------------------------------------
digest="$(printf '%064d' 0 | tr 0 a)"
upper="$(tr a-f A-F <<<"$digest")"
printf '{"images": {"disk": {"amd64": "ghcr.io/o/dfirswarm-disk:1.2@sha256:%s", "arm64": "ghcr.io/o/dfirswarm-disk@sha256:%s"}}}\n' "$digest" "$digest" > "$TMP/lock-good.json"
python3 "$R" check-lock "$TMP/lock-good.json" >/dev/null || fail "a lock pinned by digest was refused"
for bad in '{"images": {"disk": {"amd64": "ghcr.io/o/dfirswarm-disk:1.2"}}}' \
           '{"images": {"disk": {"amd64": "ghcr.io/o/dfirswarm-disk@sha256:abc"}}}' \
           '{"images": {"disk": {"amd64": "ghcr.io/o/dfirswarm-disk@sha256:'"$upper"'"}}}' \
           '{"images": {"disk": "ghcr.io/o/dfirswarm-disk@sha256:'"$digest"'"}}' \
           '{"images": {}}' \
           '{"disk": {"amd64": "ghcr.io/o/dfirswarm-disk@sha256:'"$digest"'"}}' \
           'not json'; do
  printf '%s\n' "$bad" > "$TMP/lock-bad.json"
  out="$(python3 "$R" check-lock "$TMP/lock-bad.json" 2>&1)" && fail "a lock entry not pinned by digest was accepted: $bad"
  grep -q 'refused' <<<"$out" || fail "the refusal should say what it refused: $out"
done
printf '{"images": {"no-such-profile": {"amd64": "r@sha256:%s"}}}\n' "$digest" > "$TMP/lock-odd.json"
out="$(python3 "$R" check-lock "$TMP/lock-odd.json" 2>&1)" || fail "an unknown profile is a warning, not a refusal: $out"
grep -q 'no such profile' <<<"$out" || fail "an unknown profile should be named: $out"
pass "a lock entry must name its image by digest; a tag, a short or upper-case digest, or a malformed lock is refused"

# --- a build context ----------------------------------------------------------
out="$(python3 "$R" build memory --out "$TMP/ctx" 2>&1)"; rc=$?
[[ $rc -eq 3 ]] || fail "a build holding programs marked not redistributable should stop without --allow-nonredistributable (rc $rc): $out"
grep -q 'never publish it' <<<"$out" || fail "the refusal should say what the flag is for: $out"
[[ ! -e "$TMP/ctx/spec.json" ]] || fail "a refused build wrote its context"
python3 "$R" build memory --out "$TMP/ctx" --allow-nonredistributable >/dev/null || fail "the build with the flag failed"
for f in spec.json Dockerfile install.py NOTICE; do [[ -f "$TMP/ctx/$f" ]] || fail "the context lacks $f"; done
jq -e '.pack_versions["memory-forensics"].version and (.pack_versions["memory-forensics"].seal | length == 64)' "$TMP/ctx/spec.json" >/dev/null \
  || fail "the spec does not carry each pack's version and seal"
[[ "$(jq -r '.redistributable' "$TMP/ctx/spec.json")" == false ]] || fail "the spec does not say the image is not for redistribution"
jq -e '.downloads[] | select(.name == "memprocfs") | .amd64.sha256 and .arm64.sha256' "$TMP/ctx/spec.json" >/dev/null || fail "memprocfs is not a pinned download"
grep -q 'dev.dfirswarm.redistributable="false"' "$TMP/ctx/Dockerfile" || fail "the image's label does not say so"
python3 "$R" build web --out "$TMP/ctx-web" >/dev/null || fail "web holds no pack program and should build without the flag"
grep -q 'dev.dfirswarm.redistributable' "$TMP/ctx-web/Dockerfile" && fail "a profile with nothing held back must inherit the base's label, not claim its own"
grep -q 'dev.dfirswarm.redistributable="${REDISTRIBUTABLE}"' "$ROOT/images/base.Dockerfile" || fail "the base image does not carry the redistributable label"
grep -q 'COPY install.py spec.json NOTICE' "$TMP/ctx/Dockerfile" || fail "the NOTICE does not go into the image"
grep -q '^vol  (memory-forensics)  Volatility Software License 1.0' "$TMP/ctx/NOTICE" || fail "the NOTICE does not name vol's licence"
seal_py="$(jq -r '.pack_versions["memory-forensics"].seal' "$TMP/ctx/spec.json")"
seal_ts="$(cd "$ROOT" && node --experimental-strip-types -e 'import("./scripts/vm.ts").then(m => console.log(m.packNeeds(["packs/memory-forensics"])[0].seal))')"
[[ "$seal_py" == "$seal_ts" ]] || fail "the recipe's seal ($seal_py) and the kickoff's ($seal_ts) differ"
pass "a build context carries pack versions and seals the kickoff computes alike, a NOTICE, and says it is not for redistribution"

# --- the pinned download ------------------------------------------------------
mkdir -p "$TMP/dl/src/tool-1.0" "$TMP/tools" "$TMP/bin"
printf '#!/bin/sh\necho tool ran\n' > "$TMP/dl/src/tool-1.0/tool"
chmod +x "$TMP/dl/src/tool-1.0/tool"
tar -czf "$TMP/dl/tool.tar.gz" -C "$TMP/dl/src" tool-1.0
sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TMP/dl/tool.tar.gz")"
# An archive that climbs out of its directory.
python3 - "$TMP/dl/evil.tar.gz" <<'EOF'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w:gz") as t:
    data = b"#!/bin/sh\necho escaped\n"
    info = tarfile.TarInfo("../../escaped")
    info.size = len(data)
    t.addfile(info, io.BytesIO(data))
EOF
evil_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TMP/dl/evil.tar.gz")"
res="$(DFIRSWARM_TOOLS_DIR="$TMP/tools" DFIRSWARM_BIN_DIR="$TMP/bin" python3 - "$ROOT/images" "$TMP/dl" "$sha" "$evil_sha" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
import install
dl, sha, evil = sys.argv[2], sys.argv[3], sys.argv[4]
a = install.arch()
def pin(url, digest, bin_=None):
    e = {"url": url, "sha256": digest}
    if bin_:
        e["bin"] = bin_
    return {"name": "tool", "version": "1.0", a: e}
out = {}
got, why = install.fetch(pin(f"file://{dl}/tool.tar.gz", sha, "tool-1.0/tool"), [])
out["good"] = [bool(got), why]
got, why = install.fetch(pin(f"file://{dl}/tool.tar.gz", "0" * 64, "tool-1.0/tool"), [])
out["bad_sha"] = [bool(got), why]
got, why = install.fetch(pin(f"file://{dl}/evil.tar.gz", evil, "escaped"), [])
out["escape"] = [bool(got), why]
got, why = install.fetch({"name": "tool", "version": "1.0", "no-such-arch": {}}, [])
out["no_arch"] = [bool(got), why]
print(json.dumps(out))
EOF
)" || fail "install.py could not be driven: $res"
# The installer says what it fetches; the verdicts are its last line.
res="$(tail -1 <<<"$res")"
[[ "$(jq -r '.good[0]' <<<"$res")" == true ]] || fail "a download whose sha256 matches was refused: $res"
[[ "$("$TMP/bin/tool")" == "tool ran" ]] || fail "the program is not linked where PATH finds it"
[[ "$(jq -r '.bad_sha[0]' <<<"$res")" == false ]] && jq -r '.bad_sha[1]' <<<"$res" | grep -q 'is not the pinned' || fail "a download with other bytes was installed: $res"
[[ "$(jq -r '.escape[0]' <<<"$res")" == false ]] && jq -r '.escape[1]' <<<"$res" | grep -q 'leaves the download' || fail "an archive that climbs out of its directory was unpacked: $res"
[[ ! -e "$TMP/escaped" && ! -e "$(dirname "$TMP")/escaped" ]] || fail "the escaping file was written"
[[ "$(jq -r '.no_arch[0]' <<<"$res")" == false ]] && jq -r '.no_arch[1]' <<<"$res" | grep -q 'build pinned' || fail "an architecture with no pin was not recorded as such: $res"
pass "a pinned download is linked onto PATH when its sha256 matches, and refused when its bytes differ, its archive climbs out, or its architecture has no pin"

# A download that arrives short is tried again; one whose whole length is
# other bytes is not (the file at the URL changed, and would again).
res="$(python3 - "$ROOT/images" "$TMP" <<'EOF'
import hashlib, http.server, json, sys, threading
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import install
body = b"runtime " * 4096
sha = hashlib.sha256(body).hexdigest()
hits = {"short": 0, "other": 0}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        name = self.path.strip("/")
        hits[name] += 1
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if name == "short" and hits[name] == 1:
            self.wfile.write(body[: len(body) // 2])
            self.close_connection = True
            return
        self.wfile.write(body if name == "short" else b"x" * len(body))
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_address[1]}"
dest = Path(sys.argv[2]) / "dl.bin"
short = install.get(f"{url}/short", dest, sha)
other = install.get(f"{url}/other", dest, sha)
print(json.dumps({"short": [short, hits["short"], dest.exists()], "other": [other, hits["other"]]}))
EOF
)" || fail "install.get could not be driven: $res"
res="$(tail -1 <<<"$res")"
jq -e '.short[0] == null and .short[1] == 2' <<<"$res" >/dev/null || fail "a download cut off halfway was not fetched again: $res"
jq -e '(.other[0] | test("is not the pinned")) and .other[1] == 1' <<<"$res" >/dev/null || fail "a whole download of other bytes was fetched again, or installed: $res"
pass "a download that arrives short is fetched again, and one of other bytes is refused at once"

# --- the other pinned kinds -----------------------------------------------------
# A pack names what no package manager has as data: an apt line from the
# image's backports, a .deb per architecture, a tag's source with its entry and
# its interpreter, a source compiled in a builder stage, and a program that
# belongs to another system. The recipe turns each into its part of the spec
# and of the Dockerfile; nothing of any one program is in the harness.
fake="$TMP/fakepacks/reverse-engineering"
mkdir -p "$fake/requires"
printf '{"id": "reverse-engineering", "name": "f", "version": "1.0.0", "description": "f", "licence": "MIT", "depends": []}\n' > "$fake/pack.json"
cat > "$fake/requires/host.json" <<JSON
{"binaries": [
 {"name": "bp-tool", "optional": true, "why": "t", "licence": "t", "redistributable": false,
  "install": {"apt": "apt-get install -y -t bookworm-backports bp-tool"}},
 {"name": "deb-tool", "optional": true, "why": "t", "licence": "t", "redistributable": false,
  "install": {"apt": "x", "download": {"version": "1", "arm64": {"url": "https://example.org/deb-tool_1_arm64.deb", "sha256": "$sha", "bin": "/opt/deb-tool/bin/deb-tool"}}}},
 {"name": "src-tool", "optional": true, "why": "t", "licence": "t", "redistributable": false,
  "install": {"apt": "x", "source": {"version": "2", "url": "https://example.org/src-tool-2.tar.gz", "sha256": "$sha", "entry": "scripts/tool.py", "run": "python", "pip": ["-r", "requirements.txt"], "skip": ["tests/data"]}}},
 {"name": "built-tool", "optional": true, "why": "t", "licence": "t", "redistributable": false,
  "install": {"apt": "x", "build": {"version": "3", "url": "https://example.org/built-tool-3.tar.gz", "sha256": "$sha", "bin": "bin/built-tool", "build_deps": ["libz-dev"], "apt_deps": ["zlib1g"]}}},
 {"name": "mac-only", "optional": true, "why": "t", "licence": "t", "redistributable": false,
  "not_in_image": "Only macOS has it."}
]}
JSON
# re also holds the ransomware pack: an empty one here.
mkdir -p "$TMP/fakepacks/ransomware-response/requires"
printf '{"id": "ransomware-response", "name": "f", "version": "1.0.0", "description": "f", "licence": "MIT", "depends": []}\n' > "$TMP/fakepacks/ransomware-response/pack.json"
printf '{"binaries": []}\n' > "$TMP/fakepacks/ransomware-response/requires/host.json"
python3 "$R" build re --packs "$TMP/fakepacks" --out "$TMP/ctx-kinds" --allow-nonredistributable >/dev/null || fail "a context of every pinned kind could not be written"
spec="$TMP/ctx-kinds/spec.json"
jq -e '.apt["bp-tool"] == false and .apt_release == {"bp-tool": "bookworm-backports"} and (.apt | has("bookworm-backports") | not)' "$spec" >/dev/null \
  || fail "an apt line's -t release is where its package comes from, not a package: $(jq -c '{apt, apt_release}' "$spec")"
jq -e '[.downloads[].name] == ["deb-tool"] and [.sources[].name] == ["src-tool"] and [.builds[].name] == ["built-tool"]' "$spec" >/dev/null \
  || fail "each pinned kind is not where the spec keeps it: $(jq -c '{d: [.downloads[].name], s: [.sources[].name], b: [.builds[].name]}' "$spec")"
jq -e '.manual == [] and .not_applicable == [{"name": "mac-only", "pack": "reverse-engineering", "why": "Only macOS has it."}]
       and ([.binaries[].name] | index("mac-only") == null)' "$spec" >/dev/null \
  || fail "another system's program is not listed as not applicable, or is still expected in the image: $(jq -c '{manual, not_applicable}' "$spec")"
grep -q '^mac-only  (reverse-engineering)  Only macOS has it.' "$TMP/ctx-kinds/NOTICE" || fail "the NOTICE does not say which programs belong to another system"
df="$TMP/ctx-kinds/Dockerfile"
grep -q '^FROM ${BASE} AS build-built-tool$' "$df" || fail "a program built from source has no builder stage: $(cat "$df")"
grep -q '^RUN python3 /tmp/dfirswarm-build/install.py --build /tmp/dfirswarm-build/build-built-tool.json$' "$df" || fail "the builder stage does not build from its own file"
jq -e '.name == "built-tool" and .bin == "bin/built-tool"' "$TMP/ctx-kinds/build-built-tool.json" >/dev/null || fail "the builder stage's file is not the program's build"
copy="$(grep -n '^COPY --from=build-built-tool /opt/dfir/tools/built-tool /opt/dfir/tools/built-tool$' "$df" | cut -d: -f1)"
spec_copy="$(grep -n '^COPY install.py spec.json NOTICE' "$df" | cut -d: -f1)"
[[ -n "$copy" && -n "$spec_copy" && "$copy" -lt "$spec_copy" ]] || fail "what the builder installed is not copied before the profile's install runs: $(cat "$df")"
pass "an apt line's backports release, a .deb, a pinned source, a build in its own stage and another system's program each land in the spec and the Dockerfile"

# install.py on each kind, with apt, the venv, the tools, the sources and bin
# all in the test's own directories. apt is a script that says what it was asked.
# (No AppleDouble ._ entries from macOS tar: a tag's tarball has none.)
export COPYFILE_DISABLE=1
K="$TMP/kinds"
mkdir -p "$K/src/proj-2.0/scripts" "$K/src/proj-2.0/tests/data" "$K/venv/bin" "$K/opt/deb-tool/bin" "$K/apt-sources"
printf 'GREETING = "helper ran"\n' > "$K/src/proj-2.0/helper.py"
printf 'import helper, sys\nprint(helper.GREETING, *sys.argv[1:])\n' > "$K/src/proj-2.0/scripts/tool.py"
printf 'big\n' > "$K/src/proj-2.0/tests/data/sample.bin"
: > "$K/src/proj-2.0/requirements.txt"
tar -czf "$K/proj-2.0.tar.gz" -C "$K/src" proj-2.0
src_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$K/proj-2.0.tar.gz")"
ln -s "$(command -v python3)" "$K/venv/bin/python"
printf 'not really a package\n' > "$K/deb-tool_1.deb"
deb_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$K/deb-tool_1.deb")"
printf '#!/bin/sh\necho deb-tool ran\n' > "$K/opt/deb-tool/bin/deb-tool"
printf '#!/bin/sh\necho "$@" >> "%s/apt.log"\n' "$K" > "$K/apt"
chmod +x "$K/apt" "$K/opt/deb-tool/bin/deb-tool"
# A source that builds the way autotools does: configure writes a Makefile
# whose install puts the program under the prefix it was given.
mkdir -p "$K/bsrc/built-3" "$K/bsrc-bad/built-3"
cat > "$K/bsrc/built-3/configure" <<'SH'
#!/bin/sh
prefix="${1#--prefix=}"
printf 'all:\n\t@echo built\ninstall:\n\tmkdir -p %s/bin\n\tprintf "#!/bin/sh\\necho built-tool ran%s\\n" > %s/bin/built-tool\n' "$prefix" "${BUILD_NOTE:+ $BUILD_NOTE}" "$prefix" > Makefile
SH
printf '#!/bin/sh\nexit 1\n' > "$K/bsrc-bad/built-3/configure"
chmod +x "$K/bsrc/built-3/configure" "$K/bsrc-bad/built-3/configure"
tar -czf "$K/built-3.tar.gz" -C "$K/bsrc" built-3
tar -czf "$K/built-bad.tar.gz" -C "$K/bsrc-bad" built-3
b_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$K/built-3.tar.gz")"
bad_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$K/built-bad.tar.gz")"
printf 'Types: deb\nURIs: http://mirror.example/debian\nSuites: bookworm\n\nTypes: deb\nURIs: http://mirror.example/debian-security\nSuites: bookworm-security\n' > "$K/apt-sources/debian.sources"
printf 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n' > "$K/os-release"
res="$(DFIRSWARM_TOOLS_DIR="$K/tools" DFIRSWARM_SRC_DIR="$K/opt-src" DFIRSWARM_BIN_DIR="$TMP/bin" DFIRSWARM_VENV="$K/venv" \
       DFIRSWARM_APT_SOURCES_DIR="$K/apt-sources" DFIRSWARM_OS_RELEASE="$K/os-release" DFIRSWARM_BUILD_DIR="$K/work" \
       python3 - "$ROOT/images" "$K" "$src_sha" "$deb_sha" "$b_sha" "$bad_sha" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
import install
K, src_sha, deb_sha, b_sha, bad_sha = sys.argv[2:7]
apt = [f"{K}/apt"]
a = install.arch()
out = {}
src = {"name": "src-tool", "version": "2", "url": f"file://{K}/proj-2.0.tar.gz", "sha256": src_sha,
       "entry": "scripts/tool.py", "run": "python", "skip": ["tests/data"]}
got, why = install.fetch_source(src, apt)
out["source"] = [bool(got), why, (got or {}).get("kind")]
got, why = install.fetch_source({**src, "name": "src-venv", "pip": ["--no-index", "-r", "requirements.txt"]}, apt)
out["source_venv"] = [bool(got), why, (got or {}).get("venv")]
got, why = install.fetch_source({**src, "name": "src-bad", "sha256": "0" * 64}, apt)
out["source_bad_sha"] = [bool(got), why]
got, why = install.fetch_source({**src, "name": "src-shell", "entry": "helper.py", "run": "no-such-runtime"}, apt)
out["no_runtime"] = [bool(got), why]
got, why = install.fetch_source({**src, "name": "src-elsewhere", "arches": ["no-such-arch"]}, apt)
out["other_arch"] = [bool(got), why]
deb = {"name": "deb-tool", "version": "1", a: {"url": f"file://{K}/deb-tool_1.deb", "sha256": deb_sha, "bin": f"{K}/opt/deb-tool/bin/deb-tool"}}
got, why = install.fetch(deb, apt)
out["deb"] = [bool(got), why, (got or {}).get("kind")]
got, why = install.fetch({**deb, "name": "deb-bad", a: {**deb[a], "sha256": "0" * 64}}, apt)
out["deb_bad_sha"] = [bool(got), why]
good = {"name": "built-tool", "version": "3", "url": f"file://{K}/built-3.tar.gz", "sha256": b_sha, "bin": "bin/built-tool",
        "env": {"BUILD_NOTE": "with its env"}}
spec = f"{K}/build.json"
open(spec, "w").write(json.dumps(good))
out["build_rc"] = install.build_source(spec)
got, why = install.link_build(good, apt)
out["build"] = [bool(got), why, (got or {}).get("kind")]
open(spec, "w").write(json.dumps({**good, "name": "built-bad", "url": f"file://{K}/built-bad.tar.gz", "sha256": bad_sha}))
out["bad_optional_rc"] = install.build_source(spec)
out["bad_link"] = list(install.link_build({**good, "name": "built-bad"}, apt))
open(spec, "w").write(json.dumps({**good, "name": "built-req", "url": f"file://{K}/built-bad.tar.gz", "sha256": bad_sha, "required": True}))
out["bad_required_rc"] = install.build_source(spec)
out["backports"] = install.enable_release("bookworm-backports")
out["other_release"] = install.enable_release("trixie")
print(json.dumps(out))
EOF
)" || fail "install.py could not be driven over the pinned kinds: $res"
res="$(tail -1 <<<"$res")"
[[ "$(jq -r '.source[0]' <<<"$res")" == true ]] || fail "a pinned source was not installed: $res"
[[ "$("$TMP/bin/src-tool" a b)" == "helper ran a b" ]] || fail "a pinned source's entry does not run through its interpreter with the checkout's modules: $("$TMP/bin/src-tool" 2>&1)"
[[ -f "$K/opt-src/src-tool/helper.py" && ! -e "$K/opt-src/src-tool/proj-2.0" ]] || fail "the archive's top directory was not dropped"
[[ ! -e "$K/opt-src/src-tool/tests/data" ]] || fail "a path the pack skips was unpacked"
[[ "$(jq -r '.source_venv[0]' <<<"$res")" == true && -x "$K/opt-src/src-venv/.venv/bin/python" ]] || fail "a source with pip arguments did not get a venv of its own: $res"
grep -q 'opt-src/src-venv/.venv/bin/python" ' "$TMP/bin/src-venv" || fail "a source with its own venv is not run by that venv's python: $(cat "$TMP/bin/src-venv")"
[[ "$(jq -r '.source_bad_sha[0]' <<<"$res")" == false ]] && jq -r '.source_bad_sha[1]' <<<"$res" | grep -q 'is not the pinned' || fail "a source with other bytes was unpacked: $res"
[[ ! -e "$K/opt-src/src-bad/helper.py" ]] || fail "a source whose sha256 failed left its files"
jq -r '.no_runtime[1]' <<<"$res" | grep -q 'its runtime no-such-runtime is not in the image' || fail "a program whose interpreter the image lacks was linked: $res"
[[ "$(jq -r '.other_arch[0]' <<<"$res")" == false && ! -e "$K/opt-src/src-elsewhere" ]] && jq -r '.other_arch[1]' <<<"$res" | grep -q 'pins it for no-such-arch only' \
  || fail "a source its pack pins for other architectures was installed here: $res"
[[ "$(jq -r '.deb[0]' <<<"$res")" == true && "$("$TMP/bin/deb-tool")" == "deb-tool ran" ]] || fail "a pinned .deb's program is not on PATH: $res"
[[ "$(jq -r '.deb[2]' <<<"$res")" == deb && "$(jq -r '.source[2]' <<<"$res")" == source ]] || fail "the image does not record each artefact's kind: $res"
grep -q "deb-tool_1.deb" "$K/apt.log" || fail "a pinned .deb was not handed to apt: $(cat "$K/apt.log")"
grep -q 'deb-bad' "$K/apt.log" && fail "apt was handed a .deb whose sha256 is not the pinned one"
[[ "$(jq -r '.deb_bad_sha[0]' <<<"$res")" == false ]] || fail "a .deb with other bytes was installed: $res"
[[ "$(jq -r '.build_rc' <<<"$res")" == 0 && "$(jq -r '.build[0]' <<<"$res")" == true ]] || fail "a source that builds was not built and linked: $res"
[[ "$("$TMP/bin/built-tool")" == "built-tool ran with its env" ]] || fail "a built program is not on PATH, or its env did not reach its configure: $("$TMP/bin/built-tool")"
jq -e '.ok == true and .kind == "build"' "$K/tools/built-tool/.dfirswarm-build.json" >/dev/null || fail "a build does not say beside its program that it built"
[[ "$(jq -r '.bad_optional_rc' <<<"$res")" == 0 ]] || fail "an optional program that does not build stopped the image: $res"
jq -r '.bad_link[1]' <<<"$res" | grep -q 'configure failed' || fail "an optional program that did not build is not recorded with why: $res"
[[ "$(jq -r '.bad_required_rc' <<<"$res")" == 1 ]] || fail "a required program that does not build did not stop the image: $res"
[[ "$(jq -r '.backports' <<<"$res")" == null ]] || fail "the image's own backports were refused: $res"
grep -q '^URIs: http://mirror.example/debian$' "$K/apt-sources/dfirswarm-bookworm-backports.sources" && grep -q '^Suites: bookworm-backports$' "$K/apt-sources/dfirswarm-bookworm-backports.sources" \
  || fail "backports do not come from the image's own mirror: $(cat "$K/apt-sources/dfirswarm-bookworm-backports.sources")"
jq -r '.other_release' <<<"$res" | grep -q "is not this image's backports" || fail "a release other than the image's backports was added: $res"
pass "install.py puts a pinned source, a .deb and a built program on PATH only when their bytes are the pinned ones, gives a source's requirements a venv of its own, builds with the pack's env, records a failed build, and adds only its own backports"

# --- what an image records ------------------------------------------------------
# The base records what a profile does: the venv as `pip list` names it (a VM's
# inventory at stop is diffed against it, so the base's own packages are not
# "installed outside the image"), the whole Debian list, a NOTICE with the npm
# and Python licences, an SBOM, and whether it may be redistributed. A profile
# built on it keeps the base's flag. A fake venv and npm stand in here.
mkdir -p "$TMP/rec/venv/bin" "$TMP/rec/fakebin" "$TMP/rec/npm/@earendil-works/pi-coding-agent/node_modules/left-pad" "$TMP/rec/npm/@earendil-works/pi-coding-agent/dist"
printf '#!/bin/sh\necho %s\n' "'[{\"name\": \"dissect.util\", \"version\": \"3.20\"}, {\"name\": \"pip\", \"version\": \"23.0.1\"}]'" > "$TMP/rec/venv/bin/pip"
printf '#!/bin/sh\necho %s\n' "'[[\"dissect.util\", \"3.20\", \"AGPL-3.0\"], [\"pip\", \"23.0.1\", \"MIT\"]]'" > "$TMP/rec/venv/bin/python"
printf '#!/bin/sh\necho %s\n' "$TMP/rec/npm" > "$TMP/rec/fakebin/npm"
chmod +x "$TMP/rec/venv/bin/pip" "$TMP/rec/venv/bin/python" "$TMP/rec/fakebin/npm"
printf '{"name": "@earendil-works/pi-coding-agent", "version": "0.87.0", "license": "MIT"}\n' > "$TMP/rec/npm/@earendil-works/pi-coding-agent/package.json"
printf '{"name": "left-pad", "version": "1.3.0", "license": "WTFPL"}\n' > "$TMP/rec/npm/@earendil-works/pi-coding-agent/node_modules/left-pad/package.json"
printf '{"type": "module"}\n' > "$TMP/rec/npm/@earendil-works/pi-coding-agent/dist/package.json"
( export PATH="$TMP/rec/fakebin:$PATH" DFIRSWARM_VENV="$TMP/rec/venv" DFIRSWARM_ETC_DIR="$TMP/rec/etc" \
         NONREDISTRIBUTABLE="dissect.util" REDISTRIBUTABLE=false
  python3 "$ROOT/images/install.py" --base >/dev/null ) || fail "install.py --base failed"
rec="$TMP/rec/etc/image.json"
jq -e '.profile == "base" and (.dpkg_all | type == "object") and .pip == {"dissect.util": "3.20", "pip": "23.0.1"}' "$rec" >/dev/null \
  || fail "the base does not record its whole Debian list and its venv as pip lists it: $(cat "$rec")"
jq -e '.redistributable == false and .nonredistributable == ["dissect.util"] and .pi == "0.87.0"' "$rec" >/dev/null \
  || fail "the base does not say it is not for redistribution, or which Pi it holds: $(cat "$rec")"
grep -q '^Not cleared for redistribution: dissect.util' "$TMP/rec/etc/NOTICE" || fail "the base NOTICE does not say what holds it back"
grep -q '^dissect.util 3.20  AGPL-3.0' "$TMP/rec/etc/NOTICE" || fail "the base NOTICE does not give the Python licences"
grep -q '^left-pad 1.3.0  WTFPL' "$TMP/rec/etc/NOTICE" || fail "the base NOTICE does not give the npm licences, nested ones included"
jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.5"
       and ([.components[].purl] | index("pkg:pypi/dissect-util@3.20") != null)
       and ([.components[].purl] | index("pkg:npm/%40earendil-works/pi-coding-agent@0.87.0") != null)
       and ([.components[] | select(.name == "module")] | length == 0)' "$TMP/rec/etc/sbom.json" >/dev/null \
  || fail "the base SBOM is not CycloneDX with the venv's and npm's packages: $(head -c 600 "$TMP/rec/etc/sbom.json")"
( export PATH="$TMP/rec/fakebin:$PATH" DFIRSWARM_VENV="$TMP/rec/venv" DFIRSWARM_ETC_DIR="$TMP/rec/etc"
  python3 - "$ROOT/images" "$sha" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
import install
spec = {"profile": "web", "packs": [], "redistributable": True, "nonredistributable": [], "apt": {},
        "binaries": [], "manual": []}
record = install.profile_record(json.loads(install.RECORD.read_text()), spec,
                                {"tool": {"version": "1.0", "url": "https://example.org/tool.tar.gz", "sha256": sys.argv[2]}},
                                {"apt": [], "pip": [], "download": []})
install.write_record(record, "dfirswarm-web")
EOF
) || fail "a profile record could not be written over the base's"
jq -e '.profile == "web" and .redistributable == false and .nonredistributable == ["dissect.util"] and .pip["dissect.util"] == "3.20"' "$rec" >/dev/null \
  || fail "a profile over a base not for redistribution claimed it was, or lost the venv: $(cat "$rec")"
jq -e --arg sha "$sha" '[.components[] | select(.name == "tool") | .hashes[0].content == $sha and (.purl | startswith("pkg:generic/tool@1.0?"))] == [true]' \
  "$TMP/rec/etc/sbom.json" >/dev/null || fail "a pinned download is not in the SBOM with its sha256"
pass "every image records its Debian list and venv for the inventory diff, a NOTICE, a CycloneDX SBOM, and the base's redistribution flag carries into a profile"

# tools.md: what an agent reads to learn what its VM holds. The base lists the
# tool library's Python packages with the note on each line; a profile adds its
# packs' programs, one a line, with what each is for, its pack and the version
# the package records hold, and says what a pack names that is not there.
tm="$TMP/rec/etc/tools.md"
[[ -f "$tm" ]] || fail "an image wrote no tools.md"
grep -q '^- `dissect.util` 3.20 — AGPL-3.0, Fox-IT. lzxpress_huffman' "$tm" || fail "tools.md does not list the base's libraries with version and note: $(cat "$tm")"
( export PATH="$TMP/rec/fakebin:$PATH" DFIRSWARM_VENV="$TMP/rec/venv" DFIRSWARM_ETC_DIR="$TMP/rec/etc"
  python3 - "$ROOT/images" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
import install
record = json.loads(install.RECORD.read_text())
record.update({"profile": "disk", "packs": ["p1"], "apt": {"sleuthkit": "4.11.1"},
               "binaries": {"mmls": "/usr/bin/mmls", "evtxecmd": "/usr/local/bin/evtxecmd", "gpg": None}})
spec = {"binaries": [
    {"name": "mmls", "pack": "p1", "why": "Partition table of a disk image.", "apt": ["sleuthkit"], "source": "apt-get install -y sleuthkit"},
    {"name": "mmls", "pack": "p2", "why": "Named twice.", "apt": ["sleuthkit"]},
    {"name": "evtxecmd", "pack": "p1", "why": "Event logs.", "source": "download 2026.5.0"},
    {"name": "gpg", "pack": "p1", "why": "OpenPGP.", "apt": ["gnupg"], "source": "apt-get install -y gnupg"}],
  "python_notes": [{"requirement": "pyAesCrypt>=6", "pack": "p1", "note": "AES Crypt containers."}],
  "not_applicable": [{"name": "log", "pack": "p3", "why": "Only macOS has it."}]}
install.TOOLS_MD.write_text(install.tools_md(record, spec))
EOF
) || fail "a profile's tools.md could not be written"
grep -q '^- `mmls` — Partition table of a disk image. (p1, p2; sleuthkit 4.11.1)$' "$tm" || fail "a program is not one line with its use, packs and package version: $(cat "$tm")"
grep -q '^- `evtxecmd` — Event logs. (p1; download 2026.5.0)$' "$tm" || fail "a pinned download does not carry its pinned version: $(cat "$tm")"
grep -q '^- `pyAesCrypt` (not installed) — AES Crypt containers. (p1)$' "$tm" || fail "a pack's library is not listed, or claims a version pip does not have: $(cat "$tm")"
grep -q '^- `gpg` (p1) — not found after the build' "$tm" || fail "a program the build left out is not said to be missing: $(cat "$tm")"
grep -q '^- `log` (p3) — Only macOS has it.$' "$tm" || fail "another system's program is not said: $(cat "$tm")"
[[ "$(grep -c '`mmls`' "$tm")" == 1 ]] || fail "a program two packs name is listed twice"
pass "every image writes tools.md: its programs and libraries one a line, with use, pack and recorded version, and what it does not hold"

# --- what a pack may declare ---------------------------------------------------
mk() { # <dir> <download json>
  mkdir -p "$1/requires" "$1/skills/a"
  printf 'Test.\n' > "$1/LICENCE"
  printf -- '---\nid: a/one\ntitle: One\nwhen: Always.\nneeds: []\ntools: []\nrequires_host: []\n---\n\nBody.\n' > "$1/skills/a/one.md"
  printf '{"binaries": [{"name": "tool", "why": "Test.", "licence": "MIT", "redistributable": true, "optional": true, "install": {"apt": "x", "download": %s}}]}\n' "$2" > "$1/requires/host.json"
  printf '{"id": "%s", "name": "t", "version": "1.0.0", "description": "t", "licence": "MIT", "depends": [], "requires": {"host": "requires/host.json"}, "secrets": []}\n' "$(basename "$1")" > "$1/pack.json"
}
mk "$TMP/p/good-pack" '{"version": "1", "amd64": {"url": "https://example.org/t", "sha256": "'"$sha"'"}}'
bash "$ROOT/scripts/pack.sh" seal "$TMP/p/good-pack" >/dev/null 2>&1 || fail "a well-formed download was refused"
for bad in '{"amd64": {"url": "https://example.org/t", "sha256": "'"$sha"'"}}' \
           '{"version": "1", "amd64": {"url": "http://example.org/t", "sha256": "'"$sha"'"}}' \
           '{"version": "1", "amd64": {"url": "https://example.org/t", "sha256": "abc"}}' \
           '{"version": "1", "amd64": {"url": "https://example.org/t", "sha256": "'"$sha"'", "bin": "../x"}}' \
           '{"version": "1"}'; do
  mk "$TMP/p/bad-pack" "$bad"
  bash "$ROOT/scripts/pack.sh" seal "$TMP/p/bad-pack" >/dev/null 2>&1 && fail "a download entry that cannot be checked was sealed: $bad"
done
pass "a pack's download needs a version, an https url, a whole sha256 and a program path inside it"

mk_entry() { # <dir> <binary entry json>
  mk "$1" '{"version": "1", "amd64": {"url": "https://example.org/t", "sha256": "'"$sha"'"}}'
  printf '{"binaries": [%s]}\n' "$2" > "$1/requires/host.json"
}
e='"name": "tool", "why": "Test.", "licence": "MIT", "redistributable": true, "optional": true'
u='"url": "https://example.org/t.tar.gz", "sha256": "'"$sha"'"'
for good in '{'"$e"', "install": {"source": {"version": "1", '"$u"', "entry": "bin/t.py", "run": "python", "pip": ["-r", "requirements.txt"], "skip": ["tests"]}}}' \
            '{'"$e"', "install": {"build": {"version": "1", '"$u"', "bin": "bin/t", "configure": ["--disable-x"], "build_deps": ["gcc"], "apt_deps": ["zlib1g"], "env": {"CFLAGS": "-O2"}}}}' \
            '{'"$e"', "install": {"download": {"version": "1", "arm64": {"url": "https://example.org/t_1_arm64.deb", "sha256": "'"$sha"'", "bin": "/opt/t/bin/t"}}}}' \
            '{'"$e"', "not_in_image": "Only macOS has it."}'; do
  mk_entry "$TMP/p/good-kind" "$good"
  bash "$ROOT/scripts/pack.sh" seal "$TMP/p/good-kind" >/dev/null 2>&1 || fail "a well-formed entry was refused: $good"
done
for bad in '{'"$e"', "install": {"source": {"version": "1", '"$u"'}}}' \
           '{'"$e"', "install": {"source": {"version": "1", "url": "http://example.org/t.tar.gz", "sha256": "'"$sha"'", "entry": "t.py"}}}' \
           '{'"$e"', "install": {"source": {"version": "1", '"$u"', "entry": "../t.py"}}}' \
           '{'"$e"', "install": {"source": {"version": "1", '"$u"', "entry": "t.py", "pip": "-r requirements.txt"}}}' \
           '{'"$e"', "install": {"source": {"version": "1", '"$u"', "entry": "t.py", "env": {"X": 1}}}}' \
           '{'"$e"', "install": {"build": {'"$u"', "bin": "bin/t"}}}' \
           '{'"$e"', "install": {"build": {"version": "1", '"$u"', "bin": "/usr/bin/t"}}}' \
           '{'"$e"', "install": {"download": {"version": "1", "arm64": {"url": "https://example.org/t_1_arm64.deb", "sha256": "'"$sha"'", "bin": "opt/t/bin/t"}}}}' \
           '{"name": "tool", "why": "Test.", "licence": "MIT", "redistributable": true, "not_in_image": "Only macOS has it."}' \
           '{'"$e"', "not_in_image": ""}'; do
  mk_entry "$TMP/p/bad-kind" "$bad"
  bash "$ROOT/scripts/pack.sh" seal "$TMP/p/bad-kind" >/dev/null 2>&1 && fail "an entry that cannot be checked, or another system's program required of an image, was sealed: $bad"
done
pass "a pinned source needs its entry, a build its program inside its prefix, a .deb the path it installs, and another system's program is never required"

# --- the tool library's imports are in every image ----------------------------
missing_lib="$(python3 - "$ROOT" <<'EOF'
import re, sys, pathlib
root = pathlib.Path(sys.argv[1])
# A module a tool imports -> the package that provides it.
provides = {"cryptography": "cryptography", "regipy": "regipy", "Evtx": "python-evtx", "dissect": "dissect.util"}
listed = {re.split(r"[<>=!~ ]", l.split("#")[0].strip())[0].lower() for l in (root / "images" / "library-python.txt").read_text().splitlines() if l.split("#")[0].strip()}
stdlib = set(sys.stdlib_module_names) | {"__future__"}
out = set()
for f in root.glob("tool-library/*/*.py"):
    for m in re.finditer(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", f.read_text(), re.M):
        mod = m.group(1)
        if mod in stdlib:
            continue
        pkg = provides.get(mod)
        if pkg is None:
            out.add(f"{mod} (in {f.parent.name}: say which package provides it)")
        elif pkg.lower() not in listed:
            out.add(f"{pkg} (imported by {f.parent.name})")
print("\n".join(sorted(out)))
EOF
)"
[[ -z "$missing_lib" ]] || fail "the tool library imports what no image installs: $missing_lib"
grep -q 'COPY library-python.txt' "$ROOT/images/base.Dockerfile" || fail "the base image does not install the tool library's imports"
pass "every third-party module the tool library imports is in images/library-python.txt, which the base image installs"

echo "recipe: all checks passed"
