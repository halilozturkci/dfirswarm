#!/usr/bin/env bash
# A build that lost a program is not an image. With the Docker VM's disk full,
# apt failed inside the optional builder stages of bulk_extractor and
# aeskeyfind; those stages still ended well, Docker cached them as they were,
# and every image built after the disk was freed lacked both programs, saying
# so only under not_installed in its image.json, until a --no-cache rebuild.
#
# This plays that failure without filling a disk and without Docker: apt-get
# is a script here that fails the way apt does when the disk is full, for the
# packages the test names. What must hold:
#   - a builder stage whose optional program did not build fails (exit 1), so
#     Docker caches nothing of it; one pinned for other architectures, or one
#     the build allows to fail, ends well with the failure recorded;
#   - at the end of the profile's install, every program the packs name is on
#     PATH unless it was left out on purpose, or the install fails, so the
#     image is never tagged; --allow-missing-optional builds it anyway and the
#     record names what is missing (missing_allowed);
#   - a stage allowed to fail carries a build id of its own, different in every
#     regenerated context; retrying the same context needs --no-cache;
#   - tests/image-programs.sh fails a program the image's record names and
#     PATH lacks, rather than skipping it.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/image-build-failures.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
I="$ROOT/images/install.py"
export DFIRSWARM_HOME="$TMP/home"

# --- the stand-in for apt, and the image's directories ----------------------------
# apt-get fails, as apt does on a full disk, for any package listed in
# $TMP/full; any other package "installs" by putting a program of the same
# name, less its -pkg suffix, in the venv's bin, which is on the image's PATH.
mkdir -p "$TMP/fakebin" "$TMP/venv/bin" "$TMP/etc" "$TMP/tools"
cat > "$TMP/fakebin/apt-get" <<SH
#!/bin/sh
echo "apt-get \$*" >> "$TMP/apt.log"
case "\$1" in update|clean|purge) exit 0 ;; esac
for p in "\$@"; do
  case "\$p" in -*|install) continue ;; esac
  if grep -qx "\$p" "$TMP/full" 2>/dev/null; then
    echo "E: You don't have enough free space in /var/cache/apt/archives/." >&2
    exit 100
  fi
  prog="\${p%-pkg}"
  printf '#!/bin/sh\necho %s ran\n' "\$prog" > "$TMP/venv/bin/\$prog"
  chmod +x "$TMP/venv/bin/\$prog"
done
exit 0
SH
# npm's global root and dpkg are the host's otherwise: nothing here.
printf '#!/bin/sh\nexit 0\n' > "$TMP/fakebin/npm"
chmod +x "$TMP/fakebin/apt-get" "$TMP/fakebin/npm"
# Every path the install writes is the test's own: the whole install runs on
# this host, and apt's real lists, tools and bin are not touched.
export PATH="$TMP/fakebin:$PATH" DFIRSWARM_VENV="$TMP/venv" DFIRSWARM_ETC_DIR="$TMP/etc" \
       DFIRSWARM_TOOLS_DIR="$TMP/tools" DFIRSWARM_BIN_DIR="$TMP/venv/bin" DFIRSWARM_BUILD_DIR="$TMP/work" \
       DFIRSWARM_SRC_DIR="$TMP/src-installed" DFIRSWARM_APT_SOURCES_DIR="$TMP/apt-sources" \
       DFIRSWARM_OS_RELEASE="$TMP/os-release" DFIRSWARM_APT_LISTS_DIR="$TMP/apt-lists"
mkdir -p "$TMP/apt-lists/partial"
ARCH="$(python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import install; print(install.arch())' "$ROOT/images")"

# A source that builds, served from a file: the build needs its build_deps first.
mkdir -p "$TMP/src/ibr-built-1"
cat > "$TMP/src/ibr-built-1/configure" <<'SH'
#!/bin/sh
prefix="${1#--prefix=}"
printf 'all:\n\t@true\ninstall:\n\tmkdir -p %s/bin\n\tprintf "#!/bin/sh\\necho ibr-built ran\\n" > %s/bin/ibr-built\n\tchmod +x %s/bin/ibr-built\n' "$prefix" "$prefix" "$prefix" > Makefile
SH
chmod +x "$TMP/src/ibr-built-1/configure"
COPYFILE_DISABLE=1 tar -czf "$TMP/ibr-built-1.tar.gz" -C "$TMP/src" ibr-built-1
sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TMP/ibr-built-1.tar.gz")"
stage() { # <file> <extra json fields>: a builder stage's file for ibr-built
  printf '{"name": "ibr-built", "pack": "p", "required": false, "version": "1", "url": "file://%s/ibr-built-1.tar.gz", "sha256": "%s", "bin": "bin/ibr-built", "build_deps": ["libibr-dev"]%s}\n' \
    "$TMP" "$sha" "$2" > "$1"
}
built_rec() { cat "$TMP/tools/ibr-built/.dfirswarm-build.json"; }

# --- a builder stage ----------------------------------------------------------------
echo libibr-dev > "$TMP/full"
stage "$TMP/stage.json" ""
python3 "$I" --build "$TMP/stage.json" >"$TMP/stage.out" 2>&1; rc=$?
[[ $rc -eq 1 ]] || fail "an optional program whose build dependencies could not install ended its stage well (rc $rc), which Docker would cache: $(cat "$TMP/stage.out")"
built_rec | jq -e '.ok == false and (.why | test("build dependencies \\(libibr-dev\\) did not install"))' >/dev/null \
  || fail "the failed stage does not record why beside what it left: $(built_rec)"
stage "$TMP/stage-may.json" ', "may_fail": true, "build_id": "x"'
python3 "$I" --build "$TMP/stage-may.json" >/dev/null 2>&1 || fail "a stage the build allows to fail did not end well"
built_rec | jq -e '.ok == false' >/dev/null || fail "a stage allowed to fail did not record its failure: $(built_rec)"
stage "$TMP/stage-elsewhere.json" ', "arches": ["no-such-arch"]'
python3 "$I" --build "$TMP/stage-elsewhere.json" >/dev/null 2>&1 || fail "a program pinned for other architectures failed its stage"
built_rec | jq -e '.ok == false and (.why | test("not built for"))' >/dev/null || fail "a program pinned elsewhere is not recorded as not built here: $(built_rec)"
stage "$TMP/stage-req.json" ', "required": true, "may_fail": true'
python3 "$I" --build "$TMP/stage-req.json" >/dev/null 2>&1 && fail "a required program that did not build ended its stage well"
pass "a builder stage whose program did not build fails, unless the program is pinned for other architectures or the build allows it to be missing"

# --- the profile's install, and the program list at its end ---------------------------
# The stage above left ibr-built unbuilt (the build allowed it, so its record
# says ok: false). Then the profile's own apt runs out of disk for one program.
write_spec() { # <file> <allow_missing_optional: true|false>
  cat > "$1" <<JSON
{"profile": "network", "packs": ["p"], "pack_versions": {}, "redistributable": true, "nonredistributable": [],
 "allow_missing_optional": $2,
 "apt": {"ibr-present-pkg": false, "ibr-lost-pkg": false}, "apt_release": {}, "pip": {}, "requirements": [],
 "binaries": [
  {"name": "ibr-present", "pack": "p", "required": false, "apt": ["ibr-present-pkg"]},
  {"name": "ibr-lost", "pack": "p", "required": false, "apt": ["ibr-lost-pkg"]},
  {"name": "ibr-elsewhere", "pack": "p", "required": false},
  {"name": "ibr-built", "pack": "p", "required": false},
  {"name": "ibr-manual", "pack": "p", "required": false}],
 "downloads": [{"name": "ibr-elsewhere", "pack": "p", "required": false, "version": "1",
                "no-such-arch": {"url": "https://example.org/x.tar.gz", "sha256": "$sha"}}],
 "sources": [], "builds": [{"name": "ibr-built", "pack": "p", "required": false, "version": "1", "bin": "bin/ibr-built"}],
 "data": [], "manual": [{"name": "ibr-manual", "pack": "p", "how": "by hand"}], "not_applicable": [], "python_notes": []}
JSON
}
echo ibr-lost-pkg > "$TMP/full"
write_spec "$TMP/spec.json" false
python3 "$I" "$TMP/spec.json" >"$TMP/main.out" 2>&1; rc=$?
[[ $rc -eq 1 ]] || fail "an install that lost two optional programs ended well (rc $rc), and the image would be tagged: $(cat "$TMP/main.out")"
grep -q 'programs this image was built to hold and does not: ibr-built, ibr-lost\.' "$TMP/main.out" \
  || fail "the failure does not name exactly the programs lost (not the one pinned elsewhere, not the manual one): $(cat "$TMP/main.out")"
grep -q '^  ibr-lost: apt could not install ibr-lost-pkg$' "$TMP/main.out" && grep -q '^  ibr-built: its build dependencies (libibr-dev) did not install$' "$TMP/main.out" \
  || fail "the failure does not say why each program is missing (the untagged image's record cannot be read): $(cat "$TMP/main.out")"
grep -q 'Disk space' "$TMP/main.out" || fail "the failure does not point at the disk-space note: $(cat "$TMP/main.out")"
jq -e '(.not_installed.apt == ["ibr-lost-pkg"]) and ([.not_installed.build[].name] == ["ibr-built"])
       and (.binaries["ibr-present"] | type == "string") and .binaries["ibr-lost"] == null and (has("missing_allowed") | not)' "$TMP/etc/image.json" >/dev/null \
  || fail "the record does not say what was lost and why: $(jq -c '{not_installed, binaries}' "$TMP/etc/image.json")"
write_spec "$TMP/spec-allow.json" true
python3 "$I" "$TMP/spec-allow.json" >"$TMP/main-allow.out" 2>&1 || fail "an install the build allows to miss optional programs failed: $(cat "$TMP/main-allow.out")"
jq -e '.missing_allowed == ["ibr-built", "ibr-lost"]' "$TMP/etc/image.json" >/dev/null \
  || fail "an image built with optional programs missing does not name them: $(jq -c '{missing_allowed}' "$TMP/etc/image.json")"
# The disk is freed: the same stage, without the allowance, builds now, and so does the install.
: > "$TMP/full"
python3 "$I" --build "$TMP/stage.json" >/dev/null 2>&1 || fail "the stage did not build once apt could install again"
python3 "$I" "$TMP/spec.json" >"$TMP/main-ok.out" 2>&1 || fail "the install failed once nothing was lost: $(cat "$TMP/main-ok.out")"
[[ ! -e "$TMP/apt-lists" ]] || fail "the install did not empty the apt lists it was pointed at"
jq -e '(.binaries | to_entries | map(select(.value == null) | .key) | sort) == ["ibr-elsewhere", "ibr-manual"]' "$TMP/etc/image.json" >/dev/null \
  || fail "a program left out on purpose is not the only kind missing: $(jq -c '.binaries' "$TMP/etc/image.json")"
pass "the install fails when a program the packs name is missing for any reason but a planned one, names each, and goes on only when the build allows it, recording what is missing"

# --- facts: what a program says about itself is kept, and recorded -------------------
# An entry's `facts` are commands whose output the build keeps, one file each
# under /etc/dfirswarm/facts/, with its sha256 in image.json. A command that
# fails or hangs is recorded as failed; an output past the cap is cut and said
# to be; a program that is not there has no fact. None of these fails the build
# of an optional program; a required one whose own command fails does.
cat > "$TMP/venv/bin/ibr-facts" <<'SH'
#!/bin/sh
case "$1 $2" in
  "--version ") echo "ibr-facts 9.9.9" ;;
  "-G fields") printf 'field.one\nfield.two\n' ;;
  "--fail ") echo "no luck" >&2; exit 3 ;;
  "--long ") head -c 5000 /dev/zero | tr '\0' x ;;
  "--hang ") exec sleep 30 ;;
esac
SH
chmod +x "$TMP/venv/bin/ibr-facts"
write_facts_spec() { # <file> <required: true|false>
  cat > "$1" <<JSON
{"profile": "network", "packs": ["p"], "pack_versions": {}, "redistributable": true, "nonredistributable": [],
 "apt": {}, "apt_release": {}, "pip": {}, "requirements": [],
 "binaries": [
  {"name": "ibr-facts", "pack": "p", "required": $2, "why": "A stand-in.",
   "facts": [["ibr-facts", "--version"], ["ibr-facts", "-G", "fields"], ["ibr-facts", "--fail"], ["ibr-facts", "--long"], ["ibr-facts", "--hang"]]},
  {"name": "ibr-gone", "pack": "p", "required": false, "facts": [["ibr-gone", "--version"]]}],
 "downloads": [], "sources": [], "builds": [], "data": [], "manual": [{"name": "ibr-gone", "pack": "p", "how": "by hand"}], "not_applicable": [], "python_notes": []}
JSON
}
write_facts_spec "$TMP/spec-facts.json" false
rm -rf "$TMP/etc/facts"
DFIRSWARM_FACTS_MAX_BYTES=1000 DFIRSWARM_FACTS_TIMEOUT=2 timeout 120 python3 "$I" "$TMP/spec-facts.json" >"$TMP/facts.out" 2>&1; rc=$?
[[ $rc -eq 0 ]] || fail "failing facts of an optional program failed the build (rc $rc): $(cat "$TMP/facts.out")"
F="$TMP/etc/facts"
[[ "$(cat "$F/ibr-facts-version.txt")" == "ibr-facts 9.9.9" ]] || fail "the version fact is not the program's output: $(ls "$F")"
[[ "$(cat "$F/ibr-facts-G-fields.txt")" == $'field.one\nfield.two' ]] || fail "the field-list fact is not the program's output"
for f in ibr-facts-version ibr-facts-G-fields; do
  want="$(sha256sum "$F/$f.txt" | cut -d' ' -f1)"
  jq -e --arg f "$f.txt" --arg s "$want" '.facts[$f].sha256 == $s and .facts[$f].status == "recorded" and .facts[$f].program == "ibr-facts"' "$TMP/etc/image.json" >/dev/null \
    || fail "image.json does not carry $f's sha256 and status: $(jq -c '.facts' "$TMP/etc/image.json")"
done
jq -e '.facts["ibr-facts-fail.txt"] | .status == "failed" and (.why | test("^exit 3: no luck"))' "$TMP/etc/image.json" >/dev/null \
  || fail "a command that failed is not recorded as failed with why: $(jq -c '.facts["ibr-facts-fail.txt"]' "$TMP/etc/image.json")"
jq -e '.facts["ibr-facts-hang.txt"] | .status == "failed" and (.why | test("^timed out after 2 s"))' "$TMP/etc/image.json" >/dev/null \
  || fail "a command that hung is not recorded as failed: $(jq -c '.facts["ibr-facts-hang.txt"]' "$TMP/etc/image.json")"
jq -e '.facts["ibr-facts-long.txt"] | .status == "capped" and .bytes == 1000 and .bytes_seen == 5000' "$TMP/etc/image.json" >/dev/null \
  || fail "an over-long output is not capped and said to be: $(jq -c '.facts["ibr-facts-long.txt"]' "$TMP/etc/image.json")"
[[ "$(wc -c < "$F/ibr-facts-long.txt")" -eq 1000 ]] || fail "the capped fact's file is not the cap"
jq -e '.facts["ibr-gone-version.txt"] | .status == "failed" and (.why | test("not on PATH"))' "$TMP/etc/image.json" >/dev/null \
  || fail "a fact of a program that is not there is not recorded as failed"
[[ ! -e "$F/ibr-gone-version.txt" ]] || fail "a program that is not there left a fact file"
grep -q 'ibr-facts-G-fields.txt`, recorded' "$TMP/etc/tools.md" && grep -q 'ibr-facts-fail.txt`, failed (exit 3' "$TMP/etc/tools.md" \
  || fail "tools.md does not name the facts beside the program: $(grep -n 'ibr-facts' "$TMP/etc/tools.md")"
write_facts_spec "$TMP/spec-facts-req.json" true
DFIRSWARM_FACTS_MAX_BYTES=1000 DFIRSWARM_FACTS_TIMEOUT=2 timeout 120 python3 "$I" "$TMP/spec-facts-req.json" >"$TMP/facts-req.out" 2>&1; rc=$?
[[ $rc -eq 1 ]] || fail "a required program whose fact command failed did not fail the build (rc $rc)"
grep -q 'a command that records a fact about a required program failed' "$TMP/facts-req.out" || fail "the failure does not say what failed: $(tail -3 "$TMP/facts-req.out")"
rm -f "$TMP/venv/bin/ibr-facts"
pass "a program's facts are kept as files with their sha256 in image.json and named in tools.md; a failing, hanging or missing one is recorded as failed, an over-long one capped and said to be"

# --- the build context: a stage allowed to fail is never taken from the cache ---------
mkdir -p "$TMP/packs/network-forensics/requires"
printf '{"id": "network-forensics", "name": "f", "version": "1.0.0", "description": "f", "licence": "MIT", "depends": []}\n' > "$TMP/packs/network-forensics/pack.json"
cat > "$TMP/packs/network-forensics/requires/host.json" <<JSON
{"binaries": [
 {"name": "opt-built", "optional": true, "why": "t", "licence": "MIT", "redistributable": true,
  "install": {"build": {"version": "1", "url": "https://example.org/o.tar.gz", "sha256": "$sha", "bin": "bin/o"}}},
 {"name": "req-built", "why": "t", "licence": "MIT", "redistributable": true,
  "install": {"build": {"version": "1", "url": "https://example.org/r.tar.gz", "sha256": "$sha", "bin": "bin/r"}}}]}
JSON
R="$ROOT/images/recipe.py"
python3 "$R" build network --packs "$TMP/packs" --out "$TMP/ctx" >/dev/null || fail "a context could not be written"
jq -e '(has("may_fail") | not) and (has("build_id") | not)' "$TMP/ctx/build-opt-built.json" >/dev/null || fail "a stage may fail without the build saying so: $(cat "$TMP/ctx/build-opt-built.json")"
jq -e '(has("allow_missing_optional") | not)' "$TMP/ctx/spec.json" >/dev/null || fail "the spec allows missing programs without the flag"
python3 "$R" build network --packs "$TMP/packs" --out "$TMP/ctx-a" --allow-missing-optional >/dev/null || fail "a context with --allow-missing-optional could not be written"
python3 "$R" build network --packs "$TMP/packs" --out "$TMP/ctx-b" --allow-missing-optional >/dev/null || fail "a second context with --allow-missing-optional could not be written"
jq -e '.may_fail == true and (.build_id | length == 32)' "$TMP/ctx-a/build-opt-built.json" >/dev/null || fail "an optional stage is not allowed to fail under the flag: $(cat "$TMP/ctx-a/build-opt-built.json")"
jq -e '(has("may_fail") | not)' "$TMP/ctx-a/build-req-built.json" >/dev/null || fail "a required program's stage was allowed to fail"
jq -e '.allow_missing_optional == true' "$TMP/ctx-a/spec.json" >/dev/null || fail "the spec does not carry the flag into the install"
[[ "$(jq -r .build_id "$TMP/ctx-a/build-opt-built.json")" != "$(jq -r .build_id "$TMP/ctx-b/build-opt-built.json")" ]] \
  || fail "two builds allowed to miss a program share a stage file, so the second would take the first's result from the cache"
# The profile's own install can end with gaps under the flag too (apt out of
# space for an optional package): its spec.json, copied in before it runs,
# carries the build's id, so that layer is not reused by the next build.
jq -e '(.build_id | length == 32) and .build_id == input.build_id' "$TMP/ctx-a/spec.json" "$TMP/ctx-a/build-opt-built.json" >/dev/null \
  || fail "the spec does not carry the build's id under the flag: $(jq -c '{build_id}' "$TMP/ctx-a/spec.json")"
[[ "$(jq -r .build_id "$TMP/ctx-a/spec.json")" != "$(jq -r .build_id "$TMP/ctx-b/spec.json")" ]] \
  || fail "two builds allowed to miss a program share a spec.json, so the second would take the first's install, gaps and all, from the cache"
jq -e '(has("build_id") | not)' "$TMP/ctx/spec.json" >/dev/null || fail "a build without the flag carries a build id, and loses its cache"
cmp -s "$TMP/ctx/build-req-built.json" "$TMP/ctx-a/build-req-built.json" || fail "a required program's stage file changed with the flag, losing its cache"
pass "a context allows optional stages to fail only with --allow-missing-optional, and each such stage file and its spec.json are its build's own"

# --- tests/image-programs.sh reads the record -------------------------------------------
# Run on this host with a PATH that holds none of the three programs: a program
# the record names fails, one the build allowed to be missing and one no pack
# names are skipped.
mkdir -p "$TMP/minbin" "$TMP/rec-etc"
py="$(python3 -c 'import os, sys; print(os.path.realpath(sys.executable))')"
ln -s "$py" "$TMP/minbin/python3"
for p in mktemp rm touch; do ln -s "$(command -v "$p")" "$TMP/minbin/$p"; done
progs() { DFIRSWARM_ETC_DIR="$TMP/rec-etc" PATH="$TMP/minbin" /bin/sh "$ROOT/tests/image-programs.sh" 2>&1; }
printf '{"binaries": {"aeskeyfind": null}}\n' > "$TMP/rec-etc/image.json"
out="$(progs)" && fail "image-programs.sh passed an image whose record names aeskeyfind and whose PATH lacks it: $out"
grep -q '^FAIL: aeskeyfind is named by this image' <<<"$out" || fail "image-programs.sh does not say which named program is missing: $out"
grep -q '^skip - gcc is not in this image' <<<"$out" || fail "a program no pack names was not skipped: $out"
printf '{"binaries": {"aeskeyfind": null}, "missing_allowed": ["aeskeyfind"]}\n' > "$TMP/rec-etc/image.json"
out="$(progs)" || fail "image-programs.sh failed a program the build was allowed to miss: $out"
grep -q '^skip - aeskeyfind is missing, as its build allowed' <<<"$out" || fail "an allowed gap is not said: $out"
printf 'not json\n' > "$TMP/rec-etc/image.json"
out="$(progs)" && fail "image-programs.sh passed an image whose record it could not read: $out"
grep -q '^FAIL:.*record (image.json) could not be read' <<<"$out" || fail "an unreadable record is not said: $out"
# A profile holding all three programs never called absent(), so an unreadable
# record escaped the old check. Refuse it before running any program probe.
for p in gcc aeskeyfind steghide; do
  printf '#!/bin/sh\ntouch "%s"\nexit 1\n' "$TMP/program-probe-ran" > "$TMP/minbin/$p"
  chmod +x "$TMP/minbin/$p"
done
out="$(progs)" && fail "image-programs.sh passed an unreadable record with every program on PATH: $out"
grep -q '^FAIL:.*record (image.json) could not be read' <<<"$out" || fail "with every program present, the unreadable record was not named: $out"
[[ ! -f "$TMP/program-probe-ran" ]] || fail "program probes ran before the record was validated"
printf '{}\n' > "$TMP/rec-etc/image.json"
out="$(progs)" && fail "image-programs.sh passed a record without its mandatory binaries map: $out"
grep -q '^FAIL:.*record (image.json) could not be read' <<<"$out" || fail "the missing binaries map was not named: $out"
[[ ! -f "$TMP/program-probe-ran" ]] || fail "program probes ran with no binaries map"
rm "$TMP/rec-etc/image.json"
out="$(progs)" && fail "image-programs.sh passed a missing record with every program on PATH: $out"
grep -q '^FAIL:.*record (image.json) could not be read' <<<"$out" || fail "a missing record was not named: $out"
pass "image-programs.sh fails a program the image's record names and PATH lacks, and one it cannot check against an unreadable record, and skips the others, saying why"

echo "image-build-failures: all checks passed"
