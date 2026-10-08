#!/usr/bin/env bash
# Symbol tables the image build makes, from files the operator fetched.
#
# What must not go wrong: a converted table must be held to its pinned content
# (json-canon/1), never to its bytes, and a converter or source that makes
# other content must fail the build; what the operator acquires must never be
# downloaded by a build, and must not be built in without the operator's
# recorded acceptance of its supplier's terms; a symbol set left out must be
# recorded as omitted, not as a failure; a download must stay on https, within
# its pinned size; the operator's store must hold only the pinned bytes, never
# in a synced folder, and only with the terms accepted; the census must say
# what a recipe reports missing, and the base pack's memory-windows recipe
# must name the kernel whose table the image lacks, or say it could not tell. Small synthetic
# fixtures only: nothing here fetches a Microsoft file or builds an image.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/symbols.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
export DFIRSWARM_HOME="$TMP/home"
sha() { python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }

# --- json-canon/1 -------------------------------------------------------------
res="$(python3 - "$ROOT/images" "$TMP" <<'EOF'
import gzip, hashlib, json, lzma, sys
sys.path.insert(0, sys.argv[1])
import install
T = sys.argv[2]
out = {}
doc = '{"b": 1, "a": {"x": "ü", "y": [1.5, 2]}, "metadata": {"producer": {"datetime": "2026-10-01T18:46:00", "name": "volatility3"}}}'
want = '{"a": {"x": "\\u00fc", "y": [1.5, 2]}, "b": 1, "metadata": {"producer": {"name": "volatility3"}}}'
out["form"] = install.canonical_json(doc.encode(), ["metadata.producer.datetime"]).decode() == want
# The same content at another time, or compressed, is the same hash; other content is not.
later = doc.replace("18:46:00", "19:00:00")
open(f"{T}/a.json.xz", "wb").write(lzma.compress(doc.encode()))
open(f"{T}/b.json.gz", "wb").write(gzip.compress(later.encode()))
open(f"{T}/c.json", "w").write(doc.replace('"b": 1', '"b": 2'))
h = lambda p: install.canonical_sha256(p, "json-canon/1", ["metadata.producer.datetime"])
out["same"] = h(f"{T}/a.json.xz") == h(f"{T}/b.json.gz") == hashlib.sha256(want.encode()).hexdigest()
out["other"] = h(f"{T}/c.json") != h(f"{T}/a.json.xz")
# Only the named path is dropped.
out["only_named"] = "datetime" in install.canonical_json(doc.encode(), []).decode()
refused = {}
for name, text in (("duplicate", '{"a": 1, "a": 2}'), ("nan", '{"a": NaN}'), ("inf", '{"a": Infinity}'),
                   ("overflow", '{"a": 1e400}'), ("not_utf8", b'{"a": "\xff"}'), ("not_json", "{a")):
    try:
        install.canonical_json(text if isinstance(text, bytes) else text.encode(), [])
        refused[name] = False
    except install.CanonError:
        refused[name] = True
out["refused"] = refused
try:
    install.canonical_sha256(f"{T}/c.json", "json-canon/9", [])
    out["unknown_rule"] = False
except install.CanonError:
    out["unknown_rule"] = True
print(json.dumps(out))
EOF
)" || fail "the canonical rule could not be driven: $res"
jq -e '.form and .same and .other and .only_named and .unknown_rule and ([.refused[]] | all)' <<<"$res" >/dev/null \
  || fail "json-canon/1 is not what it says: $res"
pass "json-canon/1: sorted, ASCII, default separators, the named field dropped, xz and gzip read, duplicate keys and non-finite numbers refused"

# --- install.py: a source converted in the build ------------------------------
D="$TMP/data"
mkdir -p "$D/venv/bin" "$D/site/fakepkg" "$D/mirror" "$D/bin"
ln -s "$(command -v python3)" "$D/venv/bin/python"
: > "$D/site/fakepkg/__init__.py"
printf 'a pdb, for the suite\n' > "$D/src.pdb"
src_sha="$(sha "$D/src.pdb")"
cp "$D/src.pdb" "$D/mirror/$src_sha"
# The converter: writes a table with the time it ran, as pdbconv does.
cat > "$D/bin/convert" <<'SH'
#!/bin/sh
echo "progress, as a converter says it"
python3 -c 'import datetime, json, lzma, sys; json_doc = {"metadata": {"producer": {"datetime": datetime.datetime.now().isoformat(), "name": "conv"}}, "symbols": {"k": 1}, "src": open(sys.argv[1]).read()}; open(sys.argv[2], "wb").write(lzma.compress(json.dumps(json_doc).encode()))' "$1" "$2"
SH
chmod +x "$D/bin/convert"
canon="$(python3 -c 'import hashlib,json,sys; d={"metadata":{"producer":{"name":"conv"}},"symbols":{"k":1},"src":open(sys.argv[1]).read()}; print(hashlib.sha256(json.dumps(d,sort_keys=True,ensure_ascii=True).encode()).hexdigest())' "$D/src.pdb")"
res="$(PYTHONPATH="$D/site" DFIRSWARM_VENV="$D/venv" DFIRSWARM_TOOLS_DIR="$D/tools" DFIRSWARM_ETC_DIR="$D/etc" DFIRSWARM_DATA_DIR="$D/mirror" PATH="$D/bin:$PATH" \
       python3 - "$ROOT/images" "$D" "$src_sha" "$canon" <<'EOF'
import json, os, sys
sys.path.insert(0, sys.argv[1])
import install
D, src_sha, canon = sys.argv[2:5]
install.IMAGE_PATH = os.environ["PATH"]
acc = {"accepted_by": "the suite", "accepted_at": "2026-10-01T00:00:00Z", "terms": {"url": "https://example.org/terms"}, "sha256": src_sha}
d = {"name": "t-K-1", "program": "prog", "version": "K-1", "url": "https://example.invalid/src.pdb", "sha256": src_sha,
     "bytes": os.path.getsize(f"{D}/src.pdb"), "package": "fakepkg", "into": "symbols", "acquire": "operator", "set": "curated",
     "acceptance": acc, "distribution_policy": "local-only",
     "commands": [["convert", "{file}", "{dir}/windows/k.pdb/K-1.json.xz"]],
     "outputs": [{"path": "windows/k.pdb/K-1.json.xz", "canonical": {"rule": "json-canon/1", "drop": ["metadata.producer.datetime"]},
                  "canonical_sha256": canon, "identity": {"pdb": "k.pdb", "guid": "K", "age": 1}}],
     "keep": False, "check": ["test", "-s", "{dir}/windows/k.pdb/K-1.json.xz"]}
out = {}
got, why = install.fetch_data(d)
out["good"] = [bool(got), why]
if got:
    out["rec"] = {"from": got["from"], "path": got["path"], "source": got["source"], "outputs": got["outputs"],
                  "transform": bool(got["transform"]["commands"]) and os.path.isfile(got["transform"]["log"]["path"]), "acceptance": got.get("acceptance"),
                  "pdb_kept": any(f.endswith(".pdb") for _r, _d, fs in os.walk(f"{D}/site") for f in fs)}
table = f"{D}/site/fakepkg/symbols/windows/k.pdb/K-1.json.xz"
first = install.sha256_file(table) if os.path.exists(table) else None
got2, _ = install.fetch_data(d)
out["bytes_differ_content_same"] = bool(got2) and got2["outputs"][0]["sha256"] != first and got2["outputs"][0]["canonical_sha256"] == canon
got, why = install.fetch_data({**d, "outputs": [{**d["outputs"][0], "canonical_sha256": "0" * 64}]})
out["other_content"] = [bool(got), why, os.path.exists(table)]
got, why = install.fetch_data({**d, "acceptance": None})
out["unaccepted"] = [bool(got), why]
os.environ["DFIRSWARM_DATA_DIR"] = ""
install.DATA_DIR = ""
got, why = install.fetch_data(d)
out["no_copy"] = [bool(got), why]
install.DATA_DIR = f"{D}/mirror"
got, why = install.fetch_data({**d, "converter": {"package": "fakepkg", "version": "9.9"}})
out["converter"] = [bool(got), why]
got, why = install.fetch_data({**d, "commands": [["false"]]})
out["command_fails"] = [bool(got), why]
print(json.dumps(out))
EOF
)" || fail "install.py could not be driven over a converted source: $res"
res="$(tail -1 <<<"$res")"
jq -e '.good == [true, null] and .rec.from == "local copy" and .rec.path == null and .rec.source.kept == false and .rec.pdb_kept == false
       and .rec.outputs[0].canonical_rule == "json-canon/1" and .rec.outputs[0].identity.guid == "K" and .rec.transform
       and .rec.acceptance.accepted_by == "the suite" and .rec.acceptance.source_sha256 == .rec.source.sha256
       and .rec.acceptance.outputs[0].canonical_sha256 == .rec.outputs[0].canonical_sha256' <<<"$res" >/dev/null \
  || fail "a converted table is not recorded with its source, transform, outputs and acceptance, or the source was kept: $res"
jq -e '.bytes_differ_content_same' <<<"$res" >/dev/null || fail "a reconversion with new bytes and the same content was not taken: $res"
jq -e '.other_content[0] == false and (.other_content[1] | test("not the pinned")) and .other_content[2] == false' <<<"$res" >/dev/null \
  || fail "a table with other content was kept: $res"
jq -e '.unaccepted[0] == false and (.unaccepted[1] | test("no recorded acceptance"))' <<<"$res" >/dev/null || fail "an operator's file was built in with no acceptance: $res"
jq -e '.no_copy[0] == false and (.no_copy[1] | test("not fetched by the build"))' <<<"$res" >/dev/null || fail "a build fetched what the operator acquires: $res"
jq -e '.converter[0] == false and (.converter[1] | test("not the pinned 9.9"))' <<<"$res" >/dev/null || fail "another converter version was not refused: $res"
jq -e '.command_fails[0] == false and (.command_fails[1] | test("its command"))' <<<"$res" >/dev/null || fail "a failed conversion was not the reason: $res"
pass "install.py converts an operator's file from its local copy, holds the table to its content, records source, transform, outputs and acceptance, and refuses other content, no acceptance, no copy, another converter"

# --- the download's bounds ----------------------------------------------------
printf '0123456789' > "$TMP/ten.bin"
res="$(python3 - "$ROOT/images" "$TMP" "$(sha "$TMP/ten.bin")" <<'EOF'
import json, sys, urllib.error
sys.path.insert(0, sys.argv[1])
import install
T, s = sys.argv[2], sys.argv[3]
from pathlib import Path
out = {}
why, _ = install.obtain(f"file://{T}/ten.bin", Path(f"{T}/got"), s, size=4)
out["over"] = why
why, _ = install.obtain(f"file://{T}/ten.bin", Path(f"{T}/got"), s, size=10)
out["exact"] = why
why, _ = install.obtain("http://example.org/x", Path(f"{T}/got"), s)
out["http"] = why
h = install.HttpsRedirects(["*.blob.core.windows.net"])
refused = []
for url in ("http://x.blob.core.windows.net/a", "https://evil.example/a", "https://x.blob.core.windows.net:8443/a"):
    try:
        h.redirect_request(None, None, 302, "", {}, url)
        refused.append(False)
    except urllib.error.URLError:
        refused.append(True)
out["redirects_refused"] = refused
out["suffix"] = [install.host_allowed("a.blob.core.windows.net", ["*.blob.core.windows.net"]), install.host_allowed("blob.core.windows.net.evil", ["*.blob.core.windows.net"])]
print(json.dumps(out))
EOF
)" || fail "the bounds could not be driven: $res"
res="$(tail -1 <<<"$res")"
jq -e '(.over | test("more than the 4")) and .exact == null and (.http | test("is not fetched")) and .redirects_refused == [true, true, true] and .suffix == [true, false]' <<<"$res" >/dev/null \
  || fail "a download passed its bounds: $res"
pass "a download stops past its pinned size, is refused on plain http, and follows a redirect only to https, on 443, to a named host"

# --- recipe.py: a curated list, the symbol sets, the operator's store ----------
P="$TMP/packs"
mkdir -p "$P/mempack/requires" "$TMP/store/blobs/sha256"
printf '{"id": "mempack", "name": "m", "version": "1.0.0", "description": "m", "licence": "MIT", "depends": []}\n' > "$P/mempack/pack.json"
printf 'a pdb, for the suite\n' > "$TMP/k.pdb"
k_sha="$(sha "$TMP/k.pdb")"
cat > "$P/mempack/requires/symbols.json" <<JSON
{"template": {"name": "prog-isf-{guid}-{age}", "version": "{guid}-{age}", "url": "https://symbols.example/{pdb}/{guid}{age}/{pdb}",
  "sha256": "{pdb_sha256}", "bytes": "{pdb_bytes}", "set": "curated", "acquire": "operator", "package": "fakepkg", "into": "symbols",
  "terms": {"supplier": "Example", "name": "Example terms", "url": "https://example.org/terms"},
  "converter": {"package": "fakepkg", "version": "{converter_version}"},
  "commands": [["convert", "{file}", "{dir}/windows/{pdb}/{guid}-{age}.json.xz"]],
  "outputs": [{"path": "windows/{pdb}/{guid}-{age}.json.xz", "canonical": {"rule": "json-canon/1", "drop": ["metadata.producer.datetime"]}, "canonical_sha256": "{isf_canonical_sha256}"}],
  "check": ["true"], "redistributable": false, "distribution_policy": "local-only", "why": "the table of {pdb} {guid} age {age}", "licence": "theirs",
  "notice": {"supplier": "Example", "source": "{pdb} {pdb_sha256}", "terms": "Example terms", "derivation": "converted", "restriction": "local-only"}},
 "entries": [{"pdb": "k.pdb", "guid": "ABCDEF0123456789ABCDEF0123456789", "age": 2, "pdb_sha256": "$k_sha", "pdb_bytes": $(wc -c < "$TMP/k.pdb" | tr -d ' '),
              "isf_canonical_sha256": "$(printf '%064d' 7)", "converter_version": "1.0"}]}
JSON
printf 'a bundle\n' > "$TMP/bundle.zip"
cat > "$P/mempack/requires/host.json" <<JSON
{"binaries": [{"name": "prog", "optional": true, "why": "t", "licence": "t", "redistributable": false,
  "install": {"apt": "python3 -m pip install fakepkg==1.0",
              "data": [{"name": "prog-bundle", "version": "1", "url": "https://bundles.example/bundle.zip", "sha256": "$(sha "$TMP/bundle.zip")", "bytes": 9,
                        "set": "broad", "package": "fakepkg", "into": "symbols", "check": ["true"], "redistributable": false, "why": "a bundle", "licence": "theirs"},
                       {"list": "requires/symbols.json"}]}}]}
JSON
printf '{"profiles": {"memory": ["mempack"]}}\n' > "$TMP/profiles.json"
# recipe.py reads profiles.json beside itself: a copy of images/ with the suite's profiles.
mkdir -p "$TMP/images"; cp "$ROOT/images/recipe.py" "$ROOT/images/install.py" "$TMP/images/"; cp "$TMP/profiles.json" "$TMP/images/profiles.json"
R="$TMP/images/recipe.py"
build() { python3 "$R" build memory --packs "$P" --allow-nonredistributable "$@"; }
out="$(build --out "$TMP/ctx-none-store" 2>&1)"; rc=$?
[[ $rc -eq 4 ]] && grep -q 'symbols fetch --accept-terms' <<<"$out" || fail "a curated build with no store did not stop before Docker saying how to fetch (rc $rc): $out"
cp "$TMP/k.pdb" "$TMP/store/blobs/sha256/$k_sha"
out="$(build --out "$TMP/ctx-unaccepted" --symbols-from "$TMP/store" 2>&1)"; rc=$?
[[ $rc -eq 4 ]] && grep -q 'no store records as accepted' <<<"$out" || fail "a curated build with the file and no acceptance was not refused (rc $rc): $out"
[[ ! -e "$TMP/ctx-unaccepted/spec.json" ]] || fail "a refused build wrote its context"
acc_manifest() { # <attended true|false>
  printf '{"version": 1, "files": {"%s": {"acceptance": {"accepted_by": "the suite", "accepted_at": "2026-10-01T00:00:00Z", "sha256": "%s", "terms": {"url": "https://example.org/terms"}, "attended": %s, "os_user": "u", "host": "h"}}}}\n' "$k_sha" "$k_sha" "$1" > "$TMP/store/manifest.json"
}
mkdir -p "$TMP/mirror"; cp "$TMP/bundle.zip" "$TMP/mirror/bundle.zip"
# A process's acceptance (no terminal on either end) is not a person's: refused unless the build says it takes it.
acc_manifest false
out="$(build --out "$TMP/ctx-unattended" --symbols-from "$TMP/store" --data-from "$TMP/mirror" 2>&1)"; rc=$?
[[ $rc -eq 4 ]] && grep -q 'accepted unattended' <<<"$out" && grep -q -- '--allow-unattended-acceptance' <<<"$out" || fail "an unattended acceptance was built in without the flag (rc $rc): $out"
out="$(build --out "$TMP/ctx-unattended" --symbols-from "$TMP/store" --data-from "$TMP/mirror" --allow-unattended-acceptance 2>&1)" || fail "--allow-unattended-acceptance did not take it: $out"
grep -q 'UNATTENDED, taken because of --allow-unattended-acceptance' <<<"$out" || fail "the build does not say the acceptance it bakes is unattended: $out"
jq -e '.data[1].acceptance | .attended == false and .unattended_allowed_by_build == true' "$TMP/ctx-unattended/spec.json" >/dev/null || fail "the spec does not record that the build allowed an unattended acceptance"
# A context that would hold the operator's copy is never in a synced folder or a checkout.
acc_manifest true
out="$(build --out "$TMP/Library/CloudStorage/Dropbox/ctx" --symbols-from "$TMP/store" --data-from "$TMP/mirror" 2>&1)"; rc=$?
[[ $rc -eq 5 ]] && grep -q 'synced folder' <<<"$out" || fail "a context in a synced folder was written (rc $rc): $out"
[[ ! -e "$TMP/Library/CloudStorage/Dropbox/ctx/data" ]] || fail "the operator's copy reached the synced folder"
mkdir -p "$TMP/checkout/.git"
out="$(build --out "$TMP/checkout/ctx" --symbols-from "$TMP/store" --data-from "$TMP/mirror" 2>&1)"; rc=$?
[[ $rc -eq 5 ]] && grep -q 'inside the git checkout' <<<"$out" || fail "a context inside a checkout was written (rc $rc): $out"
build --out "$TMP/checkout/ctx-none" --symbol-set none >/dev/null 2>&1 || fail "a context holding no copy was refused in a checkout (CI builds there)"
out="$(build --out "$TMP/ctx" --symbols-from "$TMP/store" --data-from "$TMP/mirror" 2>&1)" || fail "a curated build with the store and an attended acceptance failed: $out"
grep -q 'prog-isf-ABCDEF0123456789ABCDEF0123456789-2: terms accepted by the suite at 2026-10-01T00:00:00Z, attended' <<<"$out" || fail "the build does not print the acceptance it bakes: $out"
S="$TMP/ctx/spec.json"
jq -e '[.data[].name] == ["prog-bundle", "prog-isf-ABCDEF0123456789ABCDEF0123456789-2"] and .data[1].bytes == 21 and (.data[1].bytes | type) == "number"
       and .data[1].url == "https://symbols.example/k.pdb/ABCDEF0123456789ABCDEF01234567892/k.pdb" and .data[1].acceptance.accepted_by == "the suite"
       and .data[1].commands[0][1] == "{file}" and .data[1].outputs[0].path == "windows/k.pdb/ABCDEF0123456789ABCDEF0123456789-2.json.xz"
       and .symbol_set == ["broad", "curated"] and .omitted.data == []' "$S" >/dev/null \
  || fail "the list was not expanded into the spec with its fields typed and its acceptance: $(jq -c '{data, symbol_set, omitted}' "$S")"
[[ -f "$TMP/ctx/data/$k_sha" && -f "$TMP/ctx/data/$(sha "$TMP/bundle.zip")" ]] || fail "the local copies are not in the context by sha256: $(ls "$TMP/ctx/data" 2>&1)"
grep -q '^RUN --mount=type=bind,source=data,target=/tmp/dfirswarm-data' "$TMP/ctx/Dockerfile" && grep -q 'DFIRSWARM_DATA_DIR=/tmp/dfirswarm-data python3' "$TMP/ctx/Dockerfile" \
  || fail "the local copies are not bound into the install step: $(cat "$TMP/ctx/Dockerfile")"
grep -q '^COPY .*data' "$TMP/ctx/Dockerfile" && fail "the local copies were copied into a layer"
grep -q 'dev.dfirswarm.data="prog-bundle,prog-isf-ABCDEF0123456789ABCDEF0123456789-2"' "$TMP/ctx/Dockerfile" || fail "the image's label does not name its data"
for k in supplier source terms derivation restriction; do grep -q "^    $k: " "$TMP/ctx/NOTICE" || fail "the NOTICE does not say the data's $k"; done
grep -q '^    distribution: local-only (a label, not a legal clearance)' "$TMP/ctx/NOTICE" || fail "the NOTICE does not say the distribution policy is a label"
build --out "$TMP/ctx-broad" --symbol-set broad >/dev/null 2>&1 || fail "--symbol-set broad needs no store"
build --out "$TMP/ctx-off" --symbol-set none >/dev/null 2>&1 || fail "--symbol-set none needs nothing"
jq -e '(.data | length) == 0 and ([.omitted.data[].set] | sort) == ["broad", "curated"] and all(.omitted.data[]; .why | test("--symbol-set none"))' "$TMP/ctx-off/spec.json" >/dev/null \
  || fail "a set left out is not recorded as omitted with why: $(jq -c .omitted "$TMP/ctx-off/spec.json")"
grep -q 'dev.dfirswarm.data' "$TMP/ctx-off/Dockerfile" && fail "an image with no data claims some"
grep -q 'left out by this build' "$TMP/ctx-off/NOTICE" || fail "the NOTICE does not say what the build left out"
build --out "$TMP/ctx-bad" --symbol-set curated,everything >/dev/null 2>&1 && fail "an unknown symbol set was accepted"
grep -qx '/ctx/' "$ROOT/.gitignore" || fail "a build context in the checkout is not ignored by git"
# The shipped list's check requires exactly one table with the identity: a second one from a broad set fails the build.
jq -e '.template.check[2] | test("grep -cF .*-eq 1")' "$ROOT/packs/memory-forensics/requires/symbols.windows.json" >/dev/null || fail "the curated check does not require exactly one table per identity"
pass "recipe.py expands a curated list, takes the operator's file and an attended acceptance from the store (an unattended one only when told, and recorded so), prints what it bakes, keeps the copy out of synced folders and checkouts, binds it into the build, labels and notices the data, records a set left out as omitted, and refuses a curated build without the file or the acceptance"

# --- install.py records the omission apart from a failure ---------------------
res="$(DFIRSWARM_ETC_DIR="$TMP/etc" python3 - "$ROOT/images" "$TMP/ctx-off/spec.json" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
import install
spec = json.load(open(sys.argv[2]))
rec = install.profile_record({}, spec, {}, {"apt": [], "pip": [], "download": [], "source": [], "build": [], "data": []})
md = install.tools_md(rec, spec)
print(json.dumps({"omitted": rec["omitted"], "failed": rec["not_installed"]["data"], "md": "left out by the build on purpose" in md}))
EOF
)" || fail "the record could not be made: $res"
jq -e '(.omitted.data | length) == 2 and .failed == [] and .md' <<<"$res" >/dev/null || fail "an omitted set is not recorded apart from a failure, or tools.md does not say it: $res"
pass "an image records a symbol set left out under omitted.data, not under not_installed, and tools.md says it"

# --- pack.sh holds a list to the same rules -------------------------------------
cp -R "$P/mempack" "$TMP/sealme"
python3 - "$TMP/sealme/requires/symbols.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["entries"][0]["isf_canonical_sha256"] = "%064d" % 7
json.dump(d, open(sys.argv[1], "w"))
EOF
bash "$ROOT/scripts/pack.sh" seal "$TMP/sealme" >/dev/null 2>&1 || fail "a pack with a valid curated list does not seal: $(bash "$ROOT/scripts/pack.sh" seal "$TMP/sealme" 2>&1)"
for broken in 'del t["bytes"]' 't["outputs"][0]["canonical"]["rule"] = "made-up/1"' 't["url"] = "http://symbols.example/{pdb}"' 't["why"] = "for {nowhere}"' 't["acquire"] = "seat"' 't["set"] = "everything"'; do
  rm -rf "$TMP/broken"; cp -R "$TMP/sealme" "$TMP/broken"
  python3 - "$TMP/broken/requires/symbols.json" "$broken" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
t = d["template"]
exec(sys.argv[2])
json.dump(d, open(sys.argv[1], "w"))
EOF
  out="$(bash "$ROOT/scripts/pack.sh" seal "$TMP/broken" 2>&1)" && fail "a curated list with ($broken) sealed: $out"
done
pass "pack.sh refuses a curated list without a size, with an unknown content rule, a plain-http url, a placeholder no entry fills, an unknown acquire or set"

# --- the operator's store: swarm.sh symbols ------------------------------------
SY=(python3 "$ROOT/scripts/symbols.py")
mkdir -p "$TMP/have/deep" "$TMP/have/other"
cp "$TMP/k.pdb" "$TMP/have/deep/k.pdb"
printf 'a pdb, for the suite, but not that one\n' > "$TMP/have/other/k.pdb"
ST="$TMP/home/symbols"
out="$("${SY[@]}" fetch --packs "$P" --from "$TMP/have" 2>&1)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'refused: fetching or storing them is your acceptance' <<<"$out" && grep -q 'Example terms (https://example.org/terms)' <<<"$out" \
  || fail "a fetch without --accept-terms was not refused naming the terms (rc $rc): $out"
[[ ! -e "$ST/blobs" ]] || fail "a refused fetch stored something"
out="$("${SY[@]}" fetch --packs "$P" --from "$TMP/have" --accept-terms 2>&1)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'nothing stands in for it' <<<"$out" || fail "an acceptance with no name was taken (rc $rc): $out"
# Nor does an enrolled examiner stand in for the name: a process could record the owner's acceptance.
mkdir -p "$TMP/home/examiners"; printf '{"id": "examiner-1"}\n' > "$TMP/home/examiners/examiner-1.json"
out="$("${SY[@]}" fetch --packs "$P" --from "$TMP/have" --accept-terms 2>&1)"; rc=$?
[[ $rc -eq 2 && ! -e "$ST/manifest.json" ]] || fail "the enrolled examiner stood in for a name the fetch was not given (rc $rc): $out"
out="$("${SY[@]}" fetch --packs "$P" --from "$TMP/have" --accept-terms --accepted-by "An Examiner" 2>&1)" || fail "a fetch --from with the terms accepted failed: $out"
[[ "$(sha "$ST/blobs/sha256/$k_sha")" == "$k_sha" ]] || fail "the store does not hold the pinned bytes under their sha256"
[[ ! -w "$ST/blobs/sha256/$k_sha" || "$(id -u)" == 0 ]] || fail "a stored file is writable"
jq -e --arg s "$k_sha" '.files[$s].acceptance | .accepted_by == "An Examiner" and .sha256 == $s and .terms.url == "https://example.org/terms" and (.accepted_at | test("^20"))
       and .attended == false and (.os_user | length) > 0 and (.host | length) > 0 and .via == "cli" and (.argv | index("--accepted-by")) != null' "$ST/manifest.json" >/dev/null \
  || fail "the store's manifest does not record who accepted which terms when, for which bytes: $(cat "$ST/manifest.json")"
jq -e 'select(.how == "from") | .acceptance.accepted_by == "An Examiner"' "$ST/fetched.jsonl" >/dev/null || fail "the fetch is not on the store's journal"
"${SY[@]}" list --packs "$P" --json | jq -e '.entries[0].held and .entries[0].acceptance.accepted_by == "An Examiner"' >/dev/null || fail "list does not say the file is held and accepted"
# A second acceptance of a held file is added, never written over the first, and journaled.
"${SY[@]}" fetch --packs "$P" --accept-terms --accepted-by "The Owner" >/dev/null 2>&1 || fail "a second acceptance of a held file failed"
jq -e --arg s "$k_sha" '.files[$s] | .acceptance.accepted_by == "The Owner" and ([.acceptances[].accepted_by] == ["An Examiner", "The Owner"])' "$ST/manifest.json" >/dev/null \
  || fail "a re-acceptance erased the earlier one: $(cat "$ST/manifest.json")"
[[ "$(jq -c 'select(.how == "accept") | .acceptance.accepted_by' "$ST/fetched.jsonl" | paste -sd, -)" == '"An Examiner","The Owner"' ]] || fail "each acceptance is not a line of the store's journal"
bash "$ROOT/scripts/swarm.sh" help symbols | grep -q -- 'fetch --accept-terms --accepted-by NAME' || fail "help symbols does not say the fetch needs the acceptance and a name"
# Only the pinned bytes: a file of another content is not taken.
rm -rf "$TMP/home2"; out="$(DFIRSWARM_HOME="$TMP/home2" "${SY[@]}" fetch --packs "$P" --from "$TMP/have/other" --accept-terms --accepted-by x 2>&1)"; rc=$?
[[ $rc -eq 1 ]] && grep -q '^missing' <<<"$out" || fail "a file with other bytes was taken, or the miss not said (rc $rc): $out"
out="$("${SY[@]}" fetch --packs "$P" --store "$TMP/Library/CloudStorage/Dropbox/symbols" --from "$TMP/have" --accept-terms --accepted-by x 2>&1)"; rc=$?
[[ $rc -eq 2 ]] && grep -q 'synced folder' <<<"$out" || fail "a store in a synced folder was not refused (rc $rc): $out"
[[ ! -e "$TMP/Library/CloudStorage/Dropbox/symbols/blobs" ]] || fail "the synced store was written"
grep -q 'symbols fetch' <(bash "$ROOT/scripts/swarm.sh" help symbols) || fail "swarm.sh has no help for symbols"
bash "$ROOT/scripts/swarm.sh" --help | grep -q 'image-for symbols' || fail "the short help does not name symbols"
pass "symbols fetch stores only the pinned bytes under their sha256, read-only, never in a synced folder, and only with the terms accepted by a name given on its command line, recorded with whether a person at a terminal did it, every acceptance kept and journaled"

# --- the census says what a recipe reports missing -----------------------------
CS="$TMP/census"
mkdir -p "$CS/sb/inputs" "$CS/pack/recipes/needs-table"
printf 'x%.0s' $(seq 1 100) > "$CS/sb/inputs/m.mem"
printf '{"id": "cpack", "name": "c", "version": "1.0.0"}\n' > "$CS/pack/pack.json"
cat > "$CS/pack/recipes/needs-table/recipe.json" <<'EOF'
{"id": "needs-table", "version": "1.0.0", "description": "d", "object": "memory image", "runtime": "python3", "entry": "run.py",
 "auto": ["kickoff"], "limits": {"seconds": 60}, "outputs": ["x"], "covers": "c", "min_bytes": 1}
EOF
cat > "$CS/pack/recipes/needs-table/run.py" <<'EOF'
import json, sys
print(json.dumps({"applies": True, "why": "w", "missing": [{"kind": "symbols", "what": "the table of kernel K", "identity": {"guid": "K"}}, {"kind": "symbols"}]}))
EOF
python3 "$ROOT/scripts/evidence_catalog.py" "$CS/sb" --plan-only --recipes-from "$CS/pack" >/dev/null 2>&1 || bash "$ROOT/scripts/evidence-catalog.sh" "$CS/sb" --plan-only --recipes-from "$CS/pack" >/dev/null 2>&1 || true
jq -e '.missing == [{"input": "inputs/m.mem", "recipe": "cpack/needs-table", "kind": "symbols", "what": "the table of kernel K", "identity": {"guid": "K"}}]' "$CS/sb/catalog/missing.json" >/dev/null \
  || fail "the census did not keep what the recipe said is missing, whole, and only what it said: $(cat "$CS/sb/catalog/missing.json" 2>&1)"
grep -q '^Missing from the images' "$CS/sb/catalog/README.md" && grep -q 'the table of kernel K' "$CS/sb/catalog/README.md" || fail "the catalogue's README does not say it plainly"
pass "the census writes what a recipe's detect reports missing to catalog/missing.json and its README"

# --- memory-windows names a kernel whose table the image lacks -------------------
MW="$ROOT/packs/computer-forensics-base/recipes/memory-windows/run.sh"
mkdir -p "$TMP/volshim"
cat > "$TMP/volshim/vol" <<'SH'
#!/bin/sh
if [ -n "$VOL_STUB_SLOW" ]; then sleep 5; fi
if [ -n "$VOL_STUB_NO_TABLE" ]; then
  echo "INFO     volatility3.framework.automagic.windows: DTB was found at: 0x1aa000" >&2
  echo "WARNING  volatility3.framework.plugins: Automagic exception occurred: volatility3.framework.exceptions.OfflineException: Volatility 3 is offline: unable to access http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/0123456789ABCDEF0123456789ABCDEFA/ntkrnlmp.pdb" >&2
  echo "Unsatisfied requirement plugins.Info.kernel.symbol_table_name"; exit 1
fi
printf 'Variable\tValue\nKernel Base\t0xf80000000000\nSymbols\tfile:///opt/v/symbols/windows/ntkrnlmp.pdb/0123456789ABCDEF0123456789ABCDEF-10.json.xz\n'
SH
chmod +x "$TMP/volshim/vol"
: > "$TMP/k.mem"
T="{\"paths\": [\"$TMP/k.mem\"], \"name\": \"inputs/k.mem\"}"
held="$(PATH="$TMP/volshim:$PATH" bash "$MW" detect --target "$T")" || fail "memory-windows does not apply to a Windows image whose table is held: $held"
jq -e '.applies and (has("missing") | not)' <<<"$held" >/dev/null || fail "a held table is said to be missing: $held"
lack="$(VOL_STUB_NO_TABLE=1 PATH="$TMP/volshim:$PATH" bash "$MW" detect --target "$T")" || fail "memory-windows does not apply when the table is missing: $lack"
jq -e '.applies and .missing[0].kind == "symbols" and .missing[0].identity == {"pdb": "ntkrnlmp.pdb", "guid": "0123456789ABCDEF0123456789ABCDEF", "age": 10} and (.missing[0].what | test("inputs/k.mem runs: this image does not hold it"))' <<<"$lack" >/dev/null \
  || fail "a missing table is not said with the kernel's identity (the age read in hexadecimal): $lack"
slow="$(VOL_STUB_SLOW=1 RECIPE_PROBE_SECONDS=1 PATH="$TMP/volshim:$PATH" bash "$MW" detect --target "$T")"; rc=$?
[[ $rc -eq 1 ]] && jq -e '(.applies | not) and .missing[0].kind == "symbols" and (.missing[0].what | test("did not answer within 1s.*unknown"))' <<<"$slow" >/dev/null \
  || fail "a probe that did not answer passed silently (rc $rc): $slow"
VOL_STUB_NO_TABLE=1 PATH="$TMP/volshim:$PATH" bash "$MW" run --target "$T" --out "$TMP/mw-out" >/dev/null
jq -e '.missing[0].identity.guid == "0123456789ABCDEF0123456789ABCDEF"' "$TMP/mw-out/coverage.json" >/dev/null || fail "the run's coverage does not say what is missing: $(cat "$TMP/mw-out/coverage.json")"
grep -q 'OfflineException' "$TMP/mw-out/windows.info.txt.stderr" || fail "Volatility's stderr is not kept whole"
jq -e '.auto == ["kickoff", "derived"]' "$ROOT/packs/computer-forensics-base/recipes/memory-windows/recipe.json" >/dev/null || fail "memory-windows is no longer what the census and the derived catalogue ask"
[[ ! -d "$ROOT/packs/memory-forensics/recipes" ]] || fail "a second recipe probes the same memory image again"
pass "memory-windows names a Windows image's kernel offline when the image lacks its table, says a probe that did not answer left it unknown, and its run's coverage says what is missing: one probe and one generation per input"

echo "symbols: all checks passed"
