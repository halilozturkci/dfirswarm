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
[[ "$(python3 "$R" profile-for macos-forensics)" == macos ]] || fail "macos-forensics has its own profile; mobile holds it only as mobile-forensics' dependency"
[[ "$(python3 "$R" profile-for mobile-forensics)" == mobile ]] || fail "mobile-forensics should be mobile"
[[ "$(python3 "$R" profile-for cloud-forensics)" == cloud ]] || fail "cloud-forensics has its own profile"
[[ "$(python3 "$R" profile-for triage-collection)" == triage ]] || fail "triage-collection has its own profile"
[[ "$(python3 "$R" profile-for no-such-pack)" == full ]] || fail "an unknown pack cannot be covered by anything smaller than full"
# The base pack alone has the `core` image (the pack and its programs, the
# Sleuth Kit among them, and no other pack's); a run with no packs at all has
# the agents' bare image.
[[ "$(python3 "$R" profile-for computer-forensics-base)" == core ]] || fail "the base pack alone should be core: $(python3 "$R" profile-for computer-forensics-base)"
[[ "$(python3 "$R" profile-for)" == base ]] || fail "a run with no packs should be base"
jp="$(python3 "$R" job-profiles computer-forensics-base)"
jq -e '. == {"computer-forensics-base": "core"}' <<<"$jp" >/dev/null || fail "a run whose only job-needing pack is the base pack should boot core: $jp"
# A run's job images: each pack in its own profile, and a dependency every
# profile holds with its dependents, not in the smallest image that holds it.
jp="$(python3 "$R" job-profiles computer-forensics-base windows-forensics mobile-forensics encrypted-containers macos-forensics)"
# disk and mobile each hold three of the run's packs (the base pack with two of the others); the tie goes to the profile of the
# fewest packs, and disk holds four since virtualization-backup-forensics joined it, so the base pack runs in mobile (it was disk).
jq -e '. == {"computer-forensics-base": "mobile", "windows-forensics": "disk", "mobile-forensics": "mobile", "encrypted-containers": "disk", "macos-forensics": "mobile"}' <<<"$jp" >/dev/null \
  || fail "the base pack of a disk and mobile run should run in mobile (three of the run's packs, the fewest packs of the tie), not in memory or disk: $jp"
jp="$(python3 "$R" job-profiles computer-forensics-base windows-forensics encrypted-containers linux-forensics)"
[[ "$(jq -r '."computer-forensics-base"' <<<"$jp")" == disk ]] || fail "the base pack goes where most of the run's packs are (disk, two), not linux (one): $jp"
[[ "$(python3 "$R" job-profiles computer-forensics-base memory-forensics | jq -r '."computer-forensics-base"')" == memory ]] || fail "with memory-forensics alone, the base pack runs in memory"
# A plain mobile-forensics run boots ONE job image: swarm.sh hands recipe.py the
# run's packs with their dependencies, the base pack and macos-forensics beside
# mobile-forensics. macos-forensics has a profile of its own now, and the base
# pack, which every profile holds, must go where the run's packs ended up and
# not be given `macos` (or `memory`) for itself.
jp="$(python3 "$R" job-profiles computer-forensics-base macos-forensics mobile-forensics)"
jq -e '. == {"computer-forensics-base": "mobile", "macos-forensics": "mobile", "mobile-forensics": "mobile"}' <<<"$jp" >/dev/null \
  || fail "a mobile-forensics run (with the base pack and macos-forensics) should boot one job image, mobile: $jp"
jp="$(python3 "$R" job-profiles computer-forensics-base macos-forensics)"
jq -e '. == {"computer-forensics-base": "macos", "macos-forensics": "macos"}' <<<"$jp" >/dev/null \
  || fail "a macos-forensics run should boot one job image, macos: $jp"
jp="$(python3 "$R" job-profiles computer-forensics-base windows-forensics macos-forensics)"
jq -e '. == {"computer-forensics-base": "macos", "windows-forensics": "disk", "macos-forensics": "macos"}' <<<"$jp" >/dev/null \
  || fail "the base pack goes to the profile of the fewest packs that holds it (macos, two; disk, three): $jp"
pass "a pack goes to the smallest profile that holds it, a pack no profile lists to the smallest that covers it, and full only when nothing smaller serves"

# The invariants of images/profiles.json. `full` holds every pack under
# packs/ (images/README.md says so, and a pack added without a line in `full`
# fails here). Every pack resolves, by profile-for, to a profile that holds it
# (it and its dependencies are among the profile's packs): never to a profile
# that merely names the same programs, which is every profile for a pack of
# stdlib Python. A pack with an image of its own gets it.
python3 - "$ROOT" <<'PYEOF'
import json, subprocess, sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root / "images"))
import recipe

packs = sorted(p.parent.name for p in (root / "packs").glob("*/pack.json"))
assert len(packs) >= 12, f"found only {packs}"
table = recipe.profiles()
members = {n: set(recipe.resolve(recipe.PACKS, v["packs"])) for n, v in table.items() if not v.get("apt")}
missing = [p for p in packs if p not in members["full"]]
assert not missing, f"packs missing from profiles.json's full: {missing}"
unknown = sorted({m for v in table.values() for m in v["packs"]} - set(packs))
assert not unknown, f"profiles.json names packs that are not under packs/: {unknown}"
chosen = {}
for p in packs:
    out = subprocess.run([sys.executable, str(root / "images" / "recipe.py"), "profile-for", p],
                         capture_output=True, text=True, check=True).stdout.strip()
    chosen[p] = out
    assert out in members, f"{p}: profile-for gave {out!r}, which is no profile"
    assert p in members[out], f"{p}: profile-for gave {out}, which does not hold it ({sorted(members[out])})"
    smaller = [n for n, m in members.items() if n != "full" and p in m and len(m) < len(members[out])]
    assert not smaller, f"{p}: {out} is not the smallest holder; {smaller} hold it with fewer packs"
for pack, profile in {"macos-forensics": "macos", "cloud-forensics": "cloud", "triage-collection": "triage",
                      "mobile-forensics": "mobile", "windows-forensics": "disk", "memory-forensics": "memory",
                      "reverse-engineering": "re", "ransomware-response": "re", "network-forensics": "network",
                      "linux-forensics": "linux", "encrypted-containers": "disk", "computer-forensics-base": "core"}.items():
    assert chosen[pack] == profile, f"{pack}: expected {profile}, got {chosen[pack]}"
# The images a run boots (the default image, which holds every pack, and the
# job images) against tests/fixtures/job-images-main.json, frozen from the
# recipe and profiles before the macos, cloud and triage profiles: every pack,
# every pair and twelve larger runs, each as swarm.sh hands it to recipe.py
# (the packs with their dependencies). The only differences allowed are the
# ones this change makes on purpose.
NEW_PROFILES = {"macos", "cloud", "triage"}
NEW_PACKS = {"macos-forensics", "cloud-forensics", "triage-collection"}
BASE_PACK = "computer-forensics-base"
# Documented in the changelog and images/README.md: no profile but full holds
# these pairs, which a smaller one used to serve by chance.
BY_HOLDING = {"encrypted-containers+ransomware-response", "memory-forensics+ransomware-response",
              "ransomware-response+windows-forensics"}
# Where the base pack's own jobs run (the third value of each entry). The set
# of images a run boots does not change for a run without a pack of the new
# profiles, but the base pack, which every profile holds, runs in another image
# of that set in ten of these runs, and in `core` when it is the run's only
# pack. It was `memory` whenever `memory` was booted, wherever the other packs
# ran; it is now the image most of the run's packs run in, then the one of the
# fewest packs, then the name. Documented in images/README.md. Any other move of
# the base pack fails here.
PLACED = {
    BASE_PACK: ("memory", "core"),
    "computer-forensics-base+linux-forensics+memory-forensics+network-forensics": ("memory", "linux"),
    "computer-forensics-base+memory-forensics+reverse-engineering+ransomware-response": ("memory", "re"),
    "computer-forensics-base+windows-forensics+encrypted-containers+memory-forensics+reverse-engineering+ransomware-response+network-forensics": ("memory", "re"),
    "computer-forensics-base+windows-forensics+memory-forensics+network-forensics+linux-forensics+mobile-forensics": ("memory", "mobile"),
    "linux-forensics+memory-forensics": ("memory", "linux"),
    "memory-forensics+mobile-forensics": ("memory", "mobile"),
    # `disk` holds virtualization-backup-forensics beside its three packs, so a tie it used to win on the fewest packs goes to `re`.
    "encrypted-containers+ransomware-response": ("disk", "re"),
    "encrypted-containers+reverse-engineering": ("disk", "re"),
    "ransomware-response+windows-forensics": ("disk", "re"),
    "reverse-engineering+windows-forensics": ("disk", "re"),
}

def booted(run, base_job=False):
    full = recipe.resolve(recipe.PACKS, run)
    default = recipe.profile_for(recipe.PACKS, full)
    jobs = recipe.job_profiles(recipe.PACKS, full)
    images = sorted(set(jobs.values()) | {default})
    return (default, images, jobs[BASE_PACK]) if base_job else (default, images)

frozen = json.loads((root / "tests" / "fixtures" / "job-images-main.json").read_text())
assert len(frozen) >= 90, len(frozen)
assert BY_HOLDING <= set(frozen) and BASE_PACK in frozen, "the frozen table lacks a documented run"
differing, placed = set(), set()
for key, (old_default, old_images, old_base) in frozen.items():
    new_default, new_images, new_base = booted(key.split("+"), base_job=True)
    # `core` is booted for a run whose job-needing pack is the base pack alone
    # and for no other run: a run that booted a domain image on main boots no
    # extra image, and no run without a pack of the new profiles (or one of the
    # three pairs below) boots more images than it did.
    assert "core" not in new_images or key == BASE_PACK, (key, new_images)
    assert key in BY_HOLDING or NEW_PACKS & set(key.split("+")) or len(new_images) <= len(old_images), (key, old_images, new_images)
    if not NEW_PACKS & set(key.split("+")) and new_base != old_base:
        assert PLACED.get(key) == (old_base, new_base), (key, "the base pack's jobs moved from", old_base, "to", new_base)
        placed.add(key)
    if (new_default, new_images) == (old_default, old_images):
        continue
    differing.add(key)
    if key in BY_HOLDING:
        assert new_default == "full" and new_images == sorted(set(old_images) | {"full"}), (key, old_default, old_images, new_default, new_images)
    elif key == BASE_PACK:
        assert (new_default, new_images) == ("core", ["core"]), (key, new_default, new_images)
    elif NEW_PACKS & set(key.split("+")):
        assert set(new_images) - set(old_images) <= NEW_PROFILES and new_default in NEW_PROFILES | {old_default}, \
            (key, "may differ only by a new profile", old_default, old_images, new_default, new_images)
    else:
        raise AssertionError(f"{key}: booted {old_default} {old_images} before the new profiles, {new_default} {new_images} now")
assert BY_HOLDING | {BASE_PACK} <= differing, "a documented difference no longer differs: " + str(sorted((BY_HOLDING | {BASE_PACK}) - differing))
assert placed == set(PLACED), "a documented move of the base pack's jobs no longer happens, or a new one does: " + str(sorted(placed ^ set(PLACED)))
# What the table cannot say for the runs that name a new profile's pack.
assert booted(["mobile-forensics"]) == ("mobile", ["mobile"]), booted(["mobile-forensics"])
assert booted([BASE_PACK, "macos-forensics", "mobile-forensics"]) == ("mobile", ["mobile"])
assert booted([BASE_PACK, "macos-forensics"]) == ("macos", ["macos"])
assert booted(["macos-forensics"]) == ("macos", ["macos"])
assert booted(["cloud-forensics"]) == ("cloud", ["cloud"]) and booted(["triage-collection"]) == ("triage", ["triage"])

# `core` holds the base pack and nothing else: its programs (the Sleuth Kit,
# plaso, dissect, bulk_extractor, ...) and no other pack's. It is the profile of
# the fewest packs of those that hold the base pack, so the tie rule gives it
# the base pack alone; the base pack alone was `memory` on main, and `cloud`
# with the rule and without `core`.
assert table["core"]["packs"] == [BASE_PACK] and members["core"] == {BASE_PACK}, members["core"]
# The tie rule: of the profiles that hold what the run needs, full last, then
# the fewest packs, then the fewest programs those packs name, then the name.
# The base pack alone is held by ten profiles of one to three packs. Pinned:
# a change of the result is a decision (change this, images/README.md and the
# changelog together), not an accident of the order of profiles.json.
named = lambda n: len(recipe.needs_of(recipe.PACKS, sorted(members[n]))[1])
holders = sorted(n for n, m in members.items() if n not in ("full", "base") and BASE_PACK in m)
assert len(holders) == 10 and "core" in holders, holders
expected = min(holders, key=lambda n: (len(members[n]), named(n), n))
assert chosen[BASE_PACK] == expected == "core", (chosen[BASE_PACK], expected)
# Unlisted packs (an installed pro or third-party pack that no profile lists)
# are matched by what they name, and `core`, the smallest profile, covers
# what the base pack covers:
#  - stdlib Python that depends on the base pack and names no program -> core;
#  - a pack naming only Sleuth Kit programs (the base pack's) -> core, with or
#    without the dependency on the base pack;
#  - a pack that names nothing and depends on nothing -> base (bare image);
#  - a pack that names a program the base pack does not (vol, tshark, pwsh)
#    -> the smallest profile that names it, never core;
#  - a pack that names programs only `full` has together -> full.
import tempfile
with tempfile.TemporaryDirectory() as unlisted:
    def unlisted_pack(name, deps, binaries=()):
        (Path(unlisted) / name / "requires").mkdir(parents=True)
        (Path(unlisted) / name / "pack.json").write_text(json.dumps({"id": name, "depends": deps}))
        (Path(unlisted) / name / "requires" / "host.json").write_text(json.dumps({"binaries": [{"name": b, "optional": True} for b in binaries]}))
    unlisted_pack("stdlib-on-base", [BASE_PACK])
    unlisted_pack("stdlib-alone", [])
    unlisted_pack("tsk-only", [], ["fls", "icat", "mmls"])
    unlisted_pack("tsk-only-on-base", [BASE_PACK], ["fls", "mactime"])
    unlisted_pack("wants-vol", [BASE_PACK], ["vol"])
    unlisted_pack("wants-tshark", [], ["tshark"])
    unlisted_pack("wants-pwsh", [BASE_PACK], ["pwsh"])
    unlisted_pack("wants-vol-and-tshark", [BASE_PACK], ["vol", "tshark"])
    search = [Path(unlisted), recipe.PACKS]
    want = {"stdlib-on-base": "core", "stdlib-alone": "base", "tsk-only": "core", "tsk-only-on-base": "core",
            "wants-vol": "memory", "wants-tshark": "network", "wants-pwsh": "cloud", "wants-vol-and-tshark": "full"}
    for pack_name, profile in want.items():
        got_profile = recipe.profile_for(search, [pack_name])
        assert got_profile == profile, (pack_name, got_profile, profile)
    # Core covers no more than the base pack names: nothing it lacks is promised.
    assert recipe.needs_of(recipe.PACKS, [BASE_PACK])[1] >= {"fls", "icat", "mmls", "mactime"}
    assert not {"vol", "tshark", "pwsh"} & recipe.needs_of(recipe.PACKS, [BASE_PACK])[1]
    # The jobs of an unlisted pack that depends on the base pack: the base pack
    # joins the pack's profile when that is not full, and boots core alone when
    # the pack went to full (so the image set is the same size as before).
    jp = recipe.job_profiles(search, recipe.resolve(search, ["wants-vol"]))
    assert jp == {BASE_PACK: "memory", "wants-vol": "memory"}, jp
    jp = recipe.job_profiles(search, recipe.resolve(search, ["wants-vol-and-tshark"]))
    assert jp == {BASE_PACK: "core", "wants-vol-and-tshark": "full"}, jp
# The order of profiles.json decides nothing: the resolutions of every pack,
# every pair and the base pack with each, and the jobs of each run, are the same
# under the file's order reversed, sorted, and five shuffles.
import random
real_profiles, table0 = recipe.profiles, recipe.profiles()
resolutions = [[p] for p in packs] + [[a, b] for i, a in enumerate(packs) for b in packs[i + 1:]]
def settle():
    return [(recipe.profile_for(recipe.PACKS, r), recipe.profile_for(recipe.PACKS, recipe.resolve(recipe.PACKS, r)),
             recipe.job_profiles(recipe.PACKS, recipe.resolve(recipe.PACKS, r))) for r in resolutions]
baseline = settle()
rng = random.Random(152)
names0 = list(table0)
for order in [names0[::-1], sorted(names0)] + [rng.sample(names0, len(names0)) for _ in range(5)]:
    recipe.profiles = lambda order=order: {k: table0[k] for k in order}
    assert settle() == baseline, f"the order of profiles.json changed a resolution: {order}"
recipe.profiles = real_profiles
# mobile depends on macos-forensics and still resolves to itself; macos is held by both.
assert "macos-forensics" in members["mobile"] and "macos-forensics" in members["macos"]
# Each own profile lists its pack alone, so it holds that pack and the base.
for name, pack in (("macos", "macos-forensics"), ("cloud", "cloud-forensics"), ("triage", "triage-collection")):
    assert table[name]["packs"] == [pack], f"{name} should list only {pack}: {table[name]}"
    assert members[name] == {"computer-forensics-base", pack}, members[name]

# The rule itself, on profiles and packs made for it: a pack that names
# nothing beyond the base's is covered by every profile, and must still go to
# the profile that holds it (a pack listed in `disk` and in `full` -> disk;
# one listed in `full` alone -> full), while a pack no profile lists is
# matched by what it names. Written in a scratch directory; recipe.profiles
# is pointed at a table made for the test.
import tempfile
with tempfile.TemporaryDirectory() as tmp:
    d = Path(tmp)
    def pack(name, deps, binaries=()):
        (d / name / "requires").mkdir(parents=True)
        (d / name / "pack.json").write_text(json.dumps({"id": name, "depends": deps}))
        (d / name / "requires" / "host.json").write_text(json.dumps({"binaries": [{"name": b, "optional": True} for b in binaries]}))
    pack("b", [], ["fls"])
    pack("mem", ["b"], ["vol"])
    pack("held-by-disk", ["b"])
    pack("held-by-full", ["b"])
    pack("unlisted", ["b"], ["vol"])
    pack("unlisted-big", ["b"], ["vol", "fls", "other"])
    recipe.profiles = lambda: {
        "memory": {"packs": ["mem"]},
        "disk": {"packs": ["held-by-disk"]},
        "full": {"packs": ["mem", "held-by-disk", "held-by-full"]},
    }
    got = lambda *names: recipe.profile_for(d, list(names), images=d)
    assert got("held-by-disk") == "disk", got("held-by-disk")
    assert got("held-by-full") == "full", "a pack only full lists goes to full, not to memory, which covers it by chance: " + got("held-by-full")
    assert got("mem") == "memory"
    assert got("held-by-disk", "mem") == "full", got("held-by-disk", "mem")
    assert got("unlisted") == "memory", "a pack no profile lists is matched by what it names: " + got("unlisted")
    assert got("unlisted-big") == "full", got("unlisted-big")
    # Ties: the same number of packs, then the programs they name, then the
    # name; whatever the order of the table.
    pack("x", ["b"], ["fls", "a1", "a2"])
    pack("y", ["b"], ["fls", "c1"])
    pack("z", ["b"], ["fls", "c1"])
    pack("lone", [])
    pack("std", ["b"])
    for order in (("zz", "yy", "xx"), ("xx", "yy", "zz"), ("yy", "xx", "zz")):
        spec = {"xx": ["x"], "yy": ["y"], "zz": ["z"]}
        recipe.profiles = lambda order=order, spec=spec: {
            "base": {"packs": []}, **{k: {"packs": spec[k]} for k in order}, "full": {"packs": ["x", "y", "z"]}}
        assert got("b") == "yy", ("fewest programs, then the name", order, got("b"))
        assert got("std") == "yy", ("an unlisted stdlib pack on the base pack: the same tie", order, got("std"))
        assert got("lone") == "base", got("lone")
        assert got("x") == "xx" and got("z") == "zz"
    # A profile of the base pack alone has the fewest packs of any holder: it
    # takes the base pack alone, and an unlisted pack that depends on it and
    # names nothing more, whatever the order of the table or the programs the
    # others name; a pack that names more goes to the profile that holds it.
    for order in (("zz", "cc", "xx"), ("cc", "xx", "zz"), ("xx", "zz", "cc")):
        spec = {"xx": ["x"], "zz": ["z"], "cc": ["b"]}
        recipe.profiles = lambda order=order, spec=spec: {
            "base": {"packs": []}, **{k: {"packs": spec[k]} for k in order}, "full": {"packs": ["x", "z", "b"]}}
        assert got("b") == "cc", ("the base pack alone has its own profile", order, got("b"))
        assert got("std") == "cc", ("an unlisted stdlib pack on the base pack: the same", order, got("std"))
        assert got("lone") == "base", got("lone")
        assert got("x") == "xx" and got("z") == "zz"
        jp = recipe.job_profiles(d, ["b"], images=d)
        assert jp == {"b": "cc"}, jp
PYEOF
[[ "$?" == 0 ]] || fail "the profile invariants do not hold (see above)"
pass "full holds every pack under packs/, every pack resolves to a profile that holds it, and macos, cloud and triage have images of their own"
# The workflows that build and boot the images list the profiles; a profile
# added to profiles.json and not there is never built.
python3 - "$ROOT" <<'PYEOF'
import re, sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root / "images"))
import recipe
want = sorted(recipe.profiles())
for wf in ("images.yml", "image-boot.yml"):
    text = (root / ".github" / "workflows" / wf).read_text()
    found = re.findall(r"^\s*profile: \[([^\]]*)\]", text, re.M)
    assert len(found) == 1, f"{wf}: expected one profile matrix, found {len(found)}"
    listed = sorted(x.strip() for x in found[0].split(","))
    assert listed == want, f"{wf} builds {listed}, profiles.json has {want}"
    # The arm64 entries (`include:`) name profiles that exist and that the
    # matrix builds for amd64, once each.
    extra = re.findall(r"^\s*- \{ profile: ([a-z0-9-]+), arch: ([a-z0-9]+) \}", text, re.M)
    assert len(extra) == len(set(extra)), f"{wf}: an include entry is listed twice: {extra}"
    # Counted by the text, not by the flow style: an entry written as a block
    # (`- profile: linux` / `arch: arm64` on two lines) is one the regex above
    # does not read, and must be caught.
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert len(extra) == code.count("arch: arm64"), f"{wf}: an include entry the check does not read ({code.count('arch: arm64')} arm64 entries in the file, {len(extra)} read)"
    for profile, arch in extra:
        assert profile in want and profile in listed, f"{wf}: include entry {profile}/{arch} names a profile that is not in the matrix"
        assert arch == "arm64", f"{wf}: include entry {profile}/{arch}: only arm64 is added to the amd64 matrix"
PYEOF
[[ "$?" == 0 ]] || fail "the images workflows do not build exactly the profiles in profiles.json"
pass "the images and image-boot workflows build every profile in profiles.json and no other"

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
# The broad set alone: the curated one needs the operator's store (below).
python3 "$R" build memory --out "$TMP/ctx" --allow-nonredistributable --symbol-set broad >/dev/null || fail "the build with the flag failed"
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
grep -qF 'vol  (memory-forensics)  Volatility Software License 1.0 (https://github.com/volatilityfoundation/volatility3/blob/develop/LICENSE.txt)' "$TMP/ctx/NOTICE" \
  || fail "the NOTICE does not name vol's licence with the link to its text"
seal_py="$(jq -r '.pack_versions["memory-forensics"].seal' "$TMP/ctx/spec.json")"
seal_ts="$(cd "$ROOT" && node --experimental-strip-types -e 'import("./scripts/vm.ts").then(m => console.log(m.packNeeds(["packs/memory-forensics"])[0].seal))')"
[[ "$seal_py" == "$seal_ts" ]] || fail "the recipe's seal ($seal_py) and the kickoff's ($seal_ts) differ"
pass "a build context carries pack versions and seals the kickoff computes alike, a NOTICE, and says it is not for redistribution"

# What the memory image is asked to hold beyond the base: Volatility's Windows
# symbol tables as pinned data (checked, put in the venv's package, warmed, and
# said in the NOTICE to carry a licence of their own), a Debian source built with
# its patches, a compiler, and the small programs a recent memory case lacked.
jq -e '.data | length == 1 and .[0].name == "vol-windows-symbols" and .[0].program == "vol" and .[0].package == "volatility3"
       and .[0].into == "symbols" and (.[0].sha256 | test("^[0-9a-f]{64}$")) and (.[0].url | startswith("https://"))
       and .[0].warm == ["vol", "-q", "isfinfo"] and .[0].redistributable == false' "$TMP/ctx/spec.json" >/dev/null \
  || fail "the memory image does not pin Volatility's Windows symbol tables as data: $(jq -c .data "$TMP/ctx/spec.json")"
grep -q '^  vol-windows-symbols data for vol: https://.*  sha256 [0-9a-f]\{64\}  \[not for redistribution\]$' "$TMP/ctx/NOTICE" \
  || fail "the NOTICE does not name the symbol tables, where they come from and that they are not for redistribution"
jq -e '.data[0].required == true and (.data[0].check | length) == 3 and .data[0].check[0] == "sh"' "$TMP/ctx/spec.json" >/dev/null \
  || fail "the symbol tables are not required of the image (vol is optional, its data was pinned on purpose), or carry no check: $(jq -c '.data[0] | {required, check}' "$TMP/ctx/spec.json")"
python3 "$R" build memory --out "$TMP/ctx-lenient" --allow-nonredistributable --allow-missing-data >/dev/null || fail "the build with --allow-missing-data failed"
jq -e '[.data[].required] == [false, false]' "$TMP/ctx-lenient/spec.json" >/dev/null || fail "--allow-missing-data does not let the build go on without a data file"
jq -e '.nonredistributable | index("vol") != null and index("vol-windows-symbols") != null' "$TMP/ctx/spec.json" >/dev/null \
  || fail "the image's record does not name the symbol tables among what is not cleared for redistribution: $(jq -c .nonredistributable "$TMP/ctx/spec.json")"
grep -q '^    licence of the data: .*Volatility Software License 1.0.*Microsoft Symbol Server' "$TMP/ctx/NOTICE" \
  || fail "the NOTICE does not say what licence the symbol tables carry"
jq -e '[.builds[] | select(.name == "aeskeyfind")] | length == 1 and (.[0].patches | length) == 4 and ([.[0].patches[].sha256 | test("^[0-9a-f]{64}$")] | all)
       and (.[0].commands | length) == 2 and .[0].bin == "bin/aeskeyfind"' "$TMP/ctx/spec.json" >/dev/null \
  || fail "aeskeyfind is not built from Debian's source with its pinned patches: $(jq -c '.builds' "$TMP/ctx/spec.json")"
grep -q '^FROM ${BASE} AS build-aeskeyfind$' "$TMP/ctx/Dockerfile" || fail "aeskeyfind has no builder stage"
grep -q '^  aeskeyfind patch: https://.*30_big-files-support.patch  sha256 [0-9a-f]\{64\}$' "$TMP/ctx/NOTICE" || fail "the NOTICE does not list the patches aeskeyfind is built with"
for prog in gcc make steghide aeskeyfind; do
  jq -e --arg p "$prog" '[.binaries[].name] | index($p) != null' "$TMP/ctx/spec.json" >/dev/null || fail "the memory image is not asked to hold $prog"
done
python3 "$R" build re --out "$TMP/ctx-re" --allow-nonredistributable >/dev/null || fail "the re build failed"
for prog in gcc make steghide; do
  jq -e --arg p "$prog" '[.binaries[].name] | index($p) != null' "$TMP/ctx-re/spec.json" >/dev/null || fail "the re image is not asked to hold $prog"
done
jq -e '(.data | length) == 0 and ([.builds[].name] | index("aeskeyfind") == null)' "$TMP/ctx-re/spec.json" >/dev/null \
  || fail "the re image takes the memory image's symbol tables or its key finder"
jq -e '.apt.gcc == false and .apt["libc6-dev"] == false' "$TMP/ctx/spec.json" >/dev/null || fail "a compiler is not an optional package of the memory image: $(jq -c .apt "$TMP/ctx/spec.json")"
pass "the memory image pins the Windows symbol tables with their licence, builds aeskeyfind from patched Debian source, and holds a compiler; the re image holds the compiler and steghide alone"


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

# A file is not redistributable because its program is: a redistributable
# program with data its pack says is not holds the image back, and one whose
# data is redistributable too does not.
mkdir -p "$TMP/fakedata/reverse-engineering/requires" "$TMP/fakedata/ransomware-response/requires"
printf '{"id": "ransomware-response", "name": "f", "version": "1.0.0", "description": "f", "licence": "MIT", "depends": []}\n' > "$TMP/fakedata/ransomware-response/pack.json"
printf '{"binaries": []}\n' > "$TMP/fakedata/ransomware-response/requires/host.json"
printf '{"id": "reverse-engineering", "name": "f", "version": "1.0.0", "description": "f", "licence": "MIT", "depends": []}\n' > "$TMP/fakedata/reverse-engineering/pack.json"
for flag in false true; do
  cat > "$TMP/fakedata/reverse-engineering/requires/host.json" <<JSON
{"binaries": [{"name": "free-tool", "optional": true, "why": "t", "licence": "MIT", "redistributable": true,
  "install": {"apt": "x", "data": {"name": "free-tables", "version": "1", "url": "https://example.org/t.zip", "sha256": "$sha", "package": "p",
              "check": ["true"], "why": "t", "licence": "Terms", "redistributable": $flag}}}]}
JSON
  python3 "$R" build re --packs "$TMP/fakedata" --out "$TMP/ctx-data-$flag" >/dev/null 2>"$TMP/data-$flag.err"; rc=$?
  if [[ $flag == false ]]; then
    [[ $rc -eq 3 ]] && grep -q 'free-tables' "$TMP/data-$flag.err" || fail "an image with non-redistributable data for a redistributable program was not held back (rc $rc): $(cat "$TMP/data-$flag.err")"
  else
    [[ $rc -eq 0 ]] && [[ "$(jq -r '.redistributable' "$TMP/ctx-data-$flag/spec.json")" == true ]] || fail "redistributable data for a redistributable program held the image back (rc $rc): $(cat "$TMP/data-$flag.err")"
  fi
done
pass "data is held back by its own redistributable flag as well as its program's"

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
[[ "$(jq -r '.bad_optional_rc' <<<"$res")" == 1 ]] || fail "an optional program that does not build ended its stage well, which Docker would cache: $res"
jq -r '.bad_link[1]' <<<"$res" | grep -q 'configure failed' || fail "an optional program that did not build is not recorded with why: $res"
[[ "$(jq -r '.bad_required_rc' <<<"$res")" == 1 ]] || fail "a required program that does not build did not stop the image: $res"
[[ "$(jq -r '.backports' <<<"$res")" == null ]] || fail "the image's own backports were refused: $res"
grep -q '^URIs: http://mirror.example/debian$' "$K/apt-sources/dfirswarm-bookworm-backports.sources" && grep -q '^Suites: bookworm-backports$' "$K/apt-sources/dfirswarm-bookworm-backports.sources" \
  || fail "backports do not come from the image's own mirror: $(cat "$K/apt-sources/dfirswarm-bookworm-backports.sources")"
jq -r '.other_release' <<<"$res" | grep -q "is not this image's backports" || fail "a release other than the image's backports was added: $res"
pass "install.py puts a pinned source, a .deb and a built program on PATH only when their bytes are the pinned ones, gives a source's requirements a venv of its own, builds with the pack's env, records a failed build and fails its stage, and adds only its own backports"

# --- pinned data, and a source built from patches and its own steps ----------
# Data a program reads (a symbol pack): checked against its sha256, put as named
# inside a Python package of the venv, and a command run once it is there so the
# index the program builds on first use is in the image. A source with no
# configure script names its steps, and the patches applied first are pinned.
D="$TMP/data"
mkdir -p "$D/venv/bin" "$D/site/fakepkg" "$D/src/tool-1.0" "$D/bin"
ln -s "$(command -v python3)" "$D/venv/bin/python"
printf 'tables that are not a program\n' > "$D/pack.zip"
data_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$D/pack.zip")"
printf '#!/bin/sh\necho "$@" > "%s/warm.out"\n' "$D" > "$D/bin/warmer"
chmod +x "$D/bin/warmer"
printf 'int main(void) { return 1; }\n' > "$D/src/tool-1.0/tool.c"
cat > "$D/src/tool-1.0/Makefile" <<'MK'
tool: tool.c
	$(CC) $(CFLAGS) -o tool tool.c
MK
printf 'int main(void) { return 0; }\n' > "$D/fixed.c"
# The patch: what a distribution adds to an upstream release.
( cd "$D" && mkdir -p a b && cp src/tool-1.0/tool.c a/tool.c && cp fixed.c b/tool.c && diff -u a/tool.c b/tool.c | sed -e '1s#.*#--- a/tool.c#' -e '2s#.*#+++ b/tool.c#' > fix.patch; true )
printf 'not a patch that applies\n' > "$D/bad.patch"
tar -czf "$D/tool-1.0.tar.gz" -C "$D/src" tool-1.0
tool_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$D/tool-1.0.tar.gz")"
patch_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$D/fix.patch")"
bad_patch_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$D/bad.patch")"
res="$(PYTHONPATH="$D/site" DFIRSWARM_VENV="$D/venv" DFIRSWARM_TOOLS_DIR="$D/tools" DFIRSWARM_BUILD_DIR="$D/work" PATH="$D/bin:$PATH" \
       python3 - "$ROOT/images" "$D" "$data_sha" "$tool_sha" "$patch_sha" "$bad_patch_sha" <<'EOF'
import json, os, sys
sys.path.insert(0, sys.argv[1])
import install
D, data_sha, tool_sha, patch_sha, bad_patch_sha = sys.argv[2:7]
# IMAGE_PATH is the real image's; the test's own program is found on PATH.
install.IMAGE_PATH = os.environ["PATH"]
out = {}
d = {"name": "prog-data", "program": "prog", "version": "1", "url": f"file://{D}/pack.zip", "sha256": data_sha,
     "package": "fakepkg", "into": "tables"}
open(f"{D}/site/fakepkg/__init__.py", "w").write("")
got, why = install.fetch_data(d)
out["good"] = [bool(got), why, (got or {}).get("path"), (got or {}).get("kind"), (got or {}).get("bytes")]
got, why = install.fetch_data({**d, "warm": ["warmer", "once", "twice"]})
out["warm"] = [bool(got), (got or {}).get("warm")]
got, why = install.fetch_data({**d, "warm": ["no-such-warmer"]})
out["warm_fails"] = [bool(got), (got or {}).get("warm")]
got, why = install.fetch_data({**d, "sha256": "0" * 64, "into": "other"})
out["bad_sha"] = [bool(got), why, os.path.exists(f"{D}/site/fakepkg/other/pack.zip")]
got, why = install.fetch_data({**d, "package": "no_such_package_here"})
out["no_package"] = [bool(got), why]
got, why = install.fetch_data({**d, "into": "../outside"})
out["escape"] = [bool(got), why, os.path.exists(f"{D}/site/outside")]
got, why = install.fetch_data({**d, "file": "named.zip"})
out["named"] = [bool(got), os.path.basename((got or {}).get("path", ""))]
for bad_name in ("../../escape.bin", "sub/escape.bin", "..", "a\\b"):
    got, why = install.fetch_data({**d, "file": bad_name, "into": "named"})
    out.setdefault("bad_names", []).append([bool(got), why])
out["escaped_file_exists"] = os.path.exists(f"{D}/site/escape.bin") or os.path.exists(f"{D}/escape.bin") or os.path.exists(f"{D}/site/fakepkg/escape.bin")
got, why = install.fetch_data({**d, "into": "checked", "check": ["true"]})
out["check_ok"] = [bool(got), (got or {}).get("check")]
got, why = install.fetch_data({**d, "into": "unchecked", "check": ["false"]})
out["check_fails"] = [bool(got), why, os.path.exists(f"{D}/site/fakepkg/unchecked/pack.zip")]
got, why = install.fetch_data({**d, "into": "unchecked2", "check": ["no-such-checker"]})
out["check_missing"] = [bool(got), why]
# A pinned artefact that is required and failed stops the image; an optional one is recorded.
held, left = {}, {"data": [], "download": []}
out["settle_required"] = [install.settle_artefact("data", {"name": "x", "required": True}, None, "download failed", held, left), left["data"]]
out["settle_optional"] = [install.settle_artefact("download", {"name": "y", "pack": "p"}, None, "download failed", held, left), [e["name"] for e in left["download"]]]
out["settle_held"] = [install.settle_artefact("data", {"name": "z", "required": True}, {"kind": "data"}, None, held, left), sorted(held)]
src = {"name": "tool", "version": "1", "url": f"file://{D}/tool-1.0.tar.gz", "sha256": tool_sha, "bin": "bin/tool",
       "patches": [{"url": f"file://{D}/fix.patch", "sha256": patch_sha}],
       "commands": [["make", "-j{jobs}"], ["mkdir", "-p", "{prefix}/bin"], ["cp", "tool", "{prefix}/bin/tool"]]}
spec = f"{D}/build.json"
open(spec, "w").write(json.dumps(src))
out["build_rc"] = install.build_source(spec)
rec = json.loads(open(f"{D}/tools/tool/.dfirswarm-build.json").read())
out["build_rec"] = [rec["ok"], [p["sha256"] for p in rec.get("patches", [])] == [patch_sha]]
out["patched_runs"] = os.system(f"{D}/tools/tool/bin/tool") >> 8
# The same source without the patch is the one that exits 1: the patch was applied.
open(spec, "w").write(json.dumps({**src, "name": "tool-unpatched", "patches": []}))
install.build_source(spec)
out["unpatched_runs"] = os.system(f"{D}/tools/tool-unpatched/bin/tool") >> 8
open(spec, "w").write(json.dumps({**src, "name": "tool-badsha", "patches": [{"url": f"file://{D}/fix.patch", "sha256": "0" * 64}]}))
install.build_source(spec)
out["badsha_rec"] = json.loads(open(f"{D}/tools/tool-badsha/.dfirswarm-build.json").read())
open(spec, "w").write(json.dumps({**src, "name": "tool-noapply", "patches": [{"url": f"file://{D}/bad.patch", "sha256": bad_patch_sha}]}))
install.build_source(spec)
out["noapply_rec"] = json.loads(open(f"{D}/tools/tool-noapply/.dfirswarm-build.json").read())
open(spec, "w").write(json.dumps({**src, "name": "tool-failstep", "patches": [], "commands": [["make"], ["false"]]}))
out["failstep_rc"] = install.build_source(spec)
out["failstep_rec"] = json.loads(open(f"{D}/tools/tool-failstep/.dfirswarm-build.json").read())
print(json.dumps(out))
EOF
)" || fail "install.py could not be driven over data and patched builds: $res"
res="$(tail -1 <<<"$res")"
[[ "$(jq -r '.good[0]' <<<"$res")" == true ]] && [[ "$(jq -r '.good[2]' <<<"$res")" -ef "$D/site/fakepkg/tables/pack.zip" ]] \
  || fail "a data file whose sha256 matches was not put inside its program's package: $res"
cmp -s "$D/pack.zip" "$D/site/fakepkg/tables/pack.zip" || fail "the data file in the package is not the pinned bytes"
jq -e '.good[3] == "data" and .good[4] == 30' <<<"$res" >/dev/null || fail "the data record does not say its kind and size: $res"
[[ "$(cat "$D/warm.out")" == "once twice" ]] && jq -e '.warm == [true, "done"]' <<<"$res" >/dev/null || fail "the warm command was not run once the data was in place: $res"
jq -e '.warm_fails == [true, "failed"]' <<<"$res" >/dev/null || fail "a warm command that fails must be recorded and must not lose the data: $res"
jq -e '.bad_sha[0] == false and (.bad_sha[1] | test("is not the pinned")) and .bad_sha[2] == false' <<<"$res" >/dev/null || fail "data with other bytes was kept: $res"
jq -e '.no_package[0] == false and (.no_package[1] | test("is not in the image"))' <<<"$res" >/dev/null || fail "data for a package the image lacks was put somewhere: $res"
jq -e '.escape[0] == false and (.escape[1] | test("leaves the package")) and .escape[2] == false' <<<"$res" >/dev/null || fail "data was put outside its package's directory: $res"
jq -e '.named == [true, "named.zip"]' <<<"$res" >/dev/null || fail "a data file does not take the name its pack gives it: $res"
jq -e '.bad_names | length == 4 and all(.[]; .[0] == false and (.[1] | test("not a plain name")))' <<<"$res" >/dev/null || fail "a data file name that climbs out of the directory, or names a path, was accepted: $res"
jq -e '.escaped_file_exists == false' <<<"$res" >/dev/null || fail "a data file was written outside its directory by its name"
jq -e '.check_ok == [true, ["true"]]' <<<"$res" >/dev/null || fail "a check that succeeds is not recorded with the data: $res"
jq -e '.check_fails[0] == false and (.check_fails[1] | test("check .* failed once the file was in place")) and .check_fails[2] == false' <<<"$res" >/dev/null || fail "data whose check fails was kept or not refused: $res"
jq -e '.check_missing[0] == false and (.check_missing[1] | test("check"))' <<<"$res" >/dev/null || fail "a check whose program is not there passed: $res"
jq -e '.settle_required == [false, []] and .settle_optional == [true, ["y"]] and .settle_held == [true, ["z"]]' <<<"$res" >/dev/null \
  || fail "a required artefact that failed does not stop the image, or an optional one is not recorded: $res"
jq -e '.build_rc == 0 and .build_rec == [true, true] and .patched_runs == 0 and .unpatched_runs == 1' <<<"$res" >/dev/null \
  || fail "a source with a pinned patch and its own steps was not built patched, or the record does not name the patch: $res"
jq -e '.badsha_rec.ok == false and (.badsha_rec.why | test("patch fix.patch: sha256 .* is not the pinned"))' <<<"$res" >/dev/null || fail "a patch with other bytes was applied: $res"
jq -e '.noapply_rec.ok == false and (.noapply_rec.why | test("patch bad.patch did not apply"))' <<<"$res" >/dev/null || fail "a patch that does not apply was not recorded as the reason: $res"
jq -e '.failstep_rc == 1 and .failstep_rec.ok == false and (.failstep_rec.why == "false failed")' <<<"$res" >/dev/null || fail "a failed step of a source's own commands is not the recorded reason, or did not fail its stage: $res"
pass "install.py puts pinned data inside its program's package only when its bytes are the pinned ones, runs the warm command, records a warm that fails, and builds a source from pinned patches and its own steps"

# --- what an image records ------------------------------------------------------
# The base records what a profile does: the venv as `pip list` names it (a VM's
# inventory at stop is diffed against it, so the base's own packages are not
# "installed outside the image"), the whole Debian list, a NOTICE with the npm
# and Python licences, an SBOM, and whether it may be redistributed. A profile
# built on it keeps the base's flag. A fake venv and npm stand in here.
mkdir -p "$TMP/rec/venv/bin" "$TMP/rec/fakebin" "$TMP/rec/npm/@earendil-works/pi-coding-agent/node_modules/left-pad" "$TMP/rec/npm/@earendil-works/pi-coding-agent/dist"
printf '#!/bin/sh\necho %s\n' "'[{\"name\": \"dissect.util\", \"version\": \"3.20\"}, {\"name\": \"pip\", \"version\": \"23.0.1\"}]'" > "$TMP/rec/venv/bin/pip"
printf '#!/bin/sh\necho %s\n' "'[[\"dissect.util\", \"3.20\", \"Apache-2.0\"], [\"pip\", \"23.0.1\", \"MIT\"]]'" > "$TMP/rec/venv/bin/python"
printf '#!/bin/sh\necho %s\n' "$TMP/rec/npm" > "$TMP/rec/fakebin/npm"
chmod +x "$TMP/rec/venv/bin/pip" "$TMP/rec/venv/bin/python" "$TMP/rec/fakebin/npm"
printf '{"name": "@earendil-works/pi-coding-agent", "version": "0.87.0", "license": "MIT"}\n' > "$TMP/rec/npm/@earendil-works/pi-coding-agent/package.json"
printf '{"name": "left-pad", "version": "1.3.0", "license": "WTFPL"}\n' > "$TMP/rec/npm/@earendil-works/pi-coding-agent/node_modules/left-pad/package.json"
printf '{"type": "module"}\n' > "$TMP/rec/npm/@earendil-works/pi-coding-agent/dist/package.json"
( export PATH="$TMP/rec/fakebin:$PATH" DFIRSWARM_VENV="$TMP/rec/venv" DFIRSWARM_ETC_DIR="$TMP/rec/etc" \
         NONREDISTRIBUTABLE="debian-gpl-packages" REDISTRIBUTABLE=false
  python3 "$ROOT/images/install.py" --base >/dev/null ) || fail "install.py --base failed"
rec="$TMP/rec/etc/image.json"
jq -e '.profile == "base" and (.dpkg_all | type == "object") and .pip == {"dissect.util": "3.20", "pip": "23.0.1"}' "$rec" >/dev/null \
  || fail "the base does not record its whole Debian list and its venv as pip lists it: $(cat "$rec")"
jq -e '.redistributable == false and .nonredistributable == ["debian-gpl-packages"] and .pi == "0.87.0"' "$rec" >/dev/null \
  || fail "the base does not say it is not for redistribution, or which Pi it holds: $(cat "$rec")"
# Every program on the image's PATH, the venv's first, by where it is: what
# the job service matches a job's programs against.
jq -e '(.on_path[0] | endswith("/rec/venv/bin/pip")) and (.on_path | all(startswith("/")))' "$rec" >/dev/null \
  || fail "the base does not record every program on its PATH, the venv's first: $(jq -c '.on_path[:5]' "$rec")"
grep -q '^Not cleared for redistribution: debian-gpl-packages' "$TMP/rec/etc/NOTICE" || fail "the base NOTICE does not say what holds it back"
grep -q '^dissect.util 3.20  Apache-2.0' "$TMP/rec/etc/NOTICE" || fail "the base NOTICE does not give the Python licences"
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
                                {"tool": {"version": "1.0", "url": "https://example.org/tool.tar.gz", "sha256": sys.argv[2]},
                                 "tool-tables": {"kind": "data", "version": "2019", "url": "https://example.org/tables.zip", "sha256": sys.argv[2]}},
                                {"apt": [], "pip": [], "download": []})
install.write_record(record, "dfirswarm-web")
EOF
) || fail "a profile record could not be written over the base's"
jq -e '.profile == "web" and .redistributable == false and .nonredistributable == ["debian-gpl-packages"] and .pip["dissect.util"] == "3.20"' "$rec" >/dev/null \
  || fail "a profile over a base not for redistribution claimed it was, or lost the venv: $(cat "$rec")"
jq -e --arg sha "$sha" '[.components[] | select(.name == "tool") | .hashes[0].content == $sha and (.purl | startswith("pkg:generic/tool@1.0?"))] == [true]' \
  "$TMP/rec/etc/sbom.json" >/dev/null || fail "a pinned download is not in the SBOM with its sha256"
jq -e '[.components[] | select(.name == "tool-tables") | .type == "data" and .properties[0].value == "data" and .externalReferences[0].type == "distribution"] == [true]' \
  "$TMP/rec/etc/sbom.json" >/dev/null || fail "pinned data is not in the SBOM as data, with its sha256 and where it was fetched from"
grep -q '^Not cleared for redistribution: debian-gpl-packages. It carries pinned data (tool-tables): no workflow of this project pushes such an image to any registry, the private one included' "$TMP/rec/etc/NOTICE" \
  || fail "the NOTICE of an image that carries pinned data does not say no workflow of ours pushes it: $(sed -n '/Not cleared/p' "$TMP/rec/etc/NOTICE")"
pass "every image records its Debian list and venv for the inventory diff, a NOTICE, a CycloneDX SBOM, and the base's redistribution flag carries into a profile"

# tools.md: what an agent reads to learn what its VM holds. The base lists the
# tool library's Python packages with the note on each line; a profile adds its
# packs' programs, one a line, with what each is for, its pack and the version
# the package records hold, and says what a pack names that is not there.
tm="$TMP/rec/etc/tools.md"
[[ -f "$tm" ]] || fail "an image wrote no tools.md"
grep -q '^- `dissect.util` 3.20 — Apache-2.0 (from 3.5; AGPL-3.0 before), Fox-IT. lzxpress_huffman' "$tm" || fail "tools.md does not list the base's libraries with version and note: $(cat "$tm")"
( export PATH="$TMP/rec/fakebin:$PATH" DFIRSWARM_VENV="$TMP/rec/venv" DFIRSWARM_ETC_DIR="$TMP/rec/etc"
  python3 - "$ROOT/images" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
import install
record = json.loads(install.RECORD.read_text())
record.update({"profile": "disk", "packs": ["p1"], "apt": {"sleuthkit": "4.11.1"},
               "binaries": {"mmls": "/usr/bin/mmls", "evtxecmd": "/usr/local/bin/evtxecmd", "gpg": None},
               "downloads": {"vol-tables": {"kind": "data", "version": "2019", "url": "https://example.org/t.zip", "sha256": "ab" * 32,
                                            "path": "/opt/dfir/venv/lib/python3.11/site-packages/volatility3/symbols/t.zip", "bytes": 5}},
               "not_installed": {"data": [{"name": "other-tables", "pack": "p3", "why": "download failed: 404"}]}})
spec = {"binaries": [
    {"name": "mmls", "pack": "p1", "why": "Partition table of a disk image.", "apt": ["sleuthkit"], "source": "apt-get install -y sleuthkit"},
    {"name": "mmls", "pack": "p2", "why": "Named twice.", "apt": ["sleuthkit"]},
    {"name": "evtxecmd", "pack": "p1", "why": "Event logs.", "source": "download 2026.5.0"},
    {"name": "gpg", "pack": "p1", "why": "OpenPGP.", "apt": ["gnupg"], "source": "apt-get install -y gnupg"}],
  "python_notes": [{"requirement": "pyAesCrypt>=6", "pack": "p1", "note": "AES Crypt containers."}],
  "data": [{"name": "vol-tables", "program": "vol", "pack": "p1", "why": "Symbol tables for vol."},
           {"name": "other-tables", "program": "vol", "pack": "p3", "why": "More tables."}],
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
grep -q '^## Data the programs read$' "$tm" && grep -q '^- `vol-tables` — Symbol tables for vol. (p1; for `vol`; at /opt/dfir/venv/lib/python3.11/site-packages/volatility3/symbols/t.zip)$' "$tm" \
  || fail "a pinned data file is not listed with what it is for and where it is: $(cat "$tm")"
grep -q '^- `other-tables` (p3) — data not installed: download failed: 404$' "$tm" || fail "a data file the build could not fetch is not said to be missing: $(cat "$tm")"
grep -q '`other-tables` — More tables' "$tm" && fail "a data file that is not in the image is listed as held"
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
# Data pins its size too: a download stops past it.
ud='"url": "https://example.org/t.tar.gz", "sha256": "'"$sha"'", "bytes": 9'
for good in '{'"$e"', "install": {"source": {"version": "1", '"$u"', "entry": "bin/t.py", "run": "python", "pip": ["-r", "requirements.txt"], "skip": ["tests"]}}}' \
            '{'"$e"', "install": {"build": {"version": "1", '"$u"', "bin": "bin/t", "configure": ["--disable-x"], "build_deps": ["gcc"], "apt_deps": ["zlib1g"], "env": {"CFLAGS": "-O2"}}}}' \
            '{'"$e"', "install": {"download": {"version": "1", "arm64": {"url": "https://example.org/t_1_arm64.deb", "sha256": "'"$sha"'", "bin": "/opt/t/bin/t"}}}}' \
            '{'"$e"', "install": {"apt": "x", "build": {"version": "1", '"$u"', "bin": "bin/t", "patches": [{'"$u"'}], "commands": [["make"], ["install", "-D", "t", "{prefix}/bin/t"]]}}}' \
            '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$ud"', "package": "volatility3", "into": "symbols", "warm": ["vol", "-q", "isfinfo"], "why": "Tables.", "licence": "Terms.", "check": ["true"], "redistributable": false}}}' \
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
           '{'"$e"', "install": {"build": {"version": "1", '"$u"', "bin": "bin/t", "patches": [{"url": "https://example.org/p.patch"}]}}}' \
           '{'"$e"', "install": {"build": {"version": "1", '"$u"', "bin": "bin/t", "patches": [{"url": "http://example.org/p.patch", "sha256": "'"$sha"'"}]}}}' \
           '{'"$e"', "install": {"build": {"version": "1", '"$u"', "bin": "bin/t", "patches": "p.patch"}}}' \
           '{'"$e"', "install": {"build": {"version": "1", '"$u"', "bin": "bin/t", "commands": ["make"]}}}' \
           '{'"$e"', "install": {"build": {"version": "1", '"$u"', "bin": "bin/t", "commands": [[]]}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {'"$ud"', "package": "p", "why": "Tables.", "licence": "Terms.", "check": ["true"], "redistributable": false}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", "url": "http://example.org/t.zip", "sha256": "'"$sha"'", "bytes": 9, "package": "p", "why": "Tables.", "licence": "Terms.", "check": ["true"], "redistributable": false}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", "url": "https://example.org/t.zip", "sha256": "abc", "bytes": 9, "package": "p", "why": "Tables.", "licence": "Terms.", "check": ["true"], "redistributable": false}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$ud"', "why": "Tables.", "licence": "Terms.", "check": ["true"], "redistributable": false}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$ud"', "package": "p", "why": "Tables.", "check": ["true"], "redistributable": false}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$ud"', "package": "p", "licence": "Terms.", "check": ["true"], "redistributable": false}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$ud"', "package": "p", "into": "../x", "why": "Tables.", "licence": "Terms.", "check": ["true"], "redistributable": false}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$ud"', "package": "p", "into": "/etc", "why": "Tables.", "licence": "Terms.", "check": ["true"], "redistributable": false}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$ud"', "package": "p", "warm": "vol isfinfo", "why": "Tables.", "licence": "Terms.", "check": ["true"], "redistributable": false}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$ud"', "package": "p", "why": "Tables.", "licence": "Terms.", "redistributable": false}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$ud"', "package": "p", "why": "Tables.", "licence": "Terms.", "check": "true", "redistributable": false}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$ud"', "package": "p", "why": "Tables.", "licence": "Terms.", "check": [], "redistributable": false}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$ud"', "package": "p", "why": "Tables.", "licence": "Terms.", "check": ["true"]}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$ud"', "package": "p", "why": "Tables.", "licence": "Terms.", "check": ["true"], "redistributable": "no"}}}' \
           '{'"$e"', "install": {"apt": "x", "data": {"version": "1", '"$u"', "package": "p", "why": "Tables.", "licence": "Terms.", "check": ["true"], "redistributable": false}}}' \
           '{"name": "tool", "why": "Test.", "licence": "MIT", "redistributable": true, "not_in_image": "Only macOS has it."}' \
           '{'"$e"', "not_in_image": ""}'; do
  mk_entry "$TMP/p/bad-kind" "$bad"
  bash "$ROOT/scripts/pack.sh" seal "$TMP/p/bad-kind" >/dev/null 2>&1 && fail "an entry that cannot be checked, or another system's program required of an image, was sealed: $bad"
done
pass "a pinned source needs its entry, a build its program inside its prefix and pinned patches and argument lists, data its package, licence and a path inside it, a .deb the path it installs, and another system's program is never required"

# --- the tool library's imports are in every image ----------------------------
# Read from each script's syntax tree, not its lines: an import inside a
# function or a try counts, and so does one by name (importlib.import_module,
# __import__), which a line pattern never saw. A module only some images
# carry is declared in the tool's manifest (optional_python) and imported
# under a try that catches ImportError, so the tool says it is missing in the
# images without it; a module imported by a computed name is refused, since
# nothing could say what it needs.
check_library_imports() { # <root>
  python3 - "$1" <<'EOF'
import ast, json, re, sys, pathlib
root = pathlib.Path(sys.argv[1])
# A module a tool imports -> the package that provides it.
provides = {"cryptography": "cryptography", "regipy": "regipy", "Evtx": "python-evtx", "dissect": "dissect.util"}
listed = {re.split(r"[<>=!~ ]", l.split("#")[0].strip())[0].lower() for l in (root / "images" / "library-python.txt").read_text().splitlines() if l.split("#")[0].strip()}
stdlib = set(sys.stdlib_module_names) | {"__future__"}
catch = {"ImportError", "ModuleNotFoundError"}

def catches_import(t):
    for h in t.handlers:
        kinds = h.type.elts if isinstance(h.type, ast.Tuple) else [h.type] if h.type is not None else []
        if any(isinstance(k, ast.Name) and k.id in catch for k in kinds):
            return True
    return False

def imports(node, guarded=False):
    # Each import with its line and whether a try that catches ImportError holds it.
    if isinstance(node, ast.Try):
        inner = guarded or catches_import(node)
        for n in node.body:
            yield from imports(n, inner)
        for part in (node.handlers, node.orelse, node.finalbody):
            for n in part:
                yield from imports(n, guarded)
        return
    if isinstance(node, ast.Import):
        for a in node.names:
            yield a.name.split(".")[0], node.lineno, guarded
    elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
        yield node.module.split(".")[0], node.lineno, guarded
    elif isinstance(node, ast.Call):
        f = node.func
        fn = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
        if fn in ("import_module", "__import__"):
            arg = node.args[0] if node.args else None
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                yield arg.value.split(".")[0], node.lineno, guarded
            else:
                yield None, node.lineno, guarded
    for child in ast.iter_child_nodes(node):
        yield from imports(child, guarded)

out = set()
for f in sorted(root.glob("tool-library/*/*.py")):
    tool = f.parent.name
    mf = f.parent / "manifest.json"
    optional = json.loads(mf.read_text()).get("optional_python") if mf.exists() else None
    if optional is not None and not (isinstance(optional, list) and all(isinstance(m, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", m) for m in optional)):
        out.add(f"{tool}: optional_python is a list of top-level module names")
        optional = []
    optional = set(optional or [])
    seen = set()
    for mod, line, guarded in imports(ast.parse(f.read_text(), str(f))):
        if mod is None:
            out.add(f"{tool} (line {line}): a module imported by a computed name, which this check cannot read; import it by name")
            continue
        if mod in stdlib:
            continue
        seen.add(mod)
        if mod in optional:
            if not guarded:
                out.add(f"{tool} (line {line}): {mod} is declared optional and imported outside a try that catches ImportError")
            continue
        pkg = provides.get(mod)
        if pkg is None:
            out.add(f"{mod} (in {tool}: say which package provides it, or declare it in optional_python)")
        elif pkg.lower() not in listed:
            out.add(f"{pkg} (imported by {tool})")
    for mod in sorted(optional - seen):
        out.add(f"{tool}: optional_python names {mod}, which it never imports")
print("\n".join(sorted(out)))
EOF
}
missing_lib="$(check_library_imports "$ROOT")"
[[ -z "$missing_lib" ]] || fail "the tool library imports what no image installs: $missing_lib"
grep -q 'COPY library-python.txt' "$ROOT/images/base.Dockerfile" || fail "the base image does not install the tool library's imports"
pass "every third-party module the tool library imports is in images/library-python.txt, which the base image installs, or declared optional and imported under a guard"

# The check itself: a library with one tool per way of getting it wrong.
lib="$TMP/libcheck"
mkdir -p "$lib/images"
cp "$ROOT/images/library-python.txt" "$lib/images/"
mk_libtool() { # <name> <optional_python JSON or ""> <script>
  mkdir -p "$lib/tool-library/$1"
  if [[ -n "$2" ]]; then printf '{"name": "%s", "optional_python": %s}\n' "$1" "$2" > "$lib/tool-library/$1/manifest.json"
  else printf '{"name": "%s"}\n' "$1" > "$lib/tool-library/$1/manifest.json"; fi
  printf '%s\n' "$3" > "$lib/tool-library/$1/run.py"
}
mk_libtool guarded '["PIL"]' $'import json\ndef load():\n    try:\n        from PIL import Image\n    except ImportError:\n        return None\n    return Image'
[[ -z "$(check_library_imports "$lib")" ]] || fail "a declared optional module under a guard was refused: $(check_library_imports "$lib")"
mk_libtool by_name '' $'import importlib\ntry:\n    importlib.import_module("pytsk3")\nexcept ImportError:\n    pass'
mk_libtool computed '' $'import importlib\nname = "pyewf"\nimportlib.import_module(name)'
mk_libtool unguarded '["pyewf"]' $'import pyewf'
mk_libtool broad '["pyewf"]' $'try:\n    import pyewf\nexcept ValueError:\n    pass'
mk_libtool stale '["numpy"]' $'import json'
got="$(check_library_imports "$lib")"
grep -q '^pytsk3 (in by_name: ' <<<"$got" || fail "a module imported by name and not declared was not seen: $got"
grep -q '^computed (line 3): a module imported by a computed name' <<<"$got" || fail "an import by a computed name was not refused: $got"
grep -q '^unguarded (line 1): pyewf is declared optional and imported outside a try' <<<"$got" || fail "a declared optional module imported unguarded was not refused: $got"
grep -q '^broad (line 2): pyewf is declared optional and imported outside a try' <<<"$got" || fail "a try that does not catch ImportError was taken for a guard: $got"
grep -q '^stale: optional_python names numpy, which it never imports' <<<"$got" || fail "a declaration nothing imports was not named: $got"
grep -q '^guarded' <<<"$got" && fail "the guarded tool was refused beside the others: $got"
pass "the library check sees imports by name, refuses a computed one, and holds a declared optional module to a guard that catches ImportError"

echo "recipe: all checks passed"
