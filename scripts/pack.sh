#!/usr/bin/env bash
# Packs: install, inspect, verify and remove. A pack carries skills, tools, host
# requirements and goal templates; see docs/packs.md for the format.
#
#   pack.sh install <dir|zip> [--yes] [--no-secrets]
#   pack.sh list
#   pack.sh show <id>
#   pack.sh verify <id>
#   pack.sh remove <id> [--yes]
#   pack.sh seal <dir>          author-side: write checksums into pack.json
#   pack.sh path <id>           print where a pack is installed
#   pack.sh resolve <id>[,<id>] print every pack dir, dependencies first
#   pack.sh adopt <tool dir> <pack dir> [--replace]
#                               author-side: take a saved tool into a pack
set -euo pipefail

HOME_DIR="${DFIRSWARM_HOME:-$HOME/.dfirswarm}"
PACKS="$HOME_DIR/packs"
# A pack's secrets live beside the packs, never inside one: a pack directory
# is mounted read-only into every agent's VM, and `verify` checks it against
# its own checksums, which a file the operator wrote would fail.
SECRETS="$HOME_DIR/secrets"
secrets_file() { printf '%s/%s.env\n' "$SECRETS" "$1"; }
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"

die() { echo "BLOCKER: $*" >&2; exit 1; }
note() { echo "$*" >&2; }

# The validator is shared by install, verify and seal so a pack cannot pass one
# and fail another.
validate_py() { cat <<'PYEOF'
import json, os, re, sys, hashlib

root = sys.argv[1]
mode = sys.argv[2]            # "seal" skips the checksum comparison
errors, warnings = [], []

def p(*a): return os.path.join(root, *a)

if not os.path.isfile(p("pack.json")):
    print("no pack.json at the top of the pack"); sys.exit(2)
try:
    man = json.load(open(p("pack.json")))
except Exception as e:
    print("pack.json is not valid JSON: %s" % e); sys.exit(2)

for key in ("id", "name", "version", "description", "licence"):
    if not man.get(key):
        errors.append("pack.json is missing %s" % key)
pid = man.get("id", "")
if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", pid or ""):
    errors.append("id must be lower case letters, digits and dashes: %r" % pid)
if not re.fullmatch(r"\d+\.\d+\.\d+", man.get("version", "")):
    errors.append("version must be MAJOR.MINOR.PATCH")

ALLOWED_TOP = {"pack.json", "README.md", "LICENCE", "LICENSE", "NOTICE",
               "skills", "tools", "vendor", "requires", "goals", "tests", "recipes"}
for name in sorted(os.listdir(root)):
    if name.startswith("."):
        continue
    if name not in ALLOWED_TOP:
        errors.append("%s is not part of the pack layout" % name)

# --- skills -----------------------------------------------------------------
FM = re.compile(r"\A---\n(.*?)\n---\n", re.S)
skills, skill_tools, skill_needs, skill_host = {}, set(), set(), set()
sdir = p("skills")
if os.path.isdir(sdir):
    for dirpath, _dirs, files in os.walk(sdir):
        for f in sorted(files):
            if not f.endswith(".md") or f == "INDEX.md":
                continue
            full = os.path.join(dirpath, f)
            rel = os.path.relpath(full, sdir)
            text = open(full, encoding="utf-8").read()
            m = FM.match(text)
            if not m:
                errors.append("skills/%s has no front matter" % rel); continue
            meta = {}
            for line in m.group(1).splitlines():
                if not line.strip() or line.startswith("#"):
                    continue
                if ":" not in line:
                    errors.append("skills/%s: front matter line is not key: value -> %r" % (rel, line)); continue
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if v.startswith("[") and v.endswith("]"):
                    meta[k] = [x.strip() for x in v[1:-1].split(",") if x.strip()]
                else:
                    meta[k] = v
            for req in ("id", "title", "when"):
                if not meta.get(req):
                    errors.append("skills/%s: front matter needs %s" % (rel, req))
            sid = meta.get("id", "")
            expect = rel[:-3].replace(os.sep, "/")
            if sid and sid != expect:
                errors.append("skills/%s: id is %r but its path says %r" % (rel, sid, expect))
            if sid in skills:
                errors.append("two skills claim the id %r" % sid)
            body = text[m.end():].strip()
            if not body:
                errors.append("skills/%s has no body" % rel)
            skills[sid] = meta
            skill_tools.update(meta.get("tools", []) or [])
            skill_needs.update(meta.get("needs", []) or [])
            skill_host.update(meta.get("requires_host", []) or [])

# --- tools ------------------------------------------------------------------
tools = {}
tdir = p("tools")
if os.path.isdir(tdir):
    for name in sorted(os.listdir(tdir)):
        d = os.path.join(tdir, name)
        if not os.path.isdir(d):
            continue
        mf = os.path.join(d, "manifest.json")
        if not os.path.isfile(mf):
            errors.append("tools/%s has no manifest.json" % name); continue
        try:
            tm = json.load(open(mf))
        except Exception as e:
            errors.append("tools/%s/manifest.json is not valid JSON: %s" % (name, e)); continue
        for key in ("name", "description", "params", "runtime", "entry"):
            if key not in tm:
                errors.append("tools/%s/manifest.json is missing %s" % (name, key))
        if tm.get("name") != name:
            errors.append("tools/%s declares the name %r" % (name, tm.get("name")))
        entry = tm.get("entry", "")
        if entry and not os.path.isfile(os.path.join(d, entry)):
            errors.append("tools/%s: entry %s is missing" % (name, entry))
        if not tm.get("description", "").strip():
            errors.append("tools/%s has an empty description" % name)
        tools[name] = tm

# --- recipes ----------------------------------------------------------------
# A recipe is a catalogue procedure the harness runs for the pack: it says
# whether it applies to an object (`entry detect`) and catalogues it into a
# directory (`entry run`), with its coverage. Its id in a run is <pack>/<name>,
# so two packs cannot both answer to one recipe.
RECIPE_AUTO = {"kickoff", "derived"}
recipes = {}
rdir = p("recipes")
if os.path.isdir(rdir):
    for name in sorted(os.listdir(rdir)):
        d = os.path.join(rdir, name)
        if not os.path.isdir(d):
            continue
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", name):
            errors.append("recipes/%s: a recipe's name is lower case letters, digits and dashes" % name); continue
        rf = os.path.join(d, "recipe.json")
        if not os.path.isfile(rf):
            errors.append("recipes/%s has no recipe.json" % name); continue
        try:
            rm = json.load(open(rf))
        except Exception as e:
            errors.append("recipes/%s/recipe.json is not valid JSON: %s" % (name, e)); continue
        for key in ("id", "version", "description", "runtime", "entry", "auto", "limits", "outputs", "covers"):
            if key not in rm:
                errors.append("recipes/%s/recipe.json is missing %s" % (name, key))
        if rm.get("id") != name:
            errors.append("recipes/%s declares the id %r" % (name, rm.get("id")))
        if not re.fullmatch(r"\d+\.\d+\.\d+", str(rm.get("version", ""))):
            errors.append("recipes/%s: version must be MAJOR.MINOR.PATCH" % name)
        if rm.get("runtime") not in ("python3", "bash"):
            errors.append("recipes/%s: runtime must be python3 or bash" % name)
        entry = str(rm.get("entry", ""))
        real = os.path.realpath(os.path.join(d, entry)) if entry else ""
        if not entry or os.path.isabs(entry) or not real.startswith(os.path.realpath(d) + os.sep):
            errors.append("recipes/%s: entry %r must be a file inside the recipe's directory" % (name, entry))
        elif not os.path.isfile(real) or os.path.islink(os.path.join(d, entry)):
            errors.append("recipes/%s: entry %s is missing or a link" % (name, entry))
        auto = rm.get("auto")
        if not isinstance(auto, list) or any(a not in RECIPE_AUTO for a in auto):
            errors.append("recipes/%s: auto is a list of %s (or empty)" % (name, ", ".join(sorted(RECIPE_AUTO))))
        lim = rm.get("limits")
        if not isinstance(lim, dict) or not isinstance(lim.get("seconds"), int) or not 1 <= lim.get("seconds") <= 14400:
            errors.append("recipes/%s: limits.seconds is a whole number from 1 to 14400" % name)
        if not isinstance(rm.get("outputs"), list) or not rm.get("outputs"):
            errors.append("recipes/%s: outputs names what the recipe writes" % name)
        if "order" in rm and not isinstance(rm.get("order"), int):
            errors.append("recipes/%s: order is a whole number (recipes run in order, then by name)" % name)
        if "object" in rm and not str(rm.get("object", "")).strip():
            errors.append("recipes/%s: object names what the recipe catalogues (\"disk image\")" % name)
        if not str(rm.get("description", "")).strip() or not str(rm.get("covers", "")).strip():
            errors.append("recipes/%s: description and covers say what it does and what it does not cover" % name)
        recipes[name] = rm

# What the dependencies carry, from the packs beside this one: the installed
# set when an installed pack is verified, the checkout's packs/ when one is
# sealed there. A name a dependency carries is no warning; one no pack in
# the set carries is, and one whose dependency is not there says so.
def _dep_names(pack_dir, seen, acc):
    try:
        dm = json.load(open(os.path.join(pack_dir, "pack.json")))
    except Exception:
        acc["missing"].add(os.path.basename(pack_dir))
        return
    tdir = os.path.join(pack_dir, "tools")
    if os.path.isdir(tdir):
        acc["tools"].update(n for n in os.listdir(tdir) if os.path.isdir(os.path.join(tdir, n)))
    for dirpath, _d, files in os.walk(os.path.join(pack_dir, "skills")):
        for f in files:
            if f.endswith(".md"):
                m = FM.match(open(os.path.join(dirpath, f), encoding="utf-8", errors="replace").read())
                if m:
                    sid = re.search(r"^id:\s*(\S+)", m.group(1), re.M)
                    if sid:
                        acc["skills"].add(sid.group(1).strip("'\""))
    try:
        for b in json.load(open(os.path.join(pack_dir, "requires", "host.json"))).get("binaries", []):
            acc["host"].add(b.get("name"))
    except Exception:
        pass
    for spec in dm.get("depends", []) or []:
        did = re.split(r"[<>=!~ ]", str(spec), maxsplit=1)[0]
        if did and did not in seen:
            seen.add(did)
            _dep_names(os.path.join(os.path.dirname(pack_dir), did), seen, acc)

deps = {"tools": set(), "skills": set(), "host": set(), "missing": set()}
_seen = {pid}
for spec in man.get("depends", []) or []:
    did = re.split(r"[<>=!~ ]", str(spec), maxsplit=1)[0]
    if did and did not in _seen:
        _seen.add(did)
        _dep_names(os.path.join(os.path.dirname(os.path.abspath(root)), did), _seen, deps)
_where = ("this pack does not carry (a dependency must: %s is not beside it)" % ", ".join(sorted(deps["missing"]))
          if deps["missing"] else
          ("neither this pack nor its dependencies carry" if man.get("depends") else "this pack does not carry"))

for t in sorted(skill_tools):
    if t not in tools and t not in deps["tools"]:
        warnings.append("a skill names the tool %r, which %s" % (t, _where))
for n in sorted(skill_needs):
    if n not in skills and n not in deps["skills"]:
        warnings.append("a skill needs %r, which %s" % (n, _where))

# --- host requirements ------------------------------------------------------
host_names = set()
hj = p("requires", "host.json")
if os.path.isfile(hj):
    try:
        hosts = json.load(open(hj))
        for b in hosts.get("binaries", []):
            for key in ("name", "why", "licence"):
                if not b.get(key):
                    errors.append("requires/host.json: a binary entry is missing %s" % key)
            if "redistributable" not in b:
                errors.append("requires/host.json: %s does not say whether it is redistributable" % b.get("name"))
            # A pinned artefact is fetched and run inside an image: its URL
            # is HTTPS, its sha256 whole, its program a path inside it (or,
            # for a .deb, where the package puts it).
            def pinned(where, e, bin_key):
                if not isinstance(e, dict) or not str(e.get("url", "")).startswith("https://"):
                    errors.append("%s needs an https url" % where)
                    return
                if not re.fullmatch(r"(sha256:)?[0-9a-f]{64}", str(e.get("sha256", ""))):
                    errors.append("%s needs the sha256 of what the url serves" % where)
                deb = str(e["url"]).split("?")[0].lower().endswith(".deb")
                if bin_key in e:
                    path = str(e[bin_key])
                    if deb and not (path.startswith("/") and ".." not in path.split("/")):
                        errors.append("%s: %s must be the absolute path the package installs" % (where, bin_key))
                    elif not deb and (path.startswith("/") or ".." in path.split("/")):
                        errors.append("%s: %s must be a path inside the download" % (where, bin_key))
            install = b.get("install") or {}
            dl = install.get("download")
            if dl is not None:
                where = "requires/host.json: %s's download" % b.get("name")
                if not isinstance(dl, dict) or not dl.get("version"):
                    errors.append("%s needs a version" % where)
                else:
                    arches = [a for a in ("amd64", "arm64") if a in dl]
                    if not arches:
                        errors.append("%s names no architecture (amd64, arm64)" % where)
                    for a in arches:
                        pinned("%s for %s" % (where, a), dl[a], "bin")
            for kind, bin_key in (("source", "entry"), ("build", "bin")):
                src = install.get(kind)
                if src is None:
                    continue
                where = "requires/host.json: %s's %s" % (b.get("name"), kind)
                if not isinstance(src, dict) or not src.get("version"):
                    errors.append("%s needs a version" % where)
                    continue
                if not src.get(bin_key):
                    errors.append("%s needs %s: the program's path inside it" % (where, bin_key))
                pinned(where, src, bin_key)
                for key in ("pip", "skip", "configure", "apt_deps", "build_deps", "arches"):
                    if key in src and not (isinstance(src[key], list) and all(isinstance(x, str) for x in src[key])):
                        errors.append("%s: %s must be a list of strings" % (where, key))
                if "env" in src and not (isinstance(src["env"], dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in src["env"].items())):
                    errors.append("%s: env must map names to strings" % where)
            # Another system's program (Apple's log, a Windows collector): no
            # image holds it, so no pack may require it of one.
            if "not_in_image" in b:
                if not isinstance(b["not_in_image"], str) or not b["not_in_image"].strip():
                    errors.append("requires/host.json: %s's not_in_image must say why" % b.get("name"))
                elif not b.get("optional"):
                    errors.append("requires/host.json: %s is not_in_image, so it cannot be required: mark it optional" % b.get("name"))
            host_names.add(b.get("name"))
    except Exception as e:
        errors.append("requires/host.json is not valid JSON: %s" % e)
for h in sorted(skill_host):
    if h not in host_names and h not in deps["host"]:
        warnings.append("a skill calls %r, which requires/host.json does not declare%s" % (h, " (nor does a dependency's)" if man.get("depends") and not deps["missing"] else ""))

# --- vendored code has to carry its licence ---------------------------------
for v in man.get("vendor", []) or []:
    for key in ("name", "licence", "url", "path"):
        if not v.get(key):
            errors.append("a vendor entry is missing %s" % key)
    vp = v.get("path", "")
    if vp and not os.path.isdir(p(vp)):
        errors.append("vendor path %s is missing" % vp)
    elif vp:
        if not any(os.path.isfile(p(vp, n)) for n in ("LICENCE", "LICENSE", "COPYING")):
            errors.append("%s has no licence file beside the code" % vp)
if (man.get("vendor") or []) and not any(os.path.isfile(p(n)) for n in ("NOTICE",)):
    errors.append("the pack vendors code but has no NOTICE")

# --- secrets ----------------------------------------------------------------
for s in man.get("secrets", []) or []:
    for key in ("name", "title", "why"):
        if not s.get(key):
            errors.append("a secret entry is missing %s" % key)
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", s.get("name", "")):
        errors.append("a secret name must be upper case with underscores: %r" % s.get("name"))
    # The hosts the secret is for. Under --isolation microvm a secret is only
    # ever injected on the way to these; without them it cannot be used there.
    hosts = s.get("hosts")
    if hosts is not None and (not isinstance(hosts, list) or not all(
            isinstance(h, str) and re.fullmatch(r"(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", h) for h in hosts)):
        errors.append("secret %s: hosts must be a list of host names" % s.get("name"))

# --- checksums --------------------------------------------------------------
def walk_files():
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for f in sorted(files):
            if f.startswith("."):
                continue
            rel = os.path.relpath(os.path.join(dirpath, f), root)
            if rel == "pack.json":
                continue
            yield rel

digests = {}
for rel in walk_files():
    h = hashlib.sha256()
    with open(os.path.join(root, rel), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    digests[rel] = h.hexdigest()

if mode == "seal":
    # A seeded tool whose manifest has no 64-hex sha256 of its entry script is
    # silently LEFT OUT of a run. Compute it here so it cannot be forgotten, and
    # do it before the checksums below, which cover the manifest.
    for name, tm in sorted(tools.items()):
        entry = tm.get("entry", "")
        body = p("tools", name, entry)
        if not entry or not os.path.isfile(body):
            continue
        h = hashlib.sha256()
        with open(body, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        digest = h.hexdigest()
        if tm.get("sha256") != digest:
            tm["sha256"] = digest
            rel = os.path.join("tools", name, "manifest.json")
            with open(p("tools", name, "manifest.json"), "w", encoding="utf-8") as fh:
                json.dump(tm, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
            # The digests above were taken before this rewrite; restate this one.
            mh = hashlib.sha256()
            with open(p("tools", name, "manifest.json"), "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 16), b""):
                    mh.update(chunk)
            digests[rel] = mh.hexdigest()

    # A recipe carries the sha256 of its entry the same way, so a run can say
    # which version of which script catalogued an object.
    for name, rm in sorted(recipes.items()):
        body = os.path.join(p("recipes", name), str(rm.get("entry", "")))
        if not os.path.isfile(body):
            continue
        digest = hashlib.sha256(open(body, "rb").read()).hexdigest()
        if rm.get("sha256") != digest:
            rm["sha256"] = digest
            rel = os.path.join("recipes", name, "recipe.json")
            with open(p(rel), "w", encoding="utf-8") as fh:
                json.dump(rm, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
            digests[rel] = hashlib.sha256(open(p(rel), "rb").read()).hexdigest()

    # The index is what every agent sees once; the bodies are fetched on demand.
    lines = ["# Skills in this pack", "",
             "Fetch a body with `skill(\"<id>\")`. A body may name others; fetch those the same way.", ""]
    for sid in sorted(skills):
        meta = skills[sid]
        lines.append("- `%s` %s: %s" % (sid, meta.get("title", ""), meta.get("when", "")))
    lines.append("")
    # A pack of recipes or tools alone has no skills and no index.
    if os.path.isdir(p("skills")):
        open(p("skills", "INDEX.md"), "w", encoding="utf-8").write("\n".join(lines))
        digests.pop("skills/INDEX.md", None)
        h = hashlib.sha256(open(p("skills", "INDEX.md"), "rb").read()).hexdigest()
        digests["skills/INDEX.md"] = h
    man["checksums"] = {"sha256": digests}
    # Assign, never setdefault: a tool added to an already-sealed pack has to
    # reach the manifest, or the manifest quietly describes the pack it used to be.
    man["tools"] = sorted(tools)
    man["skills"] = len(skills)
    if recipes:
        man["recipes"] = ["%s/%s" % (pid, n) for n in sorted(recipes)]
    else:
        man.pop("recipes", None)
    with open(p("pack.json"), "w", encoding="utf-8") as fh:
        json.dump(man, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
else:
    recorded = (man.get("checksums") or {}).get("sha256") or {}
    if not recorded:
        errors.append("pack.json carries no checksums; seal the pack first")
    else:
        for rel, want in sorted(recorded.items()):
            got = digests.get(rel)
            if got is None:
                errors.append("%s is in the checksums but missing from the pack" % rel)
            elif got != want:
                errors.append("%s does not match its checksum" % rel)
        for rel in sorted(digests):
            if rel not in recorded:
                errors.append("%s is in the pack but not in the checksums" % rel)

out = {"id": pid, "name": man.get("name"), "version": man.get("version"),
       "skills": len(skills), "tools": sorted(tools),
       "recipes": ["%s/%s" % (pid, n) for n in sorted(recipes)], "depends": man.get("depends") or [],
       "secrets": man.get("secrets") or [], "vendor": man.get("vendor") or [],
       "host": sorted(host_names), "errors": errors, "warnings": warnings}
print(json.dumps(out))
sys.exit(1 if errors else 0)
PYEOF
}

validate() { # <dir> <mode> -> prints the json summary, non-zero on error
  local dir="$1" mode="${2:-check}" out rc=0
  out="$("$PY" -c "$(validate_py)" "$dir" "$mode" 2>&1)" || rc=$?
  printf '%s\n' "$out"
  return $rc
}

show_problems() { # <summary json>
  "$PY" - "$1" <<'PYEOF'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print(sys.argv[1], file=sys.stderr); sys.exit(0)
for w in d.get("warnings", []):
    print("  warning: %s" % w, file=sys.stderr)
for e in d.get("errors", []):
    print("  refused: %s" % e, file=sys.stderr)
PYEOF
}

cmd_seal() {
  local dir="${1:?pack directory}"
  [[ -d "$dir" ]] || die "$dir is not a directory"
  local out; out="$(validate "$dir" seal)" || { show_problems "$out"; die "the pack does not validate"; }
  show_problems "$out"
  echo "sealed: $("$PY" -c 'import json,sys;d=json.loads(sys.argv[1]);print("%s %s, %d skills, %d tools" % (d["id"], d["version"], d["skills"], len(d["tools"])))' "$out")"
}

collect_secrets() { # <pack dir> <install dir> <interactive 0|1>
  local src="$1" dst="$2" interactive="$3"
  local names; names="$("$PY" -c '
import json,sys
m=json.load(open(sys.argv[1]))
for s in m.get("secrets") or []:
    print("%s\t%s\t%s\t%s\t%s" % (s["name"], s["title"], s["why"], "required" if s.get("required") else "optional", s.get("url","")))
' "$src/pack.json")"
  [[ -n "$names" ]] || return 0
  install -d -m 700 "$SECRETS"
  local env_file
  env_file="$(secrets_file "$(basename "$dst")")"
  : > "$env_file"; chmod 600 "$env_file"
  while IFS=$'\t' read -r name title why need url; do
    [[ -n "$name" ]] || continue
    local value="${!name:-}"
    if [[ -z "$value" && "$interactive" == "1" ]]; then
      note ""
      note "  $title ($name), $need"
      note "  $why"
      [[ -n "$url" ]] && note "  get one: $url"
      read -r -s -p "  value (blank to skip): " value < /dev/tty || value=""
      note ""
    fi
    if [[ -z "$value" ]]; then
      [[ "$need" == "required" ]] && die "$name is required by this pack and was not given"
      note "  $name: not set; the tools that need it will say so"
      continue
    fi
    printf '%s=%s\n' "$name" "$value" >> "$env_file"
    note "  $name: stored in $env_file (0600)"
  done <<< "$names"
}

cmd_install() {
  local src="" yes=0 secrets=1
  while (($#)); do
    case "$1" in
      --yes|-y) yes=1; shift ;;
      --no-secrets) secrets=0; shift ;;
      -*) die "unknown option $1" ;;
      *) src="$1"; shift ;;
    esac
  done
  [[ -n "$src" ]] || die "usage: pack.sh install <dir|zip>"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local dir=""
  if [[ -f "$src" && "$src" == *.zip ]]; then
    command -v unzip >/dev/null 2>&1 || die "unzip is not on this host"
    unzip -q "$src" -d "$tmp/x" || die "could not unzip $src"
    local tops; tops="$(find "$tmp/x" -mindepth 1 -maxdepth 1)"
    [[ "$(printf '%s\n' "$tops" | wc -l | tr -d ' ')" == "1" ]] || die "the zip must hold exactly one directory at its top"
    dir="$tops"
    [[ -d "$dir" ]] || die "the top of the zip is not a directory"
  elif [[ -d "$src" ]]; then
    dir="$src"
  else
    die "$src is neither a directory nor a zip"
  fi

  local out; out="$(validate "$dir" check)" || { show_problems "$out"; die "the pack does not validate"; }
  show_problems "$out"
  local id ver; id="$("$PY" -c 'import json,sys;print(json.loads(sys.argv[1])["id"])' "$out")"
  ver="$("$PY" -c 'import json,sys;print(json.loads(sys.argv[1])["version"])' "$out")"
  [[ "$(basename "$dir")" == "$id" ]] || die "the directory is named $(basename "$dir") but the pack id is $id"

  # dependencies, by id and minimum version
  local deps; deps="$("$PY" -c 'import json,sys;print("\n".join(json.loads(sys.argv[1])["depends"]))' "$out")"
  while read -r dep; do
    [[ -n "$dep" ]] || continue
    local dep_id="${dep%%>=*}" dep_min=""
    [[ "$dep" == *">="* ]] && dep_min="${dep##*>=}"
    [[ -f "$PACKS/$dep_id/pack.json" ]] || die "this pack depends on $dep_id, which is not installed"
    if [[ -n "$dep_min" ]]; then
      local have; have="$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["version"])' "$PACKS/$dep_id/pack.json")"
      "$PY" -c 'import sys
def t(v): return tuple(int(x) for x in v.split("."))
sys.exit(0 if t(sys.argv[1]) >= t(sys.argv[2]) else 1)' "$have" "$dep_min" \
        || die "this pack needs $dep_id >= $dep_min and $have is installed"
    fi
  done <<< "$deps"

  local dst="$PACKS/$id"
  if [[ -d "$dst" && "$yes" != "1" ]]; then
    local old; old="$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["version"])' "$dst/pack.json" 2>/dev/null || echo "?")"
    note "  $id $old is already installed; installing $ver over it"
  fi
  install -d -m 700 "$PACKS"
  rm -rf "$dst.new"
  cp -R "$dir" "$dst.new"
  rm -rf "$dst.old"
  [[ -d "$dst" ]] && mv "$dst" "$dst.old"
  mv "$dst.new" "$dst"
  # a pack's own files are never writable by the run
  find "$dst" -type d -exec chmod 755 {} +
  find "$dst" -type f -exec chmod 644 {} +
  find "$dst/tools" -name '*.py' -exec chmod 755 {} + 2>/dev/null || true
  if [[ -d "$dst.old" ]]; then
    # A store from before secrets moved out of the pack directory: carried
    # over once, then the old copy goes with the old install.
    if [[ -f "$dst.old/secrets.env" && ! -f "$(secrets_file "$id")" ]]; then
      install -d -m 700 "$SECRETS"
      cp "$dst.old/secrets.env" "$(secrets_file "$id")" && chmod 600 "$(secrets_file "$id")"
    fi
    rm -rf "$dst.old"
  fi

  [[ "$secrets" == "1" ]] && collect_secrets "$dst" "$dst" "$([[ -t 0 ]] && echo 1 || echo 0)"
  echo "installed $id $ver into $dst"
  "$PY" -c 'import json,sys
d=json.loads(sys.argv[1])
print("  %d skills, %d tools, %d host requirements" % (d["skills"], len(d["tools"]), len(d["host"])))' "$out"
}

cmd_list() {
  [[ -d "$PACKS" ]] || { echo "no packs installed"; return 0; }
  local any=0
  for d in "$PACKS"/*/; do
    [[ -f "$d/pack.json" ]] || continue
    any=1
    "$PY" -c '
import json,sys,os
d=json.load(open(sys.argv[1]))
sec = os.path.isfile(sys.argv[2])
print("  %-28s %-8s %s%s" % (d["id"], d["version"], d.get("description","")[:60], "  [secrets set]" if sec else ""))' "$d/pack.json" "$(secrets_file "$(basename "$d")")"
  done
  [[ "$any" == "1" ]] || echo "no packs installed"
}

cmd_show() {
  local id="${1:?pack id}"; local d="$PACKS/$id"
  [[ -f "$d/pack.json" ]] || die "$id is not installed"
  "$PY" - "$d" "$(secrets_file "$id")" <<'PYEOF'
import json, os, sys, re
d = sys.argv[1]
m = json.load(open(os.path.join(d, "pack.json")))
print("%s %s  (%s)" % (m["name"], m["version"], m["licence"]))
print(m["description"])
if m.get("depends"): print("\ndepends on: %s" % ", ".join(m["depends"]))
idx = os.path.join(d, "skills", "INDEX.md")
if os.path.isfile(idx):
    print("\nskills:")
    for line in open(idx, encoding="utf-8"):
        if line.startswith("- "): print("  " + line[2:].rstrip())
td = os.path.join(d, "tools")
if os.path.isdir(td):
    print("\ntools:")
    for n in sorted(os.listdir(td)):
        mf = os.path.join(td, n, "manifest.json")
        if os.path.isfile(mf):
            print("  %-20s %s" % (n, json.load(open(mf))["description"][:70]))
hj = os.path.join(d, "requires", "host.json")
if os.path.isfile(hj):
    print("\nhost requirements:")
    for b in json.load(open(hj)).get("binaries", []):
        have = any(os.access(os.path.join(p, b["name"]), os.X_OK) for p in os.environ.get("PATH","").split(":") if p)
        # An optional binary is needed for one kind of case, not for the pack to work.
        state = "present" if have else ("optional" if b.get("optional") else "MISSING")
        print("  %-16s %-8s %s" % (b["name"], state, b["why"]))
if m.get("secrets"):
    env = sys.argv[2]
    have = set()
    if os.path.isfile(env):
        have = {l.split("=",1)[0] for l in open(env) if "=" in l}
    print("\nsecrets:")
    for s in m["secrets"]:
        print("  %-18s %-8s %s" % (s["name"], "set" if s["name"] in have else "unset", s["title"]))
if m.get("vendor"):
    print("\nvendored:")
    for v in m["vendor"]:
        print("  %-20s %-16s %s" % (v["name"], v["licence"], v["url"]))
PYEOF
}

cmd_verify() {
  local id="${1:?pack id}"; local d="$PACKS/$id"
  [[ -f "$d/pack.json" ]] || die "$id is not installed"
  local out; out="$(validate "$d" check)" || { show_problems "$out"; die "$id does not verify"; }
  show_problems "$out"
  echo "$id verifies: every file matches its checksum"
}

cmd_remove() {
  local id="${1:?pack id}"; local d="$PACKS/$id"
  [[ -d "$d" ]] || die "$id is not installed"
  rm -rf "$d"
  echo "removed $id"
}

cmd_path() { local id="${1:?pack id}"; [[ -d "$PACKS/$id" ]] || die "$id is not installed"; echo "$PACKS/$id"; }

# Every pack dir for a comma-separated list, dependencies first, no duplicates.
cmd_resolve() {
  local list="${1:?pack ids}"
  "$PY" - "$PACKS" "$list" <<'PYEOF'
import json, os, sys
packs, want = sys.argv[1], [x for x in sys.argv[2].split(",") if x.strip()]
seen, order = set(), []
def visit(pid, chain):
    if pid in seen: return
    if pid in chain:
        print("BLOCKER: packs depend on each other: %s" % " -> ".join(chain + [pid]), file=sys.stderr); sys.exit(1)
    mf = os.path.join(packs, pid, "pack.json")
    if not os.path.isfile(mf):
        print("BLOCKER: pack %s is not installed" % pid, file=sys.stderr); sys.exit(1)
    m = json.load(open(mf))
    for dep in m.get("depends") or []:
        visit(dep.split(">=")[0], chain + [pid])
    seen.add(pid); order.append(pid)
for p in want:
    visit(p.strip(), [])
# A run holds one tool per name, so two packs that carry a tool of the same
# name with different scripts leave one pack's skills calling the other's
# tool. Said here, before the kickoff copies either; the same script in both
# is the same tool and says nothing.
held = {}
for p in order:
    td = os.path.join(packs, p, "tools")
    if not os.path.isdir(td):
        continue
    for name in sorted(os.listdir(td)):
        mf = os.path.join(td, name, "manifest.json")
        if not os.path.isfile(mf):
            continue
        try:
            sha = json.load(open(mf)).get("sha256")
        except Exception:
            sha = None
        if name not in held:
            held[name] = (p, sha)
        elif held[name][1] != sha:
            print("WARN: packs %s and %s both carry a tool named %s, with different scripts; a run holds one "
                  "tool per name, so one pack's skills would call the other's. Rename one of them."
                  % (held[name][0], p, name), file=sys.stderr)
for p in order:
    print(os.path.join(packs, p))
PYEOF
}

# A tool a run forged and `swarm.sh tools --save` kept, taken into a pack's
# source: its script checked against the sha256 its manifest carries, its
# manifest reduced to what a pack tool declares (the run's by/at/version and
# any pack field stay behind), its provenance kept beside it. The author reads
# it and seals the pack; nothing here seals for them.
cmd_adopt() {
  local tool="${1:-}" pack="${2:-}" replace=0
  [[ "${3:-}" == "--replace" ]] && replace=1
  [[ -n "$tool" && -n "$pack" ]] || die "usage: pack.sh adopt <tool dir> <pack dir> [--replace]"
  [[ -f "$tool/manifest.json" ]] || die "$tool has no manifest.json"
  [[ -f "$pack/pack.json" ]] || die "$pack is not a pack (no pack.json)"
  "$PY" - "$tool" "$pack" "$replace" <<'ADOPT_EOF'
import hashlib, json, os, re, shutil, sys
tool, pack, replace = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
m = json.load(open(os.path.join(tool, "manifest.json")))
name = m.get("name", "")
if not re.fullmatch(r"[a-z][a-z0-9_]{2,31}", name):
    sys.exit(f"BLOCKER: {name!r} is not a tool name")
entry = m.get("entry", "")
body = os.path.join(tool, entry)
if not entry or "/" in entry or not os.path.isfile(body) or os.path.islink(body):
    sys.exit(f"BLOCKER: {name}: entry {entry!r} is not a file in the tool's directory")
digest = hashlib.sha256(open(body, "rb").read()).hexdigest()
if m.get("sha256") != digest:
    sys.exit(f"BLOCKER: {name}: its script does not match the sha256 in its manifest; it was changed after it was forged")
dest = os.path.join(pack, "tools", name)
if os.path.exists(dest) and not replace:
    sys.exit(f"BLOCKER: {pack} already has a tool {name}; --replace to take this one instead")
shutil.rmtree(dest, ignore_errors=True)
os.makedirs(dest)
for root, dirs, files in os.walk(tool):
    for f in files:
        src = os.path.join(root, f)
        rel = os.path.relpath(src, tool)
        if rel == "manifest.json" or os.path.islink(src):
            continue
        os.makedirs(os.path.dirname(os.path.join(dest, rel)), exist_ok=True)
        shutil.copyfile(src, os.path.join(dest, rel))
keep = {k: m[k] for k in ("name", "description", "params", "runtime", "entry", "timeout_seconds", "example") if k in m}
with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as fh:
    json.dump(keep, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
print(f"adopted {name} into {pack}/tools/{name}; read it, then: pack.sh seal {pack}")
ADOPT_EOF
}

case "${1:-}" in
  install) shift; cmd_install "$@" ;;
  list) shift; cmd_list "$@" ;;
  show) shift; cmd_show "$@" ;;
  verify) shift; cmd_verify "$@" ;;
  remove) shift; cmd_remove "$@" ;;
  seal) shift; cmd_seal "$@" ;;
  path) shift; cmd_path "$@" ;;
  resolve) shift; cmd_resolve "$@" ;;
  adopt) shift; cmd_adopt "$@" ;;
  ""|-h|--help|help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown command $1" ;;
esac
