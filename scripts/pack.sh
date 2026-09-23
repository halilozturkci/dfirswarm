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
set -euo pipefail

HOME_DIR="${DFIRSWARM_HOME:-$HOME/.dfirswarm}"
PACKS="$HOME_DIR/packs"
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
               "skills", "tools", "vendor", "requires", "goals", "tests"}
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

for t in sorted(skill_tools):
    if t not in tools:
        # A dependency may carry it; the full set is resolved at kickoff.
        warnings.append("a skill names the tool %r, which this pack does not carry (a dependency must)" % t)
for n in sorted(skill_needs):
    if n not in skills:
        # A dependency may carry it; resolve names across packs at kickoff, not here.
        warnings.append("a skill needs %r, which this pack does not carry (a dependency must)" % n)

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
            host_names.add(b.get("name"))
    except Exception as e:
        errors.append("requires/host.json is not valid JSON: %s" % e)
for h in sorted(skill_host):
    if h not in host_names:
        warnings.append("a skill calls %r, which requires/host.json does not declare" % h)

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

    # The index is what every agent sees once; the bodies are fetched on demand.
    lines = ["# Skills in this pack", "",
             "Fetch a body with `skill(\"<id>\")`. A body may name others; fetch those the same way.", ""]
    for sid in sorted(skills):
        meta = skills[sid]
        lines.append("- `%s` %s: %s" % (sid, meta.get("title", ""), meta.get("when", "")))
    lines.append("")
    open(p("skills", "INDEX.md"), "w", encoding="utf-8").write("\n".join(lines))
    digests.pop("skills/INDEX.md", None)
    h = hashlib.sha256(open(p("skills", "INDEX.md"), "rb").read()).hexdigest()
    digests["skills/INDEX.md"] = h
    man["checksums"] = {"sha256": digests}
    # Assign, never setdefault: a tool added to an already-sealed pack has to
    # reach the manifest, or the manifest quietly describes the pack it used to be.
    man["tools"] = sorted(tools)
    man["skills"] = len(skills)
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
       "skills": len(skills), "tools": sorted(tools), "depends": man.get("depends") or [],
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
  install -d -m 700 "$dst"
  local env_file="$dst/secrets.env"
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
  [[ -d "$dst.old" ]] && { cp -R "$dst.old/secrets.env" "$dst/secrets.env" 2>/dev/null || true; rm -rf "$dst.old"; }

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
sec = os.path.isfile(os.path.join(os.path.dirname(sys.argv[1]), "secrets.env"))
print("  %-28s %-8s %s%s" % (d["id"], d["version"], d.get("description","")[:60], "  [secrets set]" if sec else ""))' "$d/pack.json"
  done
  [[ "$any" == "1" ]] || echo "no packs installed"
}

cmd_show() {
  local id="${1:?pack id}"; local d="$PACKS/$id"
  [[ -f "$d/pack.json" ]] || die "$id is not installed"
  "$PY" - "$d" <<'PYEOF'
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
    env = os.path.join(d, "secrets.env")
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
for p in order:
    print(os.path.join(packs, p))
PYEOF
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
  ""|-h|--help|help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown command $1" ;;
esac
