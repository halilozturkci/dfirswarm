#!/usr/bin/env python3
"""Turn packs into image recipes, and say which image a run needs.

  recipe.py build PROFILE --out DIR [--base IMAGE] [--packs DIR] [--allow-nonredistributable] [--allow-missing-data]
                 [--symbol-set curated,broad|curated|broad|none] [--data-from DIR]... [--symbols-from DIR]...
  recipe.py profile-for [--installed DIR]... [--tools-from DIR]... PACK...
                                       the profile that serves these packs: the smallest one that holds
                                       them, else the smallest that covers what they name, else full
  recipe.py list                       profiles and the packs each resolves to
  recipe.py check-lock FILE            refuse a lock entry not pinned by digest

A profile is a named set of packs (images/profiles.json), with every pack's
dependencies added, so an image never lacks the base its method builds on.
For each pack, `requires/host.json` says which binaries its method calls and
how to install them, and `requires/python.txt` lists the libraries its tools
import. The packs are the single source: a microVM run's probe checks the
image against them (scripts/vm.ts imageFit), and this turns the same lines
into an image. On the host the agents install what they lack themselves.

`profile-for` finds each pack where a run finds it: a PACK given as a path is
that directory; a name is looked up in each --installed DIR (default
$DFIRSWARM_HOME/packs, where scripts/pack.sh installs, ~/.dfirswarm/packs
without it), then in --packs-dir (this repository's packs/). An installed
pack the repository does not carry, a pro or third-party one, is then matched
by what it names, like any other. --tools-from names a tool directory whose
manifests say which programs they call (`requires`): those move the choice to
a bigger image only when one smaller than `full` has them all.

`check-lock` reads an images lock (`{"images": {PROFILE: {ARCH: REF}}}`, what
SWARM_IMAGES_LOCK names) and refuses an entry that is not `name@sha256:` and
64 hex digits: a tag can be moved under a run, a digest cannot.

`build` writes DIR/spec.json (what to install, and what cannot be installed
from a package manager), DIR/NOTICE (every program, its pack, its licence and
where it comes from) and DIR/Dockerfile, and copies install.py beside them,
so DIR is a complete build context:

  docker build -t dfirswarm-re:dev-amd64 DIR

A program or a data file a pack marks `redistributable: false` stops the build
unless `--allow-nonredistributable` is given: an image that stays on this
machine or in a private registry, never one published for others to pull, and
one that carries pinned data (`install.data`) is pushed by no workflow of ours,
the pro edition's included. The image then says so (image.json, its label, its
NOTICE).

A program no package manager has may carry a pinned artefact in its pack,
each fetched by install.py and refused unless its sha256 is the pinned one:

  install.download   a version, and per architecture a URL, its sha256 and the
                     program's path inside the archive. A `.deb` is installed
                     by apt, so its dependencies come from Debian; its `bin`,
                     when it has one, is where the package puts the program.
                     An architecture with no entry is recorded as not installed.
  install.source     one archive for every architecture (a tag's tarball),
                     unpacked under /opt/dfir/src/<name>, its `pip` arguments
                     run in a venv of its own there, its `entry` put on PATH.
  install.build      a source archive compiled in a builder stage of the
                     image (`./configure --prefix`, `make`, `make install`),
                     so the image carries the program and not the compiler.
                     A source with no configure script names its steps
                     (`commands`, argument lists run in the tree) and the
                     pinned `patches` applied first. `env` is the environment
                     of a source's pip, or of a build's configure and make;
                     `arches`, the architectures a source or a build is for
                     (every one when absent).
  install.data       one file a program reads and that is not a program (a
                     symbol table pack, a rule set), the same bytes for every
                     architecture: a url and its sha256, put as named inside
                     a Python package of the image's venv (`package`, `into`).
                     `warm` is a command run once it is there, for a program
                     that indexes what it finds the first time it runs;
                     `check` one that must then succeed (the images workflow
                     runs it again with no network). The entry says whether
                     it is `redistributable` and carries its own `licence`,
                     which the NOTICE states beside the program's. A data
                     file that cannot be had fails the build even for an
                     optional program (`build --allow-missing-data` goes on
                     without it, and the image records what is missing).
                     It may be a list, or {"list": FILE}: a template and
                     entries in a file of the pack, expanded entry by entry.
                     `set` (curated, broad) is what --symbol-set selects; a
                     set left out is recorded as omitted. `commands` and
                     `outputs` convert a source in the build, each output's
                     content pinned (`canonical`, `canonical_sha256`) for one
                     `converter` version; `acquire: "operator"` is never
                     fetched by the build, only taken from the operator's
                     store (--symbols-from) with the recorded acceptance of
                     its terms, and the build stops before Docker without it.
                     Local copies (--data-from, $DFIRSWARM_DATA_DIR) are bound
                     into the install step, never copied into a layer.

Every program the packs name must be in the image when its build ends,
optional or not, unless it is left out on purpose (a download with no build
for this architecture, a source or a build pinned for others with `arches`, a
program no line installs): an optional one that could not be installed stops
the build, so a build that went wrong (apt out of disk space) is not tagged,
and a builder stage that failed is not cached as a success. `build
--allow-missing-optional` builds the image without such programs and records
them; its spec.json and every builder stage it lets fail carry a build id of
their own. Regenerating the context changes that id and reruns the install
and those stages; reusing an existing context needs `docker build --no-cache`
to avoid taking an earlier build's gaps from the cache.

`run` names the interpreter a download's or a source's program needs:
`python` (the program's own venv, else the image's), or any program the image
holds (`perl`, `dotnet`, which a pack may pin as a download of its own). An apt
line with `-t <codename>-backports` comes from the image's Debian backports.

A program marked `not_in_image` (with why) belongs to another system than the
analysis image — Apple's `log`, a collector run on the source host — and is
listed as not applicable, not as missing. Anything else no line above installs
is listed under `manual` and never installed.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKS = HERE.parent / "packs"
# The programs every image has, since images/base.Dockerfile installs them:
# a tool that calls one of these needs no profile for it.
BASE_PROGRAMS = {"python3", "node", "jq", "sqlite3", "file", "xxd", "socat", "strings", "hexdump", "unzip",
                 "7z", "xz", "bzip2", "zstd", "curl", "exiftool", "rg"}
APT = re.compile(r"^(?:sudo\s+)?apt(?:-get)?\s+install\s+(.+)$")
# apt's own ways of naming the release a package comes from.
RELEASE_FLAGS = {"-t", "--target-release", "--default-release"}
PIP = re.compile(r"^python3\s+-m\s+pip\s+install\s+(.+)$")


def profiles() -> dict:
    """name -> {"packs": [...], "apt": [...]}; a bare list is the packs alone."""
    raw = json.loads((HERE / "profiles.json").read_text())["profiles"]
    return {name: (v if isinstance(v, dict) else {"packs": v}) for name, v in raw.items()}


def pack_dir(packs, name: str) -> Path:
    """Where pack `name` is: the first of `packs` (one directory of packs, or
    several searched in order) that holds it, else where the first would."""
    roots = [packs] if isinstance(packs, Path) else list(packs)
    for r in roots:
        if (r / name / "pack.json").is_file():
            return r / name
    return roots[0] / name


def depends(packs, name: str) -> list:
    manifest = pack_dir(packs, name) / "pack.json"
    if not manifest.exists():
        return []
    deps = json.loads(manifest.read_text()).get("depends") or []
    return [re.split(r"[<>=!~ ]", d, maxsplit=1)[0] for d in deps]


def resolve(packs, names: list) -> list:
    """The packs and everything they depend on, dependencies first."""
    out: list = []

    def visit(name: str, trail: tuple) -> None:
        if name in out:
            return
        if name in trail:
            raise SystemExit(f"recipe: dependency cycle through {name}")
        for dep in depends(packs, name):
            visit(dep, trail + (name,))
        out.append(name)

    for n in names:
        visit(n, ())
    return out


def words(tail: str) -> list:
    return [w for w in tail.split() if not w.startswith("-")]


def apt_words(tail: str) -> tuple:
    """The packages an apt line installs, and the release it takes them from
    (`-t bookworm-backports`), if it names one."""
    toks, pkgs, release = tail.split(), [], None
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in RELEASE_FLAGS and i + 1 < len(toks):
            release, i = toks[i + 1], i + 2
            continue
        if t.startswith("--target-release=") or t.startswith("--default-release="):
            release = t.split("=", 1)[1]
        elif not t.startswith("-"):
            pkgs.append(t)
        i += 1
    return pkgs, release


def pack_version(packs, name: str) -> dict:
    """The pack's version and seal (sha256 of its sorted checksums), as vm.ts packSeal computes it."""
    manifest = json.loads((pack_dir(packs, name) / "pack.json").read_text())
    sums = (manifest.get("checksums") or {}).get("sha256") or {}
    ordered = {k: sums[k] for k in sorted(sums)}
    seal = hashlib.sha256(json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return {"version": manifest.get("version", "?"), "seal": seal}


# A template's placeholder: {field}, filled from a pinned list's entry.
PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
# What recipe.py build --symbol-set may name: the sets a data entry declares.
SYMBOL_SETS = ("curated", "broad")


def fill_template(t, row: dict):
    """A template with each {field} of row filled in: a string that is one
    placeholder takes the field's value as it is (a number stays a number);
    a placeholder row does not name is left for install.py ({file}, {dir})."""
    if isinstance(t, str):
        m = PLACEHOLDER.fullmatch(t)
        if m and m.group(1) in row:
            return row[m.group(1)]
        return PLACEHOLDER.sub(lambda m: str(row[m.group(1)]) if m.group(1) in row else m.group(0), t)
    if isinstance(t, list):
        return [fill_template(x, row) for x in t]
    if isinstance(t, dict):
        return {k: fill_template(v, row) for k, v in t.items()}
    return t


def data_entries(pack: Path, data) -> list:
    """A program's install.data as a list of entries: one object, a list of
    them, or {"list": FILE}, a file of the pack holding a `template` (an
    install.data entry with {field} placeholders) and `entries` (one object of
    fields each), expanded into one entry per row. The harness knows the
    template's kinds, never what the fields mean."""
    if data is None:
        return []
    out = []
    for item in data if isinstance(data, list) else [data]:
        if isinstance(item, dict) and "list" in item:
            root = pack.resolve()
            path = (pack / str(item["list"])).resolve()
            if not str(path).startswith(f"{root}/"):
                raise SystemExit(f"recipe: {pack.name}: data list {item['list']} is not inside the pack")
            doc = json.loads(path.read_text())
            for row in doc.get("entries") or []:
                out.append({**fill_template(doc.get("template") or {}, row), "listed_in": str(item["list"])})
        elif isinstance(item, dict):
            out.append(item)
    return out


def local_copy(dirs: list, d: dict) -> Path | None:
    """A local copy of a data entry's pinned bytes in one of dirs: by its
    sha256 (DIR/<sha256>, DIR/sha256/<sha256>, DIR/blobs/sha256/<sha256>, the
    layout scripts/symbols.py keeps), else by its file name, checked."""
    want = str(d.get("sha256", "")).removeprefix("sha256:").lower()
    name = d.get("file") or Path(d.get("url", "")).name
    for root in dirs:
        root = Path(root)
        for p in (root / want, root / "sha256" / want, root / "blobs" / "sha256" / want, root / name):
            if p.is_file() and not p.is_symlink():
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    while chunk := f.read(1 << 20):
                        h.update(chunk)
                if h.hexdigest() == want:
                    return p
    return None


def acceptance(dirs: list, sha256: str) -> dict | None:
    """The operator's recorded acceptance of the terms for these bytes, from
    a symbol store's manifest.json (scripts/symbols.py writes it), or None."""
    for root in dirs:
        try:
            files = json.loads((Path(root) / "manifest.json").read_text()).get("files") or {}
        except (OSError, ValueError, AttributeError):
            continue
        acc = (files.get(sha256) or {}).get("acceptance")
        if isinstance(acc, dict) and acc.get("accepted_by") and acc.get("sha256") == sha256:
            return acc
    return None


def place_copy(src: Path, dest: Path) -> None:
    """dest as a hard link to src where the file system allows, else a copy."""
    dest.unlink(missing_ok=True)
    try:
        os.link(src, dest)
    except OSError:
        shutil.copyfile(src, dest)


KINDS = ("apt", "pip", "apt_release", "requirements", "binaries", "manual", "downloads", "sources", "builds",
         "data", "not_applicable", "python_notes", "python_locks", "pip_locks", "lock_files")


def lock_entry(spec: dict, pack: str, path: Path, label: str) -> dict:
    """A hash lock of a pack (a file under its requires/): the reference the spec
    carries ({name, sha256}) and the file the build copies into the context
    (spec["lock_files"], whose `from` build() removes before writing spec.json).
    Its content is checked by `install.lock_problem` at the seal and at the build."""
    if not path.is_file():
        raise SystemExit(f"recipe: {pack}: the lock {label} is not in the pack (seal the pack: pack.sh checks it)")
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    name = f"{pack}-{path.name}"
    if not any(f["name"] == name for f in spec["lock_files"]):
        spec["lock_files"].append({"name": name, "sha256": sha, "from": str(path)})
    return {"name": name, "sha256": sha}


def empty() -> dict:
    return {k: ({} if k in ("apt", "pip", "apt_release") else []) for k in KINDS}


def add_data(spec: dict, packs, name: str, b: dict, install: dict) -> None:
    """Data the program reads (symbol tables, rules, definitions): its own entry
    in the spec, whatever installs the program, named for the program unless the
    pack names it. One entry, a list of them, or a pack's pinned list file
    expanded entry by entry (data_entries). Required whatever its program is:
    the pack pinned it on purpose (build --allow-missing-data goes on without
    it). Not for redistribution when either it or its program says so."""
    for item in data_entries(pack_dir(packs, name), install.get("data")):
        spec["data"].append({"program": b["name"], "pack": name,
                             "redistributable": b.get("redistributable", True) is not False
                             and item.get("redistributable", True) is not False,
                             **{"name": f"{b['name']}-data", **item}, "required": True})


def read_pack(packs, name: str) -> dict:
    spec = empty()
    host = pack_dir(packs, name) / "requires" / "host.json"
    if host.exists():
        for b in json.loads(host.read_text())["binaries"]:
            install = b.get("install") or {}
            line = install.get("apt", "").strip()
            required = not b.get("optional", False)
            # Another system's program (Apple's log, a collector run on the
            # source host): no Linux image holds it, and none lacks it.
            if b.get("not_in_image"):
                spec["not_applicable"].append({"name": b["name"], "pack": name, "why": b["not_in_image"]})
                # The program is in no image, but what a pack pins for a tool to
                # read (definitions, rules) is still installed: the data belongs to
                # the pack, not to the program's being run here.
                add_data(spec, packs, name, b, install)
                continue
            spec["binaries"].append({"name": b["name"], "pack": name, "required": required,
                                     "licence": b.get("licence"),
                                     "redistributable": b.get("redistributable", True) is not False,
                                     "source": line, "why": b.get("why", "")})
            # Commands whose output the build keeps as facts about the program
            # (install.py records each under /etc/dfirswarm/facts/); the
            # seal has checked their shape.
            if b.get("facts"):
                spec["binaries"][-1]["facts"] = b["facts"]
            pinned = [k for k in ("build", "source", "download") if isinstance(install.get(k), dict)]
            if pinned:
                kind = pinned[0]
                spec[kind + "s"].append({"name": b["name"], "pack": name, "required": required, **install[kind]})
                if kind == "source":
                    for key in ("pip_lock", "pip_after_lock"):
                        if install[kind].get(key):
                            spec["sources"][-1][key] = lock_entry(spec, name, pack_dir(packs, name) / str(install[kind][key]), str(install[kind][key]))
                spec["binaries"][-1]["source"] = {"download": "download", "source": "source",
                                                  "build": "built from source"}[kind] + f" {install[kind].get('version', '?')}"
            elif m := APT.match(line):
                pkgs, release = apt_words(m.group(1))
                spec["binaries"][-1]["apt"] = pkgs
                for p in pkgs:
                    spec["apt"][p] = spec["apt"].get(p, False) or required
                    if release:
                        spec["apt_release"][p] = release
            elif m := PIP.match(line):
                spec["binaries"][-1]["pip"] = words(m.group(1))
                if install.get("pip_lock"):
                    # Installed from the pack's hash lock (pip --require-hashes), not from the
                    # names on the line: the lock holds the set and its dependencies.
                    ref = lock_entry(spec, name, pack_dir(packs, name) / str(install["pip_lock"]), str(install["pip_lock"]))
                    spec["pip_locks"].append({"program": b["name"], "pack": name, "required": required,
                                              "packages": words(m.group(1)), **ref})
                    spec["binaries"][-1]["locked"] = True
                else:
                    for p in words(m.group(1)):
                        spec["pip"][p] = spec["pip"].get(p, False) or required
            else:
                spec["manual"].append({"name": b["name"], "pack": name, "how": line or "no install line"})
            add_data(spec, packs, name, b, install)
    reqs = pack_dir(packs, name) / "requires" / "python.txt"
    # requires/python.lock beside python.txt: the pack's Python set installed with
    # hash checking, in place of the lines of python.txt (which stay the notes).
    py_lock = pack_dir(packs, name) / "requires" / "python.lock"
    if py_lock.is_file():
        spec["python_locks"].append({"pack": name, **lock_entry(spec, name, py_lock, "requires/python.lock")})
    if reqs.exists():
        for raw in reqs.read_text().splitlines():
            line, _, note = raw.partition("#")
            line = line.strip()
            if line:
                if not py_lock.is_file():
                    spec["requirements"].append(line)
                # What the pack says the library is for, for the image's
                # tools.md: the comment on its line.
                spec["python_notes"].append({"requirement": line, "pack": name, "note": " ".join(note.split())})
    return spec


def merge(specs: list) -> dict:
    out = empty()
    for s in specs:
        for kind in ("apt", "pip"):
            for p, req in s[kind].items():
                out[kind][p] = out[kind].get(p, False) or req
        out["apt_release"].update(s["apt_release"])
        out["requirements"] += [r for r in s["requirements"] if r not in out["requirements"]]
        out["binaries"] += s["binaries"]
        out["python_notes"] += [n for n in s["python_notes"] if not any(x["requirement"] == n["requirement"] for x in out["python_notes"])]
        out["manual"] += s["manual"]
        for kind in ("python_locks", "pip_locks", "lock_files"):
            out[kind] += [x for x in s[kind] if x not in out[kind]]
        # A program two packs pin is installed once, as the first pins it.
        for kind in ("downloads", "sources", "builds", "data", "not_applicable"):
            for d in s[kind]:
                if not any(x["name"] == d["name"] for x in out[kind]):
                    out[kind].append(d)
    return out


def notice(spec: dict) -> str:
    """Every program an image holds, its pack, its licence and where it came from."""
    lines = [f"dfirswarm-{spec['profile']}: third-party programs in this image, by pack.",
             "Each is its authors' work under its own licence; none is dfirswarm's.",
             "Python packages follow with their licences, as the build found them.", ""]
    seen = set()
    for b in spec["binaries"]:
        key = (b["name"], b["pack"])
        if key in seen:
            continue
        seen.add(key)
        flag = "" if b.get("redistributable", True) else "  [not for redistribution]"
        lines.append(f"{b['name']}  ({b['pack']})  {b.get('licence') or 'licence not stated'}  <- {b.get('source') or '?'}{flag}")
    for d in spec["downloads"]:
        for arch in ("amd64", "arm64"):
            if isinstance(d.get(arch), dict):
                lines.append(f"  {d['name']} {arch}: {d[arch].get('url')}  sha256 {d[arch].get('sha256')}")
    for kind in ("sources", "builds"):
        for d in spec.get(kind, []):
            lines.append(f"  {d['name']} {'source' if kind == 'sources' else 'built from'}: {d.get('url')}  sha256 {d.get('sha256')}")
            for patch in d.get("patches") or []:
                lines.append(f"  {d['name']} patch: {patch.get('url')}  sha256 {patch.get('sha256')}")
    # Data a program reads has its own licence, which is not always the
    # program's: it is said here, beside where it came from.
    licences_said = set()
    for d in spec.get("data", []):
        flag = "" if d.get("redistributable", True) else "  [not for redistribution]"
        lines.append(f"  {d['name']} data for {d['program']}: {d.get('url')}  sha256 {d.get('sha256')}{flag}")
        n = d.get("notice") if isinstance(d.get("notice"), dict) else {}
        for key in ("supplier", "source", "terms", "derivation", "restriction"):
            if n.get(key):
                lines.append(f"    {key}: {n[key]}")
        if d.get("distribution_policy"):
            lines.append(f"    distribution: {d['distribution_policy']} (a label, not a legal clearance)")
        # One licence text said once, however many entries share it.
        if d.get("licence") and d["licence"] not in licences_said:
            licences_said.add(d["licence"])
            lines.append(f"    licence of the data: {d['licence']}")
        elif d.get("licence"):
            lines.append("    licence of the data: as above")
    for d in (spec.get("omitted") or {}).get("data", []):
        lines.append(f"  {d['name']} data for {d.get('program', '?')}: left out by this build ({d.get('why', '')})")
    if spec.get("not_applicable"):
        lines += ["", "Named by a pack, and not in this image because they belong to another system:"]
        lines += [f"{d['name']}  ({d['pack']})  {d['why']}" for d in spec["not_applicable"]]
    return "\n".join(lines) + "\n"


def requirement_names(packs, name: str) -> set:
    names = set()
    reqs = pack_dir(packs, name) / "requires" / "python.txt"
    if reqs.exists():
        for raw in reqs.read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                names.add(re.split(r"[<>=!~\[ ;]", line, maxsplit=1)[0].lower())
    return names


def needs_of(packs, names: list) -> tuple:
    """The programs these packs require, every program they name, and the Python packages their tools import."""
    required, named, python = set(), set(), set()
    for n in names:
        host = pack_dir(packs, n) / "requires" / "host.json"
        if host.exists():
            for b in json.loads(host.read_text())["binaries"]:
                named.add(b["name"])
                if not b.get("optional", False):
                    required.add(b["name"])
        python |= requirement_names(packs, n)
    return required, named, python


def tool_programs(dirs: list) -> set:
    """The programs the tools in these directories call, as each manifest's
    `requires` names them (tool-library/, a run's saved tools)."""
    out = set()
    for d in dirs:
        for mf in sorted(Path(d).glob("*/manifest.json")):
            try:
                req = json.loads(mf.read_text()).get("requires") or []
            except (OSError, ValueError):
                continue
            out |= {r for r in req if isinstance(r, str) and r}
    return out


def profile_for(search, wanted: list, programs: set = frozenset(), images=PACKS) -> str:
    """The profile whose image serves the wanted packs, in this order:

    1. A profile that HOLDS them: the wanted packs and their dependencies are
       all among the profile's packs (images/profiles.json, each pack's
       dependencies added). The smallest holder other than `full` wins (the
       tie rule below). `full` holds every pack, so a pack no smaller profile
       lists gets `full`, never a profile that merely happens to name the
       same programs: a pack whose tools use nothing beyond the base's (a
       pack of stdlib Python) is covered by every profile, and covering
       picks none of them for a reason.
    2. Only for a pack no profile holds, `full` included (an installed pro or
       third-party pack, which images/ does not list): the smallest profile
       that COVERS what the packs use, since a pack's skills and tools come
       from the pack itself and not from the image. Covering means every
       program the packs name, required or optional, is one the profile's
       packs name too, and every Python package their tools import is in the
       profile.
    3. Otherwise `full`.

    The tie rule, for the candidates of the step that decides: `full` last,
    then the fewest packs, then the fewest programs the profile's packs name
    (the least built, pulled and listed for nothing the run asked for), then
    the profile's name. The order of images/profiles.json decides nothing.
    The base pack alone (it names the Sleuth Kit programs, which the `base`
    image lacks) is held by `core`, the profile of that pack alone, which has
    the fewest packs of any holder; a pack no profile lists that depends on the
    base pack, or names only programs the base pack names and imports only
    the Python packages it installs, is covered by `core` for the same reason. A pack that names a program the base pack does
    not (the Volatility or tshark of another pack) is not covered by `core`,
    and goes to the smallest profile that names it, or to `full`. A run with
    no packs at all (and no library tool that needs a program) is `base`, the
    agents' bare image.

    The wanted packs are read from `search` (where the run's packs are
    installed); a profile's own packs from `images` (what the images are built
    from). `programs` are what the run's library tools call: among the
    candidates of the step that decides, one smaller than `full` that also
    names every one of them is preferred."""
    need = set(resolve(search, wanted))
    if not need and not set(programs) - BASE_PROGRAMS:
        return "base"
    # A pack found nowhere cannot be covered by anything known.
    if any(not (pack_dir(search, n) / "pack.json").exists() for n in need):
        return "full"
    _, want_named, want_python = needs_of(search, sorted(need))
    holding, covering = [], []
    # A profile with extra packages is chosen by name, never by its packs.
    for name, prof in profiles().items():
        if prof.get("apt"):
            continue
        members = resolve(images, prof["packs"])
        _, named, python = needs_of(images, members)
        row = (name, len(members), set(programs) - BASE_PROGRAMS <= named, len(named))
        if need <= set(members):
            holding.append(row)
        elif want_named <= named and want_python <= python:
            covering.append(row)
    # Membership decides first. A tool's programs move the choice to a bigger
    # image only when one smaller than full has them all; otherwise the packs
    # decide, and the probe says which program is missing.
    for candidates in (holding, covering):
        if not candidates:
            continue
        pool = [s for s in candidates if s[2] and s[0] != "full"] or candidates
        # The tie rule: full last, then the fewest packs, then the fewest
        # programs the profile's packs name (the least that is built, pulled
        # and listed for nothing the run asked for), then the profile's name.
        # The order of images/profiles.json decides nothing.
        return min(pool, key=lambda s: (s[0] == "full", s[1], s[3], s[0]))[0]
    return "full"


def job_profiles(search, wanted: list, images=PACKS) -> dict:
    """The profile each of a run's packs runs its jobs in: its own
    (profile_for), unless that profile would serve it alone and a profile
    chosen for another of the run's packs, full aside, holds it too. A
    dependency every profile holds (computer-forensics-base) is placed last,
    once the other packs have moved: profile_for gives it `core`, which a run
    of other packs would then boot for nothing else, so it goes where the
    run's packs ended up (a run of computer-forensics-base, macos-forensics and
    mobile-forensics boots one image, mobile). `core` is booted only for a run
    whose job-needing packs are the base pack alone, or when every other pack of
    the run went to `full`, which the base pack does not join."""
    own = {name: profile_for(search, [name], images=images) for name in wanted}
    table = profiles()
    members = {name: set(resolve(images, prof["packs"])) for name, prof in table.items() if not prof.get("apt")}
    out = dict(own)
    everywhere = {n for n in own if all(n in m for q, m in members.items() if q != "base")}
    for names in ([n for n in own if n not in everywhere], [n for n in own if n in everywhere]):
        # Recounted for each group: a pack that moved has left its profile.
        users = {}
        for prof in out.values():
            users[prof] = users.get(prof, 0) + 1
        for name in names:
            prof = out[name]
            if users[prof] > 1:
                continue
            hold = [q for q in set(out.values()) if q not in (prof, "full") and q in members and name in members[q]]
            if hold:
                # The profile most of the run's packs run in, then the smallest.
                out[name] = min(hold, key=lambda q: (-users[q], len(members[q]), q))
    return out


def install_mod():
    """images/install.py, beside this file: its synced-folder and checkout checks."""
    sys.path.insert(0, str(HERE))
    import install
    return install


def symbol_sets(value: str):
    """The sets --symbol-set names, or None when it names one that is not known."""
    names = {x.strip() for x in str(value).split(",") if x.strip()}
    if names == {"none"}:
        return set()
    if not names or not names <= set(SYMBOL_SETS):
        return None
    return names


def default_data_mirror() -> list:
    """$DFIRSWARM_DATA_DIR, else $DFIRSWARM_HOME/data when it exists: local copies of pinned data."""
    if os.environ.get("DFIRSWARM_DATA_DIR"):
        return [Path(os.environ["DFIRSWARM_DATA_DIR"])]
    home = os.environ.get("DFIRSWARM_HOME") or str(Path.home() / ".dfirswarm")
    mirror = Path(home) / "data"
    return [mirror] if mirror.is_dir() else []


def default_symbol_store() -> list:
    """$DFIRSWARM_HOME/symbols, where scripts/symbols.py keeps what it fetched, when it exists."""
    home = os.environ.get("DFIRSWARM_HOME") or str(Path.home() / ".dfirswarm")
    store = Path(home) / "symbols"
    return [store] if store.is_dir() else []


def installed_dirs() -> list:
    """Where scripts/pack.sh installs packs: $DFIRSWARM_HOME/packs."""
    home = os.environ.get("DFIRSWARM_HOME") or str(Path.home() / ".dfirswarm")
    return [Path(home) / "packs"]


# An image reference pinned by digest: [registry[:port]/]path[:tag]@sha256:<64 hex>.
DIGEST_REF = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
    r"(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?"
    r"@sha256:[0-9a-f]{64}$")


def check_lock(path: Path) -> tuple:
    """(errors, warnings, entries) for an images lock: every entry must name
    its image by digest, since the kickoff boots exactly what the lock says."""
    errors, warnings, entries = [], [], 0
    try:
        lock = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        return [f"{path} is not readable JSON: {e}"], [], 0
    images = lock.get("images") if isinstance(lock, dict) else None
    if not isinstance(images, dict) or not images:
        return [f"{path} has no \"images\" object ({{PROFILE: {{ARCH: REF}}}})"], [], 0
    known = profiles()
    for profile, arches in sorted(images.items()):
        if not isinstance(arches, dict):
            errors.append(f"{profile}: not an object of architecture -> image reference")
            continue
        if profile not in known:
            warnings.append(f"{profile}: no such profile in images/profiles.json; the kickoff never asks for it")
        for a, ref in sorted(arches.items()):
            entries += 1
            if a not in ("amd64", "arm64"):
                warnings.append(f"{profile}/{a}: not an architecture the kickoff asks for (amd64, arm64)")
            if not isinstance(ref, str) or not DIGEST_REF.match(ref):
                errors.append(f"{profile}/{a}: {ref!r} is not pinned by digest (name@sha256:<64 hex digits>)")
    return errors, warnings, entries


def build(a) -> int:
    table = profiles()
    if a.profile not in table:
        print(f"recipe: no profile {a.profile}; one of {', '.join(sorted(table))}", file=sys.stderr)
        return 2
    members = table[a.profile]["packs"]
    extra_apt = table[a.profile].get("apt", [])
    missing = [p for p in members if not (a.packs / p).is_dir()]
    if missing:
        print(f"recipe: no such pack(s): {', '.join(missing)}", file=sys.stderr)
        return 2
    packs = resolve(a.packs, members)
    spec = merge([read_pack(a.packs, p) for p in packs])
    for pkg in extra_apt:
        spec["apt"][pkg] = True
    if a.allow_missing_optional:
        # Regenerating a context invalidates optional stages and the profile
        # install. Reusing this context for docker build still uses its cache:
        # that retry needs --no-cache, or a newly generated context.
        # The profile's own install may now end with gaps too (apt out of space
        # for an optional package): spec.json, copied in before it runs,
        # carries the same id, so that layer is not reused either.
        build_id = uuid.uuid4().hex
        spec["allow_missing_optional"] = True
        spec["build_id"] = build_id
        for d in spec["builds"]:
            if not d.get("required"):
                d.update({"may_fail": True, "build_id": build_id})
    # Programs, and the data a program reads (a symbol pack), that are not
    # cleared for redistribution: the image names each in its record.
    held_back = sorted({b["name"] for b in spec["binaries"] if not b.get("redistributable", True)}
                       | {d["name"] for d in spec["data"] if not d.get("redistributable", True)})
    if held_back and not a.allow_nonredistributable:
        print(f"recipe: {a.profile} would hold {len(held_back)} program(s) or data file(s) their packs mark redistributable: false "
              f"({', '.join(held_back)}). Build with --allow-nonredistributable for an image that stays on this "
              f"machine or in a private registry; never publish it.", file=sys.stderr)
        return 3
    # The symbol sets this build takes (--symbol-set): an entry that names a
    # set not chosen is left out on purpose and recorded as omitted, never as
    # a failure. An entry naming no set is always taken.
    chosen = symbol_sets(a.symbol_set)
    if chosen is None:
        print(f"recipe: --symbol-set {a.symbol_set}: name {', '.join(SYMBOL_SETS)} (comma-separated), or none", file=sys.stderr)
        return 2
    omitted = [{"name": d["name"], "pack": d["pack"], "program": d["program"], "set": d["set"],
                "why": f"--symbol-set {a.symbol_set}: the {d['set']} set is left out"}
               for d in spec["data"] if d.get("set") and d["set"] not in chosen]
    spec["data"] = [d for d in spec["data"] if not d.get("set") or d["set"] in chosen]
    if a.allow_missing_data:
        for d in spec["data"]:
            d["required"] = False
    # Local copies of the pinned bytes (a data mirror, the operator's symbol
    # store), by sha256: the build then fetches nothing it was given. An entry
    # the operator acquires is never fetched by a build: without its copy the
    # build stops here, before docker, saying how to get it.
    local_dirs = [x for x in (a.data_from or []) + (a.symbols_from or []) if x]
    copies = {}
    lacking, unaccepted, unattended = [], [], []
    for d in spec["data"]:
        sha = str(d["sha256"]).removeprefix("sha256:").lower()
        got = local_copy(local_dirs, d)
        # What the operator acquires is built in only with the operator's
        # recorded acceptance of its terms, which the image then carries.
        if d.get("acquire") == "operator":
            acc = acceptance(local_dirs, sha)
            # A process's acceptance (no terminal on either end) is not a
            # person's: taken only when the build says so, and recorded so.
            if got and acc and acc.get("attended") is not True and not a.allow_unattended_acceptance:
                got = None
                if d.get("required"):
                    unattended.append((d, acc))
                acc = None
            if got and acc:
                if acc.get("attended") is not True:
                    acc = {**acc, "unattended_allowed_by_build": True}
                d["acceptance"] = acc
            elif got:
                got = None
                if d.get("required"):
                    unaccepted.append(d)
            elif d.get("required"):
                lacking.append(d)
        if got:
            copies[sha] = got
    if unattended:
        print(f"recipe: {a.profile} would hold {len(unattended)} data file(s) whose terms were accepted unattended (no terminal on "
              "either end of the fetch, so a process, not a person at a terminal): "
              + "; ".join(f"{d['name']} (by {acc.get('accepted_by')}, {acc.get('accepted_at')}, {acc.get('os_user')}@{acc.get('host')})" for d, acc in unattended)
              + ". The owner accepts at a terminal (scripts/swarm.sh symbols fetch --accept-terms --accepted-by NAME), or this "
              "build says it takes an unattended acceptance (--allow-unattended-acceptance), which the image then records.", file=sys.stderr)
        return 4
    if lacking or unaccepted:
        where = (f"no copy is in {', '.join(str(x) for x in local_dirs)}" if local_dirs
                 else "no --symbols-from or --data-from was given, and there is no symbol store at the default place")
        if lacking:
            print(f"recipe: {a.profile} would hold {len(lacking)} data file(s) the operator acquires, and {where}: "
                  + "; ".join(f"{d['name']} (sha256 {d['sha256']}, {d['url']})" for d in lacking)
                  + ".", file=sys.stderr)
        if unaccepted:
            print(f"recipe: {a.profile} would hold {len(unaccepted)} data file(s) the operator acquires whose terms no store "
                  "records as accepted: " + "; ".join(f"{d['name']} (sha256 {d['sha256']})" for d in unaccepted)
                  + ". Nothing is built in without that acceptance.", file=sys.stderr)
        print("Fetch them first, accepting their terms (scripts/swarm.sh symbols fetch --accept-terms --accepted-by NAME, "
              "with --from DIR for a copy you have), or build with --symbol-set naming the sets you want "
              "(none leaves every symbol set out).", file=sys.stderr)
        return 4
    spec = {"profile": a.profile, "packs": packs, "profile_apt": list(extra_apt),
            "pack_versions": {p: pack_version(a.packs, p) for p in packs},
            "redistributable": not held_back, "nonredistributable": held_back,
            "symbol_set": sorted(chosen), "omitted": {"data": omitted}, **spec}

    # Only ever "false" from here: with nothing held back, the image is as
    # redistributable as its base, whose label it then inherits (the base
    # sets it), and image.json says the same (install.py).
    redistributable = ' \\\n      dev.dfirswarm.redistributable="false"' if held_back else ""
    # A context that holds a copy of what the operator acquired (a PDB) is
    # never in a folder a sync client copies, nor in a git checkout, where
    # `git add -A` would stage it.
    restricted = [d["name"] for d in spec["data"] if str(d["sha256"]).removeprefix("sha256:").lower() in copies
                  and (d.get("acquire") == "operator" or d.get("redistributable") is False)]
    if restricted:
        where = install_mod().synced(a.out)
        repo = install_mod().in_checkout(a.out)
        if where or repo:
            print(f"recipe: --out {a.out} is {'in a synced folder (' + where + ')' if where else 'inside the git checkout ' + repo}, "
                  f"and the context would hold a copy of {', '.join(restricted)}, which is not for redistribution. "
                  "Give --out a directory outside every synced folder and checkout (under $TMPDIR, say), and remove "
                  "its data/ once the image is built.", file=sys.stderr)
            return 5
    for d in spec["data"]:
        if d.get("acceptance"):
            acc = d["acceptance"]
            print(f"recipe: {d['name']}: terms accepted by {acc.get('accepted_by')} at {acc.get('accepted_at')}, "
                  f"{'attended (a terminal on both ends)' if acc.get('attended') is True else 'UNATTENDED, taken because of --allow-unattended-acceptance'}"
                  f", {acc.get('os_user')}@{acc.get('host')}: the image records it", file=sys.stderr)
    a.out.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(a.out / "data", ignore_errors=True)
    if copies:
        (a.out / "data").mkdir()
        for sha, src in copies.items():
            place_copy(src, a.out / "data" / sha)
    # The pip hash locks the packs name, copied beside the spec (the name carries
    # the pack, the spec carries each file's sha256 and install.py checks it).
    shutil.rmtree(a.out / "locks", ignore_errors=True)
    for lf in spec["lock_files"]:
        (a.out / "locks").mkdir(exist_ok=True)
        shutil.copyfile(lf.pop("from"), a.out / "locks" / lf["name"])
    (a.out / "spec.json").write_text(json.dumps(spec, indent=1) + "\n")
    (a.out / "NOTICE").write_text(notice(spec))
    shutil.copy(HERE / "install.py", a.out / "install.py")
    # A program built from source is built in a stage of its own, from the
    # same base, and only what `make install` put under its prefix is copied
    # across: the compiler and the -dev packages stay behind. Each stage reads
    # its own file, so every profile that builds the program shares its cache.
    stages, copy_lines = [], []
    for d in spec["builds"]:
        stage = "build-" + re.sub(r"[^a-z0-9]+", "-", d["name"].lower()).strip("-")
        (a.out / f"{stage}.json").write_text(json.dumps(d, indent=1) + "\n")
        stages.append(f"""FROM ${{BASE}} AS {stage}
COPY install.py {stage}.json /tmp/dfirswarm-build/
RUN python3 /tmp/dfirswarm-build/install.py --build /tmp/dfirswarm-build/{stage}.json
""")
        copy_lines.append(f"COPY --from={stage} /opt/dfir/tools/{d['name']} /opt/dfir/tools/{d['name']}\n")
    # The local copies are bound into the install step, not copied into a
    # layer: an 840 MB file copied in and deleted after still weighs 840 MB.
    install = ("RUN --mount=type=bind,source=data,target=/tmp/dfirswarm-data \\\n"
               " DFIRSWARM_DATA_DIR=/tmp/dfirswarm-data python3 /tmp/dfirswarm-build/install.py /tmp/dfirswarm-build/spec.json \\\n"
               if copies else "RUN python3 /tmp/dfirswarm-build/install.py /tmp/dfirswarm-build/spec.json \\\n")
    # What data the image carries, on the image itself: a pusher can refuse it
    # by inspecting the image, not only its build context.
    data_label = f' \\\n      dev.dfirswarm.data="{",".join(d["name"] for d in spec["data"])}"' if spec["data"] else ""
    (a.out / "Dockerfile").write_text(f"""# Generated by images/recipe.py from packs: {", ".join(packs) or "none"}. Do not edit.
ARG BASE={a.base}
{"".join(s + chr(10) for s in stages)}FROM ${{BASE}}
{"".join(copy_lines)}COPY install.py spec.json NOTICE /tmp/dfirswarm-build/
{"COPY locks /tmp/dfirswarm-build/locks" + chr(10) if spec["lock_files"] else ""}{install} && rm -rf /tmp/dfirswarm-build
ENV PATH=/opt/dfir/venv/bin:$PATH
LABEL org.opencontainers.image.title="dfirswarm-{a.profile}" \\
      dev.dfirswarm.profile="{a.profile}" \\
      dev.dfirswarm.packs="{",".join(packs)}"{redistributable}{data_label}
""")
    req_apt = sum(spec["apt"].values())
    print(f"{a.profile}: {len(packs)} pack(s), {len(spec['apt'])} apt ({req_apt} required), {len(spec['pip'])} pip, "
          f"{len(spec['requirements'])} python requirements, {len(spec['downloads'])} pinned downloads, "
          f"{len(spec['sources'])} pinned sources, {len(spec['builds'])} built from source, "
          f"{len(spec['data'])} pinned data files ({len(copies)} from local copies, {len(omitted)} left out by --symbol-set), "
          f"{len(spec['manual'])} neither, {len(spec['not_applicable'])} not applicable"
          + (f"; NOT for redistribution ({len(held_back)} programs)" if held_back else ""))
    if a.allow_missing_optional:
        print("recipe: optional programs may be missing. Before retrying, regenerate this context with recipe.py build, "
              "or use docker build --no-cache when reusing it; its build id changes only when the context is generated.",
              file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("profile")
    b.add_argument("--packs", type=Path, default=PACKS)
    b.add_argument("--out", required=True, type=Path)
    b.add_argument("--base", default="dfirswarm-base:dev-amd64")
    b.add_argument("--allow-nonredistributable", action="store_true",
                   help="build an image holding programs or data files their packs mark redistributable: false (never publish it)")
    b.add_argument("--allow-missing-optional", action="store_true",
                   help="go on when an optional program cannot be installed or built; the image records it (not_installed, "
                        "missing_allowed); regenerate the context before each retry, or use docker build --no-cache")
    b.add_argument("--allow-missing-data", action="store_true",
                   help="go on when a pinned data file (a symbol pack) cannot be fetched; the image records it under not_installed.data")
    b.add_argument("--symbol-set", default=os.environ.get("DFIRSWARM_SYMBOL_SET", "curated,broad"),
                   help="the symbol sets the image takes: curated (the exact tables a pack lists, from the operator's store), "
                        "broad (bulk collections), both comma-separated (the default), or none; a set left out is recorded as omitted")
    b.add_argument("--data-from", type=Path, action="append", default=default_data_mirror(),
                   help="a directory of local copies of pinned data, by sha256 or by file name (default $DFIRSWARM_DATA_DIR, "
                        "else $DFIRSWARM_HOME/data when it exists); repeatable")
    b.add_argument("--allow-unattended-acceptance", action="store_true",
                   help="take an acceptance of a supplier's terms recorded with no terminal on either end (a process's, not a "
                        "person's); the image records that this build allowed it")
    b.add_argument("--symbols-from", type=Path, action="append", default=default_symbol_store(),
                   help="the operator's symbol store (scripts/swarm.sh symbols fetch writes it; default $DFIRSWARM_HOME/symbols when it exists); repeatable")
    f = sub.add_parser("profile-for")
    f.add_argument("packs", nargs="*", help="pack ids, or pack directories")
    f.add_argument("--packs-dir", type=Path, default=PACKS, help="the packs the images are built from")
    f.add_argument("--installed", type=Path, action="append",
                   help="where the run's packs are installed (default $DFIRSWARM_HOME/packs); repeatable")
    f.add_argument("--tools-from", type=Path, action="append", default=[],
                   help="a tool directory whose manifests' `requires` name the programs they call; repeatable")
    j = sub.add_parser("job-profiles", help="{pack: profile} for a run's packs, each dependency with its dependents where one of their profiles holds it")
    j.add_argument("packs", nargs="*", help="pack ids, or pack directories")
    j.add_argument("--packs-dir", type=Path, default=PACKS)
    j.add_argument("--installed", type=Path, action="append")
    sub.add_parser("list").add_argument("--packs-dir", type=Path, default=PACKS)
    c = sub.add_parser("check-lock")
    c.add_argument("lock", type=Path)
    a = ap.parse_args()
    if a.cmd == "build":
        return build(a)
    if a.cmd == "profile-for":
        # A pack given as a directory is looked up there first; a name, where
        # pack.sh installs, then in the repository.
        given = [Path(p) for p in a.packs if "/" in p]
        search = [g.parent for g in given] + (a.installed or installed_dirs()) + [a.packs_dir]
        names = [Path(p).name if "/" in p else p for p in a.packs]
        print(profile_for(search, names, tool_programs(a.tools_from), a.packs_dir))
        return 0
    if a.cmd == "job-profiles":
        given = [Path(p) for p in a.packs if "/" in p]
        search = [g.parent for g in given] + (a.installed or installed_dirs()) + [a.packs_dir]
        names = [Path(p).name if "/" in p else p for p in a.packs]
        print(json.dumps(job_profiles(search, names, a.packs_dir)))
        return 0
    if a.cmd == "check-lock":
        errors, warnings, entries = check_lock(a.lock)
        for w in warnings:
            print(f"  warning: {w}", file=sys.stderr)
        for e in errors:
            print(f"  refused: {e}", file=sys.stderr)
        if errors:
            print(f"recipe: {a.lock}: {len(errors)} entr{'y' if len(errors) == 1 else 'ies'} not pinned by digest", file=sys.stderr)
            return 1
        print(f"{a.lock}: {entries} image(s), each pinned by digest")
        return 0
    print(json.dumps({name: {"packs": resolve(a.packs_dir, prof["packs"]), "apt": prof.get("apt", [])} for name, prof in profiles().items()}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
