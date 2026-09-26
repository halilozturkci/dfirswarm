#!/usr/bin/env python3
"""Turn packs into image recipes, and say which image a run needs.

  recipe.py build PROFILE --out DIR [--base IMAGE] [--packs DIR]
  recipe.py profile-for [--installed DIR]... [--tools-from DIR]... PACK...
                                       the smallest profile that serves these packs
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

A program a pack marks `redistributable: false` stops the build unless
`--allow-nonredistributable` is given: an image that stays on this machine or
in a private registry, never one published for others to pull. The image then
says so (image.json, its label, its NOTICE).

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
                     `env` is the environment of a source's pip, or of a
                     build's configure and make; `arches`, the architectures
                     a source or a build is for (every one when absent).

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
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKS = HERE.parent / "packs"
# The programs every image has, since images/base.Dockerfile installs them:
# a tool that calls one of these needs no profile for it.
BASE_PROGRAMS = {"python3", "node", "jq", "sqlite3", "file", "xxd", "socat", "strings", "hexdump", "unzip",
                 "7z", "xz", "bzip2", "zstd", "curl", "exiftool"}
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


KINDS = ("apt", "pip", "apt_release", "requirements", "binaries", "manual", "downloads", "sources", "builds",
         "not_applicable", "python_notes")


def empty() -> dict:
    return {k: ({} if k in ("apt", "pip", "apt_release") else []) for k in KINDS}


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
                continue
            spec["binaries"].append({"name": b["name"], "pack": name, "required": required,
                                     "licence": b.get("licence"),
                                     "redistributable": b.get("redistributable", True) is not False,
                                     "source": line, "why": b.get("why", "")})
            pinned = [k for k in ("build", "source", "download") if isinstance(install.get(k), dict)]
            if pinned:
                kind = pinned[0]
                spec[kind + "s"].append({"name": b["name"], "pack": name, "required": required, **install[kind]})
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
                for p in words(m.group(1)):
                    spec["pip"][p] = spec["pip"].get(p, False) or required
            else:
                spec["manual"].append({"name": b["name"], "pack": name, "how": line or "no install line"})
    reqs = pack_dir(packs, name) / "requires" / "python.txt"
    if reqs.exists():
        for raw in reqs.read_text().splitlines():
            line, _, note = raw.partition("#")
            line = line.strip()
            if line:
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
        # A program two packs pin is installed once, as the first pins it.
        for kind in ("downloads", "sources", "builds", "not_applicable"):
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
    """The smallest profile whose image serves the wanted packs: one that holds
    them and their dependencies, or one that covers what they use, since a
    pack's skills and tools come from the pack itself and not from the image.
    Covering means every program the packs name, required or optional, is one
    the profile's packs name too, and every Python package their tools import
    is in the profile. `full` holds every pack, so it is always a candidate and
    only ever the choice when nothing smaller serves.

    The wanted packs are read from `search` (where the run's packs are
    installed); a profile's own packs from `images` (what the images are built
    from). `programs` are what the run's library tools call: among the
    profiles that serve the packs, one smaller than `full` that also names
    every one of them is preferred."""
    need = set(resolve(search, wanted))
    if not need and not set(programs) - BASE_PROGRAMS:
        return "base"
    # A pack found nowhere cannot be covered by anything known.
    if any(not (pack_dir(search, n) / "pack.json").exists() for n in need):
        return "full"
    _, want_named, want_python = needs_of(search, sorted(need))
    serving = []
    # A profile with extra packages is chosen by name, never by its packs.
    for name, prof in profiles().items():
        if prof.get("apt"):
            continue
        members = resolve(images, prof["packs"])
        _, named, python = needs_of(images, members)
        holds = need <= set(members)
        if not holds and not (want_named <= named and want_python <= python):
            continue
        serving.append((name, len(members), 0 if holds else 1, set(programs) - BASE_PROGRAMS <= named))
    if not serving:
        return "full"
    # A tool's programs move the choice to a bigger image only when one
    # smaller than full has them all; otherwise the packs decide, and the
    # probe says which program is missing.
    pool = [s for s in serving if s[3] and s[0] != "full"] or serving
    # Fewest packs first; between two of a size, the one that holds them.
    return min(pool, key=lambda s: (s[1], s[2]))[0]


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
    held_back = sorted({b["name"] for b in spec["binaries"] if not b.get("redistributable", True)})
    if held_back and not a.allow_nonredistributable:
        print(f"recipe: {a.profile} would hold {len(held_back)} program(s) their packs mark redistributable: false "
              f"({', '.join(held_back)}). Build with --allow-nonredistributable for an image that stays on this "
              f"machine or in a private registry; never publish it.", file=sys.stderr)
        return 3
    spec = {"profile": a.profile, "packs": packs, "profile_apt": list(extra_apt),
            "pack_versions": {p: pack_version(a.packs, p) for p in packs},
            "redistributable": not held_back, "nonredistributable": held_back, **spec}

    # Only ever "false" from here: with nothing held back, the image is as
    # redistributable as its base, whose label it then inherits (the base
    # sets it), and image.json says the same (install.py).
    redistributable = ' \\\n      dev.dfirswarm.redistributable="false"' if held_back else ""
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "spec.json").write_text(json.dumps(spec, indent=1) + "\n")
    (a.out / "NOTICE").write_text(notice(spec))
    shutil.copy(HERE / "install.py", a.out / "install.py")
    # A program built from source is built in a stage of its own, from the
    # same base, and only what `make install` put under its prefix is copied
    # across: the compiler and the -dev packages stay behind. Each stage reads
    # its own file, so every profile that builds the program shares its cache.
    stages, copies = [], []
    for d in spec["builds"]:
        stage = "build-" + re.sub(r"[^a-z0-9]+", "-", d["name"].lower()).strip("-")
        (a.out / f"{stage}.json").write_text(json.dumps(d, indent=1) + "\n")
        stages.append(f"""FROM ${{BASE}} AS {stage}
COPY install.py {stage}.json /tmp/dfirswarm-build/
RUN python3 /tmp/dfirswarm-build/install.py --build /tmp/dfirswarm-build/{stage}.json
""")
        copies.append(f"COPY --from={stage} /opt/dfir/tools/{d['name']} /opt/dfir/tools/{d['name']}\n")
    (a.out / "Dockerfile").write_text(f"""# Generated by images/recipe.py from packs: {", ".join(packs) or "none"}. Do not edit.
ARG BASE={a.base}
{"".join(s + chr(10) for s in stages)}FROM ${{BASE}}
{"".join(copies)}COPY install.py spec.json NOTICE /tmp/dfirswarm-build/
RUN python3 /tmp/dfirswarm-build/install.py /tmp/dfirswarm-build/spec.json \\
 && rm -rf /tmp/dfirswarm-build
ENV PATH=/opt/dfir/venv/bin:$PATH
LABEL org.opencontainers.image.title="dfirswarm-{a.profile}" \\
      dev.dfirswarm.profile="{a.profile}" \\
      dev.dfirswarm.packs="{",".join(packs)}"{redistributable}
""")
    req_apt = sum(spec["apt"].values())
    print(f"{a.profile}: {len(packs)} pack(s), {len(spec['apt'])} apt ({req_apt} required), {len(spec['pip'])} pip, "
          f"{len(spec['requirements'])} python requirements, {len(spec['downloads'])} pinned downloads, "
          f"{len(spec['sources'])} pinned sources, {len(spec['builds'])} built from source, "
          f"{len(spec['manual'])} neither, {len(spec['not_applicable'])} not applicable"
          + (f"; NOT for redistribution ({len(held_back)} programs)" if held_back else ""))
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
                   help="build an image holding programs their packs mark redistributable: false (never publish it)")
    f = sub.add_parser("profile-for")
    f.add_argument("packs", nargs="*", help="pack ids, or pack directories")
    f.add_argument("--packs-dir", type=Path, default=PACKS, help="the packs the images are built from")
    f.add_argument("--installed", type=Path, action="append",
                   help="where the run's packs are installed (default $DFIRSWARM_HOME/packs); repeatable")
    f.add_argument("--tools-from", type=Path, action="append", default=[],
                   help="a tool directory whose manifests' `requires` name the programs they call; repeatable")
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
