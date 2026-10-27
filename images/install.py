#!/usr/bin/env python3
"""Runs inside the image build. Installs what spec.json names and records
what the image ended up holding.

  install.py SPEC          a profile image: install what the spec names, then record
  install.py --base        the base image: record only (base.Dockerfile installs)
  install.py --build FILE  a builder stage: compile one program from its pinned
                           source under /opt/dfir/tools/<name>, which the
                           profile's stage copies (recipe.py writes both)

A package a pack marks required stops the build if it cannot be installed,
and so does a required program that is not on PATH afterwards. An optional
one that fails is recorded and the install goes on, but at the end every
program the packs name must be on PATH unless it was left out on purpose (a
download with no build for this architecture, a source or a build pinned for
other architectures, a program no line installs): a program that should be
here and is not stops the build, so nothing is tagged. A full disk once made
apt fail for optional programs and the image came out without them, saying so
only in its record. `recipe.py build --allow-missing-optional` lets such an
image be built, and it records what it lacks. The record,
/etc/dfirswarm/image.json, is what a run
cites for "which tools, at which versions, examined this"; /etc/dfirswarm/
NOTICE says whose each program is and under which licence; /etc/dfirswarm/
sbom.json lists every package the image holds (Debian, Python, npm, pinned
downloads with their sha256) as a CycloneDX document.

Every image, the base included, records its whole Debian package list
(`dpkg_all`) and its venv (`pip`): what a VM holds at stop is compared with
them (scripts/vm.ts INVENTORY_SCRIPT), so an install outside the image is
named and the image's own packages are not.

A pinned data file (`install.data`: a program's tables or rules, which the
program reads and which are not a program) is fetched and checked the same
way and put, as named, where the program looks for it: inside a Python package
of the image's venv (`package`, `into`). Its pack may name a command to run
once it is there (`warm`), for a program that indexes what it finds on first
use and would otherwise do it in every VM the image boots, and a command that
must succeed afterwards (`check`; the images workflow runs it again with no
network). A data file that cannot be had fails the build even when its program
is optional: the pack pinned it on purpose, and an image without it would say
the program is there while what it reads is not. `recipe.py build
--allow-missing-data` goes on without it, and the image then records it under
`not_installed.data`; one its build left out on purpose (`--symbol-set`) is
under `omitted.data`. An entry with `commands` is a source converted in the
build (fetch_data): the outputs are hashed, compared by content where pinned
(json-canon/1, canonical_sha256), and recorded apart from the source. An entry
the operator acquires is never downloaded here, and needs the operator's
recorded acceptance of its terms.

Every download is bounded: HTTPS on every redirect hop (at most five), no more
bytes than pinned (`bytes`, else DFIRSWARM_FETCH_MAX_BYTES), within
DFIRSWARM_FETCH_SECONDS in all. A local copy by sha256 in DFIRSWARM_DATA_DIR
(recipe.py build --data-from, --symbols-from) is used, still checked, instead
of the network.

A pinned download is fetched over HTTPS, checked against its sha256 before
anything is unpacked, unpacked under /opt/dfir/tools/<name>/ and put on PATH
by a wrapper in /usr/local/bin. An architecture with no entry is recorded,
not guessed. A `.deb` is installed by apt from where it was checked, so its
dependencies come from Debian. A pinned source is checked the same way,
unpacked under /opt/dfir/src/<name>/ (its archive's one top directory
dropped), given a venv of its own there when it names Python requirements —
one program's pins never move another's — and its entry is put on PATH the
same way, through its interpreter. A program built from source is checked,
configured with its prefix under /opt/dfir/tools, made and installed in a
builder stage; a failure there is recorded beside what it left and fails
the stage (a stage that ends well is cached, and a cached failure would be
every later build's), unless the program is not for this architecture or the
build allows optional programs to be missing. A source with no
configure script names its steps (`commands`, each an argument list run in the
unpacked tree, `{prefix}` and `{jobs}` filled in) and the pinned patches to
apply first (`patches`, each a url and a sha256, applied with `patch -p1`).
Every pinned artefact is in image.json (`downloads`, with its kind), the
NOTICE and the SBOM.
"""
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# Where the image's venv and record live; a test sets both.
VENV = Path(os.environ.get("DFIRSWARM_VENV", "/opt/dfir/venv"))
ETC = Path(os.environ.get("DFIRSWARM_ETC_DIR", "/etc/dfirswarm"))
RECORD = ETC / "image.json"
NOTICE = ETC / "NOTICE"
SBOM = ETC / "sbom.json"
# What an agent in a VM reads to learn what its image holds: one line a
# program, grep-able. The run's contract names this file and no program.
TOOLS_MD = ETC / "tools.md"
# Where pinned downloads go, where pinned sources are unpacked, where their
# programs are linked, and where apt's sources are; a test sets them.
TOOLS = Path(os.environ.get("DFIRSWARM_TOOLS_DIR", "/opt/dfir/tools"))
SRC = Path(os.environ.get("DFIRSWARM_SRC_DIR", "/opt/dfir/src"))
BIN = Path(os.environ.get("DFIRSWARM_BIN_DIR", "/usr/local/bin"))
APT_SOURCES = Path(os.environ.get("DFIRSWARM_APT_SOURCES_DIR", "/etc/apt/sources.list.d"))
# apt's package lists, emptied once the install is done; a test that runs the
# whole install on a host points this at its own directory.
APT_LISTS = Path(os.environ.get("DFIRSWARM_APT_LISTS_DIR", "/var/lib/apt/lists"))
OS_RELEASE = Path(os.environ.get("DFIRSWARM_OS_RELEASE", "/etc/os-release"))
# What a build leaves beside its program: whether it built, and from what.
BUILT = ".dfirswarm-build.json"
# The image's PATH, the venv first: where its programs are looked for.
IMAGE_PATH = f"{VENV / 'bin'}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
os.environ.setdefault("DEBIAN_FRONTEND", "noninteractive")


def run(cmd: list[str], cwd=None, env: dict | None = None) -> bool:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=cwd, env={**os.environ, **env} if env else None).returncode == 0


def arch() -> str:
    try:
        return subprocess.run(["dpkg", "--print-architecture"], capture_output=True, text=True).stdout.strip()
    except FileNotFoundError:
        return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(os.uname().machine, os.uname().machine)


def clean(name: str) -> str:
    """An archive member's name without the ./ some archivers put first."""
    while name.startswith("./"):
        name = name[2:]
    return name


def top_dir(names: list) -> str:
    """The one directory every member of an archive is under (a tag's
    tarball has one: <repo>-<tag>/), or "" when there is none."""
    names = [n for n in map(clean, names) if n not in ("", ".")]
    tops = {n.split("/", 1)[0] for n in names}
    if len(tops) != 1:
        return ""
    top = next(iter(tops))
    return top if any(n.startswith(top + "/") and len(n) > len(top) + 1 for n in names) else ""


def skipped(rel: str, skip: list) -> bool:
    return any(rel == s.strip("/") or rel.startswith(s.strip("/") + "/") for s in skip)


def safe_members(t: tarfile.TarFile, dest: Path, strip: bool = False, skip: list = ()) -> list:
    """Regular files, directories and links that stay under dest; nothing
    else. Debian 12's Python (3.11.2) predates extractall's filter argument.
    With strip, the archive's one top directory is dropped from every name;
    a member under a `skip` path (relative to what is kept) is left out."""
    root = dest.resolve()
    members = t.getmembers()
    top = top_dir([m.name for m in members]) if strip else ""
    keep = []
    for m in members:
        if top:
            name = clean(m.name)
            if not name.startswith(top + "/") or not name[len(top) + 1:].strip("/"):
                continue
            m.name = name[len(top) + 1:]
            if m.islnk() and clean(m.linkname).startswith(top + "/"):
                m.linkname = clean(m.linkname)[len(top) + 1:]
        if skip and skipped(clean(m.name), skip):
            continue
        target = (root / m.name).resolve()
        if not (target == root or str(target).startswith(f"{root}/")):
            raise ValueError(f"{m.name} leaves the download's directory")
        if m.issym() or m.islnk():
            link = (target.parent / m.linkname).resolve() if m.issym() else (root / m.linkname).resolve()
            if not str(link).startswith(f"{root}/"):
                raise ValueError(f"{m.name} links outside the download's directory")
        elif not (m.isfile() or m.isdir()):
            continue
        m.mode &= 0o755
        keep.append(m)
    return keep


DOWNLOAD_ATTEMPTS = 3
# A download's bounds: no more redirects than this, every hop over HTTPS, no
# more bytes than its pin says (or this many when it pins none), and no longer
# than this in all. A pack's URL is https (pack.sh); file:// and a loopback
# http:// are a test's.
MAX_REDIRECTS = 5
MAX_BYTES = int(os.environ.get("DFIRSWARM_FETCH_MAX_BYTES", str(4 << 30)))
FETCH_SECONDS = int(os.environ.get("DFIRSWARM_FETCH_SECONDS", "3600"))
# A local copy of what a pin names, by its sha256 (recipe.py build --data-from
# and --symbols-from put them here): used instead of the network, still checked.
DATA_DIR = os.environ.get("DFIRSWARM_DATA_DIR", "")


class HttpsRedirects(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to https and only MAX_REDIRECTS times; the
    host it lands on is said, never the query (a signed URL is a credential
    of sorts). Any other scheme is refused."""
    max_redirections = MAX_REDIRECTS

    def __init__(self, allowed_hosts: list | None = None):
        super().__init__()
        self.allowed_hosts = allowed_hosts
        self.last_host = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlparse(newurl)
        if u.scheme != "https":
            raise urllib.error.URLError(f"a redirect to {u.scheme or 'no scheme'}:// was refused: every hop must be https")
        if u.port not in (None, 443):
            raise urllib.error.URLError(f"a redirect to port {u.port} was refused: every hop must be https on 443")
        if self.allowed_hosts is not None and not host_allowed(u.hostname or "", self.allowed_hosts):
            raise urllib.error.URLError(f"a redirect to {u.hostname} was refused: not one of {', '.join(self.allowed_hosts)}")
        print(f"+ redirected to {u.hostname}", flush=True)
        self.last_host = u.hostname
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def host_allowed(host: str, allowed: list) -> bool:
    """host is one of allowed, where `*.example.org` stands for any name under it."""
    host = host.lower().rstrip(".")
    for a in allowed:
        a = a.lower()
        if host == a or (a.startswith("*.") and host.endswith(a[1:]) and len(host) > len(a) - 1):
            return True
    return False


# Where a sync client copies what is put there: a store of the operator's
# files, and a build context holding a copy of one, never go there.
SYNCED = ("/Library/CloudStorage/", "/Library/Mobile Documents/", "/Dropbox/", "/OneDrive", "/Google Drive/",
          "/iCloud Drive/", "/Box Sync/")


def synced(path: Path) -> str | None:
    """The marker of a synced folder the path is in, or None."""
    real = str(Path(path).expanduser().resolve()) + "/"
    for m in SYNCED:
        if m in real:
            return m.strip("/")
    return None


def in_checkout(path: Path) -> str | None:
    """The git checkout the path is in (a directory above it holding .git), or None."""
    p = Path(path).expanduser().resolve()
    for d in (p, *p.parents):
        if (d / ".git").exists():
            return str(d)
    return None


def local_copy(sha256: str) -> Path | None:
    """The mirror's file for this sha256, or None."""
    if not DATA_DIR:
        return None
    p = Path(DATA_DIR) / sha256
    return p if p.is_file() else None


def fetch_once(url: str, dest: Path, size: int | None, allowed_hosts: list | None = None, opener_handlers: list | None = None) -> tuple:
    """One bounded download of url to dest: (sha256 hex, bytes got,
    Content-Length or None). Raises OSError (URLError among them) when it
    cannot, or when it passes its bounds. opener_handlers replace the
    redirect rule (an HttpsRedirects of the caller's) and add others."""
    u = urllib.parse.urlparse(url)
    # A pack's URL is https (pack.sh refuses any other); file:// and a
    # loopback http:// server are a test's.
    if not (u.scheme in ("https", "file") or (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1"))):
        raise urllib.error.URLError(f"{u.scheme}:// is not fetched: a pinned URL is https")
    cap = size if size is not None else MAX_BYTES
    deadline = time.monotonic() + FETCH_SECONDS
    digest = hashlib.sha256()
    got = 0
    # Named: a host behind a bot filter (Eric Zimmerman's) refuses Python's
    # own User-Agent with a 403, and says so in no other way.
    req = urllib.request.Request(url, headers={"User-Agent": "dfirswarm-image-build (+https://github.com/halilozturkci/dfirswarm)"})
    opener = urllib.request.build_opener(*(opener_handlers or [HttpsRedirects(allowed_hosts)]))
    with opener.open(req, timeout=300) as r, open(dest, "wb") as out:
        length = r.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > cap:
            raise urllib.error.URLError(f"the server offers {length} bytes, more than the {cap} this pin allows")
        while chunk := r.read(1 << 20):
            got += len(chunk)
            if got > cap:
                raise urllib.error.URLError(f"more than the {cap} bytes this pin allows")
            if time.monotonic() > deadline:
                raise urllib.error.URLError(f"not done within {FETCH_SECONDS} s")
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest(), got, length


def obtain(url: str, dest: Path, sha256: str, size: int | None = None, offline: bool = False) -> tuple:
    """Put the pinned bytes at dest: from the local mirror when it holds them
    (DFIRSWARM_DATA_DIR), else from url unless `offline`. Returns (why it
    failed or None, how: "local copy" | "download"). Bytes that are not the
    pinned ones are deleted. A download that fails or ends short is tried
    again: a runtime that arrived cut off after twelve slow minutes, with the
    right bytes at that URL a minute later, took three programs that need it
    out of an image."""
    want = sha256.removeprefix("sha256:").lower()
    mirror = local_copy(want)
    if mirror:
        print(f"+ copy {mirror} (the local copy of {url})", flush=True)
        digest = hashlib.sha256()
        with open(mirror, "rb") as src, open(dest, "wb") as out:
            while chunk := src.read(1 << 20):
                digest.update(chunk)
                out.write(chunk)
        if digest.hexdigest() == want and (size is None or dest.stat().st_size == size):
            return None, "local copy"
        dest.unlink(missing_ok=True)
        return f"the local copy {mirror} is not the pinned bytes (sha256 {digest.hexdigest()})", "local copy"
    if offline:
        return "it is not fetched by the build, and no local copy of it was given", "local copy"
    why = None
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        print(f"+ fetch {url}" + (f" (attempt {attempt} of {DOWNLOAD_ATTEMPTS})" if attempt > 1 else ""), flush=True)
        try:
            hexd, got, length = fetch_once(url, dest, size)
        except (OSError, http.client.HTTPException) as e:
            dest.unlink(missing_ok=True)
            why = f"download failed: {e}"
            # A refusal by the bounds is not cured by asking again.
            if "refused" in str(e) or "more than" in str(e) or "is not fetched" in str(e):
                break
            continue
        if hexd == want and (size is None or got == size):
            return None, "download"
        dest.unlink(missing_ok=True)
        short = f" after {got} of {length} bytes" if length and length.isdigit() and int(length) != got else ""
        why = f"sha256 {hexd}{short} is not the pinned {want}" if hexd != want else f"{got} bytes, not the pinned {size}"
        # The whole length and other bytes: the file at the URL changed, and
        # another attempt fetches the same wrong bytes.
        if not short and length:
            break
    return why, "download"


def get(url: str, dest: Path, sha256: str, size: int | None = None) -> str | None:
    """Fetch url to dest and check it against the pinned sha256 (and size).
    Returns why it failed, or None."""
    return obtain(url, dest, sha256, size)[0]


def wrapper(name: str, program: Path, run_with: str | None = None, run_from_dir: bool = False,
            python: Path | None = None, pythonpath: Path | None = None) -> str | None:
    """Put `name` on PATH as a small script that runs the program, through its
    interpreter when it names one: `python` (the program's own venv when it
    has one, else the image's), or a program the image holds (perl, dotnet).
    Returns why it could not, or None."""
    # A wrapper, not a link: a program that finds its own files from $0 (uac
    # does) would look in the link's directory and find nothing.
    if run_with == "python":
        interp = str(python or VENV / "bin" / "python")
    elif run_with:
        interp = shutil.which(run_with, path=f"{BIN}:{VENV / 'bin'}:{os.environ.get('PATH', '')}")
        if not interp:
            return f"its runtime {run_with} is not in the image"
    else:
        interp = None
        program.chmod(0o755)
    # A program that must run from its own directory (uac checks `pwd`)
    # gets a wrapper that changes into it: paths given to it must then be
    # absolute, which its pack says.
    target = f'"./{program.name}"' if run_from_dir else f'"{program}"'
    lines = ["#!/bin/sh"]
    if pythonpath:
        # Run from a checkout, as its README runs it: its own modules import.
        lines.append(f'export PYTHONPATH="{pythonpath}${{PYTHONPATH:+:$PYTHONPATH}}"')
    if run_from_dir:
        lines.append(f'cd "{program.parent}" || exit 1')
    lines.append(f'exec "{interp}" {target} "$@"' if interp else f'exec {target} "$@"')
    link = BIN / name
    link.unlink(missing_ok=True)
    link.write_text("\n".join(lines) + "\n")
    link.chmod(0o755)
    return None


def fetch(d: dict, apt: list) -> tuple:
    """Install one pinned download. Returns (record, failure reason)."""
    entry = d.get(arch())
    if not isinstance(entry, dict) or not entry.get("url") or not entry.get("sha256"):
        return None, f"no {arch()} build pinned"
    if d.get("apt_deps") and not run(apt + list(d["apt_deps"])):
        return None, f"its libraries ({', '.join(d['apt_deps'])}) did not install"
    dest = TOOLS / d["name"]
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / Path(urllib.parse.urlparse(entry["url"]).path).name
    why = get(entry["url"], archive, entry["sha256"])
    if why:
        return None, why
    want = entry["sha256"].removeprefix("sha256:").lower()
    name = archive.name.lower()
    if name.endswith(".deb"):
        # A Debian package: apt installs it from where it was checked, and
        # takes what it depends on from Debian's archive.
        ok = run(apt + [str(archive)])
        shutil.rmtree(dest, ignore_errors=True)
        if not ok:
            return None, "apt could not install the package"
        if not entry.get("bin"):
            if not shutil.which(d["name"], path=os.environ.get("PATH", "")):
                return None, f"the package does not put {d['name']} on PATH"
            return {"kind": "deb", "version": d.get("version"), "url": entry["url"], "sha256": want}, None
        program = Path(entry["bin"])
        if not program.is_file():
            return None, f"{entry['bin']} is not what the package installed"
    else:
        try:
            unpack(archive, name, dest)
        except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as e:
            return None, f"could not unpack: {e}"
        program = dest / entry.get("bin", archive.name)
        if not program.is_file():
            return None, f"{entry.get('bin', archive.name)} is not in what was downloaded"
    why = wrapper(d["name"], program, d.get("run"), bool(d.get("run_from_dir")))
    if why:
        return None, why
    return {"kind": "deb" if name.endswith(".deb") else "download", "version": d.get("version"),
            "url": entry["url"], "sha256": want}, None


def unpack(archive: Path, name: str, dest: Path, strip: bool = False, skip: list = ()) -> None:
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            names = z.namelist()
            top = top_dir(names) if strip else ""
            root = dest.resolve()
            for info in z.infolist():
                rel = clean(info.filename)
                if top:
                    rel = rel[len(top) + 1:] if rel.startswith(top + "/") else ""
                if not rel.strip("/") or (skip and skipped(rel, skip)):
                    continue
                target = (root / rel).resolve()
                if not (target == root or str(target).startswith(f"{root}/")):
                    raise ValueError(f"{info.filename} leaves the download's directory")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
        archive.unlink()
    elif name.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar")):
        with tarfile.open(archive) as t:
            t.extractall(dest, members=safe_members(t, dest, strip, skip))
        archive.unlink()


def fetch_source(d: dict, apt: list) -> tuple:
    """Install one pinned source: checked, unpacked under SRC/<name>, its
    Python requirements in a venv of its own, its entry on PATH. Returns
    (record, failure reason)."""
    if d.get("arches") and arch() not in d["arches"]:
        return None, f"not for {arch()}: its pack pins it for {', '.join(d['arches'])} only"
    if not d.get("url") or not d.get("sha256") or not d.get("entry"):
        return None, "no url, sha256 and entry pinned"
    if d.get("apt_deps") and not run(apt + list(d["apt_deps"])):
        return None, f"its libraries ({', '.join(d['apt_deps'])}) did not install"
    dest = SRC / d["name"]
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    archive = SRC / f".{d['name']}-{Path(urllib.parse.urlparse(d['url']).path).name}"
    why = get(d["url"], archive, d["sha256"])
    if why:
        return None, why
    try:
        unpack(archive, archive.name.lower(), dest, strip=True, skip=list(d.get("skip") or []))
    except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as e:
        archive.unlink(missing_ok=True)
        return None, f"could not unpack: {e}"
    venv = None
    if d.get("pip") or d.get("pip_after"):
        # Its own venv: one program's pins (an old beautifulsoup4, an exact
        # numpy) must not move what another program or the tool library imports.
        venv = dest / ".venv"
        if not run([sys.executable, "-m", "venv", str(venv)]):
            return None, "its venv could not be made"
        # `env` reaches what pip builds: an sdist's own configure reads it.
        # `pip_after` is a second install into the same venv, for what one
        # resolve cannot say: a dependency installed with --no-deps at a pinned
        # commit, over the unpinned URL a requirement names for it.
        for key in ("pip", "pip_after"):
            if d.get(key) and not run([str(venv / "bin" / "pip"), "install", "--no-cache-dir", *d[key]], cwd=dest, env=d.get("env")):
                return None, f"its Python requirements (pip install {' '.join(d[key])}) did not install"
    program = dest / d["entry"]
    if not program.is_file():
        return None, f"{d['entry']} is not in the archive"
    python = venv / "bin" / "python" if venv else None
    why = wrapper(d["name"], program, d.get("run"), bool(d.get("run_from_dir")), python,
                  dest if d.get("run") == "python" else None)
    if why:
        return None, why
    rec = {"kind": "source", "version": d.get("version"), "url": d["url"],
           "sha256": d["sha256"].removeprefix("sha256:").lower(), "dir": str(dest)}
    if venv:
        rec["venv"] = str(venv)
    return rec, None


PACKAGE_DIR = """
import importlib.util, os, sys
spec = importlib.util.find_spec(sys.argv[1])
print(os.path.dirname(spec.origin) if spec and spec.origin else "")
"""


def package_dir(package: str) -> Path | None:
    """The directory of a Python package in the image's venv, or None."""
    py = VENV / "bin" / "python"
    if not py.exists():
        return None
    out = subprocess.run([str(py), "-c", PACKAGE_DIR, package], capture_output=True, text=True).stdout.strip()
    return Path(out) if out else None


# The rule a derived file's content is compared by, versioned: a converter
# that writes the time it ran into its output (Volatility's pdbconv does, in
# metadata.producer.datetime) makes new bytes every time from the same input,
# so its output is pinned by content, never by its bytes.
#
# json-canon/1: decompress (xz or gzip, by their magic; at most
# CANON_MAX_BYTES), decode UTF-8 strictly, parse JSON refusing a duplicate key
# and a number that is not finite, remove the dotted paths the pin names (only
# those), and hash json.dumps(sort_keys=True, ensure_ascii=True) with the
# default separators, UTF-8, no trailing newline.
CANON_RULES = ("json-canon/1",)
CANON_MAX_BYTES = 1 << 30


class CanonError(ValueError):
    pass


def inflate(path: Path, limit: int = CANON_MAX_BYTES) -> bytes:
    """A file's bytes, decompressed when it is xz or gzip, refused past limit."""
    import gzip
    import lzma
    with open(path, "rb") as f:
        head = f.read(6)
    opener = lzma.open if head.startswith(b"\xfd7zXZ\x00") else gzip.open if head[:2] == b"\x1f\x8b" else open
    out = bytearray()
    with opener(path, "rb") as f:
        while chunk := f.read(1 << 20):
            out += chunk
            if len(out) > limit:
                raise CanonError(f"more than {limit} bytes once decompressed")
    return bytes(out)


def canonical_json(raw: bytes, drop: list) -> bytes:
    """The canonical form of a JSON document (json-canon/1), less the dotted paths in drop."""
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise CanonError(f"duplicate key {k!r}")
            d[k] = v
        return d

    def finite(text):
        v = float(text)
        if v != v or v in (float("inf"), float("-inf")):
            raise CanonError(f"a number that is not finite ({text})")
        return v

    def constant(name):
        raise CanonError(f"a number that is not finite ({name})")

    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=finite, parse_constant=constant)
    except UnicodeDecodeError as e:
        raise CanonError(f"not UTF-8: {e}") from None
    except json.JSONDecodeError as e:
        raise CanonError(f"not JSON: {e}") from None
    for path in drop:
        *parents, last = path.split(".")
        node = obj
        for part in parents:
            node = node.get(part) if isinstance(node, dict) else None
        if isinstance(node, dict):
            node.pop(last, None)
    return json.dumps(obj, sort_keys=True, ensure_ascii=True).encode("utf-8")


def canonical_sha256(path: Path, rule: str, drop: list) -> str:
    if rule not in CANON_RULES:
        raise CanonError(f"no canonical rule {rule!r} (known: {', '.join(CANON_RULES)})")
    return hashlib.sha256(canonical_json(inflate(path), drop)).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def venv_answer(code: str, *args: str) -> str:
    """What the image's venv Python prints for code, or ""."""
    py = VENV / "bin" / "python"
    if not py.exists():
        return ""
    return subprocess.run([str(py), "-c", code, *args], capture_output=True, text=True).stdout.strip()


def placeholders(argv: list, fill: dict) -> list:
    """argv with {file} and {dir} filled in; every other brace left as it is."""
    return [re.sub(r"\{(file|dir)\}", lambda m: fill[m.group(1)], str(a)) for a in argv]


def resolve_argv(argv: list) -> list:
    argv = list(argv)
    argv[0] = shutil.which(argv[0], path=IMAGE_PATH) or argv[0]
    return argv


def fetch_data(d: dict) -> tuple:
    """Install one pinned data file a program reads: checked against its sha256
    (and `bytes`), then put, under the name it has at its URL (or `file`), in
    `into` inside the directory of the Python package `package`, where the
    program looks for it. The same bytes for every architecture.

    An entry with `commands` is a source the build turns into what the program
    reads: it is fetched into a work directory, each command (an argument list,
    {file} the source and {dir} where the program looks) is run, every file in
    `outputs` must then be there, each is hashed, and one with `canonical` is
    compared by its content (json-canon/1) with the pinned `canonical_sha256`;
    the source is kept only with `keep`. `converter` pins the version of the
    package that converts, since a content hash holds for one version alone.
    An entry acquired by the operator (`acquire: "operator"`) is never fetched
    here: it comes from the local copy the build was given, or not at all.
    Returns (record, failure reason)."""
    if not d.get("url") or not d.get("sha256") or not d.get("package"):
        return None, "no url, sha256 and package pinned"
    root = package_dir(d["package"])
    if not root:
        return None, f"its program's Python package {d['package']} is not in the image"
    dest_dir = (root / d.get("into", "")).resolve()
    if not (dest_dir == root.resolve() or str(dest_dir).startswith(f"{root.resolve()}/")):
        return None, f"{d.get('into')} leaves the package's directory"
    name = d.get("file") or Path(urllib.parse.urlparse(d["url"]).path).name
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        return None, f"the file name {name!r} is not a plain name"
    conv = d.get("converter") if isinstance(d.get("converter"), dict) else None
    if conv and conv.get("package") and conv.get("version"):
        have = venv_answer("import importlib.metadata as m, sys; print(m.version(sys.argv[1]))", conv["package"])
        if have != conv["version"]:
            return None, (f"its converter {conv['package']} is {have or 'not installed'}, not the pinned {conv['version']}: "
                          "the content of what it makes is pinned for that version alone")
    # What the operator acquires is built in only with the operator's recorded
    # acceptance of its terms (recipe.py copies it from the symbol store).
    if d.get("acquire") == "operator" and not (isinstance(d.get("acceptance"), dict) and d["acceptance"].get("accepted_by")):
        return None, ("no recorded acceptance of its terms: the operator fetches it accepting them "
                      "(scripts/swarm.sh symbols fetch --accept-terms), then recipe.py build --symbols-from")
    commands = d.get("commands") or []
    dest_dir.mkdir(parents=True, exist_ok=True)
    work = None
    if commands:
        # A source to be converted is not put where the program looks.
        work = TOOLS / ".data-work" / d["name"]
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True)
        dest = work / name
    else:
        dest = dest_dir / name
    why, how = obtain(d["url"], dest, d["sha256"], d.get("bytes"), offline=d.get("acquire") == "operator")
    if why:
        if work:
            shutil.rmtree(work, ignore_errors=True)
        if d.get("acquire") == "operator":
            why += " (the operator fetches it: scripts/swarm.sh symbols fetch, then recipe.py build --symbols-from)"
        return None, why
    rec = {"kind": "data", "version": d.get("version"), "url": d["url"],
           "sha256": d["sha256"].removeprefix("sha256:").lower(), "path": str(dest),
           "bytes": dest.stat().st_size, "program": d.get("program"), "from": how}
    for key in ("set", "acquire", "identity", "distribution_policy", "redistributable", "terms"):
        if key in d:
            rec[key] = d[key]
    made: list = []

    def undo(reason: str) -> tuple:
        for f in made:
            Path(f).unlink(missing_ok=True)
        if work:
            shutil.rmtree(work, ignore_errors=True)
        else:
            dest.unlink(missing_ok=True)
        return None, reason

    if commands:
        fill = {"file": str(dest), "dir": str(dest_dir)}
        # Where each output goes exists before the commands run: a converter
        # writes a file, not the directories above it.
        for o in d.get("outputs") or []:
            rel = str(o.get("path", ""))
            if rel and not rel.startswith("/") and ".." not in rel.split("/"):
                (dest_dir / rel).parent.mkdir(parents=True, exist_ok=True)
        # What the commands say is kept whole in the image, named in the
        # record: a converter's progress runs to megabytes, past what a build
        # log shows.
        log = ETC / "data-logs" / f"{d['name']}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.unlink(missing_ok=True)
        ran = []
        for argv in commands:
            argv = placeholders(argv, fill)
            ran.append(argv)
            print("+", " ".join(argv), f"(its output: {log})", flush=True)
            try:
                with open(log, "ab") as lf:
                    lf.write(("+ " + " ".join(argv) + "\n").encode())
                    lf.flush()
                    ok = subprocess.run(resolve_argv(argv), cwd=work, stdout=lf, stderr=subprocess.STDOUT).returncode == 0
            except OSError as e:
                with open(log, "ab") as lf:
                    lf.write(f"could not run: {e}\n".encode())
                ok = False
            if not ok:
                # The build that fails keeps no image: the end of what it said is shown here.
                tail = log.read_bytes()[-8192:].decode("utf-8", "replace")
                print(f"--- the last {len(tail)} of {log.stat().st_size} bytes of {log} ---\n{tail}", file=sys.stderr, flush=True)
                return undo(f"its command ({' '.join(argv)}) failed")
        outputs = []
        for o in d.get("outputs") or []:
            rel = str(o.get("path", ""))
            p = (dest_dir / rel).resolve()
            if not rel or rel.startswith("/") or ".." in rel.split("/") or not str(p).startswith(f"{dest_dir}/"):
                return undo(f"the output {rel!r} is not a path inside {dest_dir}")
            if not p.is_file():
                return undo(f"its commands left no {rel}")
            made.append(str(p))
            p.chmod(0o644)
            orec = {"path": str(p), "sha256": sha256_file(p), "bytes": p.stat().st_size}
            canon = o.get("canonical") if isinstance(o.get("canonical"), dict) else None
            if canon:
                drop = [str(x) for x in canon.get("drop") or []]
                try:
                    got = canonical_sha256(p, str(canon.get("rule")), drop)
                except (CanonError, OSError, EOFError) as e:
                    return undo(f"{rel}: its content could not be read by {canon.get('rule')}: {e}")
                orec.update({"canonical_rule": canon.get("rule"), "canonical_drop": drop, "canonical_sha256": got})
                want = str(o.get("canonical_sha256") or "").lower()
                if want and got != want:
                    return undo(f"{rel}: its content ({canon.get('rule')}) is sha256 {got}, not the pinned {want}: "
                                "another converter, or another source, made it")
            if isinstance(o.get("identity"), dict):
                orec["identity"] = o["identity"]
            outputs.append(orec)
        keep = bool(d.get("keep", False))
        rec["source"] = {"url": d["url"], "sha256": rec["sha256"], "bytes": rec["bytes"], "from": how, "kept": keep}
        rec["transform"] = {"commands": [[a.replace(str(dest), name) for a in argv] for argv in ran],
                            "package": d["package"],
                            "package_version": venv_answer("import importlib.metadata as m, sys; print(m.version(sys.argv[1]))", d["package"]) or None,
                            "python": venv_answer("import platform; print(platform.python_version())") or None}
        if conv:
            rec["transform"]["converter"] = conv
        rec["transform"]["log"] = {"path": str(log), "sha256": sha256_file(log), "bytes": log.stat().st_size}
        rec["outputs"] = outputs
        if keep:
            kept = dest_dir / name
            shutil.move(str(dest), kept)
            kept.chmod(0o644)
            rec["path"] = str(kept)
        else:
            rec["path"] = None
        shutil.rmtree(work, ignore_errors=True)
        work = None
    else:
        dest.chmod(0o644)
    if isinstance(d.get("acceptance"), dict):
        # Who accepted the supplier's terms, when, for which bytes, and what
        # this image made of them: the acceptance travels with the table.
        rec["acceptance"] = {**d["acceptance"], "source_sha256": rec["sha256"],
                             "outputs": [{k: o[k] for k in ("path", "sha256", "canonical_rule", "canonical_sha256") if k in o}
                                         for o in rec.get("outputs") or []]}
    fill = {"file": rec["path"] or "", "dir": str(dest_dir)}
    if d.get("warm"):
        # A program that indexes what it finds the first time it runs is run
        # once here, so the image holds the index and no VM builds it again.
        try:
            rec["warm"] = "done" if run(resolve_argv(placeholders(d["warm"], fill))) else "failed"
        except OSError:
            # The program is not there (its own install failed): the data
            # is, and the record says it was not warmed.
            rec["warm"] = "failed"
    if d.get("check"):
        # What the pack says must hold once the file is there: the program
        # finds it. A file the program cannot find is not installed.
        argv = placeholders(d["check"], fill)
        try:
            ok = run(resolve_argv(argv))
        except OSError:
            ok = False
        if not ok:
            if rec["path"]:
                Path(rec["path"]).unlink(missing_ok=True)
            return undo(f"its check ({' '.join(argv)[:160]}) failed once the file was in place")
        rec["check"] = argv
    return rec, None


def build_source(spec_path: str) -> int:
    """A builder stage: compile one program from its pinned source, installed
    under TOOLS/<name>, and say beside it whether it built. A program that did
    not build fails the stage, optional or not: Docker caches a stage that
    ends well, and a failure kept in the cache (apt out of disk space) would be
    every later build's, the image silently without the program. Two
    exceptions end well with the failure recorded, for the profile's stage to
    copy: a program its pack pins for other architectures, and an optional one
    the build allows to be missing (`may_fail`, which recipe.py sets with a
    build id of its own, so that stage is never taken from the cache)."""
    d = json.loads(Path(spec_path).read_text())
    dest = TOOLS / d["name"]
    dest.mkdir(parents=True, exist_ok=True)

    def done(why: str | None, elsewhere: bool = False) -> int:
        rec = {"kind": "build", "version": d.get("version"), "url": d.get("url"),
               "sha256": str(d.get("sha256", "")).removeprefix("sha256:").lower(), "ok": why is None}
        if d.get("patches"):
            rec["patches"] = [{"url": p.get("url"), "sha256": str(p.get("sha256", "")).removeprefix("sha256:").lower()}
                              for p in d["patches"]]
        if why:
            rec["why"] = why
        (dest / BUILT).write_text(json.dumps(rec, indent=1) + "\n")
        if why:
            print(f"{d['name']} did not build: {why}", file=sys.stderr)
            if d.get("required"):
                return 1
            return 0 if elsewhere or d.get("may_fail") else 1
        return 0

    if d.get("arches") and arch() not in d["arches"]:
        return done(f"not built for {arch()} (its pack builds it for {', '.join(d['arches'])})", elsewhere=True)
    if not d.get("url") or not d.get("sha256") or not d.get("bin"):
        return done("no url, sha256 and bin pinned")
    apt = ["apt-get", "install", "-y", "--no-install-recommends"]
    if d.get("build_deps") and not (run(["apt-get", "update"]) and run(apt + list(d["build_deps"]))):
        return done(f"its build dependencies ({', '.join(d['build_deps'])}) did not install")
    work = Path(os.environ.get("DFIRSWARM_BUILD_DIR", "/tmp/dfirswarm-src")) / d["name"]
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    archive = work.parent / f".{d['name']}-{Path(urllib.parse.urlparse(d['url']).path).name}"
    why = get(d["url"], archive, d["sha256"])
    if why:
        return done(why)
    try:
        unpack(archive, archive.name.lower(), work, strip=True)
    except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as e:
        return done(f"could not unpack: {e}")
    jobs = str(os.cpu_count() or 2)
    env = d.get("env")
    # A pack that patches its source (a distribution's fixes to an old
    # upstream release) pins each patch like the archive: checked first, then
    # applied in order.
    for patch in d.get("patches") or []:
        if not patch.get("url") or not patch.get("sha256"):
            return done("a patch with no url and sha256 pinned")
        pname = Path(urllib.parse.urlparse(patch["url"]).path).name
        file = work.parent / f".{d['name']}.patch.{pname}"
        why = get(patch["url"], file, patch["sha256"])
        if why:
            return done(f"patch {pname}: {why}")
        applied = run(["patch", "-p1", "--batch", "-i", str(file)], cwd=work)
        file.unlink(missing_ok=True)
        if not applied:
            return done(f"patch {pname} did not apply")
    if d.get("commands"):
        # A source with no configure script: the pack names its steps.
        for argv in d["commands"]:
            argv = [str(a).replace("{prefix}", str(dest)).replace("{jobs}", jobs) for a in argv]
            if not run(argv, cwd=work, env=env):
                return done(f"{argv[0]} failed")
    else:
        if not run(["./configure", f"--prefix={dest}", *d.get("configure", [])], cwd=work, env=env):
            return done("./configure failed")
        if not run(["make", f"-j{jobs}"], cwd=work, env=env):
            return done("make failed")
        # install-strip where the build has it: a program's debug symbols are
        # most of its size and no examination reads them.
        if not (run(["make", "install-strip"], cwd=work, env=env) or run(["make", "install"], cwd=work, env=env)):
            return done("make install failed")
    shutil.rmtree(work, ignore_errors=True)
    if not (dest / d["bin"]).is_file():
        return done(f"{d['bin']} is not what make install put under {dest}")
    return done(None)


def link_build(d: dict, apt: list) -> tuple:
    """A program its builder stage compiled: the libraries it runs with, and
    its wrapper. Returns (record, failure reason)."""
    dest = TOOLS / d["name"]
    try:
        rec = json.loads((dest / BUILT).read_text())
    except (OSError, ValueError):
        return None, "its builder stage left no record"
    if not rec.get("ok"):
        return None, rec.get("why") or "it did not build"
    if d.get("apt_deps") and not run(apt + list(d["apt_deps"])):
        return None, f"its libraries ({', '.join(d['apt_deps'])}) did not install"
    why = wrapper(d["name"], dest / d["bin"], d.get("run"))
    if why:
        return None, why
    return {k: rec[k] for k in ("kind", "version", "url", "sha256", "patches") if k in rec}, None


def enable_release(release: str) -> str | None:
    """Make apt see `release`, when it is this image's Debian backports
    (bookworm-backports on bookworm), from the mirror the image already uses.
    Returns why not, or None. Nothing else is added: a package from another
    release would mix two Debians in one image."""
    try:
        rel = dict(line.split("=", 1) for line in OS_RELEASE.read_text().splitlines() if "=" in line)
        codename = rel.get("VERSION_CODENAME", "").strip('"')
    except OSError:
        codename = ""
    if not codename or release != f"{codename}-backports":
        return f"{release} is not this image's backports ({codename or 'unknown'}-backports)"
    # The image's own mirror (debian.sources), not the security one.
    uris = [line.split()[1] for f in sorted(APT_SOURCES.glob("*.sources")) for line in f.read_text().splitlines()
            if line.startswith("URIs:") and len(line.split()) > 1]
    mirror = next((u for u in uris if not u.rstrip("/").endswith("-security")), "http://deb.debian.org/debian")
    APT_SOURCES.mkdir(parents=True, exist_ok=True)
    (APT_SOURCES / f"dfirswarm-{release}.sources").write_text(
        f"Types: deb\nURIs: {mirror}\nSuites: {release}\nComponents: main\n"
        f"Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n")
    return None


LICENCES = r"""
import json
from importlib import metadata as m
rows = []
for d in m.distributions():
    md = d.metadata
    lic = md.get("License-Expression") or ""
    if not lic:
        classifiers = [c.split(" :: ")[-1] for c in (md.get_all("Classifier") or []) if c.startswith("License")]
        lic = "; ".join(classifiers) or (md.get("License") or "")
    rows.append([md["Name"], d.version, " ".join(lic.split()) or "licence not stated"])
print(json.dumps(sorted(rows)))
"""


def python_packages(venv: Path = VENV) -> list:
    """Every Python package in a venv (the image's, or a pinned source's own):
    [name, version, the licence its metadata states]."""
    if not (venv / "bin" / "python").exists():
        return []
    listed = subprocess.run([str(venv / "bin" / "python"), "-c", LICENCES], capture_output=True, text=True).stdout
    return json.loads(listed or "[]")


def source_venvs(record: dict) -> list:
    """(program, venv) for each pinned source that has a venv of its own."""
    return [(name, Path(d["venv"])) for name, d in sorted((record.get("downloads") or {}).items()) if d.get("venv")]


def npm_packages() -> list:
    """Every package under npm's global root, nested dependencies included:
    [name, version, licence]. Pi and what it pulls in live there."""
    try:
        root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True, timeout=60).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return []
    if not root or not os.path.isdir(root):
        return []
    rows = set()
    top = Path(root)

    def modules(d: Path) -> bool:
        return d == top or d.name == "node_modules"

    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != ".bin"]
        here = Path(dirpath)
        # A package is a directory right under node_modules (npm's global
        # root is one), or under a scope in it.
        if "package.json" not in files or not (
                modules(here.parent) or (here.parent.name.startswith("@") and modules(here.parent.parent))):
            continue
        try:
            pj = json.loads((here / "package.json").read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(pj, dict) or not pj.get("name") or not pj.get("version"):
            continue
        lic = pj.get("license") or pj.get("licenses") or ""
        if isinstance(lic, dict):
            lic = lic.get("type", "")
        elif isinstance(lic, list):
            lic = " OR ".join(str(x.get("type", "")) if isinstance(x, dict) else str(x) for x in lic)
        rows.add((str(pj["name"]), str(pj["version"]), " ".join(str(lic).split()) or "licence not stated"))
    return [list(r) for r in sorted(rows)]


def dpkg_versions(names: list = ()) -> dict:
    """Debian package -> version: the named ones, or every one the image holds."""
    try:
        out = subprocess.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n", *names],
                             capture_output=True, text=True).stdout
    except FileNotFoundError:
        return {}
    return dict(line.split("\t", 1) for line in out.splitlines() if "\t" in line)


def pip_versions() -> dict:
    """The venv's packages as `pip list` names them: what INVENTORY_SCRIPT diffs against."""
    if not (VENV / "bin" / "pip").exists():
        return {}
    listed = subprocess.run([str(VENV / "bin" / "pip"), "list", "--format=json"],
                            capture_output=True, text=True).stdout
    return {p["name"]: p["version"] for p in json.loads(listed or "[]")}


def purl(kind: str, name: str, version: str, **qualifiers) -> str:
    q = lambda v: urllib.parse.quote(str(v), safe="")
    if kind == "npm" and name.startswith("@") and "/" in name:
        scope, _, base = name.partition("/")
        path = f"{q(scope)}/{q(base)}"
    elif kind == "pypi":
        path = q(re.sub(r"[-_.]+", "-", name).lower())
    else:
        path = q(name)
    tail = "&".join(f"{k}={q(v)}" for k, v in qualifiers.items() if v)
    return f"pkg:{kind}/{path}@{q(version)}" + (f"?{tail}" if tail else "")


def distro() -> str:
    """debian-12 for a bookworm image, from /etc/os-release."""
    try:
        rel = dict(line.split("=", 1) for line in OS_RELEASE.read_text().splitlines() if "=" in line)
        return f"{rel['ID'].strip(chr(34))}-{rel['VERSION_ID'].strip(chr(34))}"
    except (OSError, KeyError):
        return "debian-12"


def sbom(record: dict, python_rows: list, npm_rows: list, own_rows: dict | None = None) -> dict:
    """The image as a CycloneDX 1.5 document: every Debian package, every
    Python package in the venv and in each pinned source's own, every global
    npm package, every pinned artefact with the sha256 it was checked against."""
    a = record.get("arch") or arch()
    os_id = distro()
    components, seen = [], set()

    def add(c: dict) -> None:
        if c["bom-ref"] not in seen:
            seen.add(c["bom-ref"])
            components.append(c)

    for name, version in sorted((record.get("dpkg_all") or {}).items()):
        ref = purl("deb", name, version, arch=a, distro=os_id)
        add({"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref,
             "properties": [{"name": "dfirswarm:licence", "value": f"/usr/share/doc/{name}/copyright"}]})
    for name, version, lic in python_rows:
        ref = purl("pypi", name, version)
        add({"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref,
             "licenses": [{"license": {"name": lic}}]})
    for program, rows in sorted((own_rows or {}).items()):
        for name, version, lic in rows:
            ref = purl("pypi", name, version)
            add({"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref,
                 "licenses": [{"license": {"name": lic}}],
                 "properties": [{"name": "dfirswarm:venv-of", "value": program}]})
    for name, version, lic in npm_rows:
        ref = purl("npm", name, version)
        add({"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref,
             "licenses": [{"license": {"name": lic}}]})
    for name, d in sorted((record.get("downloads") or {}).items()):
        ref = purl("generic", name, d.get("version") or "unknown", download_url=d.get("url"),
                   checksum=f"sha256:{d.get('sha256')}")
        kind = d.get("kind", "download")
        add({"type": "data" if kind == "data" else "application", "bom-ref": ref, "name": name,
             "version": d.get("version") or "unknown",
             "purl": ref, "hashes": [{"alg": "SHA-256", "content": d.get("sha256")}],
             "externalReferences": [{"type": "distribution" if kind in ("download", "deb", "data")
                                     else "source-distribution", "url": d.get("url")}],
             "properties": [{"name": "dfirswarm:kind", "value": kind}]
             + [{"name": "dfirswarm:output", "value": f"{o.get('path')} sha256 {o.get('sha256')}"
                 + (f" content-sha256 {o['canonical_sha256']} ({o.get('canonical_rule')})" if o.get("canonical_sha256") else "")}
                for o in d.get("outputs") or []]
             + ([{"name": "dfirswarm:distribution", "value": d["distribution_policy"]}] if d.get("distribution_policy") else [])})
    profile = record.get("profile", "?")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "dfirswarm images/install.py"}]},
            "component": {
                "type": "container", "bom-ref": f"dfirswarm-{profile}", "name": f"dfirswarm-{profile}",
                "properties": [
                    {"name": "dfirswarm:profile", "value": profile},
                    {"name": "dfirswarm:packs", "value": ",".join(record.get("packs") or [])},
                    {"name": "dfirswarm:redistributable", "value": str(record.get("redistributable", True)).lower()},
                    {"name": "dfirswarm:arch", "value": a},
                ],
            },
        },
        "components": components,
    }


def notice(head: str, record: dict, python_rows: list, npm_rows: list, own_rows: dict | None = None) -> str:
    """The image's NOTICE: its own head (a profile's is the recipe's, program
    by pack), then what the whole image holds, the base's part included."""
    lines = [head.rstrip("\n"), ""]
    if record.get("nonredistributable"):
        data = sorted(k for k, v in (record.get("downloads") or {}).items() if v.get("kind") == "data")
        # An image that carries pinned data is built by whoever uses it: no
        # workflow of this project pushes one anywhere, the pro edition's
        # included, so "a private registry" is not on offer for it.
        keep = (f"It carries pinned data ({', '.join(data)}): no workflow of this project pushes such an image to any "
                "registry, the private one included. Keep it on the machine that built it; whoever needs one builds their own."
                if data else "Keep this image on this machine or in a private registry.")
        lines += ["Not cleared for redistribution: " + ", ".join(record["nonredistributable"]) + ". " + keep, ""]
    lines += ["Debian packages: every one in this image, with its version, is in image.json (dpkg_all)",
              "and sbom.json; each one's licence is in /usr/share/doc/<package>/copyright.", ""]
    if npm_rows:
        lines += ["Node packages installed globally (npm root -g):"]
        lines += [f"{name} {version}  {lic}" for name, version, lic in npm_rows] + [""]
    lines += [f"Python packages in {VENV}:"]
    lines += [f"{name} {version}  {lic}" for name, version, lic in python_rows]
    for program, rows in sorted((own_rows or {}).items()):
        venv = (record.get("downloads") or {}).get(program, {}).get("venv", "?")
        lines += ["", f"Python packages in {venv}, {program}'s own:"]
        lines += [f"{name} {version}  {lic}" for name, version, lic in rows]
    return "\n".join(lines) + "\n"


def requirement_notes(path: Path) -> list:
    """A requirements file's packages with the comment on each one's line."""
    notes = []
    if path.exists():
        for raw in path.read_text().splitlines():
            line, _, note = raw.partition("#")
            if line.strip():
                notes.append({"requirement": line.strip(), "note": " ".join(note.split())})
    return notes


def dist_name(requirement: str) -> str:
    return re.split(r"[<>=!~\[; ]", requirement.strip(), maxsplit=1)[0]


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def tools_md(record: dict, spec: dict | None) -> str:
    """/etc/dfirswarm/tools.md: every program the image's packs put in it, what
    it is for (the pack's own words), its pack and the version installed, one
    line each; the Python libraries likewise; and what a pack names that this
    image does not hold. Versions come from the package records, not from
    running each program: a --version probe answered "invalid option" for a
    third of them."""
    pip = {norm(k): v for k, v in (record.get("pip") or {}).items()}
    apt = record.get("apt") or {}
    on_path = record.get("binaries") or {}
    packs = record.get("packs") or []
    lines = [f"# Programs in this VM ({record.get('profile', '?')} image)", "",
             f"Packs: {', '.join(packs) if packs else 'none (the base image: the shell, Python and the tool library)'}.",
             "One program or library a line: its name, what it is for, its pack, the version installed.",
             "Find one with `grep -i <word> /etc/dfirswarm/tools.md`. Programs are on PATH; the libraries",
             "import in `python3` (the image's venv comes first on PATH). What this file does not name is",
             "not in the image.", ""]
    rows, gone, seen = [], [], {}
    for b in (spec or {}).get("binaries", []):
        if b["name"] in seen:
            seen[b["name"]]["packs"].append(b["pack"])
            continue
        entry = {**b, "packs": [b["pack"]]}
        seen[b["name"]] = entry
        if on_path.get(b["name"]):
            rows.append(entry)
        else:
            gone.append(entry)

    def version(b: dict) -> str:
        if b.get("apt"):
            got = [f"{p} {apt[p]}" for p in b["apt"] if apt.get(p)]
            if got:
                return ", ".join(got)
        if b.get("pip"):
            got = [f"{dist_name(p)} {pip[norm(dist_name(p))]}" for p in b["pip"] if pip.get(norm(dist_name(p)))]
            if got:
                return ", ".join(got)
        src = b.get("source") or ""
        return src if isinstance(src, str) and re.match(r"(download|source|built from source) ", src) else ""

    if rows:
        lines += ["## Programs", ""]
        for b in sorted(rows, key=lambda x: x["name"].lower()):
            v = version(b)
            lines.append(f"- `{b['name']}` — {b.get('why') or 'no description'} ({', '.join(b['packs'])}{'; ' + v if v else ''})")
        lines.append("")
    libs = []
    for n in list(record.get("python_library") or []) + list((spec or {}).get("python_notes") or []):
        name = dist_name(n["requirement"])
        if any(norm(name) == norm(x[0]) for x in libs):
            continue
        libs.append((name, n.get("note", ""), n.get("pack", "base image")))
    if libs:
        lines += ["## Python libraries", ""]
        for name, note, pack in sorted(libs, key=lambda x: x[0].lower()):
            v = pip.get(norm(name))
            lines.append(f"- `{name}` {v or '(not installed)'} — {note or 'no description'} ({pack})")
        lines.append("")
    # The profile's own Debian packages (a browser, its fonts) are in no pack,
    # so no program line names them; without these lines the file would say
    # they are not in the image.
    extra = [p for p in (spec or {}).get("profile_apt") or []]
    if extra:
        lines += ["## Packages the profile adds", ""]
        for p in extra:
            lines.append(f"- `{p}` {apt.get(p) or '(not installed)'} — installed for the {record.get('profile', '?')} profile itself, in no pack")
        lines.append("")
    # Data a program reads and is not a program (symbol tables, rules): where
    # it is, and what it covers, in the pack's words.
    held = record.get("downloads") or {}
    data_in = [d for d in (spec or {}).get("data", []) if held.get(d["name"])]
    data_out = {x["name"]: x for x in (record.get("not_installed") or {}).get("data") or []}
    if data_in:
        lines += ["## Data the programs read", ""]
        for d in sorted(data_in, key=lambda x: x["name"].lower()):
            h = held[d["name"]]
            where = ", ".join(o["path"] for o in h.get("outputs") or []) or h.get("path") or "?"
            ident = "; ".join(" ".join(f"{k} {v}" for k, v in o["identity"].items()) for o in h.get("outputs") or [] if o.get("identity"))
            lines.append(f"- `{d['name']}` — {d.get('why') or 'no description'} ({d.get('pack', '?')}; for `{d.get('program', '?')}`; "
                         f"{'identity ' + ident + '; ' if ident else ''}at {where})")
        lines.append("")
    na = (spec or {}).get("not_applicable") or record.get("not_applicable") or []
    omitted = (record.get("omitted") or {}).get("data") or []
    if gone or na or data_out or omitted:
        lines += ["## Named by a pack, not in this image", ""]
        for b in sorted(gone, key=lambda x: x["name"].lower()):
            lines.append(f"- `{b['name']}` ({', '.join(b['packs'])}) — not found after the build ({b.get('source') or 'no install line'})")
        for n, x in sorted(data_out.items()):
            lines.append(f"- `{n}` ({x.get('pack', '')}) — data not installed: {x.get('why', 'the build did not say why')}")
        for x in sorted(omitted, key=lambda x: x.get("name", "")):
            lines.append(f"- `{x.get('name', '?')}` ({x.get('pack', '')}) — data left out by the build on purpose: {x.get('why', 'the build did not say why')}")
        for d in na:
            lines.append(f"- `{d['name']}` ({d.get('pack', '')}) — {d.get('why', 'another system')}")
        lines.append("")
    return "\n".join(lines)


def on_path(path: str = IMAGE_PATH) -> list:
    """Every program on the image's PATH, by where it is: a shell utility as
    much as a pack's program. The job service picks the smallest image whose
    record holds every program a job runs; `binaries` names only the packs'."""
    found = []
    for d in path.split(":"):
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for name in names:
            p = os.path.join(d, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                found.append(p)
    return found


def write_record(record: dict, head: str, spec: dict | None = None) -> None:
    """image.json with the whole package inventory, every program on PATH,
    the NOTICE, the SBOM, and tools.md, the list an agent reads."""
    record["arch"] = arch()
    record["dpkg_all"] = dpkg_versions()
    record["pip"] = pip_versions()
    record["on_path"] = on_path()
    record["sbom"] = str(SBOM)
    record["tools_md"] = str(TOOLS_MD)
    python_rows, npm_rows = python_packages(), npm_packages()
    own_rows = {name: python_packages(venv) for name, venv in source_venvs(record)}
    ETC.mkdir(parents=True, exist_ok=True)
    RECORD.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
    NOTICE.write_text(notice(head, record, python_rows, npm_rows, own_rows))
    SBOM.write_text(json.dumps(sbom(record, python_rows, npm_rows, own_rows), indent=1) + "\n")
    TOOLS_MD.write_text(tools_md(record, spec))


def base() -> int:
    """The base image's record. base.Dockerfile installs; this says what it
    holds, in the fields a profile image has, so a VM booted from the base
    diffs against a whole baseline. Whether the base may be redistributed is
    the Dockerfile's to say (REDISTRIBUTABLE, NONREDISTRIBUTABLE)."""
    npm = {name: version for name, version, _ in npm_packages()}
    held = [x for x in os.environ.get("NONREDISTRIBUTABLE", "").replace(",", " ").split() if x]
    try:
        node = subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip() or None
    except FileNotFoundError:
        node = None
    record = {
        "profile": "base",
        "pi": npm.get("@earendil-works/pi-coding-agent") or os.environ.get("PI_VERSION"),
        "node": node,
        "python": "%d.%d" % sys.version_info[:2],
        "packs": [],
        "pack_versions": {},
        "redistributable": os.environ.get("REDISTRIBUTABLE", "false") == "true" and not held,
        "nonredistributable": held,
        "apt": {},
        "downloads": {},
        "binaries": {},
        "not_installed": {"apt": [], "pip": [], "download": [], "data": [], "manual": []},
        "omitted": {"data": []},
        # What the tool library imports, with the note on each line: every
        # image's tools.md lists them, a profile's after its own packs'.
        "python_library": requirement_notes(Path(__file__).parent / "library-python.txt"),
    }
    write_record(record, "dfirswarm-base: the agent runtime every seat boots, and the third-party software in it.\n"
                         "Each is its authors' work under its own licence; none is dfirswarm's.\n"
                         "Node.js and Pi run the agent, Debian's packages are the examiner's shell, and the venv\n"
                         "holds what the tool library imports (images/library-python.txt).")
    print(f"image.json: base, {len(record['dpkg_all'])} Debian and {len(record['pip'])} Python packages recorded")
    return 0


def profile_record(record: dict, spec: dict, downloads: dict, failed: dict) -> dict:
    """A profile image's record over the one its base wrote. An image is
    redistributable only when what it was built on is too: the base's own
    flags carry into every profile built on it."""
    path = IMAGE_PATH
    held = sorted(set(record.get("nonredistributable") or []) | set(spec.get("nonredistributable", [])))
    record.update({
        "profile": spec["profile"],
        "packs": spec["packs"],
        "pack_versions": spec.get("pack_versions", {}),
        "redistributable": bool(spec.get("redistributable", True) and record.get("redistributable", True) and not held),
        "nonredistributable": held,
        "apt": dpkg_versions(list(spec["apt"])) if spec["apt"] else {},
        "downloads": downloads,
        "binaries": {b["name"]: shutil.which(b["name"], path=path) for b in spec["binaries"]},
        "not_installed": {"apt": failed["apt"], "pip": failed["pip"], "download": failed["download"],
                          "source": failed.get("source", []), "build": failed.get("build", []),
                          "data": failed.get("data", []), "manual": spec["manual"]},
        # Named by a pack, and another system's: not missing from this image.
        "not_applicable": spec.get("not_applicable", []),
        # Data a pack pins that this build left out on purpose (recipe.py
        # build --symbol-set): said apart from what could not be had.
        "omitted": {"data": spec.get("omitted", {}).get("data", [])},
    })
    return record


def missing_programs(spec: dict, record: dict) -> list:
    """The programs this image was built to hold and does not: every program
    its packs name that is not on PATH, less those left out on purpose (a
    download with no build pinned for this architecture, a source or a build
    its pack pins for other architectures, a program no line installs)."""
    here = arch()
    elsewhere = {d["name"] for d in spec.get("downloads", []) if not isinstance(d.get(here), dict)}
    elsewhere |= {d["name"] for kind in ("sources", "builds") for d in spec.get(kind, [])
                  if d.get("arches") and here not in d["arches"]}
    elsewhere |= {m["name"] for m in spec.get("manual", [])}
    return sorted({b["name"] for b in spec["binaries"]
                   if not record["binaries"].get(b["name"]) and b["name"] not in elsewhere})


def missing_reasons(spec: dict, failed: dict, names: list) -> list:
    """(program, why) for each missing program, from what the install
    recorded: the image is not tagged, so its image.json is not there to read."""
    whys = {e["name"]: e["why"] for kind in ("download", "source", "build") for e in failed.get(kind, [])}
    out = []
    for name in names:
        entry = next((b for b in spec["binaries"] if b["name"] == name), {})
        apt_lost = [x for x in entry.get("apt") or [] if x in failed["apt"]]
        pip_lost = [x for x in entry.get("pip") or [] if x in failed["pip"]]
        out.append((name, whys.get(name) or (f"apt could not install {', '.join(apt_lost)}" if apt_lost else None)
                    or (f"pip could not install {', '.join(pip_lost)}" if pip_lost else None)
                    or "not on PATH after its install"))
    return out


def install_apt(spec: dict, apt: list, failed: dict) -> bool:
    """The spec's Debian packages, each from the release its pack names
    (bookworm-backports) or the image's own. False when a required one fails."""
    by_release: dict = {}
    for p, req in spec["apt"].items():
        by_release.setdefault(spec.get("apt_release", {}).get(p), []).append((p, req))
    unavailable = {r: enable_release(r) for r in by_release if r}
    if not run(["apt-get", "update"]):
        return False
    for release, pkgs in by_release.items():
        required = [p for p, req in pkgs if req]
        optional = [p for p, req in pkgs if not req]
        if release and unavailable.get(release):
            print(f"apt: {unavailable[release]}", file=sys.stderr)
            if required:
                print(f"required apt packages from {release} failed: {required}", file=sys.stderr)
                return False
            failed["apt"] += optional
            continue
        cmd = apt + (["-t", release] if release else [])
        if required and not run(cmd + required):
            print(f"required apt packages failed: {required}", file=sys.stderr)
            return False
        # The package cache is emptied after each install: a profile of many
        # packs filled a 59 GB builder disk, which apt then reported as bad
        # signatures on the next update.
        run(["apt-get", "clean"])
        for p in optional:
            if not run(cmd + [p]):
                failed["apt"].append(p)
            run(["apt-get", "clean"])
    return True


def settle_artefact(kind: str, d: dict, got, why, downloads: dict, failed: dict) -> bool:
    """Record one pinned artefact: held, or failed. A required one that failed
    stops the image (False); an optional one is recorded with why. A pinned data
    file is required whatever its program is (recipe.py), unless the operator
    built with --allow-missing-data."""
    if got:
        downloads[d["name"]] = got
        return True
    if d.get("required"):
        hint = " (recipe.py build --allow-missing-data goes on without it)" if kind == "data" else ""
        print(f"required {kind} {d['name']} failed: {why}{hint}", file=sys.stderr)
        return False
    failed[kind].append({"name": d["name"], "pack": d.get("pack"), "why": why})
    return True


def main(spec_path: str) -> int:
    spec = json.loads(Path(spec_path).read_text())
    failed = {"apt": [], "pip": [], "download": [], "source": [], "build": [], "data": []}
    apt = ["apt-get", "install", "-y", "--no-install-recommends"]
    if not install_apt(spec, apt, failed):
        return 1

    sources = spec.get("sources", [])
    compiles = bool(spec["pip"] or spec["requirements"] or any(d.get("pip") for d in sources))
    # Some wheels have no build for every architecture (flare-floss pulls
    # binary2strings, which arm64 has to compile), and some none at all
    # (dfvfs pulls libewf-python and libfvde-python, sdists only; a pinned
    # source's requirements pull more). The compiler, and what a source says
    # its requirements build with, is here for the build only and leaves with it.
    build_deps = ["build-essential", "python3-dev"]
    for d in sources:
        build_deps += [x for x in d.get("build_deps") or [] if x not in build_deps]
    # The compiler failing to install is the build's failure, said here, not
    # later as every pip and source build that needed it.
    if compiles and not run(apt + build_deps):
        print(f"required build dependencies failed: {build_deps}", file=sys.stderr)
        return 1
    if spec["pip"] or spec["requirements"]:
        if not run([sys.executable, "-m", "venv", str(VENV)]):
            return 1
        pip = [str(VENV / "bin" / "pip"), "install", "--no-cache-dir"]
        required = [p for p, req in spec["pip"].items() if req] + spec["requirements"]
        if required and not run(pip + required):
            print(f"required python packages failed: {required}", file=sys.stderr)
            return 1
        for p in [p for p, req in spec["pip"].items() if not req]:
            if not run(pip + [p]):
                failed["pip"].append(p)

    downloads = {}

    def settle(kind: str, d: dict, got, why) -> bool:
        return settle_artefact(kind, d, got, why, downloads, failed)

    # A runtime first (dotnet, pinned as a download of its own), then what
    # runs on it.
    for d in sorted(spec.get("downloads", []), key=lambda d: bool(d.get("run"))):
        if not settle("download", d, *fetch(d, apt)):
            return 1
    for d in sources:
        if not settle("source", d, *fetch_source(d, apt)):
            return 1
    # Data goes in after the venv, since it is put inside a package of it.
    for d in spec.get("data", []):
        if not settle("data", d, *fetch_data(d)):
            return 1
    if compiles:
        run(["apt-get", "purge", "-y", "--auto-remove", *build_deps])
    for d in spec.get("builds", []):
        if not settle("build", d, *link_build(d, apt)):
            return 1
    run(["apt-get", "clean"])
    shutil.rmtree(APT_LISTS, ignore_errors=True)

    record = profile_record(json.loads(RECORD.read_text()) if RECORD.exists() else {}, spec, downloads, failed)
    missing = missing_programs(spec, record)
    if missing and spec.get("allow_missing_optional"):
        record["missing_allowed"] = missing
    here = Path(spec_path).parent / "NOTICE"
    write_record(record, here.read_text() if here.exists() else f"dfirswarm-{spec['profile']}", spec)
    found = sum(1 for v in record["binaries"].values() if v)
    print(f"image.json: {found}/{len(record['binaries'])} binaries on PATH, "
          f"{len(failed['apt'])} apt, {len(failed['pip'])} pip, {len(failed['download'])} download, "
          f"{len(failed['source'])} source, {len(failed['build'])} build and {len(failed['data'])} data optional failures, "
          f"{len(spec['manual'])} manual, {len(spec.get('not_applicable', []))} not applicable")
    # A program a pack requires and the image does not have is a broken
    # image, whatever the package manager said: the run would find out first.
    lacking = sorted({b["name"] for b in spec["binaries"] if b.get("required") and not record["binaries"].get(b["name"])})
    if lacking:
        print(f"required programs missing from the image: {', '.join(lacking)}", file=sys.stderr)
        return 1
    # The program list, checked at the end: an optional program that should be
    # here and is not is a build that went wrong (apt out of disk space did
    # this), not an image to tag. Each is said here with why.
    if missing and not spec.get("allow_missing_optional"):
        print(f"programs this image was built to hold and does not: {', '.join(missing)}.", file=sys.stderr)
        for name, why in missing_reasons(spec, failed, missing):
            print(f"  {name}: {why}", file=sys.stderr)
        print("Free disk space for Docker if that is the cause (images/README.md, \"Disk space\") and build again, "
              "or build with recipe.py build --allow-missing-optional for an image that records them as missing.",
              file=sys.stderr)
        return 1
    if missing:
        print(f"optional programs missing, as the build allows (--allow-missing-optional): {', '.join(missing)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--base"]:
        sys.exit(base())
    if sys.argv[1:2] == ["--build"] and len(sys.argv) == 3:
        sys.exit(build_source(sys.argv[2]))
    sys.exit(main(sys.argv[1]))
