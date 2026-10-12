#!/usr/bin/env python3
"""Extract one Sleuth Kit address from a disk image to a new file, and say exactly what came out.

The extraction is streamed: icat's output goes through a block at a time into a file that is
created new (an existing file is never replaced) while it is hashed, so a pagefile or a virtual disk
of any size is never held in memory. An output budget (`max_bytes`) and a time budget (`max_seconds`)
bound it; a run that hits one, or whose icat fails part way, keeps what it wrote as `<output>.partial`
and says so (status partial): no truncated file keeps its own name. The result names the image, the
volume offset in sectors, the sector size passed to the Sleuth Kit (-b, only when given), the address
asked for, icat's exit code and where its stderr is kept. A 1 or 2 sector size is not guessed.
"""
import hashlib
import json
import os
import re
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path

TOOL = {"name": "icat_extract", "version": 8}
BLOCK = 1 << 20
MAX_BYTES_DEFAULT = 32 * 1024 ** 3
MAX_BYTES_CEILING = 1024 ** 4
MAX_SECONDS_DEFAULT = 1500
MAX_SECONDS_CEILING = 1700        # inside the manifest's own 1800-second limit: a longer budget would be killed, not reported
SECTOR_MAX = 65536
INODE = re.compile(r"^\d+(-\d+(-\d+)?)?$")

def _catalogue_slug(path):
    """The directory name the kickoff's catalogue gives an input: its path under
    inputs/ with every byte outside [A-Za-z0-9._-] made "_" (evidence-catalog.sh)."""
    import os, re
    rel = os.fsencode(os.path.relpath(path, "inputs"))
    return os.fsdecode(re.sub(rb"[^A-Za-z0-9._-]", b"_", rel))


def _inputs_roots():
    """inputs/, and each set held in place as a link directly under it (inputs.json names the sets): the only links followed.
    Any other link under inputs/ is a name and not a place to walk: following one could leave the evidence for the rest of the file system."""
    import json, os
    roots = ["inputs"]
    try:
        with open("inputs.json", encoding="utf-8") as fh:
            sets = json.load(fh).get("sets") or []
    except (OSError, ValueError, AttributeError):
        sets = []
    for entry in sets:
        name = entry.get("name") if isinstance(entry, dict) else None
        if isinstance(name, str) and name and "/" not in name and os.path.islink(os.path.join("inputs", name)):
            roots.append(os.path.join("inputs", name))
    return roots


def _resolve_image(explicit=None):
    """A pack tool belongs to no case: find the image under inputs/ instead of
    baking one in. One candidate is used; several mean the caller must say which.
    An image is known by its extension or, lacking one (a raw `dd` of a web
    server named after the host), by the catalogue: the kickoff writes
    catalog/<input>/partitions.txt for every input it read as a disk."""
    import glob, os
    if explicit:
        return explicit
    cands = []
    for ext in ("*.E01", "*.e01", "*.raw", "*.dd", "*.001", "*.img", "*.vhd", "*.vhdx"):
        cands += glob.glob(os.path.join("inputs", ext))
    seen = set()
    for root_dir in _inputs_roots():
        for base, _dirs, files in os.walk(root_dir, followlinks=False):
            for f in files:
                p = os.path.join(base, f)
                if os.path.isfile(os.path.join("catalog", _catalogue_slug(p), "partitions.txt")):
                    cands.append(p)
    cands = sorted(set(cands))
    if len(cands) == 1:
        return cands[0]
    if not cands:
        raise SystemExit('{"ok": false, "error": "no disk image under inputs/; pass image="}')
    raise SystemExit('{"ok": false, "error": "several images under inputs/; pass image=", "candidates": %s}' % json.dumps(cands))


def _resolve_offset(image, explicit=None):
    """The volume's start sector for icat -o. Given, it is used as is; not
    given, the catalogue says: one filesystem catalogued (catalog/<input>/p<start>/)
    is that start, several mean the caller must say which, none is sector 0."""
    import os, re
    if explicit is not None:
        return explicit
    root = os.path.join("catalog", _catalogue_slug(image))
    starts = sorted(int(d[1:]) for d in (os.listdir(root) if os.path.isdir(root) else [])
                    if re.fullmatch(r"p\d+", d) and os.path.isdir(os.path.join(root, d)))
    if len(starts) == 1:
        return starts[0]
    if not starts:
        return 0
    raise SystemExit('{"ok": false, "error": "several filesystems in %s; pass offset= (a start sector, see %s/partitions.txt)", "candidates": %s}' % (image, root, json.dumps(starts)))


def _resolve_catalog(explicit=None):
    """The catalogue directory for the one image the kickoff catalogued, or
    the one named: by its name under catalog/, as the index lists it
    (catalog=Case4.E01 was a traceback), or by its path."""
    import os
    root = "catalog"
    subs = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))) if os.path.isdir(root) else []
    if explicit:
        for cand in (explicit, os.path.join(root, explicit)):
            if os.path.isdir(cand):
                return cand
        raise SystemExit(json.dumps({"ok": False, "error": "no catalogue %s" % explicit, "candidates": subs}))
    if not os.path.isdir(root):
        raise SystemExit('{"ok": false, "error": "no catalog/ in this run; pass catalog="}')
    if len(subs) == 1:
        return os.path.join(root, subs[0])
    if not subs:
        raise SystemExit('{"ok": false, "error": "catalog/ is empty; pass catalog="}')
    # A disk and a memory image catalogue two directories, and only the
    # disk's has filesystems (partitions.txt): with one such, it is the one.
    disks = [d for d in subs if os.path.isfile(os.path.join(root, d, "partitions.txt"))]
    if len(disks) == 1:
        return os.path.join(root, disks[0])
    raise SystemExit('{"ok": false, "error": "several catalogues; pass catalog=", "candidates": %s}' % json.dumps(subs))

def _catalogued(image, offset, inode):
    """What the catalogue's path list says `inode` is on this filesystem:
    [{"type", "path", "deleted", "address"}], [] when there is no list or no line. An address
    with an attribute (168-128-4) matches only that attribute's lines; a bare record number
    matches every attribute of the record, each with its own address."""
    import os, re
    listing = os.path.join("catalog", _catalogue_slug(image), "p%s" % offset, "filelist.txt")
    if not os.path.isfile(listing):
        return []
    parts = str(inode).split("-")
    want_rec, want_attr = parts[0], (parts[1], parts[2]) if len(parts) == 3 else None
    marks = (" %s-" % want_rec, " %s:" % want_rec, " %s(" % want_rec)
    rx = re.compile(r"^\S/(\S) (\* )?(\d+)(?:-(\d+)-(\d+))?(?:\([^)]*\))?:\t(.*)$")
    out = []
    with open(listing, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not any(m in line for m in marks):
                continue
            m = rx.match(line.rstrip("\n"))
            if not m or m.group(3) != want_rec:
                continue
            attr = (m.group(4), m.group(5)) if m.group(4) else None
            if want_attr and attr != want_attr:
                continue
            out.append({"type": m.group(1), "path": m.group(6), "deleted": bool(m.group(2)),
                        "address": m.group(3) + ("-%s-%s" % attr if attr else "")})
    return out


def fail(msg, **extra):
    print(json.dumps({"error": msg, **extra}))
    sys.exit(1)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    job, bound = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and bound:
        bound = Path(bound).resolve()
        if bound not in dest.parents:
            fail("in a job an output is a path under $OUT, the one place a job writes (the rest of the run is read-only there)",
                 output=str(out), out=str(bound), hint="give {OUT}/<name>, or work/extracted/<your id>/<name>, which the harness maps there")
    return dest


try:
    d = json.load(sys.stdin)
except ValueError as exc:
    fail("arguments are not valid JSON", reason=str(exc))
if not isinstance(d, dict):
    fail("arguments are a JSON object")
inode = d.get("inode")
output = d.get("output")
image = _resolve_image(d.get("image"))
if inode is None or not isinstance(output, str) or not output:
    fail("need inode and output")
if isinstance(inode, bool) or not (isinstance(inode, int) and inode >= 0 or isinstance(inode, str) and INODE.match(inode)):
    fail("inode is a Sleuth Kit address: a number, or number-type-id for an NTFS stream (168-128-4)", inode=inode)
# 084284 is address 84284: icat would read a leading zero as octal. The address is held as its numbers.
inode = "-".join(str(int(part)) for part in str(inode).split("-"))
sector_size = d.get("sector_size")
if sector_size is not None and (not isinstance(sector_size, int) or isinstance(sector_size, bool)
                                or sector_size < 512 or sector_size > SECTOR_MAX or sector_size % 512):
    fail("sector_size must be a multiple of 512 from 512 to %d (the Sleuth Kit's -b takes no other)" % SECTOR_MAX, sector_size=sector_size)
max_bytes = d.get("max_bytes", MAX_BYTES_DEFAULT)
if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 1 <= max_bytes <= MAX_BYTES_CEILING:
    fail("max_bytes is a whole number from 1 to %d" % MAX_BYTES_CEILING, max_bytes=max_bytes)
max_seconds = d.get("max_seconds", MAX_SECONDS_DEFAULT)
if not isinstance(max_seconds, int) or isinstance(max_seconds, bool) or not 1 <= max_seconds <= MAX_SECONDS_CEILING:
    fail("max_seconds is a whole number from 1 to %d" % MAX_SECONDS_CEILING, max_seconds=max_seconds)
dest = resolve_output(output)
if not os.path.isfile(image):
    fail(f"image not found: {image}")
offset = _resolve_offset(image, d.get("offset"))
# A directory's inode gives icat its index, not a file: an agent extracted
# Edge's History directory (d/d 84284) as "EdgeHistory.db", 272 bytes of
# $INDEX_ROOT, and read "file is not a database" from it. Said here when the
# catalogue lists the inode only as a directory and no attribute was named.
listed = _catalogued(image, offset, inode)
if listed and "-" not in str(inode) and all(e["type"] == "d" for e in listed):
    fail("inode %s is a directory, not a file: icat would give its index" % inode, path=listed[0]["path"],
         hint="take the file's own inode from the catalogue's filelist.txt, or name an attribute (inode-type-id)")

if os.path.lexists(output) or dest.exists() or dest.is_symlink():
    fail("output already exists; an extract never replaces a file: choose a new path", output=output)

cmd = ["icat"] + (["-b", str(sector_size)] if sector_size else []) + ["-o", str(offset), image, str(inode)]
if not shutil.which("icat"):
    fail("icat is not on PATH", install="brew install sleuthkit, or apt-get install -y sleuthkit")
try:
    dest.parent.mkdir(parents=True, exist_ok=True)
except OSError as exc:
    fail("the output directory cannot be made: %s" % (exc.strerror or exc), output=output)
# The name it will have if it is whole; what is written goes to a name of its own until then.
part = dest.with_name(dest.name + ".partial")
n = 1
while part.exists() or part.is_symlink():
    n += 1
    part = dest.with_name("%s.partial.%d" % (dest.name, n))
# icat's stderr goes to a file made new, whatever else is there (O_EXCL: no other file is opened over or through).
err_path, err_fd, k = None, None, 0
while err_fd is None:
    k += 1
    err_path = dest.with_name(dest.name + ".icat.stderr" + ("" if k == 1 else ".%d" % k))
    try:
        err_fd = os.open(str(err_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        continue
    except OSError as exc:
        fail("icat's stderr file could not be created: %s" % (exc.strerror or exc), output=output)
digest = hashlib.sha256()
size = 0
status, why = "complete", None
started = time.monotonic()
try:
    out_fd = os.open(str(part), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
except OSError as exc:
    os.close(err_fd)
    os.unlink(err_path)
    fail("the output could not be created: %s" % (exc.strerror or exc), output=output)
with os.fdopen(out_fd, "wb") as out, os.fdopen(err_fd, "wb") as errf:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf)
    pipe = proc.stdout.fileno()
    try:
        while True:
            # Waited for with the clock running: an icat that stalls (a damaged image, a stuck read) is stopped at the
            # budget, not waited on for ever behind a read that returns nothing.
            left = max_seconds - (time.monotonic() - started)
            if left <= 0 or not select.select([pipe], [], [], min(left, 5))[0]:
                if time.monotonic() - started > max_seconds:
                    status, why = "partial", "the time budget of %d seconds was reached; icat was stopped" % max_seconds
                    break
                continue
            block = os.read(pipe, BLOCK)
            if not block:
                break
            room = max_bytes - size
            if len(block) > room:
                block = block[:room]
                out.write(block)
                digest.update(block)
                size += len(block)
                status, why = "partial", "the output budget of %d bytes was reached; icat was stopped, and the rest of the stream was not read" % max_bytes
                break
            out.write(block)
            digest.update(block)
            size += len(block)
            if time.monotonic() - started > max_seconds:
                status, why = "partial", "the time budget of %d seconds was reached; icat was stopped" % max_seconds
                break
    except OSError as exc:
        status, why = "partial", "the write failed after %d bytes: %s" % (size, exc.strerror or exc)
    finally:
        if status != "complete":
            proc.kill()
        proc.stdout.close()
        rc = proc.wait()
if status == "complete" and rc != 0:
    status, why = "partial", "icat exited %d after %d bytes" % (rc, size)
if os.path.getsize(err_path) == 0:
    os.unlink(err_path)
    err_path = None
err = ""
if err_path:
    with open(err_path, "r", encoding="utf-8", errors="replace") as fh:
        err = fh.read(4000).strip()
stream_whole = status == "complete"
if status == "complete":
    # Whole: it takes its own name, and never over a file that appeared there while icat ran (a link fails where the name
    # is taken; a file system with no links gets a rename after a look).
    try:
        os.link(part, dest)
        os.unlink(part)
    except FileExistsError:
        status, why = "partial", "%s appeared while icat was running, and an extract never replaces a file; the whole stream is kept as %s" % (output, os.path.basename(part))
    except OSError:
        if os.path.lexists(dest):
            status, why = "partial", "%s appeared while icat was running, and an extract never replaces a file; the whole stream is kept as %s" % (output, os.path.basename(part))
        else:
            os.rename(part, dest)
    shown = output if status == "complete" else output + part.name[len(dest.name):]
else:
    if size == 0:
        os.unlink(part)
        fail(err or "icat exit %s" % rc, image=image, inode=inode, offset=offset, sector_size=sector_size, icat_exit=rc, command=" ".join(cmd))
    # The partial sits beside the name it would have had: said under the name the caller gave, with its suffix.
    shown = output + part.name[len(dest.name):]
files = [e for e in listed if e["type"] != "d"]
catalogued = (next((e for e in files if not e["deleted"]), None) or (files or [None])[0] or {}).get("path")
result = {"tool": TOOL, "path": shown, "size": size, "sha256": digest.hexdigest(), "image": image, "offset": offset,
          "sector_size": sector_size, "inode": str(inode), "status": status, "icat_exit": rc, "command": " ".join(cmd),
          "catalog_path": catalogued, "catalog_paths": [{"address": e["address"], "path": e["path"], "deleted": e["deleted"]} for e in files]}
if why and stream_whole:
    result["problem"] = why
    result["note"] = "the whole stream was written, and is kept as %s: size and sha256 are of it" % shown
elif why:
    result["problem"] = why
    result["note"] = "what was written is kept as %s and is not the whole stream: size and sha256 are of those bytes alone" % shown
if err_path:
    result["stderr_file"] = output + err_path.name[len(dest.name):]
    result["stderr_head"] = err[:400]
print(json.dumps(result))
sys.exit(0 if status == "complete" else 1)
