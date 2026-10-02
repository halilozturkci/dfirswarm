#!/usr/bin/env python3
"""Extract an inode from an E01 image to a path. Args come from JSON stdin."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

def _catalogue_slug(path):
    """The directory name the kickoff's catalogue gives an input: its path under
    inputs/ with every byte outside [A-Za-z0-9._-] made "_" (evidence-catalog.sh)."""
    import os, re
    rel = os.fsencode(os.path.relpath(path, "inputs"))
    return os.fsdecode(re.sub(rb"[^A-Za-z0-9._-]", b"_", rel))


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
    for base, _dirs, files in os.walk("inputs", followlinks=True):
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
    [{"type", "path", "deleted"}], [] when there is no list or no line."""
    import os, re
    listing = os.path.join("catalog", _catalogue_slug(image), "p%s" % offset, "filelist.txt")
    if not os.path.isfile(listing):
        return []
    want = str(inode).split("-")[0]
    marks = (" %s-" % want, " %s:" % want, " %s(" % want)
    rx = re.compile(r"^\S/(\S) (\* )?(\d+)(?:-\d+-\d+)?(?:\([^)]*\))?:\t(.*)$")
    out = []
    with open(listing, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not any(m in line for m in marks):
                continue
            m = rx.match(line.rstrip("\n"))
            if m and m.group(3) == want:
                out.append({"type": m.group(1), "path": m.group(4), "deleted": bool(m.group(2))})
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
    return dest


d = json.load(sys.stdin)
inode = d.get("inode")
output = d.get("output")
image = _resolve_image(d.get("image"))
if inode is None or not isinstance(output, str) or not output:
    fail("need inode and output")
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
r = subprocess.run(
    ["icat", "-o", str(offset), image, str(inode)],
    capture_output=True,
)
if r.returncode != 0:
    err = r.stderr.decode("utf-8", "replace").strip() or f"icat exit {r.returncode}"
    fail(err, image=image, inode=inode, offset=offset)
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_bytes(r.stdout)
digest = hashlib.sha256(r.stdout).hexdigest()
files = [e for e in listed if e["type"] != "d"]
catalogued = (next((e for e in files if not e["deleted"]), None) or (files or [None])[0] or {}).get("path")
print(json.dumps({"path": output, "size": len(r.stdout), "sha256": digest, "image": image, "offset": offset, "catalog_path": catalogued}))
