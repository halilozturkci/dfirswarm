#!/usr/bin/env python3
import hashlib, json, re, sys, os, tempfile

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



# Directories of catalog/ that are the catalogue's machinery, not a catalogue.
RESERVED = {"gen", "revisions", "probes"}


def _revision(wanted=None):
    """The catalogue revision read: the one named, or the newest complete one
    (its MANIFEST.json is written last). None when the run has none."""
    import os
    root = os.path.join("catalog", "revisions")
    done = sorted(int(n) for n in os.listdir(root) if n.isdigit() and os.path.isfile(os.path.join(root, n, "MANIFEST.json"))) if os.path.isdir(root) else []
    if wanted is not None and str(wanted).strip() != "":
        try:
            n = int(wanted)
        except (TypeError, ValueError):
            raise SystemExit(json.dumps({"ok": False, "error": "revision is a whole number", "revisions": done}))
        if n not in done:
            raise SystemExit(json.dumps({"ok": False, "error": "no complete revision %s here (yet)" % n, "revisions": done}))
        return n
    return done[-1] if done else None


def _generations(rev):
    """The generations a revision lists: id -> directory."""
    import os
    if rev is None:
        return {}
    try:
        index = json.load(open(os.path.join("catalog", "revisions", str(rev), "index.json")))
    except Exception:
        return {}
    return {g["id"]: os.path.join("catalog", "gen", g["id"]) for g in index.get("generations", []) if isinstance(g, dict) and g.get("id")}


def _resolve_catalog(explicit=None, rev=None):
    """The catalogue directory for the one image the kickoff catalogued, or
    the one named: by its name under catalog/, as the index lists it
    (catalog=Case4.E01 was a traceback), by its path, or by a generation id
    (catalog=g0003) the revision read lists."""
    import os
    root = "catalog"
    subs = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)) and d not in RESERVED) if os.path.isdir(root) else []
    gens = _generations(rev)
    if explicit:
        if explicit in gens:
            return gens[explicit]
        for cand in (explicit, os.path.join(root, explicit)):
            if os.path.isdir(cand) and os.path.basename(os.path.normpath(cand)) not in RESERVED:
                return cand
        raise SystemExit(json.dumps({"ok": False, "error": "no catalogue %s" % explicit, "candidates": subs + sorted(gens)}))
    if not os.path.isdir(root):
        raise SystemExit('{"ok": false, "error": "no catalog/ in this run; pass catalog="}')
    if len(subs) == 1:
        return os.path.join(root, subs[0])
    if not subs:
        raise SystemExit(json.dumps({"ok": False, "error": "no catalogue here yet%s; pass catalog=" % (" (the kickoff's recipes may still be running: each revision is announced on the board)" if rev is not None else ""), "candidates": sorted(gens)}))
    # A disk and a memory image catalogue two directories, and only the
    # disk's has filesystems (partitions.txt): with one such, it is the one.
    disks = [d for d in subs if os.path.isfile(os.path.join(root, d, "partitions.txt"))]
    if len(disks) == 1:
        return os.path.join(root, disks[0])
    raise SystemExit('{"ok": false, "error": "several catalogues; pass catalog=", "candidates": %s}' % json.dumps(subs + sorted(gens)))

args = json.load(sys.stdin)
pattern = args.get("pattern") or ""
which = args.get("which") or "filelist"
flags = re.IGNORECASE if args.get("ignore_case", True) else 0
try:
    limit = max(1, int(args.get("limit") or 50))
    offset = max(0, int(args.get("offset") or 0))
except (TypeError, ValueError):
    print(json.dumps({"ok": False, "error": "limit and offset must be whole numbers"}))
    sys.exit(1)
exclude = args.get("exclude") or ""
try:
    rx = re.compile(pattern, flags)
except re.error as e:
    print(json.dumps({"error": str(e)}))
    sys.exit(1)
ex = re.compile(exclude, flags) if exclude else None
revision = _revision(args.get("revision"))
base = os.path.normpath(_resolve_catalog(args.get("catalog") if isinstance(args, dict) else None, revision))
# catalog=Case4.E01/p2048 names the filesystem as well.
named_part = ""
if re.fullmatch(r"p\d+", os.path.basename(base)):
    base, named_part = os.path.dirname(base), os.path.basename(base)
# The catalog keeps one directory per filesystem, named by its first sector
# (p0 for an image with no partition table, p2048 for a usual first
# partition): the one there is, or the one the caller names.
parts = sorted(n for n in os.listdir(base) if re.fullmatch(r"p\d+", n) and os.path.isdir(os.path.join(base, n)))
want = str(args.get("partition") or named_part).strip()
if want and not want.startswith("p"):
    want = "p" + want
if which in ("partitions", "members"):
    part = None
elif want:
    if want not in parts:
        print(json.dumps({"ok": False, "error": "no filesystem at %s in %s; pass partition= one of these" % (want, base), "partitions": parts}))
        sys.exit(1)
    part = want
elif len(parts) == 1:
    part = parts[0]
elif not parts:
    print(json.dumps({"ok": False, "error": "the catalogue %s holds no filesystem listing (see its partitions.txt and README.md)" % base}))
    sys.exit(1)
else:
    print(json.dumps({"ok": False, "error": "several filesystems in %s; pass partition= one of these" % base, "partitions": parts}))
    sys.exit(1)
files = {"filelist": "filelist.txt", "timeline": "timeline.csv", "bodyfile": "bodyfile.txt", "fsstat": "fsstat.txt"}
if which == "partitions":
    path = os.path.join(base, "partitions.txt")
elif which == "members":
    # An archive's member list (archive-members recipe): n, type, path, …, locator.
    path = os.path.join(base, "members.tsv")
elif which in files:
    path = os.path.join(base, part, files[which])
else:
    print(json.dumps({"error": "which must be filelist|timeline|bodyfile|fsstat|partitions|members"}))
    sys.exit(1)
if not os.path.isfile(path):
    have = sorted(os.listdir(os.path.dirname(path))) if os.path.isdir(os.path.dirname(path)) else []
    print(json.dumps({"ok": False, "error": "%s is not in the catalogue" % path, "there": have}))
    sys.exit(1)
# Every match goes to a file as it is found; the call returns one page of
# them. When that page is not all of them, the file is kept under the
# caller's scratch and named, so the rest is read from it (or paged with
# offset=) instead of searched for again with a bigger limit. The same
# search over the same read-only catalogue writes the same file.
key = hashlib.sha256(json.dumps([path, pattern, flags, exclude]).encode("utf-8")).hexdigest()[:16]
keep_dir = os.path.join("work", os.environ.get("AGENT_ID") or "catalog-search", "catalog-search")
keep = os.path.join(keep_dir, "%s-%s.txt" % (which, key))
hits = []
total = 0
tmp = None
try:
    os.makedirs(keep_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=keep_dir, prefix=".catalog-search-")
    all_out = os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape")
except OSError as e:
    all_out, keep_error = None, "%s: %s" % (keep_dir, e.strerror or e)
with open(path, "r", errors="replace") as f:
    for i, line in enumerate(f, 1):
        if rx.search(line):
            if ex and ex.search(line):
                continue
            total += 1
            text = line.rstrip("\n")
            if all_out:
                all_out.write("%d\t%s\n" % (i, text))
            if total > offset and len(hits) < limit:
                hits.append({"n": i, "line": text})
result = {"which": which, "partition": part, "file": path, "revision": revision, "pattern": pattern, "matched": total, "offset": offset, "returned": len(hits), "hits": hits}
more = offset + len(hits) < total
result["next_offset"] = offset + len(hits) if more else None
if all_out:
    all_out.close()
    if more or offset:
        os.replace(tmp, keep)
        result["all_matches"] = keep
        result["all_matches_format"] = "one match per line: the line number in the catalogue file, a tab, the line"
    else:
        os.unlink(tmp)
elif more or offset:
    result["all_matches_error"] = "the whole match set could not be written (%s); page through it with offset=" % keep_error
print(json.dumps(result))
