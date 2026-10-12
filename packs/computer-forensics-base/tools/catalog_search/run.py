#!/usr/bin/env python3
import hashlib, json, re, signal, sys, os, tempfile, time

TOOL = {"name": "catalog_search", "version": 10}
PATTERN_MAX = 4096
LINE_MAX = 1 << 20
BUDGET_SECONDS = 25
# What reading a revision's index could not do, said in the answer instead of read as an empty list.
INDEX_PROBLEMS = {}

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


def _index(rev, strict=False):
    """The generations a revision lists, as its index records them. An index that cannot be
    read is not an empty one: strict says so and stops, otherwise the problem is kept and the
    answer carries it."""
    import os
    if rev is None:
        return []
    path = os.path.join("catalog", "revisions", str(rev), "index.json")
    try:
        with open(path) as fh:
            index = json.load(fh)
        listed = index["generations"]
        if not isinstance(listed, list):
            raise ValueError("generations is not a list")
    except (OSError, ValueError, KeyError, TypeError) as e:
        why = "%s: %s" % (path, getattr(e, "strerror", None) or e)
        INDEX_PROBLEMS[rev] = why
        if strict:
            raise SystemExit(json.dumps({"ok": False, "error": "revision_unavailable", "revision": rev, "why": why,
                                         "hint": "the revision's index could not be read; nothing here says the catalogue holds no generations"}))
        return []
    return [g for g in listed if isinstance(g, dict) and g.get("id")]


def _generations(rev):
    """The generations a revision lists: id -> directory."""
    import os
    return {g["id"]: os.path.join("catalog", "gen", g["id"]) for g in _index(rev)}


def _about(g):
    """What a generation is, in one record: what made it and over what, how
    far it got and why not further, and its readable form when there is one."""
    cov = g.get("coverage") or {}
    t = g.get("target") or {}
    out = {"id": g["id"], "recipe": g.get("recipe"), "object": t.get("ref") or t.get("name"), "status": g.get("status"),
           "trigger": g.get("trigger"), "made_by_job": g.get("parent")}
    why = [str(x) for x in (cov.get("errors") or []) + (cov.get("limits_hit") or [])] + ([str(cov["why"])] if cov.get("why") else [])
    if g.get("status") != "complete" and why:
        out["why"] = why
    if g.get("readable_form"):
        out["readable_form"] = g["readable_form"]
    return out


def _generation_of(path):
    """The generation id (gNNNN) the directory `path` is, or lies inside, by where it really is; None if it is none."""
    gen_root = os.path.realpath(os.path.join("catalog", "gen"))
    real = os.path.realpath(path)
    if real == gen_root or not real.startswith(gen_root + os.sep):
        return None
    first = os.path.relpath(real, gen_root).split(os.sep)[0]
    return first if re.fullmatch(r"g\d{4}", first) else None


def _resolve_catalog(explicit=None, rev=None):
    """The catalogue directory for the one image the kickoff catalogued, or
    the one named: by its name under catalog/, as the index lists it
    (catalog=Case4.E01 was a traceback), by its path, or by a generation id
    (catalog=g0003) the revision read lists."""
    import os
    root = "catalog"
    subs = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)) and d not in RESERVED) if os.path.isdir(root) else []
    if explicit and rev is not None and re.fullmatch(r"g\d{4}", str(explicit)):
        _index(rev, strict=True)              # a generation id is looked up in the index, and an index that cannot be read is said so
    gens = _generations(rev)
    if explicit:
        if explicit in gens:
            if not os.path.isdir(gens[explicit]):
                raise SystemExit(json.dumps({"ok": False, "error": "generation %s is listed by revision %s but its directory %s is not here" % (explicit, rev, gens[explicit]),
                                             "hint": "the catalogue was copied without it, or it was removed; nothing here says what it held"}))
            return gens[explicit]
        catalog_real = os.path.realpath(root)
        for cand in (explicit, os.path.join(root, explicit)):
            # A catalogue is a directory under catalog/: a path to anywhere else is not one, whatever it holds.
            inside = os.path.realpath(cand) == catalog_real or os.path.realpath(cand).startswith(catalog_real + os.sep)
            if os.path.isdir(cand) and inside and os.path.basename(os.path.normpath(cand)) not in RESERVED:
                # A generation is read only when the revision read lists it, whatever the
                # directory is called: an absolute path, a ./ spelling or a link is held to
                # the generation it resolves to.
                gid = _generation_of(cand)
                if gid:
                    listed = {g["id"] for g in _index(rev, strict=True)} if rev is not None else set()
                    if gid not in listed:
                        raise SystemExit(json.dumps({"ok": False, "error": "%s is not in catalogue revision %s" % (gid, rev), "candidates": sorted(listed)}))
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
LIMIT_MAX = 1000
try:
    limit = 50 if args.get("limit") is None else int(args["limit"])
    offset = 0 if args.get("offset") is None else int(args["offset"])
except (TypeError, ValueError):
    print(json.dumps({"ok": False, "error": "limit and offset must be whole numbers"}))
    sys.exit(1)
if not 1 <= limit <= LIMIT_MAX or offset < 0:
    print(json.dumps({"ok": False, "error": "limit is a whole number from 1 to %d (every match is kept in a file when the page is not all of them) and offset is not negative" % LIMIT_MAX}))
    sys.exit(1)
exclude = args.get("exclude") or ""
if not isinstance(pattern, str) or not isinstance(exclude, str):
    print(json.dumps({"ok": False, "error": "pattern and exclude are strings"}))
    sys.exit(1)
for name, text in (("pattern", pattern), ("exclude", exclude)):
    if len(text) > PATTERN_MAX:
        print(json.dumps({"ok": False, "error": "%s is %d characters; this tool takes at most %d" % (name, len(text), PATTERN_MAX)}))
        sys.exit(1)
try:
    budget = int(args.get("max_seconds") or BUDGET_SECONDS)
    if not 1 <= budget <= BUDGET_SECONDS:
        raise ValueError
except (TypeError, ValueError):
    print(json.dumps({"ok": False, "error": "max_seconds is a whole number from 1 to %d" % BUDGET_SECONDS}))
    sys.exit(1)
try:
    rx = re.compile(pattern, flags)
except re.error as e:
    print(json.dumps({"error": str(e)}))
    sys.exit(1)
try:
    ex = re.compile(exclude, flags) if exclude else None
except re.error as e:
    print(json.dumps({"ok": False, "error": "exclude is not a regular expression: %s" % e}))
    sys.exit(1)


def earlier_answers(path):
    """How many other files answer this same question in the folder (name.ext, name.2.ext, ...): one more for every different
    answer, and none is deleted, so the count is said."""
    stem, ext = os.path.splitext(os.path.basename(str(path)))
    base = re.sub(r"\.\d+$", "", stem)
    rx = re.compile(r"^%s(\.\d+)?%s$" % (re.escape(base), re.escape(ext)))
    try:
        return max(0, sum(1 for n in os.listdir(os.path.dirname(str(path)) or ".") if rx.match(n)) - 1)
    except OSError:
        return 0


def _same_bytes(a, b):
    """Two files with the same bytes (compared in blocks, never whole)."""
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(1 << 20), fb.read(1 << 20)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


class _Budget(Exception):
    pass


def _alarm(*_):
    raise _Budget()


# One budget for the whole search. A pattern that backtracks badly on one line is interrupted too:
# the regular-expression engine checks for signals as it runs.
if hasattr(signal, "SIGALRM"):
    signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, budget)
revision = _revision(args.get("revision"))
if which == "generations":
    # Every generation of the revision read, what it is and how far it got;
    # pattern filters by recipe, object and status; paged like any search.
    rows = [_about(g) for g in _index(revision, strict=True)]
    kept, interrupted = [], False
    try:
        for r in rows:
            if rx.search(" ".join(str(r.get(k) or "") for k in ("id", "recipe", "object", "status", "trigger"))):
                kept.append(r)
    except _Budget:
        interrupted = True
    finally:
        if hasattr(signal, "setitimer"):
            signal.setitimer(signal.ITIMER_REAL, 0)
    page = kept[offset:offset + limit]
    result = {"which": "generations", "revision": revision, "pattern": pattern, "matched": len(kept), "offset": offset, "returned": len(page), "generations": page,
              "complete": not interrupted}
    if interrupted:
        result["interrupted"] = ("the search stopped at its %d-second budget: the generations listed are those matched up to there, so matched is a lower bound "
                                 "(a pattern that backtracks badly does this; simplify it)" % budget)
    if offset + len(page) < len(kept):
        result["next_offset"] = offset + len(page)
    print(json.dumps(result))
    sys.exit(0)
base = os.path.normpath(_resolve_catalog(args.get("catalog") if isinstance(args, dict) else None, revision))


def _this_generation():
    """The generation base is, as the revision read records it, or None."""
    gid = _generation_of(base)
    if not gid or os.path.relpath(os.path.realpath(base), os.path.realpath(os.path.join("catalog", "gen"))) != gid:
        return None
    return next((_about(g) for g in _index(revision) if g["id"] == gid), None)
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
    about = _this_generation()
    print(json.dumps({"ok": False, "error": "the catalogue %s holds no filesystem listing (see its partitions.txt and README.md)" % base, **({"generation": about} if about else {})}))
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
    print(json.dumps({"error": "which must be filelist|timeline|bodyfile|fsstat|partitions|members|generations"}))
    sys.exit(1)
if not os.path.isfile(path):
    have = sorted(os.listdir(os.path.dirname(path))) if os.path.isdir(os.path.dirname(path)) else []
    # A partial generation says why, and where its readable form is.
    about = _this_generation()
    print(json.dumps({"ok": False, "error": "%s is not in the catalogue" % path, **({"generation": about} if about else {}), "there": have}))
    sys.exit(1)
# Every match goes to a file as it is found; the call returns one page of
# them. When that page is not all of them, the file is kept and named, so the
# rest is read from it (or paged with offset=) instead of searched for again
# with a bigger limit. The same search over the same read-only catalogue writes
# the same file. In a job the file is written under $OUT, the one place a job
# writes, and named as the store will hold it; called directly, under the
# caller's own work directory.
key = hashlib.sha256(json.dumps([path, pattern, flags, exclude]).encode("utf-8")).hexdigest()[:16]
job, job_out = os.environ.get("JOB_ID"), os.environ.get("OUT")
if job and job_out:
    keep_dir = os.path.join(job_out, "catalog-search")
    shown_dir = "store/jobs/%s/out/catalog-search" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
else:
    keep_dir = os.path.join("work", re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "catalog-search").strip(".") or "catalog-search", "catalog-search")
    shown_dir = keep_dir
keep = os.path.join(keep_dir, "%s-%s.txt" % (which, key))
shown = os.path.join(shown_dir, "%s-%s.txt" % (which, key))
hits = []
total = 0
tmp = None
stopped_at = None
too_long = 0
last_line = 0
try:
    os.makedirs(keep_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=keep_dir, prefix=".catalog-search-")
    all_out = os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape")
except OSError as e:
    all_out, keep_error = None, "%s: %s" % (keep_dir, e.strerror or e)
try:
    with open(path, "rb") as f:
        i = 0
        while True:
            raw = f.readline(LINE_MAX + 1)
            if not raw:
                break
            i += 1
            last_line = i
            if len(raw) > LINE_MAX and not raw.endswith(b"\n"):
                # A line this long is not a catalogue row; the rest of it is skipped, and counted.
                while True:
                    more = f.readline(LINE_MAX)
                    if not more or more.endswith(b"\n"):
                        break
                too_long += 1
                continue
            line = raw.decode("utf-8", "replace")
            line = line[:-2] if line.endswith("\r\n") else line[:-1] if line.endswith("\n") else line      # the line's own terminator, CRLF or LF, is not part of it
            if rx.search(line):
                if ex and ex.search(line):
                    continue
                total += 1
                text = line
                if all_out:
                    all_out.write("%d\t%s\n" % (i, text))
                if total > offset and len(hits) < limit:
                    hits.append({"n": i, "line": text})
except _Budget:
    stopped_at = last_line
finally:
    if hasattr(signal, "setitimer"):
        signal.setitimer(signal.ITIMER_REAL, 0)
result = {"tool": TOOL, "which": which, "partition": part, "file": path, "revision": revision, "pattern": pattern, "matched": total, "offset": offset, "returned": len(hits), "hits": hits, "complete": stopped_at is None and not too_long}
if stopped_at is not None:
    result["interrupted"] = ("the search stopped at its %d-second budget after line %d of %s: the matches are those found up to there, so matched is a lower bound "
                             "(a pattern that backtracks badly does this; simplify it)" % (budget, stopped_at, os.path.basename(path)))
if too_long:
    result["lines_not_searched"] = too_long
    result["lines_not_searched_why"] = "longer than %d bytes: not a catalogue row" % LINE_MAX
if INDEX_PROBLEMS.get(revision):
    result["revision_index_problem"] = INDEX_PROBLEMS[revision]
more = offset + len(hits) < total
result["next_offset"] = offset + len(hits) if more else None
if all_out:
    all_out.close()
    if more or offset or stopped_at is not None:
        # Nothing already at the name is replaced: an earlier answer to this search, complete, stays when this one was cut short.
        keep_stem, keep_ext = os.path.splitext(keep)
        shown_stem, _ = os.path.splitext(shown)
        k = 1
        while True:
            suffix = "" if k == 1 else ".%d" % k
            held = keep_stem + suffix + keep_ext
            try:
                os.link(tmp, held)
            except FileExistsError:
                if _same_bytes(tmp, held):                # the same answer again (a page of the same search): the file is already there
                    os.unlink(tmp)
                    break
                k += 1
                continue
            except OSError:
                if os.path.lexists(held):
                    if _same_bytes(tmp, held):
                        os.unlink(tmp)
                        break
                    k += 1
                    continue
                os.rename(tmp, held)
            else:
                os.unlink(tmp)
            break
        result["all_matches"] = shown_stem + suffix + keep_ext
        result["earlier_answers"] = earlier_answers(held)
        result["all_matches_format"] = "one match per line: the line number in the catalogue file, a tab, the line"
    else:
        os.unlink(tmp)
elif more or offset:
    result["all_matches_error"] = "the whole match set could not be written (%s); page through it with offset=" % keep_error
print(json.dumps(result))
