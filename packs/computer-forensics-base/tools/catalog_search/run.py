#!/usr/bin/env python3
import hashlib, json, re, signal, sys, os, tempfile, time


# BEGIN SHARED STOP
# The same text is in every tool that carries this block (tests/pack-shared-stop.test.ts holds the copies equal). SIGTERM, SIGINT and SIGHUP end the tool with JSON
# (status failed with interrupted true: a stop is not a status, the statuses are complete, partial and failed; exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
# The handlers are in as soon as the module has run as far as this block, with a minimal last word until main() installs the tool's own (only
# the start of the interpreter and the compiling of the file come before it). The first signal counts: a second one does nothing while the
# first is answered. print_answer holds the stop signals back while the answer is printed, so exactly one complete document is written
# (the ransomware tools print through it; the windows tools hold the signals in the emit of their boundary block, and carry this text unused).
import signal
import time

STOP = {"last_word": None, "deadline": None}


def set_deadline(seconds):
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    for page in list(globals().get("PAGES", ())):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    last_word = STOP["last_word"]
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def install_signal_handlers(last_word=None):
    STOP["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "failed", "interrupted": True,
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back: a signal that came in the middle of the write would end the process there, with the
    answer cut. The tool ends by itself right after, so a signal that is held is not lost for good."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    STOP["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


install_signal_handlers(lambda signum: interrupted_answer(signum))
# END SHARED STOP

PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes


class _Held:
    _tmp = None


HELD = _Held()             # the hidden file of the match list being written
PAGES.append(HELD)

TOOL = {"name": "catalog_search", "version": 15}
PATTERN_MAX = 4096
LINE_MAX = 1 << 20
BUDGET_SECONDS = 25
# What reading a revision's index could not do, said in the answer instead of read as an empty list.
INDEX_PROBLEMS = {}
# A refusal lists the names it could have taken (catalogues, revisions, filesystems): at most this many, with the count.
LISTED_MAX = 200


def _status(result):
    """status and status_basis for an answer that has none (docs/packs.md, "The tool contract"): failed on a refusal or an error;
    partial when the clock, an unsearchable line or a match file that could not be written left something undone; complete otherwise."""
    if result.get("ok") is False or "error" in result:
        return "failed", "the tool stopped with an error and read no result (see error)"
    if result.get("interrupted"):
        return "partial", ("the search stopped at its time budget (see interrupted): matched is a lower bound, and the matches found up to there "
                           "are counted and paged%s" % (", with every one in the file all_matches names" if result.get("all_matches") else ""))
    if result.get("lines_not_searched"):
        return "partial", ("%d line(s) were longer than the tool reads and were not searched (lines_not_searched); every other line was, "
                           "so matched is a lower bound" % result["lines_not_searched"])
    if result.get("all_matches_error"):
        return "partial", ("the search finished and this page is right, but the file that should hold every match could not be written "
                           "(all_matches_error): the rest is reached only by paging with offset=")
    if result.get("which") == "generations":
        return "complete", "every generation the revision lists was checked against the pattern; matched counts all of them and this page holds %d" % result.get("returned", 0)
    if result.get("all_matches"):
        return "complete", ("every line of the catalogue file was searched; matched counts all of them, this page holds %d, and every match is in the "
                            "file all_matches names" % result.get("returned", 0))
    return "complete", ("every line of the catalogue file was searched; matched counts all of them and this page holds %d%s"
                        % (result.get("returned", 0), "" if result.get("next_offset") is None else ", the rest by next_offset"))


def _answer(result, code=0):
    """Print the one answer, with its status and status_basis, and end. A refusal's lists of names are cut at LISTED_MAX with
    their count (the catalogue holds the whole)."""
    result = dict(result)
    if result.get("ok") is False or "error" in result:
        for key in [k for k, v in result.items() if isinstance(v, list) and len(v) > LISTED_MAX]:
            result[key + "_total"] = len(result[key])
            result[key] = result[key][:LISTED_MAX]
    if "status" not in result:
        result["status"], result["status_basis"] = _status(result)
    print_answer(result)
    sys.exit(code)


def _unexpected(kind, value, _tb):
    """An exception nobody expected is an answer too: the class only, never a message, which could quote the evidence."""
    budget_class = globals().get("_Budget")
    if budget_class is not None and issubclass(kind, budget_class):
        sys.stdout.write(json.dumps({"ok": False, "error": "the time budget ran out before the search began", "status": "partial",
                                     "status_basis": "the search's time budget ran out while the catalogue was being located, so no file was searched"}) + "\n")
    else:
        sys.stdout.write(json.dumps({"ok": False, "error": "internal error: %s" % kind.__name__, "status": "failed",
                                     "status_basis": "the tool stopped with an error and read no result (see error)"}) + "\n")
    sys.stdout.flush()
    os._exit(1)


sys.excepthook = _unexpected

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
            _answer({"ok": False, "error": "revision is a whole number", "revisions": done}, 1)
        if n not in done:
            _answer({"ok": False, "error": "no complete revision %s here (yet)" % n, "revisions": done}, 1)
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
            _answer({"ok": False, "error": "revision_unavailable", "revision": rev, "why": why,
                                         "hint": "the revision's index could not be read; nothing here says the catalogue holds no generations"}, 1)
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
                _answer({"ok": False, "error": "generation %s is listed by revision %s but its directory %s is not here" % (explicit, rev, gens[explicit]),
                                             "hint": "the catalogue was copied without it, or it was removed; nothing here says what it held"}, 1)
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
                        _answer({"ok": False, "error": "%s is not in catalogue revision %s" % (gid, rev), "candidates": sorted(listed)}, 1)
                return cand
        _answer({"ok": False, "error": "no catalogue %s" % explicit, "candidates": subs + sorted(gens)}, 1)
    if not os.path.isdir(root):
        _answer({"ok": False, "error": "no catalog/ in this run; pass catalog="}, 1)
    if len(subs) == 1:
        return os.path.join(root, subs[0])
    if not subs:
        _answer({"ok": False, "error": "no catalogue here yet%s; pass catalog=" % (" (the kickoff's recipes may still be running: each revision is announced on the board)" if rev is not None else ""), "candidates": sorted(gens)}, 1)
    # A disk and a memory image catalogue two directories, and only the
    # disk's has filesystems (partitions.txt): with one such, it is the one.
    disks = [d for d in subs if os.path.isfile(os.path.join(root, d, "partitions.txt"))]
    if len(disks) == 1:
        return os.path.join(root, disks[0])
    _answer({"ok": False, "error": "several catalogues; pass catalog=", "candidates": subs + sorted(gens)}, 1)

try:
    args = json.load(sys.stdin)
except ValueError as exc:
    _answer({"ok": False, "error": "arguments are not valid JSON", "reason": str(exc)}, 1)
if not isinstance(args, dict):
    _answer({"ok": False, "error": "arguments are a JSON object"}, 1)
pattern = args.get("pattern") or ""
which = args.get("which") or "filelist"
flags = re.IGNORECASE if args.get("ignore_case", True) else 0
LIMIT_MAX = 1000
try:
    limit = 50 if args.get("limit") is None else int(args["limit"])
    offset = 0 if args.get("offset") is None else int(args["offset"])
except (TypeError, ValueError, OverflowError):
    _answer({"ok": False, "error": "limit and offset must be whole numbers"}, 1)
if not 1 <= limit <= LIMIT_MAX or offset < 0:
    _answer({"ok": False, "error": "limit is a whole number from 1 to %d (every match is kept in a file when the page is not all of them) and offset is not negative" % LIMIT_MAX}, 1)
exclude = args.get("exclude") or ""
if not isinstance(pattern, str) or not isinstance(exclude, str):
    _answer({"ok": False, "error": "pattern and exclude are strings"}, 1)
for name in ("which", "catalog", "partition"):
    if args.get(name) is not None and not isinstance(args[name], str):
        _answer({"ok": False, "error": "%s is a string" % name}, 1)
for name, text in (("pattern", pattern), ("exclude", exclude)):
    if len(text) > PATTERN_MAX:
        _answer({"ok": False, "error": "%s is %d characters; this tool takes at most %d" % (name, len(text), PATTERN_MAX)}, 1)
try:
    budget = int(args.get("max_seconds") or BUDGET_SECONDS)
    if not 1 <= budget <= BUDGET_SECONDS:
        raise ValueError
except (TypeError, ValueError, OverflowError):
    _answer({"ok": False, "error": "max_seconds is a whole number from 1 to %d" % BUDGET_SECONDS}, 1)
try:
    rx = re.compile(pattern, flags)
except re.error as e:
    _answer({"error": str(e)}, 1)
try:
    ex = re.compile(exclude, flags) if exclude else None
except re.error as e:
    _answer({"ok": False, "error": "exclude is not a regular expression: %s" % e}, 1)


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


def _same_bytes(a, b, deadline=None):
    """Whether two files hold the same bytes (read in blocks, never whole). Each is opened without waiting and without following a link
    (O_NONBLOCK, O_NOFOLLOW) and looked at with fstat first: only two regular files of one size are read, so a FIFO, a device, a
    directory or a link at either name is never read (a FIFO would hold the tool for ever). Past `deadline` (a monotonic time) the
    answer is False."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fa = fb = None
    try:
        fa = os.fdopen(os.open(str(a), flags), "rb")
        fb = os.fdopen(os.open(str(b), flags), "rb")
        sa, sb = os.fstat(fa.fileno()), os.fstat(fb.fileno())
        if (sa.st_mode & 0o170000) != 0o100000 or (sb.st_mode & 0o170000) != 0o100000 or sa.st_size != sb.st_size:
            return False
        while True:
            if deadline is not None and time.monotonic() > deadline:
                return False
            x, y = fa.read(1 << 20), fb.read(1 << 20)
            if x != y:
                return False
            if not x:
                return True
    except OSError:
        return False
    finally:
        for fh in (fa, fb):
            if fh is not None:
                fh.close()


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
    _answer(result)
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
        _answer({"ok": False, "error": "no filesystem at %s in %s; pass partition= one of these" % (want, base), "partitions": parts}, 1)
    part = want
elif len(parts) == 1:
    part = parts[0]
elif not parts:
    about = _this_generation()
    _answer({"ok": False, "error": "the catalogue %s holds no filesystem listing (see its partitions.txt and README.md)" % base, **({"generation": about} if about else {})}, 1)
else:
    _answer({"ok": False, "error": "several filesystems in %s; pass partition= one of these" % base, "partitions": parts}, 1)
files = {"filelist": "filelist.txt", "timeline": "timeline.csv", "bodyfile": "bodyfile.txt", "fsstat": "fsstat.txt"}
if which == "partitions":
    path = os.path.join(base, "partitions.txt")
elif which == "members":
    # An archive's member list (archive-members recipe): n, type, path, …, locator.
    path = os.path.join(base, "members.tsv")
elif which in files:
    path = os.path.join(base, part, files[which])
else:
    _answer({"error": "which must be filelist|timeline|bodyfile|fsstat|partitions|members|generations"}, 1)
if not os.path.isfile(path):
    have = sorted(os.listdir(os.path.dirname(path))) if os.path.isdir(os.path.dirname(path)) else []
    # A partial generation says why, and where its readable form is.
    about = _this_generation()
    _answer({"ok": False, "error": "%s is not in the catalogue" % path, **({"generation": about} if about else {}), "there": have}, 1)
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


def _stopped(signum):
    print(json.dumps({"tool": TOOL, "status": "partial", "interrupted": True, "signal": signum, "which": which, "file": path,
                      "matched_so_far": total, "searched_to_line": last_line,
                      "status_basis": "the tool was stopped by signal %d during the search: the matches counted so far are a lower bound, and the file of every match was not kept" % signum}), flush=True)


install_signal_handlers(_stopped)
try:
    os.makedirs(keep_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=keep_dir, prefix=".catalog-search-")
    HELD._tmp = tmp
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
_answer(result)
