#!/usr/bin/env python3
"""evidence-catalog: the standard first pass over forensic inputs, once, before
the agents start, into <sandbox>/catalog/ (harness-owned, read-only).

    scripts/evidence-catalog.sh <sandbox> [--plan-only] [--recipes-from PACKDIR]...
    scripts/evidence-catalog.sh --candidates <sandbox>

The census is the harness's: every file under inputs/ gets a row in
catalog/coverage.tsv with its size and status — catalogued, partial, planned,
a further segment of a set, not catalogued, not probed (under 64 KB) — and
why. What an input is, and how it is catalogued, is the packs' knowledge: each
pack's recipes/<name>/ (recipe.json and an entry) says whether it applies to
an object (`entry detect --target T`) and catalogues it (`entry run --target T
--out DIR`), writing its own index.tsv and coverage.json. The recipes whose
`auto` holds "kickoff" are asked, pack by pack, then by their `order`, then by
name. The target is JSON: the input's path first, then the rest of its segment
set in order, its name and its ref.

By default the recipes that apply run here, each time-boxed by its
limits.seconds, into catalog/<slug>/ (the first recipe for an input) or
catalog/<slug>.<recipe>/ (any further one). With --plan-only nothing runs:
catalog/plan.json lists what applies to what, for the job service to run once
the run is up, and the rows say "planned". Recipes come from each
--recipes-from pack directory, else SWARM_PACK_DIRS (colon-separated), else
the computer-forensics-base pack in this checkout.

The index, catalog/README.md, lists every catalog file with its row count and
size and what was not catalogued; swarm.sh copies it into SWARM.md.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SMALL = 65536
LIST_AT_MOST = 20
# Directories under inputs/ reached a second time through a link: walked
# once, and named in the index so the skip is on the record.
LOOPS = []


def candidates(sandbox):
    """Every regular file under inputs/, following links (an --inputs-bind
    inputs/ is itself a link), in one order. A directory reached twice (a
    link back up the tree) is walked once, as find -L does: a loop would
    otherwise list the same files again at every depth."""
    base = os.path.join(sandbox, "inputs")
    found, seen = [], set()
    for dirpath, dirs, files in os.walk(base, followlinks=True):
        try:
            st = os.stat(dirpath)
        except OSError:
            dirs[:] = []
            continue
        if (st.st_dev, st.st_ino) in seen:
            LOOPS.append(os.path.relpath(dirpath, base))
            dirs[:] = []
            continue
        seen.add((st.st_dev, st.st_ino))
        dirs.sort()
        for f in files:
            p = os.path.join(dirpath, f)
            if os.path.isfile(p):
                found.append(p)
    return sorted(found, key=os.fsencode)


def catalog_slug(rel_under):
    """Two inputs can share a basename (node1/sda.E01, node2/sda.E01): the slug
    is the whole path under inputs/ with every byte outside [A-Za-z0-9._-] as _."""
    return re.sub(rb"[^A-Za-z0-9._-]", b"_", os.fsencode(rel_under)).decode("ascii")


SEGMENT = re.compile(r"^(?P<stem>.+)\.(?P<ext>[Ee][0-9][0-9]|[Ee][A-Za-z][A-Za-z]|[Ee][Xx][0-9][0-9]|[Ss][0-9][0-9]|[0-9][0-9][0-9])$")
FIRSTS = ("E01", "e01", "Ex01", "ex01", "EX01", "S01", "s01", "001")


def continuation_of(path):
    """The first segment's name when `path` is a further segment of a set whose
    first segment is beside it; None otherwise. EWF counts .E01 … .E99 .EAA …
    (.Ex01 for EnCase 7), split raw .001 .002 …; libewf and The Sleuth Kit read
    the whole set from its first segment, so only that one is catalogued."""
    base = os.path.basename(path)
    m = SEGMENT.match(base)
    if not m or m.group("ext") in FIRSTS:
        return None
    for ext in FIRSTS:
        first = "%s.%s" % (m.group("stem"), ext)
        if os.path.isfile(os.path.join(os.path.dirname(path), first)):
            return first
    return None


def shown(name):
    """A name for a table or a TSV field: tabs, newlines and backslashes escaped."""
    return name.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")


def human(b):
    if b >= 1073741824:
        return "%.1f GB" % (b / 1073741824)
    if b >= 1048576:
        return "%.1f MB" % (b / 1048576)
    if b >= 1024:
        return "%.1f KB" % (b / 1024)
    return "%d B" % b


def list_recipes(packs):
    """The recipes whose auto holds "kickoff", pack by pack, then by order and name."""
    seen, rows = set(), []
    for pack in packs:
        try:
            pid = json.load(open(os.path.join(pack, "pack.json"))).get("id") or os.path.basename(pack.rstrip("/"))
        except Exception:
            pid = os.path.basename(pack.rstrip("/"))
        rdir = os.path.join(pack, "recipes")
        if not os.path.isdir(rdir):
            continue
        found = []
        for name in sorted(os.listdir(rdir)):
            d = os.path.join(rdir, name)
            try:
                r = json.load(open(os.path.join(d, "recipe.json")))
            except Exception:
                continue
            if "kickoff" not in (r.get("auto") or []):
                continue
            found.append((int(r.get("order", 100)), name, d, r))
        for _o, name, d, r in sorted(found, key=lambda x: (x[0], x[1])):
            rid = "%s/%s" % (pid, name)
            if rid in seen:
                continue
            seen.add(rid)
            rows.append({"id": rid, "name": name, "dir": d, "runtime": r.get("runtime", "bash"), "min_bytes": int(r.get("min_bytes", SMALL)),
                         "entry": r.get("entry", ""), "seconds": int((r.get("limits") or {}).get("seconds", 900)),
                         "object": r.get("object", "object"), "sha256": r.get("sha256", "")})
    return rows


def recipe_argv(r, verb, target, extra):
    runtime = "python3" if r["runtime"] == "python3" else "bash"
    return [runtime, os.path.join(r["dir"], r["entry"]), verb, "--target", json.dumps(target)] + extra


def run_limited(argv, seconds, stderr_path):
    """Run with a deadline; (exit code, stdout). 142 on the deadline, as
    alarm() gave the shell version."""
    with open(stderr_path, "wb") as err:
        try:
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=err, timeout=seconds)
            return p.returncode, p.stdout.decode("utf-8", "replace")
        except subprocess.TimeoutExpired as e:
            return 142, (e.stdout or b"").decode("utf-8", "replace")


def drop_if_empty(path):
    try:
        if os.path.isfile(path) and os.path.getsize(path) == 0:
            os.unlink(path)
    except OSError:
        pass


def rmdir_quiet(path):
    try:
        os.rmdir(path)
        return True
    except OSError:
        return False


class Catalog:
    def __init__(self, sandbox, plan_only, packs):
        self.sandbox = sandbox
        self.out = os.path.join(sandbox, "catalog")
        self.plan_only = plan_only
        self.recipes = list_recipes(packs)
        self.index, self.notes, self.coverage, self.plan = [], [], [], []
        self.objects = {}
        for r in self.recipes:
            self.objects.setdefault(r["object"], 0)

    def add_index(self, rel, what):
        p = os.path.join(self.out, rel)
        if not os.path.isfile(p):
            return
        with open(p, "rb") as fh:
            rows = sum(1 for _ in fh)
        self.index.append("| `catalog/%s` | %s | %d | %s |" % (rel, what, rows, human(os.path.getsize(p))))

    def cover(self, rel_raw, size, status, why):
        self.coverage.append((shown(rel_raw), size, status, shown(why)))

    def empty(self):
        # Emptied, not removed: in a VM catalog/ is a mount of its own, the one
        # writable place in an otherwise read-only run, and a mount point
        # cannot be removed from inside.
        os.makedirs(self.out, exist_ok=True)
        for name in os.listdir(self.out):
            # The store's generations and revisions are the job service's
            # record, not this pass's: a second census leaves them alone.
            if name in ("gen", "revisions"):
                continue
            p = os.path.join(self.out, name)
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def run(self):
        self.empty()
        found = candidates(self.sandbox)
        sets = {}
        for img in found:
            first = continuation_of(img)
            if first:
                sets.setdefault(os.path.join(os.path.dirname(img), first), []).append(img)
        for loop in LOOPS:
            self.notes.append("inputs/%s is a directory already walked by another path (a link loop): its files are listed once, under their first path" % shown(loop))
        segments_skipped, segment_sets = 0, []
        for img in found:
            rel_under = os.path.relpath(img, os.path.join(self.sandbox, "inputs"))
            rel_raw = "inputs/" + rel_under
            rel = shown(rel_raw)
            size = os.path.getsize(img)
            # Each recipe says the smallest object it is asked about (a disk
            # image: 64 KB; Windows memory: 64 MB; a zip: 22 bytes); below all
            # of them a file is not offered to any.
            if not any(size >= r["min_bytes"] for r in self.recipes):
                floor = min((r["min_bytes"] for r in self.recipes), default=SMALL)
                self.cover(rel_raw, size, "not probed", "smaller than any recipe of this run asks about (%s): not offered to the recipes" % human(floor))
                continue
            first = continuation_of(img)
            if first:
                segments_skipped += 1
                if first not in segment_sets:
                    segment_sets.append(first)
                self.cover(rel_raw, size, "segment", "a further segment of %s: the set is read, and catalogued, from that one" % first)
                continue
            slug = catalog_slug(rel_under)
            paths = [img] + sorted(sets.get(img, []), key=os.fsencode)
            target = {"paths": paths, "name": rel_raw, "ref": "input:" + rel_under}
            self.one(rel_raw, rel, size, slug, target)
        self.write(segments_skipped, segment_sets)

    def one(self, rel_raw, rel, size, slug, target):  # noqa: C901
        applied, whys = [], []
        for r in self.recipes:
            if size < r["min_bytes"]:
                continue
            probe = os.path.join(self.out, "probes", slug, r["name"])
            os.makedirs(probe, exist_ok=True)
            rc, verdict = run_limited(recipe_argv(r, "detect", target, ["--probe-out", probe]), 300, os.path.join(probe, "detect.stderr"))
            drop_if_empty(os.path.join(probe, "detect.stderr"))
            try:
                why = str(json.loads(verdict.strip().splitlines()[-1]).get("why", "")) if verdict.strip() else ""
            except Exception:
                why = ""
            if rc == 0:
                applied.append(r)
                rmdir_quiet(probe)
            else:
                if rc != 1:
                    why = "its detect step failed (exit %d)%s" % (rc, ": " + why if why else "")
                if "is not in this image" in why:
                    self.notes.append("%s — no catalogue of %s by %s" % (why, rel, r["id"]))
                line = "%s: %s" % (r["id"], why or "does not apply")
                if not rmdir_quiet(probe):
                    line += " (what it wrote: catalog/probes/%s/%s/)" % (slug, r["name"])
                whys.append(line)
            rmdir_quiet(os.path.join(self.out, "probes", slug))
            rmdir_quiet(os.path.join(self.out, "probes"))
        if not applied:
            self.cover(rel_raw, size, "not catalogued", "no recipe of this run applies" + (": " + "; ".join(whys) if whys else ""))
            return
        statuses, by = [], []
        for n, r in enumerate(applied):
            self.objects[r["object"]] = self.objects.get(r["object"], 0) + 1
            dir_rel = slug if n == 0 else "%s.%s" % (slug, r["name"])
            if self.plan_only:
                self.plan.append({"input": rel_raw, "recipe": r["id"], "recipe_dir": r["dir"], "recipe_sha256": r["sha256"],
                                  "seconds": r["seconds"], "target": target, "alias": "catalog/" + dir_rel})
                by.append(r["id"])
                continue
            d = os.path.join(self.out, dir_rel)
            os.makedirs(d, exist_ok=True)
            rc, _ = run_limited(recipe_argv(r, "run", target, ["--out", d]), r["seconds"], os.path.join(d, "recipe.stderr"))
            drop_if_empty(os.path.join(d, "recipe.stderr"))
            try:
                cov = json.load(open(os.path.join(d, "coverage.json")))
            except Exception:
                cov = {}
            status = cov.get("status") or "failed"
            if rc == 142:
                status = "partial"
                self.notes.append("%s on %s: stopped at its limit of %ds" % (r["id"], rel, r["seconds"]))
            idx = os.path.join(d, "index.tsv")
            if os.path.isfile(idx):
                for line in open(idx, encoding="utf-8", errors="replace"):
                    f, _, what = line.rstrip("\n").partition("\t")
                    if f:
                        self.add_index("%s/%s" % (dir_rel, f), what)
            # A recipe names its files relative to its own directory; the note
            # says which recipe, which input and where that directory is.
            for e in (cov.get("errors") or []) + (cov.get("limits_hit") or []):
                self.notes.append("%s on %s (catalog/%s/): %s" % (r["id"], rel, dir_rel, str(e).replace("\n", " ")))
            if os.path.isfile(os.path.join(d, "recipe.stderr")):
                self.add_index(dir_rel + "/recipe.stderr", "what %s said on stderr" % r["id"])
            statuses.append(status)
            by.append("%s:%s" % (r["id"], status))
            rmdir_quiet(d)
        who = ", ".join(by)
        if self.plan_only:
            self.cover(rel_raw, size, "planned", "to be catalogued once the run is up by " + who)
        elif all(s == "complete" for s in statuses):
            self.cover(rel_raw, size, "catalogued", "under catalog/%s/ by %s" % (slug, who))
        elif any(s in ("complete", "partial") for s in statuses):
            self.cover(rel_raw, size, "partial", "catalogued in part under catalog/%s/ by %s (Not built, in the index)" % (slug, who))
        else:
            self.cover(rel_raw, size, "not catalogued", "the recipes that apply did not finish: %s (Not built, in the index)" % who)

    def count(self, status):
        return sum(1 for c in self.coverage if c[2] == status)

    def listing(self, status, heading):
        rows = [c for c in self.coverage if c[2] == status]
        if not rows:
            return []
        lines = ["", heading + ":"]
        for path, size, _s, why in rows[:LIST_AT_MOST]:
            lines.append("- `%s` (%s): %s" % (path, human(size), why))
        if len(rows) > LIST_AT_MOST:
            lines.append("- and %d more, every one in `catalog/coverage.tsv`" % (len(rows) - LIST_AT_MOST))
        return lines

    def write(self, segments_skipped, segment_sets):
        with open(os.path.join(self.out, "coverage.tsv"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("input\tbytes\tstatus\twhy\n")
            for c in self.coverage:
                fh.write("%s\t%d\t%s\t%s\n" % c)
        self.add_index("coverage.tsv", "every input, one row each: path, bytes, status (catalogued, partial, planned, segment, not catalogued, not probed) and why")
        if self.plan_only:
            with open(os.path.join(self.out, "plan.json"), "w", encoding="utf-8") as fh:
                json.dump({"recipes": self.plan}, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
            self.add_index("plan.json", "what the job service runs once the run is up: recipe, input, target")
        objects = "".join("%d %s(s), " % (n, obj) for obj, n in self.objects.items())
        lines = ["Summary: %s%d catalog file(s); %d input file(s): %d catalogued, %d partial, %d planned, %d segment(s) of a set, %d not catalogued, %d not probed"
                 % (objects, len(self.index), len(self.coverage), self.count("catalogued"), self.count("partial"), self.count("planned"),
                    self.count("segment"), self.count("not catalogued"), self.count("not probed"))]
        if segments_skipped:
            lines += ["", "Segmented images: %d further segment(s) belong to the set(s) catalogued above (%s) and were not catalogued separately — libewf and The Sleuth Kit read the whole set from the first segment, so pass that one to every tool."
                      % (segments_skipped, ", ".join(segment_sets))]
        lines += ["", "Coverage: every input has a row in `catalog/coverage.tsv` with its status and why. An input that is not catalogued has no file list or timeline here: open it with other tools. Missing from the catalog is not missing from the evidence."]
        if self.plan_only and self.count("planned"):
            lines += ["", "Being built: the inputs marked planned are catalogued by the job service once the run is up; each recipe's result is a generation under `catalog/gen/`, each change a new numbered revision under `catalog/revisions/`, announced on the board."]
        lines += self.listing("planned", "Planned")
        lines += self.listing("not catalogued", "Not catalogued")
        lines += self.listing("partial", "Catalogued in part")
        lines += self.listing("not probed", "Not probed (smaller than any recipe asks about)")
        lines += ["", "| File | What | Rows | Size |", "| --- | --- | --- | --- |"] + self.index
        if self.notes:
            lines += ["", "Not built:"] + ["- %s" % n for n in self.notes]
        with open(os.path.join(self.out, "README.md"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print("evidence-catalog: " + lines[0])


def main(argv):
    if len(argv) >= 2 and argv[1] == "--candidates":
        if len(argv) < 3 or not os.path.isdir(os.path.join(argv[2], "inputs")):
            print("evidence-catalog: --candidates needs a sandbox with inputs/", file=sys.stderr)
            return 2
        for p in candidates(argv[2]):
            print(p)
        return 0
    if len(argv) < 2 or not os.path.isdir(os.path.join(argv[1], "inputs")):
        print("evidence-catalog: usage: evidence-catalog.sh <sandbox> [--plan-only] [--recipes-from PACKDIR]... (needs inputs/)", file=sys.stderr)
        return 2
    sandbox, rest = argv[1], argv[2:]
    plan_only, packs = False, []
    i = 0
    while i < len(rest):
        if rest[i] == "--plan-only":
            plan_only = True
            i += 1
        elif rest[i] == "--recipes-from" and i + 1 < len(rest):
            packs.append(rest[i + 1])
            i += 2
        else:
            print("evidence-catalog: unknown option %s" % rest[i], file=sys.stderr)
            return 2
    if not packs and os.environ.get("SWARM_PACK_DIRS"):
        packs = [p for p in os.environ["SWARM_PACK_DIRS"].split(":") if p]
    if not packs and os.path.isdir(os.path.join(ROOT, "packs", "computer-forensics-base", "recipes")):
        packs = [os.path.join(ROOT, "packs", "computer-forensics-base")]
    # The operator's knobs keep their names: a step's box and the memory
    # probe's, handed to the recipes under theirs.
    if os.environ.get("SWARM_CATALOG_STEP_TIMEOUT") and not os.environ.get("RECIPE_STEP_SECONDS"):
        os.environ["RECIPE_STEP_SECONDS"] = os.environ["SWARM_CATALOG_STEP_TIMEOUT"]
    if os.environ.get("SWARM_CATALOG_MEMORY_PROBE_TIMEOUT") and not os.environ.get("RECIPE_PROBE_SECONDS"):
        os.environ["RECIPE_PROBE_SECONDS"] = os.environ["SWARM_CATALOG_MEMORY_PROBE_TIMEOUT"]
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    Catalog(sandbox, plan_only, packs).run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
