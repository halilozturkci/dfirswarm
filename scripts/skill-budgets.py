#!/usr/bin/env python3
"""The size budgets of a pack's skills, in one place.

    skill-budgets.py check  [--packs-dir DIR] [--golden FILE]
    skill-budgets.py seal   PACK_DIR [--also DIR] [--golden FILE]
    skill-budgets.py golden [--packs-dir DIR]

`check` holds every pack of DIR (default: packs/ of this checkout) to the
budgets and prints what it found; the exit is 1 when a finding is neither on the
golden list nor a warning. It is what tests/skill-budgets.test.sh runs. `seal`
is what `pack.sh seal` runs before it writes anything: it prints a JSON object
{"errors": [...], "warnings": [...]} for one pack, and the pack is refused when
"errors" is not empty. `golden` prints the golden list for what the packs have
now.

The budgets (docs/packs.md, "Writing a pack that holds up", "Skill size"). A
token is estimated as bytes / 4.245 of the whole skill file, front matter
included, as the pack tests have always done; this program has no tokenizer.

  leaf     a skill is at most 800 tokens. Over 800 is a warning; over 1,000 is
           a finding, and the one thing `seal` refuses;
  router   a skill with `router: true` is at most 400 tokens (500 for windows-forensics,
           linux-forensics, memory-forensics and macos-forensics; the limits are in
           scripts/skill-budgets.json);
  lines    no skill file has more than 300 lines;
  entry    the skill's line in skills/INDEX.md is at most 40 tokens;
  depth    `needs` reaches at most 2 skills deep;
  chain    a skill and every skill its `needs` reach, across the pack's
           `depends`, are at most 1,900 tokens together (100 under the 2,000
           the pack tests allowed). A chain within 150 tokens of that is a
           warning that names the skills it is made of and, for a skill of
           another pack, the one whose growth pushes the dependant over.

The golden list, tests/skill-budgets.golden: one line per known finding, `pack
kind skill-id ceiling`, sorted as `LC_ALL=C sort` sorts, no (pack, kind, skill)
twice; `#` lines and blank lines are skipped. The ceiling is the most the
skill's value (tokens, lines, depth) may be: a skill that grows past it fails,
one that shrinks and is still over keeps its line, and one that is within the
budget no longer happens, so its line has to go. `golden` writes the ceiling a
little above the value (a multiple of 25 tokens or 10 lines, with at least half
that much room) so that a typo fix is not a failure. `seal` reads the list by pack id
(pack.sh passes --golden), so a copy of a shipped pack seals as the pack does and
a pack of another id has no listed findings.

Stdlib only, Python 3.8 or later.
"""
import argparse
import json
import math
import os
import re
import sys

BYTES_PER_TOKEN = 4.245
LEAF_WARN, LEAF_REFUSE, ROUTER_MAX = 800, 1000, 400


def _router_limits():
    """The router limits, from scripts/skill-budgets.json beside this file (the one place both languages read)."""
    default, by_pack = ROUTER_MAX, {}
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "skill-budgets.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        default = int(data.get("router_max", default))
        by_pack = {str(k): int(v) for k, v in (data.get("router_max_by_pack") or {}).items()}
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return default, by_pack


ROUTER_MAX, ROUTER_MAX_BY_PACK = _router_limits()


def router_max(pid):
    """The most tokens a router of pack `pid` may have."""
    return ROUTER_MAX_BY_PACK.get(pid, ROUTER_MAX)


LINES_MAX, ENTRY_MAX, DEPTH_MAX = 300, 40, 2
CHAIN_MAX, CHAIN_MARGIN = 1900, 150
KINDS = ("leaf", "router", "lines", "entry", "depth", "chain")
# What `golden` adds to a value, so that a small edit is no failure.
SLACK = {"leaf": 25, "router": 25, "chain": 25, "lines": 10, "entry": 5, "depth": 1}

FM = re.compile(r"\A---\n(.*?)\n---\n", re.S)
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def tokens(text):
    return len(text.encode("utf-8")) / BYTES_PER_TOKEN


def front_matter(block):
    meta = {}
    for line in block.splitlines():
        if ":" not in line or line.startswith("#"):
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        meta[k] = [x.strip() for x in v[1:-1].split(",") if x.strip()] if v.startswith("[") and v.endswith("]") else v
    return meta


def load_pack(path):
    """A pack as {id, depends, skills: {skill id: {rel, text, meta}}}, or None."""
    try:
        man = json.load(open(os.path.join(path, "pack.json"), encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(man, dict):
        return None
    pid = man.get("id") if isinstance(man.get("id"), str) else os.path.basename(os.path.normpath(path))
    skills = {}
    sdir = os.path.join(path, "skills")
    for dirpath, dirs, files in os.walk(sdir):
        dirs.sort()
        for f in sorted(files):
            if not f.endswith(".md") or f == "INDEX.md":
                continue
            full = os.path.join(dirpath, f)
            text = open(full, encoding="utf-8").read()
            m = FM.match(text)
            if not m:
                continue  # pack.sh refuses a skill with no front matter
            meta = front_matter(m.group(1))
            sid = meta.get("id")
            if isinstance(sid, str) and sid:
                skills[sid] = {"rel": os.path.relpath(full, path), "text": text, "meta": meta}
    deps = [re.split(r"[<>=!~ ]", d)[0].strip() for d in man.get("depends") or [] if isinstance(d, str)]
    return {"id": pid, "depends": deps, "skills": skills}


def load_registry(dirs, first=None):
    """Every pack found under DIRS (and FIRST, a pack directory, ahead of them), by id."""
    reg = {}
    paths = [first] if first else []
    for d in dirs:
        if os.path.isdir(d):
            paths += [os.path.join(d, n) for n in sorted(os.listdir(d))]
    for p in paths:
        if os.path.isdir(p):
            pack = load_pack(p)
            if pack and pack["id"] not in reg:
                reg[pack["id"]] = pack
    return reg


class Budgets:
    def __init__(self, reg):
        self.reg = reg
        self._closure = {}

    def closure(self, pid):
        """The pack, then its `depends` and theirs, in the order a name is looked up."""
        if pid not in self._closure:
            seen, queue = [], [pid]
            while queue:
                x = queue.pop(0)
                if x in seen or x not in self.reg:
                    continue
                seen.append(x)
                queue += self.reg[x]["depends"]
            self._closure[pid] = seen
        return self._closure[pid]

    def resolve(self, pid, ref):
        """(pack, skill id) a `needs` entry names: `pack:id`, or the id in the closure's first pack that has it."""
        clo = self.closure(pid)
        if ":" in ref:
            p, sid = ref.split(":", 1)
            if p in clo and sid in self.reg[p]["skills"]:
                return (p, sid)
        for p in clo:
            if ref in self.reg[p]["skills"]:
                return (p, ref)
        return None

    def chain(self, pid, sid):
        """(members, depth, cycle): every skill reached by `needs`, the skill itself first."""
        members, depth, cycle = [(pid, sid)], 0, []

        def walk(p, s, d, path):
            nonlocal depth
            depth = max(depth, d)
            needs = self.reg[p]["skills"][s]["meta"].get("needs") or []
            for ref in needs if isinstance(needs, list) else []:
                hit = self.resolve(p, ref)
                if hit is None:
                    continue  # tests/pack-tools.test.sh fails an id nothing resolves
                if hit in path:
                    cycle.append(" > ".join("%s %s" % k for k in path + [hit]))
                    continue
                if hit not in members:
                    members.append(hit)
                walk(hit[0], hit[1], d + 1, path + [hit])

        walk(pid, sid, 0, [(pid, sid)])
        return members, depth, cycle

    def size(self, key):
        return tokens(self.reg[key[0]]["skills"][key[1]]["text"])

    def entry(self, pid, sid):
        meta = self.reg[pid]["skills"][sid]["meta"]
        return "- `%s` %s: %s" % (sid, meta.get("title", ""), meta.get("when", ""))

    def findings(self, packs=None):
        """(errors, warnings): dicts of pack, kind, id, value, text. A warning has kind `warn-...`."""
        errors, warnings = [], []
        totals = {}  # (pack, skill) -> chain total, for the dependants' warnings

        def err(pid, kind, sid, value, text):
            errors.append({"pack": pid, "kind": kind, "id": sid, "value": value, "text": "%s: %s: %s" % (pid, sid, text)})

        for pid in sorted(packs if packs is not None else self.reg):
            for sid in sorted(self.reg[pid]["skills"]):
                s = self.reg[pid]["skills"][sid]
                size, lines = tokens(s["text"]), s["text"].count("\n") + 1
                router = s["meta"].get("router") == "true"
                if router and size > router_max(pid):
                    err(pid, "router", sid, size, "the router is %.0f tokens, over its budget of %d" % (size, router_max(pid)))
                elif not router and size > LEAF_REFUSE:
                    err(pid, "leaf", sid, size, "%.0f tokens, over the %d a skill may have (budget %d): split it into leaves" % (size, LEAF_REFUSE, LEAF_WARN))
                elif not router and size > LEAF_WARN:
                    warnings.append("%s: %s: %.0f tokens, over the leaf budget of %d (sealing refuses above %d)" % (pid, sid, size, LEAF_WARN, LEAF_REFUSE))
                if lines > LINES_MAX:
                    err(pid, "lines", sid, lines, "%d lines, over the %d a skill file may have" % (lines, LINES_MAX))
                e = tokens(self.entry(pid, sid))
                if e > ENTRY_MAX:
                    err(pid, "entry", sid, e, "its index entry is %.1f tokens, over %d: shorten `title` or `when`" % (e, ENTRY_MAX))
                members, depth, cycle = self.chain(pid, sid)
                for c in cycle:
                    err(pid, "depth", sid, 99, "`needs` loops: %s" % c)
                if depth > DEPTH_MAX:
                    err(pid, "depth", sid, depth, "`needs` reaches %d deep, over %d" % (depth, DEPTH_MAX))
                total = sum(self.size(m) for m in members)
                totals[(pid, sid)] = (total, members)
                if total > CHAIN_MAX:
                    err(pid, "chain", sid, total, "its needs chain is %.0f tokens, over %d (%d skill(s): %s)"
                        % (total, CHAIN_MAX, len(members), self.describe(members)))
        return errors, warnings, totals

    def describe(self, members):
        return ", ".join("%s%s (%.0f)" % ("" if p == members[0][0] else p + ":", s, self.size((p, s))) for p, s in members)

    def margin_warnings(self, totals, packs, known):
        """The chains within CHAIN_MARGIN of the limit, and what a base skill's growth would do to its dependants."""
        out, near = [], {}
        for key, (total, members) in sorted(totals.items()):
            room = CHAIN_MAX - total
            if room < 0 and key in known:
                continue
            if room < CHAIN_MARGIN:
                near[key] = room
        for (pid, sid), room in sorted(near.items()):
            if pid in packs and room >= 0:
                members = totals[(pid, sid)][1]
                out.append("%s: %s: its needs chain is %.0f tokens, %.0f under the %d limit; it is made of %s; growing any of them by more than %.0f tokens pushes it over"
                           % (pid, sid, CHAIN_MAX - room, room, CHAIN_MAX, self.describe(members), room))
        # For each skill that dependants in other packs reach: who it would push over.
        reached = {}
        for (pid, sid), room in near.items():
            for member in totals[(pid, sid)][1][1:]:
                if member[0] != pid:
                    reached.setdefault(member, []).append(((pid, sid), room))
        for member, deps in sorted(reached.items()):
            if member[0] not in packs:
                continue
            deps.sort(key=lambda d: (d[1], d[0]))
            least = deps[0][1]
            text = ", ".join("%s %s (%s)" % (p, s, "%.0f tokens of room" % r if r >= 0 else "already %.0f over" % -r) for (p, s), r in deps)
            if least >= 0:
                out.append("%s: %s (%.0f tokens) is in the needs chain of %d skill(s) of other packs within %d tokens of the %d limit: growing it by more than %.0f tokens pushes %s over"
                           % (member[0], member[1], self.size(member), len(deps), CHAIN_MARGIN, CHAIN_MAX, least,
                              "them" if len(deps) > 1 else "it") + " - " + text)
            else:
                out.append("%s: %s (%.0f tokens) is in the needs chain of %d skill(s) of other packs that are over the %d limit or within %d of it: %s"
                           % (member[0], member[1], self.size(member), len(deps), CHAIN_MAX, CHAIN_MARGIN, text))
        return out


def read_golden(path):
    """({(pack, kind, id): (ceiling, line number)}, errors)."""
    golden, errors, prev, seen = {}, [], None, {}
    if not os.path.isfile(path):
        return golden, ["%s is missing: the known findings are held to it" % os.path.relpath(path, ROOT)]
    name = os.path.relpath(path, ROOT) if path.startswith(ROOT) else path
    for n, raw in enumerate(open(path, encoding="utf-8"), 1):
        line = raw.rstrip("\n")
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split(" ")
        if len(f) != 4 or not all(f) or f[1] not in KINDS or not re.fullmatch(r"\d+", f[3]):
            errors.append("%s line %d is not `pack kind skill-id ceiling` (kind one of %s, the ceiling a whole number)" % (name, n, ", ".join(KINDS)))
            continue
        key = tuple(f[:3])
        if key in seen:
            errors.append("%s line %d repeats line %d" % (name, n, seen[key]))
        elif prev is not None and line < prev:
            errors.append("%s line %d is out of order (sort the file as LC_ALL=C sort does)" % (name, n))
        else:
            golden[key] = (int(f[3]), n)
            seen[key] = n
            prev = line
    return golden, errors


def apply_golden(errors, golden, stale_for=None):
    """Split the findings into those that fail and those on the list; list lines that no longer happen."""
    failing, known, seen = [], [], set()
    for e in errors:
        key = (e["pack"], e["kind"], e["id"])
        if key in golden:
            seen.add(key)
            ceiling, n = golden[key]
            if e["value"] > ceiling:
                failing.append("%s (it is %.0f, past the ceiling of %d on its golden line %d: it may only shrink)" % (e["text"], e["value"], ceiling, n))
            else:
                known.append(e)
        else:
            failing.append(e["text"] + " (it is not on the golden list: fix it)")
    for key, (ceiling, n) in sorted(golden.items(), key=lambda kv: kv[1][1]):
        if key not in seen and (stale_for is None or key[0] in stale_for):
            failing.append("tests/skill-budgets.golden line %d, `%s %s %s %d`, no longer happens: remove the line" % ((n,) + key + (ceiling,)))
    return failing, known


def golden_lines(errors):
    out = {}
    for e in errors:
        slack = SLACK[e["kind"]]
        if e["kind"] == "depth":
            ceiling = int(e["value"])
        else:
            ceiling = int(math.ceil(e["value"] / slack) * slack)
            if ceiling - e["value"] < slack / 2.0:
                ceiling += slack
        out[(e["pack"], e["kind"], e["id"])] = ceiling
    return sorted("%s %s %s %d" % (k + (v,)) for k, v in out.items())


def cmd_check(args):
    reg = load_registry([args.packs_dir])
    b = Budgets(reg)
    errors, warnings, totals = b.findings()
    golden, gerrors = read_golden(args.golden)
    failing, known = apply_golden(errors, golden)
    keys = {(e["pack"], e["kind"], e["id"]) for e in errors if (e["pack"], e["kind"], e["id"]) in golden}
    known_chains = {(p, s) for (p, k, s) in keys if k == "chain"}
    warnings += b.margin_warnings(totals, set(reg), known_chains)
    n_skills = sum(len(p["skills"]) for p in reg.values())
    print("checked %d packs: %d skills" % (len(reg), n_skills))
    kinds = {}
    for e in known:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    print("budgets: %d finding(s) in all, %d of them on the golden list%s" % (
        len(errors), len(known), " (" + ", ".join("%s %d" % kv for kv in sorted(kinds.items())) + ")" if kinds else ""))
    if args.verbose:
        for e in known:
            print("  known: " + e["text"])
    for w in warnings:
        print("warning: " + w)
    for f in gerrors + failing:
        print("  " + f)
    return 1 if gerrors or failing else 0


def cmd_seal(args):
    pack_dir = os.path.abspath(args.pack_dir)
    reg = load_registry([os.path.dirname(pack_dir)] + list(args.also or []), first=pack_dir)
    pack = load_pack(pack_dir)
    out = {"errors": [], "warnings": []}
    if pack is None:
        print(json.dumps(out))
        return 0  # pack.sh's validator names a pack.json that is not there
    pid = pack["id"]
    b = Budgets(reg)
    errors, warnings, totals = b.findings([pid])
    # The pack's own findings, and its dependants' chains the pack's skills are part of.
    golden = {}
    if args.golden:
        golden, gerrors = read_golden(args.golden)
        out["errors"] += gerrors
    failing, known = apply_golden([e for e in errors if e["kind"] in ("leaf", "router")], golden, stale_for=set())
    out["errors"] += failing
    # Everything else is the lint's to fail; sealing says it.
    for e in errors:
        if e["kind"] in ("leaf", "router"):
            continue
        key = (e["pack"], e["kind"], e["id"])
        if key in golden and e["value"] <= golden[key][0]:
            continue
        warnings.append(e["text"] + " (tests/skill-budgets.test.sh fails on it)")
    listed = [e for e in errors if (e["pack"], e["kind"], e["id"]) in golden and e["value"] <= golden[(e["pack"], e["kind"], e["id"])][0]]
    for e in listed:
        if e["kind"] in ("leaf", "router"):
            warnings.append("%s: %s: %.0f tokens, over the %d a skill may have; it is on tests/skill-budgets.golden with a ceiling of %d, which it may not pass"
                            % (e["pack"], e["id"], e["value"], LEAF_REFUSE if e["kind"] == "leaf" else router_max(e["pack"]), golden[(e["pack"], e["kind"], e["id"])][0]))
    if listed:
        kinds = {}
        for e in listed:
            kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
        warnings.append("%s: %d known finding(s) are on tests/skill-budgets.golden (%s); `python3 scripts/skill-budgets.py check --verbose` lists them"
                        % (pid, len(listed), ", ".join("%s %d" % kv for kv in sorted(kinds.items()))))
    _e, _w, all_totals = b.findings()
    known_chains = {(p, s) for (p, k, s), (c, _n) in golden.items() if k == "chain" and (p, s) in all_totals and all_totals[(p, s)][0] <= c}
    over = []
    for key, (total, members) in sorted(all_totals.items()):
        if key[0] != pid and total > CHAIN_MAX and key not in known_chains and any(m[0] == pid for m in members[1:]):
            over.append("%s: %s: its needs chain is %.0f tokens, over %d, and it reaches %s of this pack (%s)"
                        % (key[0], key[1], total, CHAIN_MAX, "skills" if sum(m[0] == pid for m in members[1:]) > 1 else "a skill",
                           ", ".join(m[1] for m in members[1:] if m[0] == pid)))
    warnings += over
    warnings += b.margin_warnings(all_totals, {pid}, known_chains)
    out["warnings"] = sorted(set(warnings))
    print(json.dumps(out))
    return 0


def cmd_golden(args):
    reg = load_registry([args.packs_dir])
    errors, _w, _t = Budgets(reg).findings()
    print("\n".join(golden_lines(errors)))
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description="skill size budgets")
    sub = ap.add_subparsers(dest="cmd", required=True)
    default_packs = os.path.join(ROOT, "packs")
    default_golden = os.path.join(ROOT, "tests", "skill-budgets.golden")
    c = sub.add_parser("check")
    c.add_argument("--packs-dir", default=default_packs)
    c.add_argument("--golden", default=default_golden)
    c.add_argument("--verbose", action="store_true")
    s = sub.add_parser("seal")
    s.add_argument("pack_dir")
    s.add_argument("--also", action="append")
    s.add_argument("--golden")
    g = sub.add_parser("golden")
    g.add_argument("--packs-dir", default=default_packs)
    args = ap.parse_args(argv)
    return {"check": cmd_check, "seal": cmd_seal, "golden": cmd_golden}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
