#!/usr/bin/env python3
"""Search the catalog filelist. Pattern is data for re.search, never eval'd."""
import glob
import hashlib
import json
import os
import re
import sys

LIMIT = 100


def fail(msg, **extra):
    print(json.dumps({"error": msg, **extra}))
    sys.exit(1)


def resolve_filelist(explicit):
    """The file list to search: the one named, or the only one the kickoff's
    catalogue holds. It used to be the AF-Case2 list on every case."""
    if explicit:
        return explicit
    found = sorted(glob.glob("catalog/*/p*/filelist.txt"))
    if len(found) == 1:
        return found[0]
    if not found:
        fail("no catalog file list under catalog/; pass path=")
    fail("several catalog file lists; pass path=", candidates=found)


d = json.load(sys.stdin)
FILELIST = resolve_filelist(d.get("path"))
pattern = d.get("pattern", "")
if not isinstance(pattern, str):
    fail("pattern must be a string")
# Compiling once names a bad pattern as a bad pattern, instead of raising
# re.error on the first line and handing the agent a traceback.
try:
    rx = re.compile(pattern, re.IGNORECASE)
except re.error as exc:
    fail("pattern is not a valid regular expression", pattern=pattern, reason=str(exc))
results = []
every = []
try:
    with open(FILELIST, "r", errors="replace") as f:
        for line in f:
            if rx.search(line):
                every.append(line.rstrip("\n"))
                if len(results) < LIMIT:
                    results.append(every[-1])
except OSError as exc:
    fail("cannot read the catalog filelist", path=FILELIST, reason=exc.strerror or str(exc))
# The answer stays the first hundred, but the rest is kept, not dropped: the
# whole match set goes to a file under the caller's scratch, named on stderr,
# which the trace keeps and the caller sees.
if len(every) > len(results):
    key = hashlib.sha256(json.dumps([FILELIST, pattern]).encode("utf-8")).hexdigest()[:16]
    keep = os.path.join("work", os.environ.get("AGENT_ID") or "catalog-search", "catalog-search", "grep_filelist-%s.txt" % key)
    try:
        os.makedirs(os.path.dirname(keep), exist_ok=True)
        with open(keep, "w", encoding="utf-8") as out:
            out.write("".join(line + "\n" for line in every))
        where = f"all {len(every)} are in {keep}"
    except OSError as exc:
        where = f"the whole set could not be written ({exc.strerror or exc})"
    sys.stderr.write(f"{len(every)} lines matched; showing the first {len(results)}; {where}\n")
print(json.dumps(results))
