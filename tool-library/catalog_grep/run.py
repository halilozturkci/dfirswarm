#!/usr/bin/env python3
import json, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1]))
from _output import LosslessPage
args = json.load(sys.stdin)
pattern = args.get("pattern", "")
ignore_case = bool(args.get("ignore_case", True))
limit = int(args.get("limit", 200))
path = args.get("path", "catalog/AF-Case2.E01/p0/filelist.txt")
flags = re.I if ignore_case else 0
rx = re.compile(pattern, flags)
out = LosslessPage("catalog_grep", [path, pattern, ignore_case], limit)
with open(path, "r", errors="replace") as f:
    for line in f:
        if rx.search(line):
            out.add(line.rstrip("\n"))
page = out.finish()
print(json.dumps({"count": page["matched"], "lines": out.page, **page}))
