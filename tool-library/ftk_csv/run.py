#!/usr/bin/env python3
import json, sys, csv, io, re
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1]))
from _output import LosslessPage

args = json.load(sys.stdin)
path = args.get("path", "inputs/Webserver.E01.csv")
contains = args.get("contains", "")
regex = args.get("regex", "")
date_contains = args.get("date_contains", "")
deleted = args.get("deleted", None)  # "yes"/"no"/None
limit = int(args.get("limit", 80))
fields = args.get("fields", None)

needles = [n for n in contains.split("|") if n] if contains else []
cre = re.compile(regex, re.I) if regex else None
needles_l = [n.lower() for n in needles]

out = LosslessPage(
    "ftk_csv",
    [path, contains, regex, date_contains, deleted, fields],
    limit,
)
with open(path, "r", encoding="utf-16", newline="") as f:
    r = csv.DictReader(f, delimiter="\t")
    for row in r:
        fp = row.get("Full Path") or ""
        fn = row.get("Filename") or ""
        blob = (fp + "\t" + fn).lower()
        if needles_l and not any(n in blob for n in needles_l):
            continue
        if cre and not cre.search(fp) and not cre.search(fn):
            continue
        if date_contains:
            dc = date_contains.lower()
            dates = " ".join([
                row.get("Created") or "",
                row.get("Modified") or "",
                row.get("Accessed") or "",
            ]).lower()
            if dc not in dates:
                continue
        if deleted is not None:
            d = (row.get("Is Deleted") or "").strip().lower()
            if d != str(deleted).lower():
                continue
        rec = {
            "name": fn,
            "path": fp,
            "size": row.get("Size (bytes)"),
            "created": row.get("Created"),
            "modified": row.get("Modified"),
            "accessed": row.get("Accessed"),
            "deleted": row.get("Is Deleted"),
        }
        if fields:
            rec = {k: rec[k] for k in fields if k in rec}
        out.add(rec)
page = out.finish()
print(json.dumps({"count": page["matched"], "rows": out.page, **page}, indent=None))
