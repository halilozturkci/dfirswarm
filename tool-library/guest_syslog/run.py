#!/usr/bin/env python3
import json, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1]))
from _output import LosslessPage
args = json.load(sys.stdin)
path = args["path"]
prefix = args.get("prefix", "Apr  6")
limit = int(args.get("limit", 200))
skip_kernel = bool(args.get("skip_kernel", True))
hour_re = args.get("hour_re")  # optional e.g. "0[89]:"
data = Path(path).read_bytes()
pat = re.compile(re.escape(prefix).encode() + rb" (\d{2}:\d{2}:\d{2}) [^\x00-\x1f]{5,160}")
hour_pat = re.compile(hour_re.encode()) if hour_re else None
seen = LosslessPage("guest_syslog", [path, prefix, skip_kernel, hour_re], limit)
seen_set = set()
for m in pat.finditer(data):
    s = m.group(0).decode("ascii", "replace")
    if skip_kernel and "kernel:" in s:
        continue
    if hour_pat and not hour_pat.search(s.encode()):
        continue
    if s in seen_set:
        continue
    seen_set.add(s)
    seen.add({"off": m.start(), "line": s})
page = seen.finish()
json.dump({"count": page["matched"], "lines": seen.page, **page}, sys.stdout)
