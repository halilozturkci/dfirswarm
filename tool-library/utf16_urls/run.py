#!/usr/bin/env python3
import json, sys, re
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1]))
from _output import LosslessPage
d = json.load(sys.stdin)
path = d["path"]
contains = (d.get("contains") or "").lower()
limit = int(d.get("limit", 200))
data = open(path, "rb").read()
out = LosslessPage("utf16_urls", [path, contains], limit)
seen = set()
# ascii
for m in re.finditer(rb'https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%\-]{6,300}', data):
    s = m.group().decode("ascii", "ignore")
    if s not in seen:
        seen.add(s)
        if not contains or contains in s.lower():
            out.add({"enc": "ascii", "off": m.start(), "text": s})
# utf16le printable runs
i = 0
n = len(data)
while i + 1 < n:
    if 32 <= data[i] < 127 and data[i + 1] == 0:
        j = i
        while j + 1 < n and 32 <= data[j] < 127 and data[j + 1] == 0:
            j += 2
        if (j - i) // 2 >= 8:
            s = data[i:j:2].decode("ascii")
            sl = s.lower()
            if ("http" in sl or "file:" in sl or "visited:" in sl or "192.168" in sl):
                if s not in seen:
                    seen.add(s)
                    if not contains or contains in sl:
                        out.add({"enc": "utf16le", "off": i, "text": s})
        i = j + 2
    else:
        i += 1
page = out.finish()
print(json.dumps({"path": path, "count": page["matched"], "urls": out.page, **page}, ensure_ascii=False))
