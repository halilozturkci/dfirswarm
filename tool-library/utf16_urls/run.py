#!/usr/bin/env python3
import json, sys, re
from pathlib import Path
# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row: object) -> None:
        assert self._out is not None
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(
                dir=self.path.parent, prefix=f".{self.path.name}-"
            )
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            assert self._tmp is not None
            os.replace(self._tmp, self.path)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result
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
