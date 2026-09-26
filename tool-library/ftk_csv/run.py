#!/usr/bin/env python3
import json, sys, csv, io, re
from datetime import datetime
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
        agent = re.sub(
            r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
        )
        self.path = Path("work") / agent / "tool-output" / f"{self.tool}-{digest}.jsonl"

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
            result["all_results"] = str(self.path)
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

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
