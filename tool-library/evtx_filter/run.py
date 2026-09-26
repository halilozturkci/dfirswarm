#!/usr/bin/env python3
import json, sys
from pathlib import Path
from xml.etree import ElementTree as ET
from Evtx.Evtx import Evtx

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

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

def parse_rec(xml):
    root = ET.fromstring(xml)
    sysel = root.find(f"{NS}System")
    d = {}
    if sysel is not None:
        eid = sysel.find(f"{NS}EventID")
        d["EventID"] = eid.text if eid is not None else None
        t = sysel.find(f"{NS}TimeCreated")
        d["TimeCreated"] = t.get("SystemTime") if t is not None else None
        rec = sysel.find(f"{NS}EventRecordID")
        d["EventRecordID"] = rec.text if rec is not None else None
        pr = sysel.find(f"{NS}Provider")
        d["Provider"] = pr.get("Name") if pr is not None else None
    data = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for child in list(ed):
            name = child.get("Name") or child.tag.replace(NS, "")
            data[name] = child.text
    d["EventData"] = data
    return d

def main():
    args = json.load(sys.stdin)
    path = args["path"]
    ids = args.get("event_ids") or ""
    idset = {x.strip() for x in ids.split(",") if x.strip()} if ids else None
    prefix = args.get("time_prefix") or ""
    contains = (args.get("contains") or "").lower()
    limit = int(args.get("limit") or 200)
    out = LosslessPage(
        "evtx_filter",
        [path, sorted(idset) if idset else [], prefix, contains],
        limit,
    )
    n = 0
    with Evtx(path) as log:
        for rec in log.records():
            xml = rec.xml()
            n += 1
            if contains and contains not in xml.lower():
                if idset is None and not prefix:
                    continue
            d = parse_rec(xml)
            if idset and str(d.get("EventID")) not in idset:
                continue
            ts = d.get("TimeCreated") or ""
            if prefix and not ts.startswith(prefix):
                continue
            if contains and contains not in json.dumps(d, default=str).lower() and contains not in xml.lower():
                continue
            out.add(d)
    page = out.finish()
    json.dump({"scanned": n, "events": out.page, **page}, sys.stdout)

if __name__ == "__main__":
    main()
