#!/usr/bin/env python3
import json, sys
from pathlib import Path
from xml.etree import ElementTree as ET
from Evtx.Evtx import Evtx

sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1]))
from _output import LosslessPage

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
