#!/usr/bin/env python3
"""Read an ESE (Extensible Storage Engine) database as tables.

The gap this closes is recorded in a delivered report's own words: "No
`esedbexport`: WebCacheV01.dat and spartan.edb could not be parsed as
tables". That file appears in four of the fifteen measured runs across 144
trace events and was never once read as tables. The same wrapper opens
SRUDB.dat (the System Resource Usage Monitor) and Edge's database, so one
tool covers three artefacts that a Windows case asks for every time.

Backed by `esedbexport` (libesedb), which writes one TSV per table into a
directory. This wraps it: list the tables, or read one with a row cap, and
return JSON either way. It never leaves its export behind in a place the
caller did not ask for.
"""
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1]))
from _output import LosslessPage


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the .dat or .edb file to read", path=args.get("path"))
    if not os.path.isfile(path):
        fail("no such file", path=path)

    table = args.get("table")
    if table is not None and not isinstance(table, str):
        fail("table must be a string", table=table)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))
    limit = min(limit, 20000)

    if shutil.which("esedbexport") is None:
        fail(
            "esedbexport is not on PATH",
            hint="brew install libesedb, or apt-get install libesedb-utils; "
            "scripts/toolbox.sh reports it with the dfir set",
        )

    out = tempfile.mkdtemp(prefix="esedb-")
    try:
        # -t names the export root; libesedb appends ".export". No -q: the
        # esedbexport Debian ships (20181229) has none, and refused the call.
        target = os.path.join(out, "db")
        proc = subprocess.run(
            ["esedbexport", "-t", target, path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        export = target + ".export"
        if not os.path.isdir(export):
            fail(
                "esedbexport produced no tables",
                status=proc.returncode,
                stderr=proc.stderr.decode("utf-8", "replace").strip()[:2000],
            )

        # libesedb names each export file <table>.<its index> (Containers.4,
        # Container_1.6): the table is the part before the index, the name
        # an agent knows it by. Taking the whole file name made every
        # table=Container_1 "no such table" in a real run.
        files = {}
        for f in os.listdir(export):
            if os.path.isfile(os.path.join(export, f)):
                base = f[: -len(".csv")] if f.endswith(".csv") else f
                m = re.fullmatch(r"(.+)\.(\d+)", base)
                files[f] = m.group(1) if m else base
        names = sorted(set(files.values()))
        if table is None:
            sizes = {}
            for f, name in files.items():
                sizes[name] = sizes.get(name, 0) + os.path.getsize(os.path.join(export, f))
            print(json.dumps({
                "path": path,
                "tables": names,
                "table_count": len(names),
                "bytes_per_table": sizes,
                "hint": "call again with table=<name> to read one",
            }, indent=2))
            return

        # By its name, or by the export file's own name (index and all).
        wanted = table.lower()
        hits = sorted(f for f, name in files.items() if wanted in (name.lower(), f.lower(), f.lower().removesuffix(".csv")))
        if not hits:
            fail("no such table", table=table, tables=names)
        chosen = files[hits[0]]
        # Tab-separated, whatever the extension says.
        src = os.path.join(export, hits[0])

        rows = LosslessPage("esedb_query", [path, table, hits[0]], limit)
        with open(src, "r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.reader(fh, delimiter="\t")
            header = next(reader, [])
            for row in reader:
                rows.add({header[i] if i < len(header) else f"col{i}": v for i, v in enumerate(row)})
        page = rows.finish()
        print(json.dumps({
            "path": path,
            "table": chosen,
            "columns": header,
            "rows": rows.page,
            "row_count": page["matched"],
            **page,
        }, indent=2))
    finally:
        shutil.rmtree(out, ignore_errors=True)


if __name__ == "__main__":
    main()
