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
