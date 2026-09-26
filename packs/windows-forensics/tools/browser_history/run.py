#!/usr/bin/env python3
"""Read a browser history database that was copied off a live or imaged disk.

This exists because of a measured failure: in one case `sqlite_query` had a
93% error rate against these files, and the cause was not the SQL. A browser
database extracted from an image arrives with its write-ahead log beside it,
and SQLite refuses to open it read-only while the WAL is unplayed — or, worse,
opens it and returns the state *before* the last session, which is the part an
examiner wants.

So: copy the database and any -wal and -shm beside it into a scratch
directory, open the copy read-write so SQLite checkpoints the WAL, and query
that. The original is never touched, and the answer includes whether a WAL was
present, because "there was a WAL and we played it" belongs in the record.

Chrome, Edge and Firefox all get a named query; anything else takes `sql`.
"""
import json
import os
import shutil
import sqlite3
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

QUERIES = {
    "chrome_history": (
        "SELECT u.id, u.url, u.title, u.visit_count, u.typed_count, "
        "datetime(u.last_visit_time/1000000-11644473600, 'unixepoch') AS last_visit_utc "
        "FROM urls u ORDER BY u.last_visit_time DESC"
    ),
    "chrome_downloads": (
        "SELECT d.id, d.target_path, d.tab_url, d.total_bytes, d.received_bytes, "
        "datetime(d.start_time/1000000-11644473600, 'unixepoch') AS start_utc, "
        "datetime(d.end_time/1000000-11644473600, 'unixepoch') AS end_utc "
        "FROM downloads d ORDER BY d.start_time DESC"
    ),
    "firefox_history": (
        "SELECT p.id, p.url, p.title, p.visit_count, "
        "datetime(p.last_visit_date/1000000, 'unixepoch') AS last_visit_utc "
        "FROM moz_places p WHERE p.last_visit_date IS NOT NULL ORDER BY p.last_visit_date DESC"
    ),
    "firefox_downloads": (
        "SELECT a.id, a.content, datetime(a.dateAdded/1000000, 'unixepoch') AS added_utc "
        "FROM moz_annos a WHERE a.anno_attribute_id IN "
        "(SELECT id FROM moz_anno_attributes WHERE name LIKE 'downloads/%') ORDER BY a.dateAdded DESC"
    ),
    "tables": "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name",
}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def statements(sql):
    """The statements of `sql`, each whole: split at a ";" only where SQLite
    says the text so far is a complete statement, so one inside a string or
    a comment stays where it is."""
    out, buf = [], ""
    for part in sql.split(";"):
        buf += part + ";"
        if sqlite3.complete_statement(buf):
            s = buf.strip().rstrip(";").strip()
            if s:
                out.append(s)
            buf = ""
    rest = buf.rstrip(";").strip()
    if rest:
        out.append(rest)
    return out


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the History, places.sqlite or other database")
    if not os.path.isfile(path):
        fail("no such file", path=path)

    query = args.get("query", "tables")
    sql = args.get("sql")
    if sql is not None and not isinstance(sql, str):
        fail("sql must be a string")
    if sql is None:
        if query not in QUERIES:
            fail("unknown query", query=query, known=sorted(QUERIES))
        sql = QUERIES[query]
    # Several statements are run one by one: sqlite3's execute takes one,
    # and "You can only execute one statement at a time" was the answer two
    # agents got for "schema; count" (sixth CTF round).
    stmts = statements(sql)
    if not stmts:
        fail("sql is empty")
    for s in stmts:
        if not s.lower().startswith(("select", "with", "pragma")):
            # This reads evidence. A statement that could write does not belong.
            fail("sql must be a SELECT, WITH or PRAGMA", statement=s)

    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer", limit=args.get("limit"))
    limit = min(limit, 20000)

    scratch = tempfile.mkdtemp(prefix="browser-")
    try:
        copy = os.path.join(scratch, os.path.basename(path))
        shutil.copy2(path, copy)
        sidecars = []
        for suffix in ("-wal", "-shm", "-journal"):
            beside = path + suffix
            if os.path.isfile(beside):
                shutil.copy2(beside, copy + suffix)
                sidecars.append(os.path.basename(beside))

        # Read-write on the *copy*, so SQLite replays and checkpoints the WAL.
        conn = sqlite3.connect(copy)
        conn.row_factory = sqlite3.Row
        results = []
        try:
            for statement_index, s in enumerate(stmts):
                try:
                    cur = conn.execute(s)
                    page = LosslessPage(
                        "browser_history",
                        [path, s, statement_index],
                        limit,
                    )
                    for row in cur:
                        page.add(dict(row))
                    kept = page.finish()
                    columns = [d[0] for d in (cur.description or [])]
                except sqlite3.Error as exc:
                    fail("sqlite refused the query", reason=str(exc), sql=s, done=len(results))
                results.append({
                    "sql": s,
                    "columns": columns,
                    "rows": page.page,
                    "row_count": kept["matched"],
                    **kept,
                })
        finally:
            conn.close()

        out = {"path": path, "query": None if args.get("sql") else query}
        # One statement answers as it always has; several answer each in turn.
        out.update({k: v for k, v in results[0].items() if k != "sql"} if len(results) == 1 else {"results": results})
        out.update({"sidecars_copied": sidecars, "wal_replayed": any(s.endswith("-wal") for s in sidecars)})
        print(json.dumps(out, indent=2, default=str))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    main()
