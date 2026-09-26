#!/usr/bin/env python3
"""Read knowledgeC.db, the closest thing macOS has to a record of a person's day.

CoreDuet records what the machine was doing for Apple's own features, and keeps
it in one SQLite file per user. The streams that matter to an examiner:

    /app/inFocus        which application was in front, and for how long
    /app/usage          application use, with the bundle id
    /display/isBacklit  the screen on and off, a proxy for somebody being there
    /device/isLocked    locked and unlocked
    /safari/history     browsing, sometimes after Safari's own history was cleared
    /app/webUsage       per-application web use, with a domain

**Every time in the file is Apple absolute: seconds since 2001-01-01 UTC.** Read
as Unix time it lands in 1970 and looks obviously broken; add the wrong constant
and it lands somewhere plausible and wrong, which is worse. The conversion is
+978307200 and it is applied here.

The database is opened read-only through a file: URI, so a query cannot write to
the evidence even by accident — and it will fail rather than silently create a
new database when the path is wrong.
"""
import datetime
import json
import os
import sqlite3
import sys

APPLE_EPOCH = 978307200


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def when(value):
    if value is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(
            float(value) + APPLE_EPOCH, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def to_apple(text):
    try:
        parsed = datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        fail("since and until must be ISO 8601, e.g. 2026-02-14T00:00:00Z", value=text)
    if not parsed.tzinfo:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.timestamp() - APPLE_EPOCH


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    db = args.get("db")
    if not isinstance(db, str) or not db:
        fail("db is required: a knowledgeC.db")
    if not os.path.isfile(db):
        fail("no such database", db=db)
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    out_file = args.get("out_file")
    if out_file is not None and (not isinstance(out_file, str) or not out_file):
        fail("out_file must be a non-empty string")

    try:
        connection = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(db), uri=True)
        connection.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        fail("cannot open the database read-only", db=db, reason=str(exc))

    try:
        # sqlite opens a file lazily, so a non-database only fails on the first read.
        tables = {r[0] for r in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.DatabaseError as exc:
        fail("this file is not a SQLite database", db=db, reason=str(exc))
    if "ZOBJECT" not in tables:
        fail("this is not a knowledgeC database: there is no ZOBJECT table",
             db=db, tables=sorted(tables))

    columns = {r["name"] for r in connection.execute("PRAGMA table_info(ZOBJECT)")}
    def maybe(name, default="NULL"):
        return "ZOBJECT.%s" % name if name in columns else default

    sql = """
        SELECT ZOBJECT.ZSTREAMNAME      AS stream,
               ZOBJECT.ZVALUESTRING     AS value,
               %s                       AS start_raw,
               %s                       AS end_raw,
               %s                       AS created_raw,
               %s                       AS seconds,
               %s                       AS bundle,
               %s                       AS uuid
          FROM ZOBJECT
    """ % (maybe("ZSTARTDATE"), maybe("ZENDDATE"), maybe("ZCREATIONDATE"),
           maybe("ZSECONDSFROMGMT"), maybe("ZVALUESTRING"), maybe("ZUUID"))
    where, params = [], []
    if args.get("stream"):
        where.append("ZOBJECT.ZSTREAMNAME LIKE ?")
        params.append(args["stream"])
    if args.get("since") and "ZSTARTDATE" in columns:
        where.append("ZOBJECT.ZSTARTDATE >= ?")
        params.append(to_apple(args["since"]))
    if args.get("until") and "ZSTARTDATE" in columns:
        where.append("ZOBJECT.ZSTARTDATE <= ?")
        params.append(to_apple(args["until"]))
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY %s" % ("ZOBJECT.ZSTARTDATE" if "ZSTARTDATE" in columns else "ZOBJECT.Z_PK")

    try:
        rows = list(connection.execute(sql, params))
    except sqlite3.Error as exc:
        fail("the query failed", reason=str(exc), sql=" ".join(sql.split()))

    entries = []
    for row in rows:
        start, end = when(row["start_raw"]), when(row["end_raw"])
        duration = None
        if row["start_raw"] is not None and row["end_raw"] is not None:
            try:
                duration = round(float(row["end_raw"]) - float(row["start_raw"]), 3)
            except (TypeError, ValueError):
                duration = None
        entries.append({"stream": row["stream"], "value": row["value"],
                        "start": start, "end": end, "duration_seconds": duration,
                        "created": when(row["created_raw"]),
                        "utc_offset_seconds": row["seconds"]})

    streams = {}
    for row in connection.execute("SELECT ZSTREAMNAME, COUNT(*) c FROM ZOBJECT GROUP BY 1 ORDER BY c DESC LIMIT 30"):
        streams[row[0]] = row[1]
    connection.close()
    if out_file:
        with open(out_file, "w", encoding="utf-8", newline="\n") as fh:
            for entry in entries:
                fh.write(json.dumps(entry, default=str, sort_keys=True) + "\n")
        inline = entries[:limit]
    else:
        inline = entries

    print(json.dumps({
        "db": db,
        "entries": inline,
        "entry_count": len(entries),
        "entries_inline": len(inline),
        "complete_entries": out_file,
        "inline_limited": bool(out_file and len(entries) > len(inline)),
        "streams_in_database": streams,
        "note": "Times are converted from the Apple epoch (2001-01-01 UTC) and returned as UTC. "
                "/app/inFocus together with /display/isBacklit is the strongest presence evidence "
                "on this platform, but it records the machine's activity and not a named person: "
                "tie it to an authentication before you attribute it. Retention varies by OS "
                "version and device state; scope absence claims to the earliest and latest rows "
                "actually present in the acquired database.",
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
