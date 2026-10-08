#!/usr/bin/env python3
"""Read knowledgeC.db: the application and device-state records macOS keeps for its own features.

CoreDuet records what the machine was doing (Apple's features use it: it is not an
audit log) in one SQLite file per user and one for the system. Streams an examiner
meets:

    /app/inFocus        which application was in front, and for how long
    /app/usage          application use, with the bundle id
    /display/isBacklit  the screen on or off (the state is in ZVALUEINTEGER)
    /device/isLocked    locked or unlocked (the state is in ZVALUEINTEGER)
    /safari/history     browsing
    /app/webUsage       per-application web use, with a domain

Which streams exist, and what they carry, vary by build and by device. This tool
inventories every stream in the file and reads what it finds; it does not assume a
stream is there.

**Every time in the file is Apple absolute: seconds since 2001-01-01 UTC.** Read as
Unix time it lands in 1970; add the wrong constant and it lands somewhere plausible
and wrong. The conversion is +978307200 and is applied here, with the raw value kept
beside the converted one.

What one entry carries (parser knowledgec_query/3): the ZOBJECT row it came from
(`z_pk`, `source_table`), the typed values (`value_string`, `value_integer`,
`value_double`, `value_type_code`), the raw and converted start, end and creation
times, the UUID, every other non-null ZOBJECT column, and, joined on the row's own
foreign keys, every non-null column of its ZSTRUCTUREDMETADATA and ZSOURCE rows under
their own names. The joins are made from the schema the file has (PRAGMA table_info),
not from a fixed column list, and the answer says which tables joined and a
fingerprint of the three tables' columns.

The database is never opened where it lies unless it has no sidecars. A write-ahead
log (-wal) beside it holds committed rows the main file does not. A rollback journal
(-journal) holds the old page images of a transaction that did not commit: it holds no
rows the main file lacks, and opening a copy that has one rolls that transaction back,
which changes the copy and not the main file as acquired. With either sidecar the
database and its sidecars are copied into a private directory, SQLite works on the copy
(the frames applied are counted; a rollback is reported in `source_used.journal` and in
`problems`), and the copy is removed; the evidence directory is not written to (a
read-only open of a WAL database creates a -shm file beside it). With no sidecar the file
is opened read-only and immutable.

Values are bounded when they are read, not after: a TEXT or BLOB cell is fetched as its
first 4096 characters or bytes and its whole byte length (SQLite is asked for
`substr`/`length`, never for the whole cell, and a large BLOB is not read at all except
its head, through a blob handle), so one 300 MB cell does not become 300 MB of Python.
A cut cell says `_truncated`, its whole length and where the whole is (`_where`: table,
column, rowid in the database as acquired); `export_oversize: true` streams each one to a
file under tool-output/ and names it.
"""
import base64
import datetime
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import urllib.parse
from pathlib import Path

PARSER = "knowledgec_query/3"
APPLE_EPOCH = 978307200
DEFAULT_MAX_STAGE = 2 << 30
VALUE_CAP = 4096
DEFAULT_INLINE_BYTES = 1 << 20
DEFAULT_MAX_EXPORT = 1 << 30
SELECT_COLUMNS_MAX = 1900
STANDARD = {"Z_PK", "ZSTREAMNAME", "ZVALUESTRING", "ZVALUEINTEGER", "ZVALUEDOUBLE", "ZVALUETYPECODE", "ZSTARTDATE",
            "ZENDDATE", "ZCREATIONDATE", "ZSECONDSFROMGMT", "ZUUID"}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place
    outside it, the run directory itself, or anything under inputs/ is refused.

    A string check is not enough: `work/../inputs/x`, an absolute path and a
    symlink that points out all name a place the tool must not write, and none
    of them starts with "inputs/". Resolving first and comparing directories
    is what actually holds, and the read-only inputs are the one place
    extracted bytes must never appear -- a later integrity check would report
    the evidence as modified. In a job $OUT is inside the run directory.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    return str(dest.relative_to(root))


# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, bounded by rows and by bytes, and when there are more
# rows the whole result is written as JSON Lines under work/<agent>/tool-output
# (in a job, $OUT/tool-output) and named. The file name is a digest of the page's
# key (a path), never of a value. Rows are written with ensure_ascii on: a path
# the filesystem gave as bytes that are not UTF-8 reaches Python as lone
# surrogates, which a UTF-8 file cannot hold and an escape can. A rerun that
# would replace a larger earlier file of the same name writes a new name and says
# which earlier file it kept.
class LosslessPage:
    def __init__(self, tool, key, limit, byte_limit=None):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.byte_limit = byte_limit
        self.page = []
        self.page_bytes = 0
        self.full = False
        self.bytes_bound_hit = False
        self.total = 0
        self._out = None
        self._tmp = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(json.dumps(row, default=str))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if not self.full and len(self.page) < self.limit:
            size = len(json.dumps(row, default=str)) if self.byte_limit is not None else 0
            if self.byte_limit is None or self.page_bytes + size <= self.byte_limit:
                self.page.append(row)
                self.page_bytes += size
                return
            self.bytes_bound_hit = True
        # From the first row that does not fit, every later row goes to the file only: the page is a prefix.
        self.full = True
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.byte_limit is not None:
            result["inline_byte_limit"] = self.byte_limit
            if self.bytes_bound_hit:
                result["inline_bounded_by_bytes"] = True
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            target, shown = self.path, self.shown
            if target.exists() and target.stat().st_size > os.path.getsize(self._tmp):
                n = 2
                while target.with_name("%s-%d%s" % (target.stem, n, target.suffix)).exists():
                    n += 1
                target = target.with_name("%s-%d%s" % (target.stem, n, target.suffix))
                shown = self.shown.rsplit("/", 1)[0] + "/" + target.name
                result["kept_earlier_larger_result"] = self.shown
            os.replace(self._tmp, target)
            result["all_results"] = shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


def when(value):
    if value is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(
            float(value) + APPLE_EPOCH, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def to_apple(text, name):
    try:
        parsed = datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        fail("since and until must be ISO 8601, e.g. 2026-02-14T00:00:00Z", **{name: text})
    if not parsed.tzinfo:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.timestamp() - APPLE_EPOCH


def quote(name):
    return '"%s"' % name.replace('"', '""')


def plain(value):
    """A non-text, non-BLOB SQLite value as JSON: an infinite REAL as its name (JSON has none)."""
    if isinstance(value, float) and not math.isfinite(value):
        return {"_float": repr(value)}
    return value


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(text))[:80]


class Shaper:
    """Turns the bounded columns of a row into JSON cells, fetches the head of a large BLOB through a blob
    handle, and streams an oversize value to a file when asked. Nothing here reads a whole cell into memory."""

    def __init__(self, connection, export, max_export):
        self.connection = connection
        self.export = export
        self.max_export = max_export
        self.exported_bytes = 0
        self.truncated = 0
        self.exported = 0
        self.export_refused = 0
        self.head_unavailable = 0
        self.dir = None
        self.shown = None

    def head(self, table, column, rowid):
        """The first VALUE_CAP bytes of one stored value, without loading the rest when a blob handle can be had."""
        try:
            with self.connection.blobopen(table, column, rowid, readonly=True) as blob:
                return blob.read(VALUE_CAP)
        except (AttributeError, sqlite3.Error):
            pass
        try:
            row = self.connection.execute("SELECT substr(%s,1,%d) FROM %s WHERE rowid = ?" % (quote(column), VALUE_CAP, quote(table)),
                                          (rowid,)).fetchone()
            value = row[0] if row else None
            return value.encode("utf-8", "backslashreplace") if isinstance(value, str) else value
        except sqlite3.Error:
            self.head_unavailable += 1
            return None

    def write_whole(self, table, column, rowid, kind):
        """Stream one stored value to a new file (1 MiB at a time); its name, or why it was not written."""
        if not hasattr(self.connection, "blobopen"):
            return {"_export": "not written: this Python has no blob handles (3.11 or later is needed)"}
        try:
            with self.connection.blobopen(table, column, rowid, readonly=True) as blob:
                size = len(blob)
                if self.exported_bytes + size > self.max_export:
                    self.export_refused += 1
                    return {"_export": "not written: it would pass max_export_bytes (%d)" % self.max_export}
                if self.dir is None:
                    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
                    if job and out:
                        self.dir = Path(out) / "tool-output" / "knowledgec-values"
                        self.shown = "store/jobs/%s/out/tool-output/knowledgec-values" % safe_name(job)
                    else:
                        self.dir = Path("work") / safe_name(os.environ.get("AGENT_ID") or "tool") / "tool-output" / "knowledgec-values"
                        self.shown = str(self.dir)
                    self.dir.mkdir(parents=True, exist_ok=True)
                base = "%s.%s.%s" % (safe_name(table), safe_name(column), rowid)
                n = 0
                while True:
                    name = "%s%s.%s" % (base, "" if n == 0 else "-%d" % n, "txt" if kind == "text" else "bin")
                    try:
                        fd = os.open(str(self.dir / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                        break
                    except FileExistsError:
                        n += 1
                with os.fdopen(fd, "wb") as out:
                    done = 0
                    while done < size:
                        block = blob.read(min(1 << 20, size - done))
                        if not block:
                            break
                        out.write(block)
                        done += len(block)
                self.exported_bytes += done
                self.exported += 1
                return {"_whole_value_file": "%s/%s" % (self.shown, name), "_whole_value_bytes_written": done}
        except (OSError, sqlite3.Error) as exc:
            return {"_export": "not written: %s: %s" % (type(exc).__name__, exc)}

    def cell(self, value, length, table, column, rowid):
        if isinstance(value, str):
            if len(value) <= VALUE_CAP:
                return value
            return self.oversize("text", value[:VALUE_CAP], length, table, column, rowid)
        if value is None and length is not None and length > VALUE_CAP:
            head = self.head(table, column, rowid)
            return self.oversize("blob", head if head is not None else b"", length, table, column, rowid)
        if isinstance(value, (bytes, bytearray)):
            return {"_blob_bytes": len(value), "_base64": base64.b64encode(bytes(value)).decode("ascii"), "_truncated": False}
        return plain(value)

    def oversize(self, kind, head, length, table, column, rowid):
        self.truncated += 1
        if kind == "text":
            out = {"_text_head": head, "_text_bytes": length, "_truncated": True}
        else:
            out = {"_blob_bytes": length, "_base64": base64.b64encode(bytes(head)).decode("ascii"), "_truncated": True}
        out["_where"] = {"table": table, "column": column, "rowid": rowid}
        if self.export and rowid is not None:
            out.update(self.write_whole(table, column, rowid, kind))
        return out


def bounded_select(alias, prefix, column):
    """Two select terms for one column: its value cut at VALUE_CAP (a large BLOB is not read at all; typeof()
    and length() are answered from the record header), and its byte length where it is TEXT or BLOB and long."""
    c = "%s.%s" % (alias, quote(column))
    value = ("CASE typeof(%s) WHEN 'text' THEN substr(%s,1,%d) WHEN 'blob' THEN "
             "CASE WHEN length(%s) > %d THEN NULL ELSE %s END ELSE %s END" % (c, c, VALUE_CAP + 1, c, VALUE_CAP, c, c))
    length = ("CASE typeof(%s) WHEN 'blob' THEN length(%s) WHEN 'text' THEN "
              "CASE WHEN length(substr(%s,1,%d)) > %d THEN length(CAST(%s AS BLOB)) END END" % (c, c, c, VALUE_CAP + 1, VALUE_CAP, c))
    return ["%s AS %s" % (value, quote(prefix + "|" + column)), "%s AS %s" % (length, quote(prefix + "#" + column))]


def sha256_copy(src, dst):
    digest = hashlib.sha256()
    with open(src, "rb") as read, open(dst, "wb") as write:
        for block in iter(lambda: read.read(1 << 20), b""):
            digest.update(block)
            write.write(block)
    return digest.hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def wal_inventory(path):
    """What the WAL says about itself, from its header and its frame headers: the frames of its current
    generation (their salts match the header's) and the last commit among them. Checksums are not verified."""
    size = os.path.getsize(path)
    info = {"bytes": size}
    if size < 32:
        info.update(state="empty or shorter than its 32-byte header", frames_valid=0, frames_committed=0)
        return info
    with open(path, "rb") as fh:
        head = fh.read(32)
        magic, _version, page, seq, salt1, salt2 = struct.unpack(">IIIIII", head[:24])
        if magic not in (0x377F0682, 0x377F0683) or not 512 <= page <= 65536 or page & (page - 1):
            info.update(state="not a WAL header (magic %08x, page size %d)" % (magic, page), frames_valid=0, frames_committed=0)
            return info
        stride = 24 + page
        total = (size - 32) // stride
        valid, committed = 0, 0
        for i in range(total):
            fh.seek(32 + i * stride)
            frame = fh.read(24)
            if len(frame) < 24:
                break
            pgno, commit, s1, s2 = struct.unpack(">IIII", frame[:16])
            if s1 != salt1 or s2 != salt2 or pgno == 0:
                break
            valid += 1
            if commit:
                committed = valid
    info.update(page_size=page, checkpoint_sequence=seq, frames_in_file=total, frames_valid=valid, frames_committed=committed,
                state="frames of the current generation counted from their salts; checksums not verified")
    return info


def stage_parent():
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        return Path(out) / "knowledgec-stage"
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    return Path("work") / agent


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

    def positive(name, default):
        value = args.get(name, default)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            fail("%s must be a positive integer" % name, **{name: value})
        return value

    limit = positive("limit", 500)
    max_stage = positive("max_stage_bytes", DEFAULT_MAX_STAGE)
    inline_bytes = positive("max_inline_bytes", DEFAULT_INLINE_BYTES)
    max_export = positive("max_export_bytes", DEFAULT_MAX_EXPORT)
    export = args.get("export_oversize", False)
    if not isinstance(export, bool):
        fail("export_oversize must be true or false")
    out_name = args.get("out_file")
    if out_name is not None and (not isinstance(out_name, str) or not out_name):
        fail("out_file must be a non-empty string")
    if out_name is not None:
        resolve_output(out_name, "out_file")   # refuses a place outside the run, or under inputs/
    since = to_apple(args["since"], "since") if args.get("since") else None
    until = to_apple(args["until"], "until") if args.get("until") else None

    problems = []
    # The sidecars decide how the file is opened. A WAL holds committed rows the main file lacks; a hot rollback
    # journal holds the old pages of a transaction that did not commit and is rolled back when the copy is opened.
    sidecars = {}
    for suffix in ("-wal", "-shm", "-journal"):
        beside = db + suffix
        if os.path.isfile(beside):
            sidecars[suffix] = {"bytes": os.path.getsize(beside)}
    stage = None
    source = {"database": db, "staged": False, "sidecars": sidecars}
    try:
        try:
            if "-wal" in sidecars or "-journal" in sidecars:
                total = os.path.getsize(db) + sum(v["bytes"] for v in sidecars.values())
                if total > max_stage:
                    fail("the database and its sidecars (%d bytes) are over max_stage_bytes (%d): nothing was read; raise it, or query the "
                         "files with a tool that applies the WAL" % (total, max_stage), db=db, sidecars=sidecars)
                parent = stage_parent()
                parent.mkdir(parents=True, exist_ok=True)
                stage = tempfile.mkdtemp(prefix="knowledgec-", dir=str(parent))
                staged_db = os.path.join(stage, os.path.basename(db))
                source["database_sha256"] = sha256_copy(db, staged_db)
                source["database_bytes"] = os.path.getsize(db)
                for suffix in sidecars:
                    sidecars[suffix]["sha256"] = sha256_copy(db + suffix, staged_db + suffix)
                if "-wal" in sidecars:
                    source["wal"] = wal_inventory(db + "-wal")
                source["staged"] = True
                source["open_mode"] = "a private copy of the database and its sidecars, read-write so SQLite works on them, removed at the end"
                connection = sqlite3.connect(staged_db)
            else:
                source["open_mode"] = "read-only and immutable, in place (no WAL or journal beside it)"
                connection = sqlite3.connect("file:%s?mode=ro&immutable=1" % urllib.parse.quote(os.path.abspath(db)), uri=True)
        except (OSError, sqlite3.Error) as exc:
            fail("the database could not be opened or staged", db=db, reason="%s: %s" % (type(exc).__name__, exc))
        connection.row_factory = sqlite3.Row
        # Text that is not UTF-8 comes back with its bytes escaped, every byte still said.
        connection.text_factory = lambda b: b.decode("utf-8", "backslashreplace")
        try:
            tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        except sqlite3.Error as exc:
            fail("this file is not a SQLite database", db=db, reason=str(exc))
        if "ZOBJECT" not in tables:
            fail("this is not a knowledgeC database: there is no ZOBJECT table", db=db, tables=tables)
        if source["staged"] and "-journal" in sidecars:
            after = sha256_file(staged_db)
            present = os.path.exists(staged_db + "-journal")
            rolled = (after != source["database_sha256"]) or not present
            source["journal"] = {"bytes": sidecars["-journal"]["bytes"], "sha256": sidecars["-journal"]["sha256"],
                                 "rollback_applied": rolled, "journal_present_after_open": present,
                                 "database_sha256_as_acquired": source["database_sha256"], "database_sha256_after_open": after}
            if rolled:
                problems.append("a rollback journal was beside the database and SQLite rolled back the uncommitted transaction it held in the "
                                "private copy: the rows below are the database as it stands after that rollback, which is not the main file "
                                "as acquired (its state changed in the copy)")
            else:
                problems.append("a rollback journal was beside the database and SQLite did not roll it back (it is not a hot journal): "
                                "it adds nothing to the rows below")
        if source["staged"] and "-wal" in sidecars:
            try:
                busy, log, done = connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
                source["wal_checkpoint"] = {"busy": busy, "log": log, "checkpointed": done}
            except sqlite3.Error as exc:
                source["wal_checkpoint"] = {"error": str(exc)}
        try:
            connection.execute("PRAGMA query_only=ON")
        except sqlite3.Error:
            pass

        def info(table, required):
            try:
                return [(r["name"], r["type"]) for r in connection.execute("PRAGMA table_info(%s)" % quote(table))]
            except sqlite3.Error as exc:
                if required:
                    fail("the schema of %s could not be read" % table, db=db, table=table, reason=str(exc))
                problems.append("the schema of %s could not be read (%s): its rows are not joined" % (table, exc))
                return []

        zobject = info("ZOBJECT", True)
        columns = {n for n, _t in zobject}
        meta_cols = info("ZSTRUCTUREDMETADATA", False) if "ZSTRUCTUREDMETADATA" in tables else []
        src_cols = info("ZSOURCE", False) if "ZSOURCE" in tables else []
        joins = {"ZSTRUCTUREDMETADATA": bool(meta_cols) and "ZSTRUCTUREDMETADATA" in columns and any(n == "Z_PK" for n, _ in meta_cols),
                 "ZSOURCE": bool(src_cols) and "ZSOURCE" in columns and any(n == "Z_PK" for n, _ in src_cols)}
        fingerprint = hashlib.sha256("\n".join(
            "%s|%s|%s" % (t, n, ty) for t, cols in (("ZOBJECT", zobject), ("ZSOURCE", src_cols), ("ZSTRUCTUREDMETADATA", meta_cols))
            for n, ty in sorted(cols)).encode("utf-8")).hexdigest()

        select = [t for n, _t in zobject for t in bounded_select("o", "o", n)] + ['o.rowid AS "o!rowid"']
        if joins["ZSTRUCTUREDMETADATA"]:
            select += [t for n, _t in meta_cols for t in bounded_select("m", "m", n)] + ['m.rowid AS "m!rowid"']
        if joins["ZSOURCE"]:
            select += [t for n, _t in src_cols for t in bounded_select("s", "s", n)] + ['s.rowid AS "s!rowid"']
        if len(select) > SELECT_COLUMNS_MAX:
            fail("this schema has %d columns to read (two terms each) and SQLite will not select more than %d: nothing was read; "
                 "query the part you need with sqlite_query" % (len(select), SELECT_COLUMNS_MAX), db=db, columns=len(select))
        sql = "SELECT %s FROM ZOBJECT AS o" % ", ".join(select)
        if joins["ZSTRUCTUREDMETADATA"]:
            sql += " LEFT JOIN ZSTRUCTUREDMETADATA AS m ON o.ZSTRUCTUREDMETADATA = m.Z_PK"
        if joins["ZSOURCE"]:
            sql += " LEFT JOIN ZSOURCE AS s ON o.ZSOURCE = s.Z_PK"
        where, params = [], []
        applied, unapplied, reasons = [], [], []
        if args.get("stream"):
            if "ZSTREAMNAME" in columns:
                where.append("o.ZSTREAMNAME LIKE ?")
                params.append(args["stream"])
                applied.append("stream")
            else:
                unapplied.append("stream")
                reasons.append("stream could not be applied: this database has no ZSTREAMNAME column, so the rows are not filtered by stream")
        for name, value, op in (("since", since, ">="), ("until", until, "<=")):
            if value is None:
                continue
            if "ZSTARTDATE" in columns:
                where.append("o.ZSTARTDATE %s ?" % op)
                params.append(value)
                applied.append(name)
            else:
                unapplied.append(name)
                reasons.append("%s could not be applied: this database has no ZSTARTDATE column, so the rows are not filtered by time" % name)
        if where:
            sql += " WHERE " + " AND ".join(where)
        order = "o.ZSTARTDATE, o.Z_PK" if "ZSTARTDATE" in columns and "Z_PK" in columns else (
            "o.ZSTARTDATE" if "ZSTARTDATE" in columns else ("o.Z_PK" if "Z_PK" in columns else "o.rowid"))
        sql += " ORDER BY " + order

        sink = None
        if out_name:
            try:
                Path(out_name).parent.mkdir(parents=True, exist_ok=True)
                # The name as the caller gave it: O_EXCL refuses a name that exists, a link (a dangling one included) as much as a file.
                fd = os.open(out_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
            except FileExistsError:
                fail("out_file already exists; the tool does not overwrite: use a new name", out_file=out_name)
            except OSError as exc:
                fail("out_file could not be created", out_file=out_name, reason="%s: %s" % (type(exc).__name__, exc))
            sink = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
        paging = None if sink else LosslessPage("knowledgec_query", [db, args.get("stream"), args.get("since"), args.get("until")],
                                                limit, inline_bytes)
        inline = []
        inline_state = {"bytes": 0, "full": False, "bounded_by_bytes": False}
        count = 0
        unconverted = 0
        shaper = Shaper(connection, export, max_export)
        try:
            cursor = connection.execute(sql, params)
        except sqlite3.Error as exc:
            fail("the query failed", reason=str(exc), sql=" ".join(sql.split())[:2000])
        names = [d[0] for d in cursor.description]
        groups = {"o": ("ZOBJECT", [n for n, _t in zobject]), "m": ("ZSTRUCTUREDMETADATA", [n for n, _t in meta_cols]),
                  "s": ("ZSOURCE", [n for n, _t in src_cols])}
        for raw in cursor:
            row = dict(zip(names, raw))
            shaped = {}
            for prefix, (table, cols) in groups.items():
                if prefix + "!rowid" not in row:
                    continue
                rowid = row[prefix + "!rowid"]
                shaped[prefix] = {c: (row[prefix + "|" + c], row[prefix + "#" + c], rowid) for c in cols}
            o = {c: v for c, (v, _n, _r) in shaped["o"].items()}
            start_raw, end_raw, created_raw = o.get("ZSTARTDATE"), o.get("ZENDDATE"), o.get("ZCREATIONDATE")
            duration = None
            if (isinstance(start_raw, (int, float)) and isinstance(end_raw, (int, float))
                    and math.isfinite(start_raw) and math.isfinite(end_raw)):
                duration = round(float(end_raw) - float(start_raw), 3)
            for r in (start_raw, end_raw, created_raw):
                if r is not None and when(r) is None:
                    unconverted += 1

            def cell(prefix, c):
                v, n, rowid = shaped[prefix][c]
                return shaper.cell(v, n, groups[prefix][0], c, rowid)

            uuid = o.get("ZUUID")
            entry = {
                "parser": PARSER, "source_table": "ZOBJECT", "z_pk": o.get("Z_PK"), "stream": cell("o", "ZSTREAMNAME") if "ZSTREAMNAME" in o else None,
                "value_string": cell("o", "ZVALUESTRING") if "ZVALUESTRING" in o else None,
                "value_integer": plain(o.get("ZVALUEINTEGER")), "value_double": plain(o.get("ZVALUEDOUBLE")),
                "value_type_code": plain(o.get("ZVALUETYPECODE")),
                "start_raw": plain(start_raw), "end_raw": plain(end_raw), "created_raw": plain(created_raw),
                "start": when(start_raw), "end": when(end_raw), "created": when(created_raw),
                "duration_seconds": duration, "utc_offset_seconds": o.get("ZSECONDSFROMGMT"),
                "uuid": None,
            }
            if isinstance(uuid, (bytes, bytearray)):
                entry["uuid"] = bytes(uuid).hex()
            elif uuid is not None:
                entry["uuid"] = cell("o", "ZUUID")
            other = {c: cell("o", c) for c, (v, n, _r) in shaped["o"].items() if c not in STANDARD and (v is not None or n is not None)}
            if other:
                entry["zobject_other"] = other
            for key, prefix in (("metadata", "m"), ("source", "s")):
                if prefix in shaped:
                    got = {c: cell(prefix, c) for c, (v, n, _r) in shaped[prefix].items() if v is not None or n is not None}
                    if got:
                        entry[key] = got
            count += 1
            if sink:
                line = json.dumps(entry, default=str, sort_keys=True)
                sink.write(line + "\n")
                if not inline_state["full"] and len(inline) < limit:
                    if inline_state["bytes"] + len(line) <= inline_bytes:
                        inline.append(entry)
                        inline_state["bytes"] += len(line)
                    else:
                        inline_state["bounded_by_bytes"] = True
                        inline_state["full"] = True
                else:
                    inline_state["full"] = True
            else:
                paging.add(entry)

        streams = LosslessPage("knowledgec_streams", [db], 200, 256 << 10)
        if "ZSTREAMNAME" in columns:
            start_col = "ZSTARTDATE" if "ZSTARTDATE" in columns else "NULL"
            try:
                for name, n, first, last in connection.execute(
                        "SELECT ZSTREAMNAME, COUNT(*), MIN(%s), MAX(%s) FROM ZOBJECT GROUP BY 1 ORDER BY 2 DESC, 1" % (start_col, start_col)):
                    streams.add({"stream": name, "count": n, "first_start_raw": plain(first), "last_start_raw": plain(last),
                                 "first_start": when(first), "last_start": when(last)})
            except sqlite3.Error as exc:
                problems.append("the stream inventory could not be made (%s): the entries are complete, the list of streams is not" % exc)
        else:
            problems.append("this database has no ZSTREAMNAME column, so there is no stream inventory and no entry has a stream")
        streams_page = streams.finish()
        connection.close()
    finally:
        if stage:
            shutil.rmtree(stage, ignore_errors=True)
            if os.environ.get("JOB_ID") and os.environ.get("OUT"):
                try:
                    os.rmdir(str(stage_parent()))      # an empty directory is not a sealed output
                except OSError:
                    pass
    if source["staged"]:
        source["staged_copy"] = "removed"

    if sink:
        sink.flush()
        os.fsync(sink.fileno())
        sink.close()
        shown, complete, limited = inline, out_name, count > len(inline)
        page = {"inline_bounded_by_bytes": inline_state["bounded_by_bytes"]}
    else:
        page = paging.finish()
        shown, complete, limited = paging.page, page.get("all_results"), page["truncated"]

    problems = reasons + problems
    wal = source.get("wal")
    if wal and not wal.get("frames_valid"):
        problems.append("a -wal file is beside the database and holds no frame of its current generation (%s): it added nothing" % wal.get("state"))
    cp = source.get("wal_checkpoint")
    if wal and wal.get("frames_valid") and cp and (cp.get("error") or cp.get("log", 0) < 1 or cp.get("busy")):
        problems.append("the WAL has frames of its current generation but SQLite did not apply them (checkpoint %s): rows committed only "
                        "in the WAL are not in this result" % json.dumps(cp))
    if unconverted:
        problems.append("%d time value(s) could not be converted from the Apple epoch; their raw values are in the entries" % unconverted)
    if shaper.head_unavailable:
        problems.append("%d large value(s) could not be read even for their first bytes; their length is given" % shaper.head_unavailable)
    if shaper.export_refused:
        problems.append("%d oversize value(s) were not written to a file: they would pass max_export_bytes (%d)" % (shaper.export_refused, max_export))
    print(json.dumps({
        "db": db,
        "parser": PARSER,
        "status": "partial" if problems else "complete",
        "problems": problems,
        "entries": shown,
        "entry_count": count,
        "entries_inline": len(shown),
        "complete_entries": complete,
        "inline_limited": bool(limited),
        "inline_bounded_by_bytes": bool(page.get("inline_bounded_by_bytes")),
        "inline_byte_limit": inline_bytes,
        **({"kept_earlier_larger_result": page["kept_earlier_larger_result"]} if page.get("kept_earlier_larger_result") else {}),
        "values": {"cap": VALUE_CAP, "truncated": shaper.truncated, "exported": shaper.exported, "exported_bytes": shaper.exported_bytes,
                   "export_requested": export,
                   "note": "A TEXT or BLOB cell longer than the cap shows its first %d characters or bytes, its whole byte length and "
                           "where the whole is in the database (_where); export_oversize: true writes each whole value to a file and names it." % VALUE_CAP},
        "filters_applied": applied,
        **({"filters_unapplied": unapplied} if unapplied else {}),
        "schema": {"tables": tables, "joins": joins, "fingerprint": fingerprint,
                   "zobject_columns": [n for n, _t in zobject]},
        "source_used": source,
        "streams": streams.page,
        "streams_total": streams_page["matched"],
        "streams_pages": streams_page,
        "note": "Times are converted from the Apple epoch (2001-01-01 UTC) and returned as UTC, with the raw value beside each. "
                "The streams list is every stream in the database, whatever the filters. since and until select rows by start time, "
                "so a record that began before the window and overlapped it is not in it. A write-ahead log beside the database is "
                "applied in a private copy and counted in source_used; a rollback journal is rolled back in the copy and reported; a "
                "-shm file is a derived index and adds nothing. These are "
                "records of application and device state the machine kept for its own features: foreground application and screen "
                "or lock state do not show a person at the keyboard, and retention varies by OS version and device, so scope an "
                "absence to the earliest and latest rows of the stream in this database.",
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
