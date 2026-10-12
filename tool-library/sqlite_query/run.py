#!/usr/bin/env python3
"""Run a read-only SQL query over a SQLite database file, bounded and typed.

What this reads: the main database file, opened read-only and immutable, through
Python's sqlite3 module (never the sqlite3 shell). An authorizer lets a statement
read and nothing else: no write, no ATTACH, no extension, no PRAGMA that sets.
What it does not read: the write-ahead log. An immutable open ignores a -wal and
a -shm beside the database, so rows committed only in the WAL are not in the
result; the tool inventories the sidecars (name, size, WAL frames) and says so
in `snapshot_status`, loudly, instead of leaving it to be found. Applying a WAL
needs a staged copy of the database set, which this tool does not make.

The answer is bounded: an inline page of rows (`limit`, and a byte ceiling), and
when the result is more than that the whole of it in a JSON Lines file, named in
`rows_file`. Each row is typed: NULL is null, an integer or a real is a number,
text is a string (text that is not UTF-8 carries its bytes in base64 beside the
escaped form), a BLOB is {blob_b64, length, sha256}. `stdout` keeps the text form
of the inline page the old tool returned (CSV with a header, or the shell's
`|`-separated list), for the callers that read it.
"""
import base64
import collections
import csv
import hashlib
import io
import json
import math
import os
import re
import sqlite3
import struct
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

TOOL = {"name": "sqlite_query", "version": 4}
DEFAULT_LIMIT = 100
LIMIT_MAX = 10000
INLINE_BYTES = 64 * 1024          # the inline page's JSON and its text form, each, as they are sent (ASCII-escaped, counted in bytes)
RAW_BUFFER_MAX = 8 * 1024 * 1024  # the raw values of the inline page held in memory; past it the rest goes to the file only
FILE_BYTES = 2 * 1024 ** 3        # the whole-result file stops here, and says so
BUDGET_SECONDS = 25
BUDGET_MAX = 110
SQL_MAX = 64 * 1024               # bytes of UTF-8
HASH_MAX = 256 * 1024 * 1024
BLOB_INLINE = 256                 # a BLOB longer than this shows its head inline; the file holds all of it
VALUE_MAX = 64 * 1024 * 1024      # the longest string or BLOB (or whole row) read: sqlite refuses a longer one before it is in memory
STREAM_AT = 1024 * 1024           # a BLOB longer than this is hashed and encoded to the file in slices, never as one more copy
SLICE_BYTES = 3 * 256 * 1024      # a multiple of 3, so each slice's base64 joins the next without padding

# What a statement may do. SELECT and READ are reading; FUNCTION is a call to a
# built-in; RECURSIVE is a recursive CTE. Everything else is refused, whatever
# the open mode would have said.
ALLOWED_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
                   getattr(sqlite3, "SQLITE_RECURSIVE", 33)}
DENIED_FUNCTIONS = {"load_extension", "fts3_tokenizer", "readfile", "writefile", "edit"}
# Pragmas that only report. A setter form (an argument) is refused for all but those
# that take a table name as their argument.
READ_PRAGMAS = {"table_info", "table_xinfo", "table_list", "index_list", "index_info", "index_xinfo",
                "foreign_key_list", "foreign_key_check", "database_list", "collation_list", "function_list",
                "module_list", "pragma_list", "compile_options", "page_size", "page_count", "freelist_count",
                "user_version", "application_id", "schema_version", "encoding", "journal_mode", "integrity_check",
                "quick_check", "data_version", "max_page_count", "auto_vacuum", "wal_autocheckpoint", "cache_size"}
PRAGMAS_WITH_NAME = {"table_info", "table_xinfo", "index_list", "index_info", "index_xinfo", "foreign_key_list",
                     "foreign_key_check", "integrity_check", "quick_check"}
LEADING = ("select", "with", "values", "pragma", "explain")


def say(obj, code=0):
    print(json.dumps(obj))
    raise SystemExit(code)


def authorizer(action, p1, p2, dbname, source):
    if action in ALLOWED_ACTIONS:
        if action == sqlite3.SQLITE_FUNCTION and (p2 or "").lower() in DENIED_FUNCTIONS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA:
        name = (p1 or "").lower()
        if name in READ_PRAGMAS and (p2 is None or name in PRAGMAS_WITH_NAME):
            return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def statements(sql):
    """The statements of `sql`, split where sqlite says one is complete (a ';' inside
    a string or a trigger body does not end it). What follows the last ';' is a statement too,
    complete or not: a line comment at its end does not hide it, and an incomplete one (an
    unterminated string, a trigger with no END) is handed to sqlite to refuse, never dropped."""
    out, start = [], 0
    for i, ch in enumerate(sql):
        if ch == ";" and sqlite3.complete_statement(sql[start:i + 1]):
            out.append(sql[start:i + 1])
            start = i + 1
    out.append(sql[start:])
    return [s.strip() for s in out if re.sub(r"(--[^\n]*\n?|/\*.*?\*/|\s|;)+", "", s, flags=re.S)]


def first_word(stmt):
    stripped = re.sub(r"^(\s|--[^\n]*\n|/\*.*?\*/)+", "", stmt, flags=re.S)
    m = re.match(r"[A-Za-z]+", stripped)
    return m.group(0).lower() if m else ""


def entropy(page):
    counts = collections.Counter(page)
    return -sum(c / len(page) * math.log2(c / len(page)) for c in counts.values())


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def wal_inventory(path):
    """What the WAL file says about itself, from its header and its frame headers:
    the frames that belong to its current generation (their salts match the header's)
    and the last commit among them. Checksums are not verified."""
    size = os.path.getsize(path)
    info = {"bytes": size}
    if size < 32:
        info["state"] = "empty or shorter than its 32-byte header"
        info["frames_valid"] = 0
        return info
    with open(path, "rb") as fh:
        head = fh.read(32)
        magic, version, page, seq, salt1, salt2 = struct.unpack(">IIIIII", head[:24])
        if magic not in (0x377F0682, 0x377F0683) or not 512 <= page <= 65536 or page & (page - 1):
            info["state"] = "not a WAL header (magic %08x, page size %d)" % (magic, page)
            info["frames_valid"] = 0
            return info
        stride = 24 + page
        total = (size - 32) // stride
        valid, last_commit = 0, 0
        for i in range(total):
            fh.seek(32 + i * stride)
            fr = fh.read(24)
            if len(fr) < 24:
                break
            pgno, commit, s1, s2 = struct.unpack(">IIII", fr[:16])
            if s1 != salt1 or s2 != salt2 or pgno == 0:
                break
            valid += 1
            if commit:
                last_commit = valid
    info.update({"page_size": page, "checkpoint_sequence": seq, "frames_in_file": total, "frames_valid": valid,
                 "frames_committed": last_commit, "state": "frames of the current generation counted from their salts; checksums not verified"})
    return info


JOURNAL_MAGIC = bytes([0xD9, 0xD5, 0x05, 0xF9, 0x20, 0xA1, 0x63, 0xD7])


def journal_inventory(path):
    """A rollback journal is hot only when its header is the journal's: a header of zeros (what journal_mode
    TRUNCATE and PERSIST leave) means there is nothing to roll back."""
    with open(path, "rb") as fh:
        head = fh.read(28)
    if head[:8] == JOURNAL_MAGIC:
        return {"state": "header present: a journal that was not rolled back"}
    if not head.strip(b"\0"):
        return {"state": "empty or zeroed header: not a hot journal (a persistent or truncated one left behind)"}
    return {"state": "a header that is not a rollback journal's; not applied, not understood"}


def sidecars(db):
    """The files beside the database, named from its real path: SQLite looks for a -wal and a -journal next to the
    file a link points at, not next to the link."""
    real = os.path.realpath(db)
    out = []
    for suffix in ("-wal", "-shm", "-journal"):
        path = real + suffix
        entry = {"name": os.path.basename(path), "present": os.path.isfile(path)}
        if entry["present"]:
            try:
                entry["bytes"] = os.path.getsize(path)
                if suffix == "-wal":
                    entry.update(wal_inventory(path))
                if suffix == "-journal" and entry["bytes"]:
                    entry.update(journal_inventory(path))
                if entry["bytes"] <= HASH_MAX:
                    entry["sha256"] = sha256_file(path)
            except OSError as exc:
                entry["error"] = exc.strerror or str(exc)
        out.append(entry)
    return out


def snapshot_status(side):
    """Said plainly: what state of the database this result is."""
    notes = []
    wal = next((s for s in side if s["name"].endswith("-wal") and s.get("present")), None)
    jrn = next((s for s in side if s["name"].endswith("-journal") and s.get("present")), None)
    if wal and wal.get("frames_valid"):
        notes.append("WAL NOT APPLIED: the main file was read immutable, so the %d frame(s) (%d committed) in %s are not in this result; "
                     "a row committed only there is missing. To read that state, stage the database with its -wal and -shm into a "
                     "writable directory ($OUT) and open the copy." % (wal["frames_valid"], wal.get("frames_committed", 0), wal["name"]))
    elif wal and wal.get("bytes"):
        notes.append("%s is present (%d bytes) and holds no valid frame; the main file is the whole database state this tool can read." % (wal["name"], wal["bytes"]))
    if jrn and jrn.get("bytes") and jrn.get("state", "").startswith("header present"):
        notes.append("%s is present (%d bytes): a rollback journal that was not rolled back; the main file may hold an interrupted write. Not applied." % (jrn["name"], jrn["bytes"]))
    elif jrn and jrn.get("bytes"):
        notes.append("%s is present (%d bytes): %s." % (jrn["name"], jrn["bytes"], jrn.get("state", "its header was not read")))
    if not notes:
        return "main file only; no WAL frames or hot journal beside it"
    return " ".join(notes)


def cell(value):
    """A typed JSON value for a cell: null, number, string, or an object that keeps what a string cannot."""
    if value is None or isinstance(value, (int, float)):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return {"real": repr(value)}
        return value
    if isinstance(value, bytes):
        return {"blob_b64": base64.b64encode(value).decode("ascii"), "length": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, _Text):
        return {"text_invalid_utf8": str(value), "bytes_b64": base64.b64encode(value.raw).decode("ascii"), "length": len(value.raw)}
    return value


class _Text(str):
    """Text from the database that was not valid UTF-8, kept with its bytes."""
    raw = b""


def text_factory(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        t = _Text(raw.decode("utf-8", "backslashreplace"))
        t.raw = bytes(raw)
        return t


def inline_cell(value):
    """The same, with a long BLOB shown by its head: the file holds it whole."""
    c = cell(value)
    if isinstance(c, dict) and "blob_b64" in c and c["length"] > BLOB_INLINE:
        return {"blob_b64_head": base64.b64encode(value[:BLOB_INLINE]).decode("ascii"), "length": c["length"], "sha256": c["sha256"],
                "head_bytes": BLOB_INLINE}
    return c


def text_cell(value, csv_mode):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return "<blob %d bytes>" % len(value)
    if isinstance(value, float):
        return "%.15g" % value
    return str(value)


def blob_json(fh, value):
    """A BLOB as {blob_b64, length, sha256}, written to `fh` in slices: the digest is taken first over views of the value,
    then the base64 is written slice by slice, so a large value costs no second copy of itself in memory."""
    digest = hashlib.sha256()
    view = memoryview(value)
    for at in range(0, len(view), SLICE_BYTES):
        digest.update(view[at:at + SLICE_BYTES])
    fh.write('{"blob_b64": "')
    for at in range(0, len(view), SLICE_BYTES):
        fh.write(base64.b64encode(view[at:at + SLICE_BYTES]).decode("ascii"))
    fh.write('", "length": %d, "sha256": "%s"}' % (len(value), digest.hexdigest()))


def earlier_answers(path):
    """How many other files answer this same question in the folder (name.ext, name.2.ext, ...): one more for every different
    answer, and none is deleted, so the count is said."""
    stem, ext = os.path.splitext(os.path.basename(str(path)))
    base = re.sub(r"\.\d+$", "", stem)
    rx = re.compile(r"^%s(\.\d+)?%s$" % (re.escape(base), re.escape(ext)))
    try:
        return max(0, sum(1 for n in os.listdir(os.path.dirname(str(path)) or ".") if rx.match(n)) - 1)
    except OSError:
        return 0


def same_bytes(a, b):
    """Two files with the same bytes (compared in blocks, never whole)."""
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(1 << 20), fb.read(1 << 20)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


def publish(tmp, path, shown):
    """Move a finished file to `path` without replacing what is there: a file at the name is an earlier answer (a complete one,
    perhaps, where this run was cut short) and stays; this one is kept beside it as name.2.ext. Returns the name it has and
    the name to show for it."""
    stem, ext = os.path.splitext(str(path))
    shown_stem, _ = os.path.splitext(shown)
    k = 1
    while True:
        suffix = "" if k == 1 else ".%d" % k
        candidate = Path(stem + suffix + ext)
        try:
            os.link(tmp, candidate)
        except FileExistsError:
            if same_bytes(tmp, candidate):                # the same answer again (a page of the same search): the file is already there
                os.unlink(tmp)
                return candidate, shown_stem + suffix + ext
            k += 1
            continue
        except OSError:                                   # a file system with no hard links: a look, then a rename
            if os.path.lexists(candidate):
                if same_bytes(tmp, candidate):
                    os.unlink(tmp)
                    return candidate, shown_stem + suffix + ext
                k += 1
                continue
            os.rename(tmp, candidate)
            return candidate, shown_stem + suffix + ext
        os.unlink(tmp)
        return candidate, shown_stem + suffix + ext


def raw_size(row):
    return sum(len(v) if isinstance(v, (bytes, str)) else 8 for v in row)


class Rows:
    """One statement's rows: an inline page, and the whole result in a file once it is more than that.

    The inline page is bounded by what is sent (its JSON and its text form, as bytes), by `limit`, and by
    the raw values held to make it (RAW_BUFFER_MAX): a row too large to hold goes to the file only."""

    def __init__(self, stmt_index, key, columns, limit):
        self.limit, self.columns = limit, columns
        self.page, self.raw_page, self.inline_bytes, self.raw_bytes = [], [], 0, 0
        self.total, self.fh, self.tmp, self.written = 0, None, None, 0
        self.file_stopped = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode()).hexdigest()[:16]
        name = "sqlite_query-%s-%d.jsonl" % (digest, stmt_index)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.error = None

    def _open(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".sqlite_query-")
        self.tmp = Path(name)
        self.fh = os.fdopen(fd, "w", encoding="utf-8")
        self.fh.write(json.dumps({"columns": self.columns}) + "\n")
        for n, row in enumerate(self.raw_page, 1):
            self._write(n, row)

    def _write(self, n, row):
        if self.file_stopped:
            return
        big = any(isinstance(v, bytes) and len(v) > STREAM_AT for v in row)
        if not big:
            line = json.dumps({"n": n, "values": [cell(v) for v in row]}, ensure_ascii=False) + "\n"
            if self.written + len(line) > FILE_BYTES:
                self.file_stopped = n
                return
            self.fh.write(line)
            self.written += len(line)
            return
        # A row with a large BLOB: its size is known before it is written, and the BLOB is encoded in slices.
        size = sum(4 * ((len(v) + 2) // 3) + 120 if isinstance(v, bytes) else len(json.dumps(cell(v), ensure_ascii=False)) + 2 for v in row) + 40
        if self.written + size > FILE_BYTES:
            self.file_stopped = n
            return
        self.fh.write('{"n": %d, "values": [' % n)
        for i, v in enumerate(row):
            if i:
                self.fh.write(", ")
            if isinstance(v, bytes) and len(v) > STREAM_AT:
                blob_json(self.fh, v)
            else:
                self.fh.write(json.dumps(cell(v), ensure_ascii=False))
        self.fh.write("]}\n")
        self.written += size

    def _drop_file(self, exc):
        """The whole-result file cannot be written (a full disk, a read-only directory): said, and no half file left."""
        self.error = "the whole result could not be written (%s): %s" % (self.path.parent, getattr(exc, "strerror", None) or exc)
        try:
            if self.fh:
                self.fh.close()
        except (OSError, ValueError):
            pass
        self.fh = False
        if self.tmp:
            try:
                self.tmp.unlink()
            except OSError:
                pass
            self.tmp = None

    def add(self, row):
        self.total += 1
        if self.fh is None:
            size = raw_size(row)
            if len(self.page) < self.limit and size <= INLINE_BYTES and self.raw_bytes + size <= RAW_BUFFER_MAX:
                inline = [inline_cell(v) for v in row]
                sent = len(json.dumps({"n": self.total, "values": inline}).encode("utf-8"))
                text = len(json.dumps("|".join(text_cell(v, False) for v in row)).encode("utf-8"))
                if self.inline_bytes + sent + text <= 2 * INLINE_BYTES:
                    self.page.append({"n": self.total, "values": inline})
                    self.raw_page.append(row)
                    self.inline_bytes += sent + text
                    self.raw_bytes += size
                    return
            try:
                self._open()
            except (OSError, UnicodeError) as exc:
                self._drop_file(exc)
        if self.fh:
            try:
                self._write(self.total, row)
            except (OSError, UnicodeError) as exc:
                self._drop_file(exc)

    def finish(self):
        info = {"row_count": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.fh:
            try:
                self.fh.flush()
                os.fsync(self.fh.fileno())
                self.fh.close()
                self.path, self.shown = publish(self.tmp, self.path, self.shown)
                self.tmp = None
                info["rows_file"] = self.shown
                info["earlier_answers"] = earlier_answers(self.path)
                info["rows_file_format"] = "JSON Lines: a header line {columns}, then one {n, values} per row; NULL is null, a BLOB is {blob_b64, length, sha256}"
                if self.file_stopped:
                    info["rows_file_stopped_at_row"] = self.file_stopped
                    info["rows_file_cap_bytes"] = FILE_BYTES
            except OSError as exc:
                self._drop_file(exc)
        if self.error:
            info["rows_file_error"] = self.error
        return info


def render(rows, columns, csv_mode):
    """The old tool's text for the inline page: CSV with a header, or the shell's list mode."""
    buf = io.StringIO()
    raw = [r for r in rows.raw_page]
    if csv_mode:
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(columns)
        for r in raw:
            w.writerow([text_cell(v, True) for v in r])
    else:
        for r in raw:
            buf.write("|".join(text_cell(v, False) for v in r) + "\n")
    return buf.getvalue()


def main():
    try:
        obj = json.load(sys.stdin)
    except ValueError as exc:
        say({"ok": False, "error": "arguments are not valid JSON", "reason": str(exc)}, 1)
    if not isinstance(obj, dict):
        say({"ok": False, "error": "arguments are a JSON object"}, 1)
    missing = [k for k in ("db_path", "sql") if not isinstance(obj.get(k), str) or not obj.get(k)]
    if missing:
        say({"ok": False, "error": "need " + " and ".join(missing), "params": ["db_path", "sql", "csv", "limit"]}, 1)
    db, sql = obj["db_path"], obj["sql"]
    for name, text in (("db_path", db), ("sql", sql)):
        if "\0" in text:
            say({"ok": False, "error": "%s holds a NUL character" % name}, 1)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            say({"ok": False, "error": "%s is not text that can be written as UTF-8 (it holds a lone surrogate)" % name}, 1)
    csv_mode = obj.get("csv", False)
    if not isinstance(csv_mode, bool):
        say({"ok": False, "error": "csv is true or false (a text such as \"false\" is not false)", "csv": csv_mode}, 1)
    if "readonly" in obj and obj["readonly"] is not True:
        if obj["readonly"] is False:
            say({"ok": False, "error": "readonly=false is not supported: this tool never opens a database for writing. "
                                       "Stage a copy under $OUT and use the sqlite3 module on the copy.", "db_path": db}, 1)
        say({"ok": False, "error": "readonly is true (the only mode this tool has) or left out", "readonly": obj["readonly"]}, 1)
    limit = obj.get("limit", DEFAULT_LIMIT)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= LIMIT_MAX:
        say({"ok": False, "error": "limit is a whole number from 1 to %d" % LIMIT_MAX, "limit": limit}, 1)
    budget = obj.get("max_seconds", BUDGET_SECONDS)
    if not isinstance(budget, int) or isinstance(budget, bool) or not 1 <= budget <= BUDGET_MAX:
        say({"ok": False, "error": "max_seconds is a whole number from 1 to %d" % BUDGET_MAX, "max_seconds": budget}, 1)
    if len(sql.encode("utf-8")) > SQL_MAX:
        say({"ok": False, "error": "sql is longer than %d bytes" % SQL_MAX}, 1)
    if not os.path.exists(db):
        say({"ok": False, "error": "database not found", "db_path": db}, 1)
    if not os.path.isfile(db):
        say({"ok": False, "error": "db_path is not a regular file", "db_path": db}, 1)
    size = os.path.getsize(db)
    if size == 0:
        say({"ok": False, "error": "the file is empty (0 bytes): it holds no database", "db_path": db}, 1)
    # sqlite says only "file is not a database" for anything else, and the sixth CTF round's agents met it on
    # Element's SQLCipher events.db without learning why. The first page says what it can: a SQLite file starts
    # with its magic; a file that does not is random from byte 0 or another format. Entropy measures randomness
    # and identifies nothing: encryption is one explanation, compression and another encrypted container others.
    with open(db, "rb") as fh:
        page = fh.read(4096)
    if not page.startswith(b"SQLite format 3\x00"):
        e = entropy(page)
        say({"ok": False, "error": "not a SQLite file: its first bytes are not the SQLite magic", "db_path": db,
             "header_hex": page[:16].hex(), "first_page_entropy_bits_per_byte": round(e, 3),
             "reading": ("random-looking from the first byte (high entropy), and not identified: an encrypted database (SQLCipher "
                         "or an app's own) is one explanation, compressed or otherwise encoded data another; no query runs without "
                         "knowing which" if e > 7.5 else "another format: identify it from its header (file_type)")}, 1)

    side = sidecars(db)
    status = snapshot_status(side)
    # immutable=1 opens a database on a read-only mount, where mode=ro alone cannot create a -shm; the path is
    # percent-encoded because a "#" or "?" in it would end the name early.
    uri = "file:%s?mode=ro&immutable=1" % urllib.parse.quote(db)
    stmts = statements(sql)
    if not stmts:
        say({"ok": False, "error": "sql holds no statement"}, 1)
    results, started = [], time.monotonic()
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        say({"ok": False, "error": "cannot open the database: %s" % exc, "db_path": db}, 1)
    conn.text_factory = text_factory
    value_limit = "%d bytes" % VALUE_MAX
    if hasattr(conn, "setlimit") and hasattr(sqlite3, "SQLITE_LIMIT_LENGTH"):
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, VALUE_MAX)
    else:
        value_limit = "not enforced (Python before 3.11 has no setlimit)"
    conn.set_authorizer(authorizer)
    conn.set_progress_handler(lambda: 1 if time.monotonic() - started > budget else 0, 20000)
    base = {"tool": TOOL, "db_path": db, "database_bytes": size, "sidecars": side, "snapshot_status": status,
            "sqlite_library": sqlite3.sqlite_version, "opened": "read-only, immutable, through an authorizer that allows reading only", "value_limit": value_limit}
    if size <= HASH_MAX:
        base["database_sha256"] = sha256_file(db)
    else:
        base["database_sha256"] = None
        base["hashing"] = "skipped: the file is larger than %d bytes; the run's own record has its sha256" % HASH_MAX
    failure = None
    for i, stmt in enumerate(stmts):
        word = first_word(stmt)
        if word not in LEADING:
            failure = {"error": "statement refused: this tool reads; a %s statement is not allowed" % (word.upper() or "?"), "statement": stmt}
            break
        rows = None
        failure_kind = None
        try:
            cur = conn.execute(stmt)
            columns = [d[0] for d in (cur.description or [])]
            rows = Rows(i, [db, size, stmt, limit], columns, limit)
            for r in cur:                    # a row at a time: a fetch of many would hold many large values at once
                rows.add(r)
        except (sqlite3.Error, ValueError, UnicodeError, OverflowError, MemoryError) as exc:
            msg = str(exc)
            if "not authorized" in msg:
                msg = "statement refused: it is not a plain read (%s)" % msg
            elif "too big" in msg:
                msg = ("a value or row in this result is longer than %d bytes, which this tool will not read into memory (sqlite: %s): select its length(), "
                       "or a piece of it with substr(), hex(substr(...)) or a range, in several queries" % (VALUE_MAX, msg))
                failure_kind = "value_too_long"
            elif "interrupted" in msg:
                msg = "stopped at the %d-second time budget; the rows before it are in rows_file when there is one" % budget
            elif isinstance(exc, MemoryError):
                msg = "out of memory reading a row"
            failure = {"error": msg, "statement": stmt}
            if failure_kind:
                failure["reason"] = failure_kind
            if "interrupted" in str(exc):
                failure["timed_out"] = True
            if rows is not None and rows.total:
                # What was read before the stop is kept and named, not dropped with the file half written.
                failure["rows_read_before_the_stop"] = rows.finish()
                failure["rows_read_before_the_stop"]["note"] = "the rows up to the stop, not the result of the statement"
                failure["rows_read_before_the_stop"]["rows"] = rows.page
            break
        info = rows.finish()
        part = {"statement": stmt, "columns": columns, **info, "rows": rows.page,
                "stdout": render(rows, columns, csv_mode)}
        results.append(part)
    conn.close()

    out = dict(base)
    if failure:
        out.update({"ok": False, "returncode": 1, "stdout": "", "stderr": failure["error"], **failure, "complete": False})
        if results:
            out["completed_statements"] = results
        say(out, 1)
    out.update({"ok": True, "returncode": 0, "stderr": "", "complete": True})
    if len(results) == 1:
        out.update(results[0])
    else:
        out["results"] = results
        out["stdout"] = "".join(r["stdout"] for r in results)
    if any(r.get("truncated") for r in results):
        out["truncated"] = True
        out["note"] = "an inline page is not the result: the whole of it is in rows_file; read it to the end before concluding"
    print(json.dumps(out))


if __name__ == "__main__":
    main()
