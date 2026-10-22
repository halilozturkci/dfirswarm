#!/usr/bin/env python3
"""Run a read-only SQL query over a SQLite database file, bounded and typed.

What this reads: the main database file, opened read-only and immutable, through
Python's sqlite3 module (never the sqlite3 shell). An authorizer lets a statement
read and nothing else: no write, no ATTACH, no extension, no PRAGMA that sets.
What it does not read: the write-ahead log of the file it is given. An immutable open ignores a -wal and
a -shm beside the database, so rows committed only in the WAL are not in the
result; the tool inventories the sidecars (name, size, WAL frames) and says so
in `snapshot_status`, loudly, instead of leaving it to be found. Applying a WAL
needs a staged copy of the database set, which this tool does not make: the
sqlite_snapshot tool does (it copies the set with hashes and has SQLite apply the
WAL in the copy, never beside the evidence), and `db_path` may be that snapshot's
directory or the database inside it. The answer then carries `snapshot` (what the
snapshot says it holds, and whether the file queried is still the one it recorded)
and `snapshot_status` says which state the rows are. `apply_wal` is not a
parameter here: asking for it is an error that names sqlite_snapshot.

The answer is bounded: an inline page of rows (`limit`, and a byte ceiling), and
when the result is more than that the whole of it in a JSON Lines file, named in
`rows_file`. Each row is typed: NULL is null, an integer or a real is a number,
text is a string (text that is not UTF-8 carries its bytes in base64 beside the
escaped form), a BLOB is {blob_b64, length, sha256}. `stdout` keeps the text form
of the inline page the old tool returned (CSV with a header, or the shell's
`|`-separated list), for the callers that read it.

VALUES TO A FILE (`write_values: true`). On a table that holds secrets (cookies, saved logins, tokens, keys, messages) an
inline page puts values in the agent's context. In this mode no value is ever in the answer: the row values of ONE table go to
a 0600 file under $OUT, and the answer carries locators (table, a row locator, column), counts, types and lengths.

  * It takes `table` (and optionally `columns`, `rowid_from`, `rowid_to`), NOT `sql`. A WHERE, LIKE, JOIN or any expression over
    a column whose values are withheld would be an oracle: one call is one bit of every row, and a few hundred calls confirm a
    guess. The mode therefore exports whole rows and takes no filter; the counts it prints are the table's (or the rowid
    range's), not a filter's. Rows are read from the table itself (NOT INDEXED) and in the table's own order, never in an
    index's, whose order would be the order of the indexed values; the order is said by an ORDER BY wherever the table has one
    that is total. SQLite reads a WITHOUT ROWID table through a covering index, NOT INDEXED or not, unless told the order, so
    every such table is ordered by its whole primary key with the key's own collations and directions: SQLite then reads the
    table's b-tree, or an index whose leading keys are that key, in the same order, and needs no sort (a sort would make the
    row at an OFFSET depend on more than the key). The answer's `n_ranks` names the columns whose values that order follows.
  * What locates a row, and what that guarantees, depends on the table (`table_kind`):
      - rowid: an ordinary rowid table. The rowid is SQLite's row key and no column's value: SQLite assigns it (one more than the
        largest, as a rule) unless the application set it in its INSERT, and what an application put there is the
        application's. The rows come in rowid order (n_ranks []), and `rowid_from`/`rowid_to` select by that key and by nothing
        a column holds.
      - alias: the table's one primary key column is declared INTEGER and SQLite keeps it in no index of its own (PRAGMA
        index_list), so SQLite makes that column the rowid: the rowid IS a value. It is never printed (answer, text form, locators
        file), no WHERE names it, and a rowid range is refused (`rowid_is_a_value`); rows are located by their position `n`.
        The rows are ordered by that key, so `n` ranks its values (which row holds the smaller one), and that is all it says
        of them. (`INTEGER PRIMARY KEY DESC` is not an alias: SQLite gives it an index, and the table is an ordinary one.)
      - without_rowid: no rowid, whatever its columns are named; located by `n`, a rowid range refused. Decided by SQLite
        (PRAGMA table_list's `wr`), or by the statement's own words where that pragma is missing. The rows come in primary-key
        order, so `n` ranks the primary key's values in the same way: for such a table the order is not independent of the
        values.
      - virtual: located by `n` in the order the module returns rows, which can be the order of a value (fts5vocab returns its
        terms sorted; n_ranks null: not known); the rowid (whatever the module makes it) is not printed and a range is refused.
        A module that cannot start under the read-only authorizer (fts5 on some SQLite builds) is the named state
        `virtual_table_unsupported`, said as JSON.
      - shadowed: a rowid table whose columns named rowid, oid and _rowid_ hide the rowid; located by `n`. Where one of its
        columns is the INTEGER PRIMARY KEY the rows are ordered by it (n ranks it, n_ranks names it); otherwise they come in
        storage order, the rowid's.
  * A cell is type:length. The length of an integer is the characters of its decimal form, so it tells its sign and order of
    magnitude (a PIN stored as an integer loses its leading zeros: 0123 is integer:3); a real's is the characters of Python's
    shortest repr, which does not (1e+20 is real:5, 12345.6 is real:7).
  * It follows the secret-safe output pattern of recovery_key_scan (docs/packs.md, "Secrets and sensitive output"): refused
    outside a job (JOB_ID and OUT set), and in a job the harness did not run as secret output (SECRET_OUTPUT=1 is set for the
    process of a secret job; the manifest makes a job of this tool with write_values one), as a JSON answer before anything is opened; the values file created once the table is
    found and its layout read, before the first row, with O_EXCL and O_NOFOLLOW and mode 0600 (a wrong table name, or a file
    that is not SQLite, leaves nothing behind; a second export in one job's $OUT is refused by name, never overwrites); no hash,
    digest or fragment of a value anywhere; a printed name that is shaped like a token withheld by the shared block below (the
    network pack's, byte for byte). The skill that sends the agent here says the job runs with `secret_output: true`.
  * Errors: nothing of a reading error is printed in this mode but what its code decides (sqlite_code). sqlite's message can
    quote a value (a generated column's json_extract quotes the value it failed on), and so can the class Python gives the
    error (a message that quotes bytes that are not UTF-8 arrives as a UnicodeDecodeError, with no code); every decision (the
    time budget, the authorizer, a value over the length limit) is taken on sqlite's result code, and on Python before 3.11,
    which gives none, on the text before the message's first quote matched whole against sqlite's fixed messages. The answer
    gives a fixed sentence and the row position; the class and the message go to the values file (the cell's line, or the end
    line when the export stopped). A row that cannot be read whole is read alone, and when that fails too, a cell at a time:
    each cell is tried alone, then every cell that can be read is read in one query (the same order, LIMIT 1 OFFSET n), so an
    exported row's cells are always one row's. A value longer than the length limit is recorded as value_too_large (its row,
    column, type and, where SQLite gives it without reading the value, its length), a cell sqlite cannot compute as
    unreadable, and the export goes on with the rest (at most PARTS_MAX rows read a cell at a time; a row none of whose cells
    can be read stops it, row_unreadable). Which cells are unreadable follows from the table's own expressions over its
    values, so it can say something of them; the schema is the evidence's, not the caller's.
  * A write that fails (a full disk) ends the export as JSON: ok false, reason values_file_error, exit 1 (a stop before the
    end is a failure, as network_log_summary says of a read that stopped early); the kept file is read back and the answer's
    counts (values_file_holds, secret_values, cells_with_a_value) are what it holds: its whole cell lines, the row of the last,
    a part of a line after them, and whether it has the end line a whole file ends with, so a file cut short (by a kill as
    well) is recognisable. A locators file that cannot be written leaves ok true and complete false (the values file is
    whole), and says what of it is left. row_count N means rows 1..N are in the locators file: a row is counted once its
    cells are written (a write that fails in row N+1 can leave that row's first lines in the values file; values_file_holds
    names the row of the last whole line).

"""
import base64
import collections
import csv
import errno
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

TOOL = {"name": "sqlite_query", "version": 7}
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

# BEGIN SHARED WITHHOLDING
# The same text is in every tool that withholds identifier-shaped strings (the network, base, virtualization and
# reverse-engineering packs), so that they withhold the same strings; the tests that hold the copies equal are
# tests/pack-network-withholding.test.ts, tests/pack-base-shared.test.ts, tests/pack-virtualization-shared.test.ts and
# tests/pack-re-process.test.ts. An identifier-shaped string is withheld wherever the tool would print one: a name, a
# path component, a URL, a message that quotes either.
COUNTS = {"names": 0, "urls": 0, "text": 0}
# A run of name characters long enough to be a token. `=` is only a padding at the end (so a key= prefix stays);
# `/` joins pieces of a base64 token and is handled apart, below.
_RUN = re.compile(r"[A-Za-z0-9_+%-]{20,}={0,2}|[A-Za-z0-9_+%-]{14,}={2}")
_SLASHED = re.compile(r"[A-Za-z0-9_+/%-]{30,}={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]{32,}")
_PREFIXED = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                       r"|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}"
                       r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"
                       r"|(?i:basic|bearer)\s+[A-Za-z0-9+/=._~-]{8,}")
# User-info: after `//` (a URL, or a scheme-relative one), or bare as name:password@host. A mailto: address is not one.
_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_BARE_USERINFO = re.compile(r"(?<![\w.%+:/-])(?!mailto:)[\w.%+-]{1,64}:[^\s/@:]{1,128}(?=@[\w\[])")


def _withheld(what, length, kind):
    COUNTS[kind] = COUNTS.get(kind, 0) + 1
    return ("<%s withheld %d characters>" % (what, length)) if what else ("<withheld %d characters>" % length)


def _token_run(run):
    """Is this run of name characters shaped like a token, and not like words, dates or versions?"""
    if _HEX.search(run):
        return True
    chunks = [(m.group()[0].isdigit(), m.start(), m.end()) for m in re.finditer(r"[A-Za-z]+|[0-9]+", run)]
    # digits packed between letters ("a9b2c7"), which words, dates and versions do not do
    packed = 0
    for i, (is_digit, start, end) in enumerate(chunks):
        if not is_digit or end - start > 3:
            continue
        before = i > 0 and not chunks[i - 1][0] and chunks[i - 1][2] == start
        after = i + 1 < len(chunks) and not chunks[i + 1][0] and chunks[i + 1][1] == end
        packed += 1 if before or after else 0
    if packed >= 3:
        return True
    letters = [c for c in run if c.isalpha()]
    case_flips = sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower())
    if len(letters) >= 20 and case_flips >= max(8, 0.4 * len(letters)):
        return True
    if run.endswith("==") and len(run) >= 16:
        return True
    if run.endswith("=") and len(run) >= 24:
        return True
    return len(run) >= 40 and run.isalnum() and any(c.isdigit() for c in run) and any(c.isalpha() for c in run)


def _randomish(piece):
    """A piece of a path that is not a plain word: digits among letters, or capitals inside a word."""
    if len(piece) < 4 or "." in piece or re.fullmatch(r"[A-Z][a-z]+", piece):
        return False
    letters = [c for c in piece if c.isalpha()]
    mixed = any(c.islower() for c in letters) and any(c.isupper() for c in letters)
    return (any(c.isdigit() for c in piece) and bool(letters)) or mixed


_SPAN_PIECE = re.compile(r"[A-Za-z0-9_+%-]+")
# A text longer than this is withheld whole, by its length, and not examined: the examination is linear, but a text of
# millions of characters is not one a name or a URL is, and the answer says how long it was.
TEXT_LIMIT = 2097152


def _grow_spans(text, spans):
    """Each flagged span takes the random-looking pieces next to it across a `/`: the head of a token is not printed.

    One pass cuts the text into pieces (runs of name characters) and keeps where each starts and ends. A span then walks
    that array by index; a piece is judged once, and a walk that reaches a piece an earlier walk has settled stops there, so
    the work is linear in the text and no range is sliced or searched again. (Looking back with a search over everything
    before a piece costs the cube of the length for a name of many `/`-joined pieces.)"""
    from bisect import bisect_left
    starts, ends = [], []
    for m in _SPAN_PIECE.finditer(text):
        starts.append(m.start())
        ends.append(m.end())
    count, size = len(starts), len(text)
    judged_left, judged_right, settled_left, settled_right = {}, {}, {}, {}

    def padded(k):       # where piece k ends with the up to two `=` of padding after it
        e = ends[k]
        if e < size and text[e] == "=":
            e += 2 if e + 1 < size and text[e + 1] == "=" else 1
        return e

    def left_ok(j):
        if j not in judged_left:
            judged_left[j] = _randomish(text[starts[j]:ends[j]])
        return judged_left[j]

    def right_ok(k):
        if k not in judged_right:
            judged_right[k] = _randomish(text[starts[k]:padded(k)])
        return judged_right[k]

    def before(at):      # the piece that growing left from offset `at` takes, or -1. `$` also ends a match before a final line break.
        if at < 2 or text[at - 1] != "/":
            return -1
        for stop in ((at - 1, at - 2) if text[at - 2] == "\n" else (at - 1,)):
            j = bisect_left(ends, stop)
            if j < count and ends[j] == stop:
                return j if left_ok(j) else -1
        return -1

    def after(k):        # the piece that growing right from the end of piece k takes, or -1
        e = padded(k)
        if k + 1 >= count or e >= size - 1 or text[e] != "/" or starts[k + 1] != e + 1:
            return -1
        return k + 1 if right_ok(k + 1) else -1

    def settle(i, step, memo):
        trail = []
        while i not in memo:
            trail.append(i)
            j = step(i)
            if j < 0:
                memo[i] = i
                break
            i = j
        final = memo[i]
        for t in trail:
            memo[t] = final
        return final

    grown = []
    for start, end in spans:
        j = before(start)
        if j >= 0:
            start = starts[settle(j, lambda i: before(starts[i]), settled_left)]
        if end < size - 1 and text[end] == "/":
            k = bisect_left(starts, end + 1)
            if k < count and starts[k] == end + 1 and right_ok(k):
                end = padded(settle(k, after, settled_right))
        grown.append((start, end))
    return grown


def token_spans(text):
    if len(text) > TEXT_LIMIT:
        return [(0, len(text))]
    spans = [m.span() for m in _PREFIXED.finditer(text)]
    for m in _RUN.finditer(text):
        if _token_run(m.group()):
            spans.append(m.span())
    # A base64 token holds `/`: pieces too short to be one alone (an AWS-style secret has two) are caught as a whole.
    for m in _SLASHED.finditer(text):
        run = m.group()
        if "/" in run and sum(1 for p in run.split("/") if _randomish(p)) >= 3 and re.search(r"[0-9+]", run):
            spans.append(m.span())
    grown = _grow_spans(text, spans) if spans else []
    grown.sort()
    merged = []
    for start, end in grown:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def token_shaped(text):
    return bool(token_spans(text))


def scrub(text, kind="text"):
    """The text with every token-shaped run and every user-info withheld."""
    if len(text) > TEXT_LIMIT:
        return _withheld("over-long text", len(text), kind)
    text = _USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    text = _BARE_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    out, last = [], 0
    for start, end in token_spans(text):
        out.append(text[last:start])
        out.append(_withheld("token-shaped text", end - start, kind))
        last = end
    out.append(text[last:])
    return "".join(out)


def redact_url(url):
    """A URL or request target without its user-info, its token-shaped path text, its query values or its fragment."""
    rest, fragment = (url.split("#", 1) + [None])[:2]
    rest, query = (rest.split("?", 1) + [None])[:2]
    scheme = authority = ""
    m = re.match(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)([^/]*)(.*)$", rest, re.S)
    if m:
        scheme, authority, rest = m.group(1), m.group(2), m.group(3)
        if "@" in authority:
            userinfo, authority = authority.rsplit("@", 1)
            authority = _withheld("userinfo", len(userinfo), "urls") + "@" + authority
    out = scheme + authority + scrub(rest, "urls")
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            name, eq, value = pair.partition("=")
            pairs.append(scrub(name, "urls") + (eq + _withheld("", len(value), "urls") if eq else ""))
        out += "?" + "&".join(pairs)
    if fragment is not None:
        out += "#" + _withheld("", len(fragment), "urls")
    return out


def cell(value):
    """Text for one tab-separated cell or one printed path: no tab or line break, and a byte that was not UTF-8
    (a lone surrogate) written as \\xNN, so that no writer raises on it."""
    text = value if isinstance(value, str) else str(value)
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)
# END SHARED WITHHOLDING

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


VALUES_MODE = [False]
# What a values-mode answer prints about the evidence's own names (the file, the table, the columns, a message quoting them)
# goes through the shared block's scrub, so a name shaped like a token is withheld on every channel. A digest of the file is
# the file's identity and stays whole.
SCRUBBED_KEYS = ("error", "stderr", "db_path", "database_opened", "table", "column", "reason", "statement")


def scrub_answer(obj):
    out = dict(obj)
    for key in SCRUBBED_KEYS:
        if isinstance(out.get(key), str):
            out[key] = scrub(out[key])
    snap = out.get("snapshot")
    if isinstance(snap, dict):
        out["snapshot"] = {k: (scrub(v) if k in ("source", "receipt") and isinstance(v, str) else v) for k, v in snap.items()}
    return out


def say(obj, code=0):
    if VALUES_MODE[0]:
        obj = scrub_answer(obj)
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


RECEIPT_MAX = 16 * 1024 * 1024


def read_receipt(path):
    try:
        if os.path.getsize(path) > RECEIPT_MAX:
            return None
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    tool = data.get("tool") if isinstance(data, dict) else None
    return data if isinstance(tool, dict) and tool.get("name") == "sqlite_snapshot" else None


def find_snapshot(db):
    """(path of the database to open, snapshot facts or None). `db` may be a sqlite_snapshot directory, or the database inside one
    (<snapshot>/original/database.sqlite or <snapshot>/applied/database.sqlite); anything else is an ordinary file."""
    if os.path.isdir(db):
        receipt = read_receipt(os.path.join(db, "snapshot.json"))
        if receipt is None:
            return db, None
        root = db
        target = os.path.join(root, receipt.get("database") or "")
    else:
        parent = os.path.dirname(os.path.abspath(db))
        root = os.path.dirname(parent)
        receipt = read_receipt(os.path.join(root, "snapshot.json")) if os.path.basename(parent) in ("original", "applied") else None
        if receipt is None:
            return db, None
        target = db
    rel = os.path.relpath(os.path.abspath(target), os.path.abspath(root))
    applied = receipt.get("applied") or {}
    wal = receipt.get("wal") or {}
    which = rel.split(os.sep)[0]
    recorded = applied.get("sha256") if which == "applied" else (receipt.get("source") or {}).get("sha256")
    facts = {
        "receipt": os.path.join(root, "snapshot.json"), "queried": rel, "queried_is": ("the copy with the WAL applied" if which == "applied" else "the copy of the main file as it was"),
        "source": (receipt.get("source") or {}).get("db_path"), "source_sha256": (receipt.get("source") or {}).get("sha256"),
        "wal_applied": bool(receipt.get("wal_applied")), "wal_frames_committed": wal.get("frames_committed"), "wal_frames_valid": wal.get("frames_valid"),
        "wal_frames_uncommitted_valid": wal.get("frames_uncommitted_valid"), "snapshot_status": receipt.get("status"),
        "snapshot_problems": receipt.get("problems") or [], "snapshot_notes": receipt.get("notes") or [], "recorded_sha256": recorded,
        "rollback_journal": (receipt.get("rollback_journal") or {}).get("state"),
    }
    return target, facts


def snapshot_note(facts, side):
    """What state of the source this snapshot's database is, in words; the plain sidecar report would be wrong inside a snapshot."""
    notes = []
    if facts["queried"].startswith("applied"):
        notes.append("SNAPSHOT: this is the copy of %s with its WAL applied by SQLite (%s committed frame(s)); the originals were not touched." % (
            facts["source"] or "the source", facts["wal_frames_committed"]))
        if facts["wal_frames_uncommitted_valid"]:
            notes.append("%d valid WAL frame(s) after the last commit were not applied." % facts["wal_frames_uncommitted_valid"])
    else:
        notes.append("SNAPSHOT: this is the snapshot's copy of the main file as it was%s." % (
            "; its WAL is NOT applied here (the applied copy is applied/database.sqlite)" if facts["wal_frames_committed"] else ""))
    if facts["rollback_journal"] and facts["rollback_journal"].startswith("header present"):
        notes.append("A hot rollback journal was beside the source and was not rolled back: the main file may hold an interrupted write.")
    if facts["snapshot_status"] != "complete":
        notes.append("The snapshot itself is %s: %s" % (facts["snapshot_status"], "; ".join(facts["snapshot_problems"][:3]) or "see its receipt"))
    return " ".join(notes)


def snapshot_status(side):
    """Said plainly: what state of the database this result is."""
    notes = []
    wal = next((s for s in side if s["name"].endswith("-wal") and s.get("present")), None)
    jrn = next((s for s in side if s["name"].endswith("-journal") and s.get("present")), None)
    if wal and wal.get("frames_valid"):
        notes.append("WAL NOT APPLIED: the main file was read immutable, so the %d frame(s) (%d committed) in %s are not in this result; "
                     "a row committed only there is missing. To read that state, run sqlite_snapshot on the database (it copies the set, hashed, and "
                     "has SQLite apply the WAL in the copy) and query the `database` it names." % (wal["frames_valid"], wal.get("frames_committed", 0), wal["name"]))
    elif wal and wal.get("bytes"):
        notes.append("%s is present (%d bytes) and holds no valid frame; the main file is the whole database state this tool can read." % (wal["name"], wal["bytes"]))
    if jrn and jrn.get("bytes") and jrn.get("state", "").startswith("header present"):
        notes.append("%s is present (%d bytes): a rollback journal that was not rolled back; the main file may hold an interrupted write. Not applied." % (jrn["name"], jrn["bytes"]))
    elif jrn and jrn.get("bytes"):
        notes.append("%s is present (%d bytes): %s." % (jrn["name"], jrn["bytes"], jrn.get("state", "its header was not read")))
    if not notes:
        return "main file only; no WAL frames or hot journal beside it"
    return " ".join(notes)


def typed_cell(value):
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
    c = typed_cell(value)
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


def publish(tmp, path, shown, left=None):
    """Move a finished file to `path` without replacing what is there: a file at the name is an earlier answer (a complete one,
    perhaps, where this run was cut short) and stays; this one is kept beside it as name.2.ext. Returns the name it has and
    the name to show for it. With a list `left`, a temporary name that cannot be removed once the file is in place is added to
    it instead of raising (the file is published; the caller says what remains)."""
    stem, ext = os.path.splitext(str(path))
    shown_stem, _ = os.path.splitext(shown)

    def drop_tmp():
        try:
            os.unlink(tmp)
        except OSError:
            if left is None:
                raise
            left.append(tmp)
    k = 1
    while True:
        suffix = "" if k == 1 else ".%d" % k
        candidate = Path(stem + suffix + ext)
        try:
            os.link(tmp, candidate)
        except FileExistsError:
            if same_bytes(tmp, candidate):                # the same answer again (a page of the same search): the file is already there
                drop_tmp()
                return candidate, shown_stem + suffix + ext
            k += 1
            continue
        except OSError:                                   # a file system with no hard links: a look, then a rename
            if os.path.lexists(candidate):
                if same_bytes(tmp, candidate):
                    drop_tmp()
                    return candidate, shown_stem + suffix + ext
                k += 1
                continue
            os.rename(tmp, candidate)
            return candidate, shown_stem + suffix + ext
        drop_tmp()
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
            line = json.dumps({"n": n, "values": [typed_cell(v) for v in row]}, ensure_ascii=False) + "\n"
            if self.written + len(line) > FILE_BYTES:
                self.file_stopped = n
                return
            self.fh.write(line)
            self.written += len(line)
            return
        # A row with a large BLOB: its size is known before it is written, and the BLOB is encoded in slices.
        size = sum(4 * ((len(v) + 2) // 3) + 120 if isinstance(v, bytes) else len(json.dumps(typed_cell(v), ensure_ascii=False)) + 2 for v in row) + 40
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
                self.fh.write(json.dumps(typed_cell(v), ensure_ascii=False))
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


# --- values to a file (write_values) ---------------------------------------------------------------------------

VALUES_NAME = "sqlite-query-values.jsonl"
VALUES_FORMAT = ("JSON Lines, mode 0600: one line per cell that is not NULL (finding_id, table: the real name, rowid: null unless the "
                 "answer's locator is rowid, n: the row's position in this export from 1, column: the real name, type, length, and value: "
                 "a BLOB is {blob_b64}, text that is not UTF-8 is {text_invalid_utf8, bytes_b64, length}; a cell that could not be "
                 "exported has not_exported: value_too_large or unreadable instead of a value, and an unreadable one its error_class and "
                 "sqlite's message), then one last line {end: true, complete, rows_read, cells_written, cells_with_a_value, "
                 "cells_not_exported, stopped, error_class, sqlite_message}. A file without the end line was cut short (the run was killed "
                 "or the disk was full). No digest of any value")
VALUES_PARAMS = ("table", "columns", "rowid_from", "rowid_to")
ROWID_NAMES = ("rowid", "oid", "_rowid_")
LOCATORS_BYTES = FILE_BYTES       # the locators file stops here, and says so; the values file still has every cell's locator
PARTS_MAX = 1000                  # rows read again a cell at a time (a value over VALUE_MAX, a cell sqlite cannot compute); past it the export stops, said

# What each kind of table is located by, and in what order its rows come (the answer's n_ranks names the columns whose values that
# order follows). A rowid range is offered only where the rowid is not the value of a column the table declares.
LOCATOR_TEXT = {
    "rowid": "rowid: the table's own row key (it is no column's value), rows in rowid order",
    "alias": ("n: the row's position in this export. The table's rowid is the value of its INTEGER PRIMARY KEY column, so it is not "
              "printed; the rows come in the order of that key, so n ranks its values and says nothing more of them"),
    "without_rowid": ("n: the row's position in this export. A WITHOUT ROWID table has no rowid and its rows come in the order of its "
                      "primary key (its columns, collations and directions), so n ranks the key's values and says nothing more of them"),
    "virtual": ("n: the row's position in this export, in the order the virtual table's module returns rows, which can be the order of a "
                "value (fts5vocab returns its terms sorted); its rowid is not printed"),
    "shadowed": ("n: the row's position in this export, in rowid order; every name of the rowid (rowid, oid, _rowid_) is a column of this "
                 "table. Where one of them is the INTEGER PRIMARY KEY (n_ranks names it), the rowid is that column's value and n ranks it"),
}
NO_RANGE = {
    "alias": ("the table's rowid is the value of its INTEGER PRIMARY KEY column, so a rowid range would select rows by that value: "
              "export the whole table (rows are located by n)", "rowid_is_a_value"),
    "without_rowid": ("rowid_from and rowid_to select by rowid, and this table has none (WITHOUT ROWID): export the whole table", "no_rowid"),
    "virtual": ("a virtual table's rowid is whatever its module makes it, possibly a value: export the whole table", "virtual_table"),
    "shadowed": ("every name of the rowid (rowid, oid, _rowid_) is a column of this table, so no range can name it: export the whole table", "rowid_shadowed"),
}


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


# What reading a row can raise: sqlite's errors, and Python's when it cannot decode the message of one (a UnicodeDecodeError, a
# ValueError: a generated column's error that quotes bytes that are not UTF-8 arrives as one, with no code).
READ_ERRORS = (sqlite3.Error, ValueError)
SQLITE_INTERRUPT, SQLITE_TOOBIG, SQLITE_AUTH = 9, 18, 23
SQLITE_ERROR_MISSING_COLLSEQ = 1 | (1 << 8)
# The fixed messages sqlite gives those codes (the wording of a denial changed between versions), for a Python that gives no code.
FIXED_MESSAGES = {"interrupted": SQLITE_INTERRUPT, "string or blob too big": SQLITE_TOOBIG, "not authorized": SQLITE_AUTH,
                  "authorization denied": SQLITE_AUTH}


def sqlite_code(exc):
    """The primary result code of a sqlite error, or None. Every decision is taken on the code, never on the message, which can
    quote a value (a generated column's json_extract does: "bad JSON path: 'it was interrupted'" must not end an export as a
    time-out). Python before 3.11 gives no code: there the text before the message's first quote decides, and only when it is,
    word for word, one of the fixed messages above, so a quoted value decides nothing. A UnicodeDecodeError (a message that
    quotes bytes that are not UTF-8) is none of these codes, whose messages are ASCII."""
    if not isinstance(exc, sqlite3.Error):
        return None
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int) and not isinstance(code, bool):
        return code & 0xFF
    head = re.split(r"['\"`\[]", str(exc), maxsplit=1)[0].strip().lower()
    return FIXED_MESSAGES.get(head)


def sqlite_class(exc):
    """The class of a sqlite error, never its message (a message can quote a value)."""
    if isinstance(exc, UnicodeDecodeError):
        return "UnicodeDecodeError (sqlite's message is not UTF-8)"
    name = getattr(exc, "sqlite_errorname", None)
    return "%s%s" % (type(exc).__name__, " " + name if isinstance(name, str) and re.fullmatch(r"SQLITE_[A-Z_]+", name) else "")


def sqlite_text(exc):
    """sqlite's message, for the values file only: bytes Python could not decode are kept, escaped."""
    if isinstance(exc, UnicodeDecodeError) and isinstance(exc.object, (bytes, bytearray)):
        return bytes(exc.object).decode("utf-8", "backslashreplace")
    return str(exc)


def refused_function(exc):
    """The authorizer refused a function (sqlite says so with SQLITE_ERROR, not SQLITE_AUTH): the message starts with sqlite's own
    fixed words, which no value comes before."""
    return isinstance(exc, sqlite3.Error) and str(exc).startswith("not authorized to use function: ")


def too_big(exc):
    return sqlite_code(exc) == SQLITE_TOOBIG


def missing_collation(exc):
    """sqlite has no collation of the name the schema gives (SQLITE_ERROR_MISSING_COLLSEQ, an extended code; on Python before 3.11,
    which gives none, sqlite's own fixed words, which no value comes before: the name after them is the schema's)."""
    if not isinstance(exc, sqlite3.Error):
        return False
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int) and not isinstance(code, bool):
        return code == SQLITE_ERROR_MISSING_COLLSEQ
    return str(exc).startswith("no such collation sequence: ")


def stops_the_export(exc):
    """An error no row-by-row reading gets past: the time budget, the authorizer (by their codes)."""
    return sqlite_code(exc) in (SQLITE_INTERRUPT, SQLITE_AUTH)


class SecretValuesRefused(Exception):
    pass


# A whole line of the values file, read back after a failed write: its kind and row are found in its head, before its value. Every
# `"` inside a JSON string is written `\"`, so these keys are matched only where they are keys.
_LINE_N = re.compile(rb'"n": (\d+), "column": ')
_LINE_VALUE = re.compile(rb'"length": (?:\d+|null), "value": ')
_LINE_MISSING = re.compile(rb'"length": (?:\d+|null), "not_exported": "([a-z_]+)"')


def _line_kind(head):
    if head.startswith(b'{"end": true'):
        return "end"
    if _LINE_VALUE.search(head):
        return "value"
    m = _LINE_MISSING.search(head)
    return m.group(1).decode("ascii") if m else None


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The pattern of recovery_key_scan (encrypted-containers), copied: call `add` once per cell with its id, its locator and the
    value. With `enabled` false it writes nothing and `summary()` says so. `add_blob` is `add` for a BLOB written in slices.
    A write that fails (a full disk) raises OSError to the caller, which stops the export and says so; `close` never raises: what
    it could not do is in `error`, the file stays as far as it was written, without its end line, and the counts are then what
    the disk holds (`disk`), read back.
    """

    def __init__(self, enabled):
        self.enabled = enabled
        self.written = 0                     # cell lines: a value, or a not_exported line
        self.valued = 0                      # cell lines that hold a value
        self.missing = collections.Counter()  # not_exported lines, by why
        self.bytes = 0
        self._fh = None
        self.error = None
        self.ended = False
        self.disk = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        refusal = values_refusal()
        if refusal:
            raise SecretValuesRefused(refusal)
        self.path = Path(self.out) / VALUES_NAME
        self.shown = "store/jobs/%s/out/%s" % (safe_name(self.job), VALUES_NAME)
        # Created once the table is known and before its first row is read: a file or a link already at that name is refused by
        # name (O_EXCL does not follow a link, a dangling one included), instead of failing, or writing through it, after the
        # export. With nothing to write it stays an empty file but for its end line, mode 0600, and the answer says written: 0.
        # OUT itself first: a file or a link to nothing at OUT is said as such, not as a values file that exists.
        out_dir = self.path.parent
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            if os.path.islink(str(out_dir)) and not os.path.exists(str(out_dir)):
                raise SecretValuesRefused("OUT is a link to nothing (its target does not exist), not a directory: %s; nothing was "
                                          "written" % out_dir)
            if os.path.lexists(str(out_dir)) and not os.path.isdir(str(out_dir)):
                raise SecretValuesRefused("OUT is not a directory (a file is at its name): %s; nothing was written" % out_dir)
            raise SecretValuesRefused("OUT could not be made: %s (%s); nothing was written" % (out_dir, describe(exc)))
        try:
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        line = json.dumps({"finding_id": finding_id, **locator, "value": value}) + "\n"
        self._fh.write(line)
        self.bytes += len(line)
        self.written += 1
        self.valued += 1

    def add_blob(self, finding_id, locator, blob):
        """A BLOB as {blob_b64}, written slice by slice: no second copy of a large value in memory, and no digest of it."""
        if not self.enabled:
            return
        head = json.dumps({"finding_id": finding_id, **locator})[:-1] + ', "value": {"blob_b64": "'
        self._fh.write(head)
        view = memoryview(blob)
        for at in range(0, len(view), SLICE_BYTES):
            self._fh.write(base64.b64encode(view[at:at + SLICE_BYTES]).decode("ascii"))
        self._fh.write('"}}\n')
        self.bytes += len(head) + 4 * ((len(blob) + 2) // 3) + 4
        self.written += 1
        self.valued += 1

    def add_missing(self, finding_id, locator, why, error=None, message=None):
        """A cell that is in the table and not in the file, said where its value would be (with sqlite's message, which can quote
        a value and is therefore written here only)."""
        if not self.enabled:
            return
        extra = {"error_class": error, "sqlite_message": message} if error else {}
        line = json.dumps({"finding_id": finding_id, **locator, "not_exported": why, **extra}) + "\n"
        self._fh.write(line)
        self.bytes += len(line)
        self.written += 1
        self.missing[why] += 1

    def end(self, record):
        """The last line: the file is whole up to here. A file without it was cut short."""
        if not self.enabled or self._fh is None or self.error:
            return
        try:
            self._fh.write(json.dumps({"end": True, **record}) + "\n")
            self.ended = True
        except OSError as exc:
            self.fail(exc)

    def fail(self, exc):
        if self.error is None:
            self.error = describe(exc)
        self.ended = False

    def disk_state(self):
        """What reached the disk, read back after a failed write, since a buffered writer takes more than a full disk keeps: the
        whole cell lines, how many hold a value and how many say not_exported (by why), the row of the last whole cell line,
        whether a part of a line follows the whole ones, and whether the last whole line is the end line. Read in blocks; of a
        line only its head is held, up to its value."""
        try:
            fd = os.open(str(self.path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return None
        st = {"cell_lines": 0, "values": 0, "not_exported": collections.Counter(), "last_row": None, "part_of_a_line": False,
              "end_line": False}
        head, kind = b"", None
        with os.fdopen(fd, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                pos = 0
                while True:
                    nl = chunk.find(b"\n", pos)
                    stop = len(chunk) if nl < 0 else nl
                    if kind is None:
                        head += chunk[pos:stop]
                        kind = _line_kind(head)
                    if nl < 0:
                        break
                    if kind == "end":
                        st["end_line"] = True
                    else:
                        st["end_line"] = False
                        st["cell_lines"] += 1
                        if kind == "value":
                            st["values"] += 1
                        elif kind:
                            st["not_exported"][kind] += 1
                        m = _LINE_N.search(head)
                        st["last_row"] = int(m.group(1)) if m else st["last_row"]
                    head, kind = b"", None
                    pos = nl + 1
        if head:
            st["part_of_a_line"], st["end_line"] = True, False
        st["not_exported"] = dict(st["not_exported"])
        return st

    def state_text(self):
        d = self.disk
        if d is None:
            return "it could not be read back, so what it holds is not known; it is kept, mode 0600"
        if d["end_line"]:
            return ("it is kept, mode 0600, and reads whole: %d cell line(s) and its end line, so the error came at its close or its "
                    "sync and the disk's copy is not confirmed" % d["cell_lines"])
        return ("it is kept, mode 0600, with %d whole cell line(s)%s%s, and has no end line: it is not the table" % (
            d["cell_lines"], " (the last of row n=%d)" % d["last_row"] if d["last_row"] else "",
            ", then a part of a line" if d["part_of_a_line"] else ""))

    def close(self):
        if self._fh is None:
            return
        fh, self._fh = self._fh, None
        try:
            fh.flush()
            os.fsync(fh.fileno())
        except OSError as exc:
            self.fail(exc)
        try:
            fh.close()
        except OSError as exc:
            self.fail(exc)
            try:
                os.close(fh.fileno())
            except (OSError, ValueError):
                pass
        if self.error:
            self.disk = self.disk_state()
            if self.disk is not None:
                self.written, self.valued = self.disk["cell_lines"], self.disk["values"]
                self.missing = collections.Counter(self.disk["not_exported"])
                self.ended = self.disk["end_line"]
            else:
                self.ended = False
            self.error = "the values file could not be written to the end (%s); %s" % (self.error, self.state_text())

    def summary(self):
        lines_missing = sum(self.missing.values())
        return {
            "requested": self.enabled,
            "written": self.written,
            "values": self.valued,
            "not_exported": lines_missing,
            "values_file": self.shown if self.enabled else None,
            # A not_exported line carries sqlite's message, which can quote a value: it is secret too.
            "contains_secret_values": self.valued + lines_missing > 0,
            "format": VALUES_FORMAT if self.enabled else None,
            "end_line_written": self.ended,
        }


REFUSED_OUTSIDE_A_JOB = ("write_values is refused outside a job: a value written here would be an ordinary file, not a sealed secret "
                         "output. Run it as job_run(tool: \"sqlite_query\", secret_output: true, args: {...}) and ask again there. "
                         "Nothing was written.")
REFUSED_NOT_SECRET = ("write_values is refused in a job that was not run as secret output: its files would be sealed as ordinary output. "
                      "The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. Run it as "
                      "job_run(tool: \"sqlite_query\", args: {...}), whose manifest makes the job secret output, or give a command job "
                      "secret_output: true; if that is refused the same way, this run's harness does not set the variable and the values "
                      "mode is not available in it. Nothing was written.")


def values_refusal():
    """Why write_values cannot be honoured here, or None: outside a job (JOB_ID and OUT not both set), or in a job the harness did not
    run as secret output (SECRET_OUTPUT not 1). Decided before anything is opened or written."""
    if not (os.environ.get("JOB_ID") and os.environ.get("OUT")):
        return REFUSED_OUTSIDE_A_JOB
    if os.environ.get("SECRET_OUTPUT") != "1":
        return REFUSED_NOT_SECRET
    return None


def values_fail(message, **extra):
    say({"ok": False, "error": message, "tool": TOOL, **extra}, 1)


def q_ident(name):
    return '"' + name.replace('"', '""') + '"'


def value_kind(value):
    """(type, length) of a cell: the length is bytes for a BLOB and for text (as UTF-8), characters of its decimal form for an
    integer, and characters of Python's shortest repr for a real (1e+20 is 5, 12345.6 is 7: not its magnitude)."""
    if value is None:
        return "null", None
    if isinstance(value, NotExported):
        return value.kind, value.length
    if isinstance(value, bytes):
        return "blob", len(value)
    if isinstance(value, _Text):
        return "text_not_utf8", len(value.raw)
    if isinstance(value, str):
        return "text", len(value.encode("utf-8", "replace"))
    if isinstance(value, float):
        return "real", len(repr(value))
    return "integer", len(str(value))


def value_json(value):
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return {"real": repr(value)}
    if isinstance(value, _Text):
        return {"text_invalid_utf8": str(value), "bytes_b64": base64.b64encode(value.raw).decode("ascii"), "length": len(value.raw)}
    return value


END_RESERVE = 4096                # room kept for the end line but for sqlite's message in it


def line_reserve(finding_id, locator, value):
    """The most bytes the values file's line for this cell can take, from what the answer prints of the cell (its locator, type
    and length: never its content): six per byte of text (the longest JSON escape of a byte, \\u0001), the exact base64 of a BLOB,
    an integer's or a real's own characters. The cap is decided on these, so where an export stops does not depend on how a value
    escapes, and the file stays within the cap since a line is never longer. A not_exported line reserves six per byte of sqlite's
    message, whose length can follow a value it quotes."""
    base = len(json.dumps({"finding_id": finding_id, **locator})) + 1      # the line but its last key, and its newline
    if isinstance(value, NotExported):
        extra = len(', "not_exported": ""') + len(value.why)
        if value.error:
            # The class is one of a few fixed names (it can say whether the message was UTF-8: a fixed room hides that).
            extra += (len(', "error_class": , "sqlite_message": ') + max(256, len(json.dumps(value.error)))
                      + 6 * len((value.message or "").encode("utf-8", "replace")) + 2)
        return base + extra
    extra = len(', "value": ')
    if isinstance(value, bytes):
        return base + extra + len('{"blob_b64": ""}') + 4 * ((len(value) + 2) // 3)
    if isinstance(value, _Text):
        n = len(value.raw)
        return base + extra + len('{"text_invalid_utf8": , "bytes_b64": "", "length": }') + 6 * n + 2 + 4 * ((n + 2) // 3) + len(str(n))
    if isinstance(value, str):
        return base + extra + 6 * len(value.encode("utf-8", "replace")) + 2
    if isinstance(value, float):
        return base + extra + max(len(repr(value)), len('{"real": "-inf"}'))
    return base + extra + len(str(value))


class NotExported:
    """A cell whose value is not in the values file: `value_too_large` (longer than VALUE_MAX: its type, and its length when SQLite
    gives it without reading the value) or `unreadable` (sqlite could not compute it: a generated column's error)."""

    def __init__(self, why, kind, length=None, error=None, message=None):
        self.why, self.kind, self.length, self.error, self.message = why, kind, length, error, message


def blank_quoted(sql):
    """A CREATE statement with its strings, quoted names and comments blanked: a default value, a name or a comment can hold any
    words."""
    out, i, n = [], 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in "'\"`":
            j = i + 1
            while j < n:
                if sql[j] == ch:
                    if j + 1 < n and sql[j + 1] == ch:   # a doubled quote is one quote inside
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
            out.append(" ")
        elif ch == "[":
            j = sql.find("]", i + 1)
            i = n if j < 0 else j + 1
            out.append(" ")
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j + 1
            out.append(" ")
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def declared_without_rowid(sql):
    """Whether a CREATE TABLE statement carries the WITHOUT ROWID option: the words after the column list's closing parenthesis."""
    text = blank_quoted(sql)
    return ")" in text and bool(re.search(r"\bWITHOUT\s+ROWID\b", text[text.rfind(")") + 1:], re.I))


def table_list_row(conn, table):
    """The table's row of PRAGMA table_list (SQLite 3.37 and later: schema, name, type, ncol, wr, strict), or None."""
    try:
        for r in conn.execute("PRAGMA table_list"):
            if len(r) > 4 and str(r[0]) == "main" and str(r[1]) == table:
                return r
    except READ_ERRORS:
        pass
    return None


def is_virtual(conn, table, sql, rootpage):
    """SQLite's own answer where it gives one (table_list's type), else the schema: a virtual table has no b-tree (rootpage 0), and
    its statement says VIRTUAL once its strings, quoted names and comments are blanked (CREATE /* x */ VIRTUAL TABLE is one, in a
    schema an application or a crafted file wrote)."""
    r = table_list_row(conn, table)
    if r is not None:
        return str(r[2]) == "virtual"
    return rootpage == 0 or bool(re.match(r"\s*create\s+virtual\s+table\b", blank_quoted(sql), re.I))


def is_without_rowid(conn, table, sql):
    """SQLite's own answer where it gives one (PRAGMA table_list, SQLite 3.37 and later: its `wr` column), else the statement's
    text. Decided before the names: columns named rowid, oid and _rowid_ hide the rowid of a rowid table and change nothing of a
    WITHOUT ROWID one."""
    r = table_list_row(conn, table)
    if r is not None:
        return bool(r[4])
    return declared_without_rowid(sql)


def primary_key_order(conn, table, info):
    """A WITHOUT ROWID table's primary key as the table stores it: (its columns, an ORDER BY of each with its collation and
    direction), so SQLite reads the table's own b-tree, or an index in the same order, and needs no sort. From PRAGMA
    index_xinfo of the key, else the key's columns from table_xinfo."""
    try:
        for r in conn.execute("PRAGMA index_list(%s)" % q_ident(table)):
            if str(r[3]) == "pk":
                keys = [x for x in conn.execute("PRAGMA index_xinfo(%s)" % q_ident(str(r[1]))) if x[5]]
                if keys and all(x[2] is not None for x in keys):
                    return [str(x[2]) for x in keys], ", ".join(
                        "%s COLLATE %s%s" % (q_ident(str(x[2])), q_ident(str(x[4] or "BINARY")), " DESC" if x[3] else "") for x in keys)
    except READ_ERRORS:
        pass
    key = [str(r[1]) for r in sorted((r for r in info if r[5]), key=lambda r: r[5])]
    return key, ", ".join(q_ident(k) for k in key)


def byte_compare(a, b):
    """The stand-in for a collation this SQLite does not have: code point order, which is UTF-8's byte order."""
    return (a > b) - (a < b)


def stand_in_collations(conn, table):
    """The collations a WITHOUT ROWID table's primary key names that this SQLite does not have (an application's own: Android's
    LOCALIZED and UNICODE), each given a byte compare, so that the key's ORDER BY can be prepared. SQLite then walks the table's
    b-tree in the order it is stored and sorts nothing (the ORDER BY names the key's own collations), so the rows come in the
    order the application's collation gave them; a comparison under that name in the table's own expressions (a generated
    column) is the byte compare's. Only a name sqlite says is missing gets one (asked of a constant, not of a value)."""
    names = []
    try:
        for r in conn.execute("PRAGMA index_list(%s)" % q_ident(table)):
            if str(r[3]) == "pk":
                for x in conn.execute("PRAGMA index_xinfo(%s)" % q_ident(str(r[1]))):
                    if x[5] and isinstance(x[4], str) and x[4] and x[4] not in names:
                        names.append(x[4])
    except READ_ERRORS:
        return []
    stood = []
    for name in names:
        try:
            conn.execute("SELECT 'a' < 'b' COLLATE %s" % q_ident(name)).fetchone()
        except READ_ERRORS as exc:
            if not missing_collation(exc):
                continue
            try:
                conn.create_collation(name, byte_compare)
                stood.append(name)
            except (sqlite3.Error, ValueError, TypeError):
                pass
    return stood


def integer_primary_key(conn, table, info):
    """The column SQLite makes the rowid of a rowid table, or None: its one primary key column when declared exactly INTEGER (any
    case of the ASCII word) and kept in no index of its own. `INTEGER PRIMARY KEY DESC` is not an alias, and SQLite then makes the
    key an index (origin pk in PRAGMA index_list); where that list cannot be read the declared type alone decides, which can only
    hide a rowid that could have been shown."""
    pk = [r for r in info if r[5]]
    declared = str(pk[0][2] or "").strip() if len(pk) == 1 else ""
    if not (declared.isascii() and declared.upper() == "INTEGER"):
        return None
    try:
        if any(str(r[3]) == "pk" for r in conn.execute("PRAGMA index_list(%s)" % q_ident(table))):
            return None
    except READ_ERRORS:
        pass
    return str(pk[0][1])


def table_layout(conn, wanted, columns):
    """(table, [(column, declared type)], kind, order) for the table `wanted`, or a refusal as JSON. `kind` is how a row is located:
    rowid (an ordinary rowid table), alias (its rowid is an INTEGER PRIMARY KEY column's value), without_rowid, virtual, or
    shadowed (a rowid table whose columns named rowid, oid and _rowid_ hide the rowid). `order` says how its rows are read:
    rowid_name (the name that reaches the rowid, kind rowid only), order_by (an ORDER BY that is the table's own order and total,
    or None: a shadowed table with no INTEGER PRIMARY KEY is read NOT INDEXED in its storage order, a virtual table in its
    module's), and ranks (the columns whose values that order follows: [] for a rowid order that is no column's, None for a
    module's, which is not known)."""
    rows = list(conn.execute("SELECT name, sql, rootpage FROM sqlite_master WHERE type = 'table' ORDER BY name"))
    found = [(str(r[0]), r[1] if isinstance(r[1], str) else "") for r in rows]
    roots = {str(r[0]): r[2] for r in rows}
    names = [n for n, _s in found]
    hits = [n for n in names if n == wanted] or [n for n in names if n.lower() == wanted.lower()]
    if len(hits) != 1:
        values_fail("the database has no table of that name (the mode reads one table; a view is not one)" if not hits
                    else "more than one table matches that name without regard to case: give it exactly", table=wanted, tables=len(names))
    table = hits[0]
    virtual = is_virtual(conn, table, dict(found)[table], roots[table])
    try:
        info = [r for r in conn.execute("PRAGMA table_xinfo(%s)" % q_ident(table)) if r[6] in (0, 2, 3)]
    except READ_ERRORS as exc:
        if virtual:
            raise VirtualTableUnsupported(exc)
        raise
    have = {str(r[1]): str(r[2] or "") for r in info}
    chosen = columns if columns is not None else [str(r[1]) for r in info]
    if not chosen:
        values_fail("the table has no column that can be read", table=table)
    for c in chosen:
        if c not in have:
            values_fail("the table has no column of that name (names are case-sensitive here)", table=table, column=c)
    layout = [(c, have[c]) for c in chosen]
    if virtual:
        return table, layout, "virtual", {"rowid_name": None, "order_by": None, "ranks": None}
    lowered = {str(r[1]).lower() for r in info}
    rowid_name = next((cand for cand in ROWID_NAMES if cand not in lowered), None)
    no_rowid = is_without_rowid(conn, table, dict(found)[table])
    if not no_rowid and rowid_name is not None:
        try:
            conn.execute("SELECT %s FROM %s LIMIT 0" % (rowid_name, q_ident(table)))
        except READ_ERRORS:
            no_rowid = True                       # SQLite has no rowid for it, whatever the statement's text says
    if no_rowid:
        # Ordered by the primary key as the table stores it: without an ORDER BY SQLite reads a WITHOUT ROWID table through a
        # covering index, in the order of another column's values, NOT INDEXED or not (columns named rowid, oid and _rowid_ change
        # nothing of that).
        key, order_by = primary_key_order(conn, table, info)
        return table, layout, "without_rowid", {"rowid_name": None, "order_by": order_by or None, "ranks": key}
    alias = integer_primary_key(conn, table, info)
    if rowid_name is None:
        # Every name of the rowid is a column. Where one column is the INTEGER PRIMARY KEY it is the rowid, and the rows are ordered
        # by it; otherwise no name reaches the rowid, and the rows are read NOT INDEXED in storage order (rowid order).
        return table, layout, "shadowed", {"rowid_name": None, "order_by": q_ident(alias) if alias else None, "ranks": [alias] if alias else []}
    if alias:
        # Its value is the rowid: the rows are ordered by the rowid, which is that column's order (n ranks it); no WHERE names it.
        return table, layout, "alias", {"rowid_name": None, "order_by": rowid_name, "ranks": [alias]}
    return table, layout, "rowid", {"rowid_name": rowid_name, "order_by": rowid_name, "ranks": []}


def export_statement(table, kind, order, what, bounds=None):
    """(statement, parameters) that read `what` from the table: from the table itself (NOT INDEXED: an index's order is the order
    of the indexed values), in the table's own order (a WITHOUT ROWID table's key, which an index can only follow), and on a
    rowid table within the rowid range. The tests read its plan."""
    stmt = "SELECT %s FROM %s%s" % (what, q_ident(table), "" if kind == "virtual" else " NOT INDEXED")
    params, conds = [], []
    if kind == "rowid":
        for key, op in (("rowid_from", ">="), ("rowid_to", "<=")):
            if bounds and key in bounds:
                conds.append("%s %s ?" % (order["rowid_name"], op))
                params.append(bounds[key])
    if conds:
        stmt += " WHERE " + " AND ".join(conds)
    if order["order_by"]:
        stmt += " ORDER BY " + order["order_by"]
    return stmt, params


class VirtualTableUnsupported(Exception):
    pass


def values_mode(obj, given, db, size, side, status, snap, limit, budget, csv_mode):
    wanted = obj.get("table")
    if not isinstance(wanted, str) or not wanted:
        values_fail("write_values needs table: the one table whose values go to the file")
    columns = obj.get("columns")
    if columns is not None and (not isinstance(columns, list) or not columns or not all(isinstance(c, str) and c for c in columns)
                                or len(set(columns)) != len(columns)):
        values_fail("columns is a list of distinct column names, or left out for every column")
    bounds = {}
    for key in ("rowid_from", "rowid_to"):
        if key in obj:
            v = obj[key]
            if not isinstance(v, int) or isinstance(v, bool) or not -2 ** 63 <= v < 2 ** 63:
                values_fail("%s is a whole number from -2**63 to 2**63-1" % key)
            bounds[key] = v
    for name, text in [("table", wanted)] + [("columns", c) for c in columns or []]:
        if "\0" in text:
            values_fail("%s holds a NUL character" % name)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            values_fail("%s is not text that can be written as UTF-8 (it holds a lone surrogate)" % name)
    uri = "file:%s?mode=ro&immutable=1" % urllib.parse.quote(db)
    started = time.monotonic()
    try:
        conn = sqlite3.connect(uri, uri=True)
    except READ_ERRORS as exc:
        values_fail("cannot open the database (%s)" % sqlite_class(exc), db_path=db)
    conn.text_factory = text_factory
    value_limit = "%d bytes" % VALUE_MAX
    if hasattr(conn, "setlimit") and hasattr(sqlite3, "SQLITE_LIMIT_LENGTH"):
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, VALUE_MAX)
    else:
        value_limit = "not enforced (Python before 3.11 has no setlimit)"
    conn.set_authorizer(authorizer)
    conn.set_progress_handler(lambda: 1 if time.monotonic() - started > budget else 0, 20000)
    try:
        table, cols, kind, order = table_layout(conn, wanted, columns)
        rowid_name = order["rowid_name"]
    except VirtualTableUnsupported as exc:
        values_fail("the table is a virtual table whose module could not be started under the read-only authorizer (%s): this "
                    "SQLite cannot export it here; its shadow tables (<name>_content, <name>_data, ...) are ordinary tables that can be"
                    % sqlite_class(exc.args[0]), table=wanted, reason="virtual_table_unsupported")
    except READ_ERRORS as exc:
        values_fail("the table's layout cannot be read (%s)" % sqlite_class(exc), table=wanted)
    if bounds and kind != "rowid":
        why, reason = NO_RANGE[kind]
        values_fail(why, table=table, reason=reason)
    stood_in = stand_in_collations(conn, table) if kind == "without_rowid" else []
    # The values file is made now: the table exists and its layout is read, and no row has been. A wrong name or a file that is
    # not SQLite leaves nothing behind, and the same job can ask again.
    try:
        values = SecretValues(True)
    except SecretValuesRefused as exc:
        say({"ok": False, "error": str(exc), "tool": TOOL, "write_values": "refused", "written": False}, 1)
    sel = ([rowid_name] if kind == "rowid" else []) + [q_ident(c) for c, _t in cols]

    def query(what, offset=None, one=False):
        stmt, params = export_statement(table, kind, order, what, bounds)
        if one:
            stmt += " LIMIT 1 OFFSET %d" % offset
        elif offset:
            stmt += " LIMIT -1 OFFSET %d" % offset
        return conn.execute(stmt, params)

    def one(what, offset):
        """One value of the row at `offset` (None when there is no such row)."""
        got = query(what, offset, one=True).fetchone()
        return None if got is None else got[0]

    def read_in_parts(offset):
        """The row at `offset`, because reading it whole failed: each cell is tried alone, then every cell that can be read is read
        in ONE query, so the cells of an exported row are always one row's (every query has the same total order, and the same
        LIMIT 1 OFFSET). A value over the length limit, and a cell sqlite cannot compute, are recorded instead of a value. A row
        skipped by OFFSET is not decoded, and typeof() and a BLOB's length() do not read the value. A row none of whose cells can
        be read is not a cell's fault: its first error is raised. None: there is no row at `offset`."""
        missing, first = {}, None
        for i, (c, _t) in enumerate(cols):
            ident = q_ident(c)
            try:
                if query(ident, offset, one=True).fetchone() is None:
                    return None
                continue
            except READ_ERRORS as exc:
                if stops_the_export(exc):
                    raise
                first = first or exc
                failed = exc
            try:
                kind_of = one("typeof(%s)" % ident, offset) or "unknown"
            except READ_ERRORS as exc:
                if stops_the_export(exc):
                    raise
                kind_of = "unknown"
            if too_big(failed):
                try:
                    length = one("%s(%s)" % ("length" if kind_of == "blob" else "octet_length", ident), offset)
                except READ_ERRORS as exc:
                    if stops_the_export(exc):
                        raise
                    length = None
                missing[i] = NotExported("value_too_large", kind_of, length if isinstance(length, int) else None)
            else:
                missing[i] = NotExported("unreadable", "unreadable", None, sqlite_class(failed), sqlite_text(failed))
        if first is not None and all(missing.get(i) is not None and missing[i].why == "unreadable" for i in range(len(cols))):
            raise first
        readable = [i for i in range(len(cols)) if i not in missing]
        what = ([rowid_name] if kind == "rowid" else []) + [q_ident(cols[i][0]) for i in readable]
        got = query(", ".join(what), offset, one=True).fetchone() if what else ()
        if got is None:
            return None
        got = list(got)
        row = [got.pop(0)] if kind == "rowid" else []
        for i in range(len(cols)):
            row.append(missing[i] if i in missing else got.pop(0))
        return tuple(row)

    names = [scrub(cell(c)) for c, _t in cols]
    stats = [{"values": collections.OrderedDict(), "length_min": None, "length_max": None} for _ in cols]
    page, page_bytes, total, nulls, file_stopped, file_stopped_rowid = [], 0, 0, 0, None, None
    reserved = 0                         # the values file's bytes as line_reserve counts them: what the cap is decided on
    missing, missing_count, parts = [], collections.Counter(), 0
    parts_limit = False
    job = os.environ.get("JOB_ID") or ""
    digest = hashlib.sha256(json.dumps([db, size, table, [c for c, _t in cols], sorted(bounds.items())], sort_keys=True, default=str).encode()).hexdigest()[:16]
    name = "sqlite_query-values-%s.jsonl" % digest
    locator_path = Path(os.environ["OUT"]) / "tool-output" / name
    locator_shown = "store/jobs/%s/out/tool-output/%s" % (safe_name(job), name)
    loc = {"fh": None, "tmp": None, "bytes": 0, "error": None, "stopped": None, "left": []}
    failure = reason = None
    sqlite_message = error_class = None
    timed_out = False

    def shown_tmp(path):
        # The tool's own temporary name (mkstemp's), not the evidence's: printed as it is, or it could not be found.
        return "store/jobs/%s/out/tool-output/%s" % (safe_name(job), cell(os.path.basename(str(path))))

    def loc_drop(exc):
        try:
            if loc["fh"] is not None:
                loc["fh"].close()
        except OSError:
            pass
        loc["fh"] = None
        if loc["tmp"] is not None:
            try:
                loc["tmp"].unlink()
            except OSError:
                loc["left"].append(shown_tmp(loc["tmp"]))
            loc["tmp"] = None
        loc["error"] = "the locators file could not be written (%s); %s" % (
            describe(exc), "what was written of it is left, unnamed by the answer, at %s" % ", ".join(loc["left"]) if loc["left"] else "none is left")

    def loc_write(text, n):
        if loc["fh"] is None or loc["stopped"]:
            return
        if loc["bytes"] + len(text) > LOCATORS_BYTES:
            loc["stopped"] = n
            return
        try:
            loc["fh"].write(text)
            loc["bytes"] += len(text)
        except OSError as exc:
            loc_drop(exc)

    # The locators file is written for every export (it has every row; the inline page has the first ones).
    try:
        locator_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(locator_path.parent), prefix=".sqlite_query-")
        loc["tmp"] = Path(tmp_name)
        loc["fh"] = os.fdopen(fd, "w", encoding="utf-8")
    except OSError as exc:
        loc_drop(exc)
    loc_write(json.dumps({"table": scrub(cell(table)), "columns": names, "locator": "rowid" if kind == "rowid" else "n"}) + "\n", 0)

    def take(row):
        """One row: its values to the values file (OSError: the values file failed), then, once the row is through, its locators to
        the answer and the locators file and its counts, so row_count N means rows 1..N in the locators file."""
        nonlocal total, nulls, file_stopped, file_stopped_rowid, page_bytes, reserved
        n = total + 1
        rid = row[0] if kind == "rowid" else None
        vals = row[1:] if kind == "rowid" else row
        cells, kinds, row_missing = [], [], []
        for i, ((col, _t), v) in enumerate(zip(cols, vals)):
            kind_of, length = value_kind(v)
            kinds.append((kind_of, length))
            if v is None:
                cells.append("null")
                continue
            if isinstance(v, NotExported):
                row_missing.append((i, v))
                cells.append("too_large:%s:%s" % (kind_of, "?" if length is None else length) if v.why == "value_too_large" else "unreadable")
            else:
                cells.append("%s:%d" % (kind_of, length))
            if file_stopped:
                continue
            finding = "V%07d" % (values.written + 1)
            locator = {"table": table, "rowid": rid, "n": n, "column": col, "type": kind_of, "length": length}
            need = line_reserve(finding, locator, v)
            if reserved + need > FILE_BYTES - END_RESERVE:
                file_stopped, file_stopped_rowid = n, rid
                continue
            reserved += need
            if isinstance(v, NotExported):
                values.add_missing(finding, locator, v.why, v.error, v.message)
            elif isinstance(v, bytes) and len(v) > STREAM_AT:
                values.add_blob(finding, locator, v)
            elif isinstance(v, bytes):
                values.add(finding, locator, {"blob_b64": base64.b64encode(v).decode("ascii")})
            else:
                values.add(finding, locator, value_json(v))
        total = n
        for st, (kind_of, length) in zip(stats, kinds):
            st["values"][kind_of] = st["values"].get(kind_of, 0) + 1
            if length is not None:
                st["length_min"] = length if st["length_min"] is None else min(st["length_min"], length)
                st["length_max"] = length if st["length_max"] is None else max(st["length_max"], length)
        nulls += sum(1 for kind_of, _l in kinds if kind_of == "null")
        for i, v in row_missing:
            missing_count[v.why] += 1
            stats[i].setdefault("not_exported", collections.Counter())[v.why] += 1
            if len(missing) < 100:
                missing.append({"n": n, "rowid": rid, "column": names[i], "why": v.why})
        line = json.dumps({"n": n, "rowid": rid, "cells": cells})
        if len(page) < limit and page_bytes + len(line) <= INLINE_BYTES:
            page.append({"n": n, "rowid": rid, "cells": cells})
            page_bytes += len(line)
        loc_write(line + "\n", n)

    def read_alone(offset):
        """The row at `offset` after reading the table failed there. Python's cursor steps to the next row before it hands over
        the current one, so the error can be the next row's: the row is read alone first, and a cell at a time only when that
        fails too (one charge against PARTS_MAX per such row). None: no row at `offset`."""
        nonlocal parts, parts_limit
        try:
            return query(", ".join(sel), offset, one=True).fetchone()
        except READ_ERRORS as exc:
            if stops_the_export(exc):
                raise
            if parts >= PARTS_MAX:
                parts_limit = True
                raise
            parts += 1
            return read_in_parts(offset)

    try:
        cur = None
        while True:
            try:
                if cur is None:
                    cur = query(", ".join(sel), total)
                row = next(cur, None)
            except READ_ERRORS as exc:
                if stops_the_export(exc) or kind == "virtual":
                    raise
                cur = None
                row = read_alone(total)
                if row is None:
                    raise
                take(row)
                continue
            if row is None:
                break
            take(row)
    except OSError as exc:
        values.fail(exc)
    except (sqlite3.Error, ValueError, OverflowError, MemoryError) as exc:
        # Nothing of the error is printed but what its code decides: sqlite's message can quote a value (a generated column's
        # json_extract does), and so can the class Python gives it (it cannot decode a message that quotes bytes that are not
        # UTF-8). The class and the message go to the values file's end line, the one place a value may be.
        code = sqlite_code(exc)
        sqlite_message = "MemoryError" if isinstance(exc, MemoryError) else sqlite_text(exc)
        error_class = sqlite_class(exc)
        where = "row n=%d (the first row not exported)" % (total + 1)
        if code == SQLITE_INTERRUPT:
            failure, reason, timed_out = "stopped at the %d-second time budget; the rows before it are in the values file" % budget, "timed_out", True
        elif code == SQLITE_AUTH:
            failure, reason = "the read-only authorizer refused what reading the table asked for; nothing past %s" % where, "not_a_plain_read"
        elif kind == "virtual":
            failure, reason = ("the virtual table's module failed at %s: this SQLite cannot export it here; its shadow tables are "
                               "ordinary tables that can be" % where), "virtual_table_unsupported"
        elif isinstance(exc, MemoryError):
            failure, reason = "out of memory reading %s" % where, "out_of_memory"
        elif parts_limit:
            failure, reason = ("%d rows had a cell that could not be read with the rest, the most read a cell at a time; the export "
                               "stopped at %s" % (PARTS_MAX, where)), "too_many_rows_read_in_parts"
        elif missing_collation(exc):
            failure, reason = ("%s could not be read: the table's schema names a collation this SQLite does not have (an "
                               "application's own), where no byte compare stands in (one does only for a WITHOUT ROWID table's "
                               "primary key). That is the schema's doing, not a value's; the collation's name is in sqlite's "
                               "message, in the values file's end line" % where), "missing_collation"
        else:
            failure, reason = ("%s could not be read: none of its cells. The error's class and sqlite's message are not printed, "
                               "since they can depend on a value; they are in the values file's end line" % where), "row_unreadable"
    finally:
        values.end({"complete": failure is None and file_stopped is None and not missing_count, "rows_read": total,
                    "cells_written": values.written, "cells_with_a_value": values.valued, "cells_not_exported": dict(values.missing),
                    "stopped": reason or ("values_file_cap" if file_stopped else None), "error_class": error_class,
                    "sqlite_message": sqlite_message})
        values.close()
        try:
            conn.close()
        except sqlite3.Error:
            pass
    published = None
    if loc["fh"] is not None:
        try:
            loc["fh"].flush()
            os.fsync(loc["fh"].fileno())
            loc["fh"].close()
            loc["fh"] = None
            left = []
            published = publish(loc["tmp"], locator_path, locator_shown, left)
            loc["tmp"] = None
            loc["left"].extend(shown_tmp(p) for p in left)
        except OSError as exc:
            loc_drop(exc)

    out = {"tool": TOOL, "db_path": given, "database_bytes": size, "sidecars": side, "snapshot_status": status,
           "sqlite_library": sqlite3.sqlite_version, "opened": "read-only, immutable, through an authorizer that allows reading only",
           "value_limit": value_limit}
    if size <= HASH_MAX:
        out["database_sha256"] = sha256_file(db)
    else:
        out["database_sha256"] = None
        out["hashing"] = "skipped: the file is larger than %d bytes; the run's own record has its sha256" % HASH_MAX
    if db != given:
        out["database_opened"] = db
    if snap:
        snap["file_matches_recorded_sha256"] = (out["database_sha256"] == snap["recorded_sha256"]) if out["database_sha256"] and snap["recorded_sha256"] else None
        if snap["file_matches_recorded_sha256"] is False:
            out["snapshot_status"] = "THE FILE QUERIED IS NOT THE ONE THE SNAPSHOT RECORDED (its sha256 differs from the receipt's): it was changed after the snapshot, or the receipt belongs to another file. " + out["snapshot_status"]
        out["snapshot"] = snap
    # ok is false when the export stopped early or the values file could not be written to its end (as network_log_summary
    # says a read that stopped early); a locators file that could not be written leaves ok true and complete false, since the
    # values file is whole.
    if failure is None and values.error:
        failure, reason = "the values file could not be written to the end: the export stopped at row n=%d" % (total + 1), "values_file_error"
    complete = (failure is None and file_stopped is None and values.error is None and not missing_count
                and loc["error"] is None and loc["stopped"] is None and published is not None)
    shown_key = lambda p: p["rowid"] if p["rowid"] is not None else p["n"]
    text = "".join("%s|%s\n" % (shown_key(p), "|".join("%s=%s" % (nm, c) for nm, c in zip(names, p["cells"]))) for p in page)
    if csv_mode:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["rowid" if kind == "rowid" else "n"] + names)
        for p in page:
            w.writerow([shown_key(p)] + p["cells"])
        text = buf.getvalue()
    out.update({
        "ok": failure is None, "returncode": 0 if failure is None else 1, "stderr": failure or "", "complete": complete,
        "mode": "values_to_file", "table": table, "table_kind": kind, "locator": "rowid" if kind == "rowid" else "n", "locator_note": LOCATOR_TEXT[kind],
        "n_ranks": None if order["ranks"] is None else [scrub(cell(c)) for c in order["ranks"]],
        "columns": [dict({"name": nm, "declared_type": scrub(cell(t)), "values": st["values"], "length_min": st["length_min"], "length_max": st["length_max"]},
                         **({"not_exported": dict(st["not_exported"])} if st.get("not_exported") else {}))
                    for nm, (_c, t), st in zip(names, cols, stats)],
        "row_count": total, "returned": len(page), "truncated": total > len(page), "rows": page,
        "cells_with_a_value": values.valued, "cells_null": nulls,
        "secret_values": values.summary(), "stdout": text,
    })
    if failure:
        out["error"] = failure
        out["reason"] = reason
        out["rows_read_before_the_stop"] = total
        if timed_out:
            out["timed_out"] = True
    if values.error:
        out["values_file_error"] = values.error
        d = values.disk
        out["values_file_state"] = ("unknown: " if d is None else "whole: " if d["end_line"] else "partial: ") + values.state_text()
        if d is not None:
            out["values_file_holds"] = {"cell_lines": d["cell_lines"], "values": d["values"], "not_exported": d["not_exported"],
                                        "last_row_with_a_whole_line": d["last_row"], "part_of_a_line_after": d["part_of_a_line"],
                                        "end_line": d["end_line"]}
    if missing_count:
        out["cells_not_exported"] = {"cells": dict(missing_count), "first": missing, "value_limit_bytes": VALUE_MAX,
                                     "note": ("value_too_large: longer than the limit; unreadable: sqlite could not compute the cell (the "
                                              "error's class and sqlite's message, which can quote a value, are in the values file only). "
                                              "Which cells are unreadable follows from the table's own expressions over its values (a "
                                              "generated column's json_extract fails on text that is not JSON), so it can say something "
                                              "of those values. Each such cell has a not_exported line in the values file%s; the rest of "
                                              "its row is exported" % (" (up to the row values_file_holds names)" if values.error else ""))}
    if stood_in:
        out["collations_stood_in"] = {
            "names": [scrub(cell(c)) for c in stood_in],
            "note": ("this SQLite does not have the collation(s) the table's primary key names (an application's own); a byte compare "
                     "stood in for each so that the key's order could be asked for. SQLite walks the table in the order it stores it "
                     "and sorts nothing, so the rows come in the order the application's collation gave them (n ranks the key, as for "
                     "any WITHOUT ROWID table); a comparison under that name in the table's own expressions (a generated column) is the "
                     "byte compare's, not the application's")}
    if published:
        out["locators_file"] = published[1]
        out["locators_file_format"] = "JSON Lines: a header line {table, columns, locator}, then one {n, rowid, cells} per row; a cell is type:length, too_large:type:length, unreadable or null; no value"
        out["earlier_answers"] = earlier_answers(published[0])
        if loc["stopped"]:
            out["locators_file_stopped_at_row"] = loc["stopped"]
            out["locators_file_cap_bytes"] = LOCATORS_BYTES
    if loc["left"]:
        out["locators_file_left"] = ("temporary file(s) that could not be removed: %s (each is the locators file or a part of it; no value "
                                     "is in it)" % ", ".join(loc["left"]))
    if loc["error"]:
        out["locators_file_error"] = loc["error"]
    if file_stopped:
        out["values_file_stopped_at_row"] = file_stopped
        out["values_file_cap_bytes"] = FILE_BYTES
        if kind == "rowid":
            out["resume"] = "in a new job (the values file of this one is kept), give rowid_from %d" % file_stopped_rowid
        else:
            out["resume"] = "this table has no rowid range (%s): export fewer columns per job" % NO_RANGE[kind][1]
    out["note"] = ("Locator output: no value, fragment, masked shape or digest of one is in this answer or in any file it names except the "
                   "values file. A cell is type:length (bytes for a BLOB and for text, characters of the decimal form for an integer, so "
                   "its length tells its order of magnitude; a real's is its shortest repr, which does not). The mode exports whole rows "
                   "of one table and takes no filter: row_count and the lengths are the table's (or the rowid range's). %s. Cite table, "
                   "the locator and column; hand a value on through the channel the operator named. The inline page is the first rows; "
                   "locators_file has every row." % LOCATOR_TEXT[kind])
    say(out, 0 if failure is None else 1)


def main():
    try:
        obj = json.load(sys.stdin)
    except ValueError as exc:
        say({"ok": False, "error": "arguments are not valid JSON", "reason": str(exc)}, 1)
    if not isinstance(obj, dict):
        say({"ok": False, "error": "arguments are a JSON object"}, 1)
    write_values = obj.get("write_values", False)
    if not isinstance(write_values, bool):
        say({"ok": False, "error": "write_values must be true or false"}, 1)
    wanted_keys = ("db_path", "table") if write_values else ("db_path", "sql")
    missing = [k for k in wanted_keys if not isinstance(obj.get(k), str) or not obj.get(k)]
    if missing:
        say({"ok": False, "error": "need " + " and ".join(missing),
             "params": ["db_path", "table", "columns", "rowid_from", "rowid_to", "write_values", "limit"] if write_values else ["db_path", "sql", "csv", "limit"]}, 1)
    if write_values:
        VALUES_MODE[0] = True
        if "sql" in obj:
            say({"ok": False, "error": "write_values takes table (and columns, rowid_from, rowid_to), not sql: a WHERE, LIKE, JOIN or any "
                                       "expression over a column whose values are withheld would confirm a guess, one call at a time. The mode "
                                       "exports whole rows of one table and takes no filter; a rowid range is offered only where the rowid is no column's "
                                       "value. For a query over values you may see, leave write_values out.", "write_values": "refused"}, 1)
    else:
        stray = [k for k in VALUES_PARAMS if k in obj]
        if stray:
            say({"ok": False, "error": "%s %s to write_values, which writes the values of one table to a sealed file; "
                                       "an ordinary query takes sql" % (", ".join(stray), "belongs" if len(stray) == 1 else "belong")}, 1)
    db = obj["db_path"]
    sql = obj.get("sql", "")
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
    if "apply_wal" in obj:
        say({"ok": False, "error": "apply_wal is not a parameter of sqlite_query, which opens the file it is given read-only and immutable and never applies a WAL. "
                                   "Run sqlite_snapshot on the database: it copies the set (database, -wal, -shm, -journal) with hashes and has SQLite apply the WAL "
                                   "in the copy, and then give this tool the snapshot's directory or its `database` as db_path.", "db_path": db}, 1)
    refusal = values_refusal() if write_values else None
    if refusal:
        say({"ok": False, "error": refusal, "tool": TOOL, "write_values": "refused", "written": False}, 1)
    if not os.path.exists(db):
        say({"ok": False, "error": "database not found", "db_path": db}, 1)
    given = db
    db, snap = find_snapshot(given)
    if not os.path.isfile(db):
        say({"ok": False, "error": "db_path is not a regular file", "db_path": given}, 1)
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
        # In values mode the caller has said the file holds secrets: its first bytes are not printed.
        head = {"write_values": "nothing was written"} if write_values else {"header_hex": page[:16].hex()}
        say({"ok": False, "error": "not a SQLite file: its first bytes are not the SQLite magic", "db_path": db,
             **head, "first_page_entropy_bits_per_byte": round(e, 3),
             "reading": ("random-looking from the first byte (high entropy), and not identified: an encrypted database (SQLCipher "
                         "or an app's own) is one explanation, compressed or otherwise encoded data another; no query runs without "
                         "knowing which" if e > 7.5 else "another format: identify it from its header (file_type)")}, 1)

    side = sidecars(db)
    status = snapshot_status(side)
    if snap:
        note = snapshot_note(snap, side)
        status = note if snap["queried"].startswith("applied") else note + " " + status
    if write_values:
        for s in side:
            s["name"] = scrub(cell(s["name"]))
        values_mode(obj, given, db, size, side, scrub(status), snap, limit, budget, csv_mode)
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
    base = {"tool": TOOL, "db_path": given, "database_bytes": size, "sidecars": side, "snapshot_status": status,
            "sqlite_library": sqlite3.sqlite_version, "opened": "read-only, immutable, through an authorizer that allows reading only", "value_limit": value_limit}
    if size <= HASH_MAX:
        base["database_sha256"] = sha256_file(db)
    else:
        base["database_sha256"] = None
        base["hashing"] = "skipped: the file is larger than %d bytes; the run's own record has its sha256" % HASH_MAX
    if db != given:
        base["database_opened"] = db
    if snap:
        snap["file_matches_recorded_sha256"] = (base["database_sha256"] == snap["recorded_sha256"]) if base["database_sha256"] and snap["recorded_sha256"] else None
        if snap["file_matches_recorded_sha256"] is False:
            base["snapshot_status"] = "THE FILE QUERIED IS NOT THE ONE THE SNAPSHOT RECORDED (its sha256 differs from the receipt's): it was changed after the snapshot, or the receipt belongs to another file. " + base["snapshot_status"]
        base["snapshot"] = snap
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
            # Decided on sqlite's code, not its message, which can quote a value (sqlite_code).
            code = sqlite_code(exc)
            msg = str(exc)
            if code == SQLITE_AUTH or refused_function(exc):
                msg = "statement refused: it is not a plain read (%s)" % msg
            elif code == SQLITE_TOOBIG:
                msg = ("a value or row in this result is longer than %d bytes, which this tool will not read into memory (sqlite: %s): select its length(), "
                       "or a piece of it with substr(), hex(substr(...)) or a range, in several queries" % (VALUE_MAX, msg))
                failure_kind = "value_too_long"
            elif code == SQLITE_INTERRUPT:
                msg = "stopped at the %d-second time budget; the rows before it are in rows_file when there is one" % budget
            elif isinstance(exc, MemoryError):
                msg = "out of memory reading a row"
            failure = {"error": msg, "statement": stmt}
            if failure_kind:
                failure["reason"] = failure_kind
            if code == SQLITE_INTERRUPT:
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
