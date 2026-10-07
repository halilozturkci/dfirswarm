#!/usr/bin/env python3
"""Read a browser history database that was copied off a live or imaged disk.

This exists because of a measured failure: in one case `sqlite_query` had a
93% error rate against these files, and the cause was not the SQL. A browser
database extracted from an image arrives with its write-ahead log beside it,
and SQLite refuses to open it read-only while the WAL is unplayed, or opens it
and returns the state *before* the last session, which is the part an examiner
wants.

So: copy the database and any -wal, -shm and -journal beside it into a scratch
directory (under $OUT in a job), open the copy read-write so SQLite checkpoints the
WAL, and query that. The original is never touched. The answer says whether a WAL
sidecar was present and how many valid frames SQLite found in it and checkpointed
(`wal_present`, `wal_checkpoint`): a sidecar that was copied is not a log that was
replayed, and a damaged WAL yields no frames. Nothing in a WAL names the database it was
written for, so a log from another database with the same page size can be applied and
its rows returned; this tool reads the log's own header and frames (`wal_inspection`:
salts, checksums, page size, the committed prefix) and compares what the formats let it
compare with the database (page size, text encoding, and the schema cookie of the last
committed copy of page 1, which only grows). A log that contradicts the database is not
copied (`wal_refused`), a rollback journal whose page size is not the database's likewise;
the wal-index (-shm) is a derived index and is never copied. What cannot be established
is said in `wal_not_established`.

Named queries: `chrome_visits` and `firefox_visits` list every visit, joined to its URL,
with the raw time, the transition and the referring visit; `chrome_url_summary` and
`firefox_url_summary` list one row per URL (a visit count and the last visit: a summary,
never a visit list; `chrome_history` and `firefox_history` are the old names of those two,
accepted and answered with a note). Anything else takes `sql`.

READ-ONLY, TWICE. A statement must begin with SELECT, WITH or PRAGMA, and the copy
is opened with an authorizer that denies everything but reading (and the pragmas that
only report).

SENSITIVE OUTPUT. A browser store can hold credentials and session tokens. Before any query
runs, every trigger of the copy is dropped (a trigger could copy a value to a table nothing
withholds) and every cell of a column that holds a credential is replaced, in the disposable
copy, by a marker that carries only its length: the `password_value` of `logins`, the `value`
and `encrypted_value` of `cookies` and `moz_cookies`, any column whose name says password,
secret, token, encrypted, card, cc, cvc, cvv, pin, ssn or iban (a number or a real in such a
column too), the text columns of a table named for cards or IBANs, any text cell that is
wholly a card number (13 to 19 digits that pass the Luhn check, as `autofill.value` can hold),
and Firefox's key database (`metadata`, `nssPrivate`). The secrets of a URL (a token or
password in its query string, fragment or user-info) are withheld in every cell the same way.
No flag brings a column value back: this tool produces none, and says which columns it
withheld, how many cells, and how many bytes or characters they held. A URL's secrets are
written whole only with `write_url_secrets: true`, in a job run with secret_output: true, to
a file under $OUT of mode 0600; the request is refused anywhere else. It decrypts nothing and
has no capability to. Usernames, URLs (with their secrets withheld) and dates are returned.
"""
import json
import os
import re
import shutil
import signal
import sqlite3
import struct
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
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
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
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

PARSER = "browser_history/3"

# Chromium page transition core types (page_transition_types.h) and Firefox visit types
# (nsINavHistoryService); the raw number is always returned beside the name.
CHROME_TRANSITION = (
    "CASE (v.transition & 255) WHEN 0 THEN 'link' WHEN 1 THEN 'typed' WHEN 2 THEN 'auto_bookmark' "
    "WHEN 3 THEN 'auto_subframe' WHEN 4 THEN 'manual_subframe' WHEN 5 THEN 'generated' "
    "WHEN 6 THEN 'start_page' WHEN 7 THEN 'form_submit' WHEN 8 THEN 'reload' WHEN 9 THEN 'keyword' "
    "WHEN 10 THEN 'keyword_generated' ELSE 'unknown' END"
)
FIREFOX_VISIT_TYPE = (
    "CASE v.visit_type WHEN 1 THEN 'link' WHEN 2 THEN 'typed' WHEN 3 THEN 'bookmark' WHEN 4 THEN 'embed' "
    "WHEN 5 THEN 'redirect_permanent' WHEN 6 THEN 'redirect_temporary' WHEN 7 THEN 'download' "
    "WHEN 8 THEN 'framed_link' WHEN 9 THEN 'reload' ELSE 'unknown' END"
)

QUERIES = {
    "chrome_visits": (
        "SELECT v.id AS visit_id, v.url AS url_id, u.url, u.title, v.visit_time AS visit_time_raw, "
        "strftime('%Y-%m-%dT%H:%M:%S', v.visit_time/1000000-11644473600, 'unixepoch') || '.' || printf('%06d', v.visit_time % 1000000) || 'Z' AS visit_utc, "
        "v.from_visit, v.transition AS transition_raw, " + CHROME_TRANSITION + " AS transition_core, v.visit_duration "
        "FROM visits v LEFT JOIN urls u ON u.id = v.url ORDER BY v.visit_time"
    ),
    "chrome_url_summary": (
        "SELECT u.id, u.url, u.title, u.visit_count, u.typed_count, u.last_visit_time AS last_visit_time_raw, "
        "datetime(u.last_visit_time/1000000-11644473600, 'unixepoch') AS last_visit_utc "
        "FROM urls u ORDER BY u.last_visit_time DESC"
    ),
    "chrome_downloads": (
        "SELECT d.id, d.target_path, d.tab_url, d.total_bytes, d.received_bytes, "
        "d.start_time AS start_time_raw, d.end_time AS end_time_raw, "
        "datetime(d.start_time/1000000-11644473600, 'unixepoch') AS start_utc, "
        "datetime(d.end_time/1000000-11644473600, 'unixepoch') AS end_utc "
        "FROM downloads d ORDER BY d.start_time DESC"
    ),
    "firefox_visits": (
        "SELECT v.id AS visit_id, v.place_id, p.url, p.title, v.visit_date AS visit_date_raw, "
        "strftime('%Y-%m-%dT%H:%M:%S', v.visit_date/1000000, 'unixepoch') || '.' || printf('%06d', v.visit_date % 1000000) || 'Z' AS visit_utc, "
        "v.from_visit, v.visit_type AS visit_type_raw, " + FIREFOX_VISIT_TYPE + " AS visit_type "
        "FROM moz_historyvisits v LEFT JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date"
    ),
    "firefox_url_summary": (
        "SELECT p.id, p.url, p.title, p.visit_count, p.last_visit_date AS last_visit_date_raw, "
        "datetime(p.last_visit_date/1000000, 'unixepoch') AS last_visit_utc "
        "FROM moz_places p WHERE p.last_visit_date IS NOT NULL ORDER BY p.last_visit_date DESC"
    ),
    "firefox_downloads": (
        "SELECT a.id, a.content, a.dateAdded AS date_added_raw, datetime(a.dateAdded/1000000, 'unixepoch') AS added_utc "
        "FROM moz_annos a WHERE a.anno_attribute_id IN "
        "(SELECT id FROM moz_anno_attributes WHERE name LIKE 'downloads/%') ORDER BY a.dateAdded DESC"
    ),
    "tables": "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name",
}
# The old names of the two URL summaries: they answered with one row per URL, not per visit.
OLD_NAMES = {"chrome_history": "chrome_url_summary", "firefox_history": "firefox_url_summary"}

# Columns that hold a credential or a session token, by table and column, and by name anywhere.
SENSITIVE_COLUMNS = {
    ("logins", "password_value"),
    ("cookies", "value"),
    ("cookies", "encrypted_value"),
    ("moz_cookies", "value"),
    ("metadata", "item1"),
    ("metadata", "item2"),
    ("nssprivate", "a11"),
    ("nssprivate", "a102"),
}
SENSITIVE_NAME = re.compile(r"passw(or)?d|passwd|\bpwd\b|secret|token|api_?key|private_?key|encrypted|card_?number|cvc|cvv|bearer", re.I)
# Words of a column or table name (split at punctuation and at camel case) that say it holds a card, an IBAN or an SSN.
CARD_WORDS = {"cc", "cvc", "cvv", "cvc2", "pin", "ssn", "iban", "card", "cards", "creditcard", "cardnumber", "ccnumber"}
# In a table named for cards, these columns describe the row; the others are withheld.
METADATA_COLUMN = re.compile(r"(^|_)(id|guid|origin|date|time|timestamp|count|length|type|status|use|used|expiration|month|year|language|modified|created|flags)(_|$)", re.I)
# A number or a real in a column that only matched by name is kept when the name says it describes the value.
NUMERIC_METADATA = re.compile(r"(^|_)(type|date|dates|count|length|time|times|timestamp|changed|used|issues|id|flags|status|size)(_|$)", re.I)
SQLITE_MAGIC = b"SQLite format 3\x00"


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


# ---- URL secrets: one design in browser_history, utf16_urls and esedb_query (a test holds the three copies identical)
#
# A URL can carry a session token, an API key or a password in its query string, its fragment or its user-info. Every URL in an
# answer has those values replaced by a marker that holds only their length ("[withheld: 12 characters]"), and the answer says how
# many were withheld, of what kind and where. The text is written whole only when the caller asks (write_url_secrets: true), only in
# a job (JOB_ID and OUT), to a file of mode 0600 that is created first and never replaced. NOT covered: a secret in a URL's path or
# title, a URL whose scheme this does not see, and a secret in free text.
import urllib.parse


class SecretValuesRefused(Exception):
    pass


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it (the secret-safe pattern of docs/packs.md)."""

    def __init__(self, enabled, tool, flag, name):
        self.enabled = enabled
        self.tool = tool
        self.flag = flag
        self.written = 0
        self._fh = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise SecretValuesRefused(
                "%s is refused outside a job: a value written here would be an ordinary file, not a sealed secret output. "
                "Run this as job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, tool)
            )
        path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        # Created now, before anything is read: a file or a link already at that name is refused by name at once (O_EXCL does
        # not follow a link, a dangling one included). With nothing found it stays an empty file, mode 0600.
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if self._fh is None:
            return
        text = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=True)
        self._fh.write(text + "\n")
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self, format_note):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": format_note if self.enabled else None,
        }


URL_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.\-]{1,15}://[^\s\"'<>\\^`{|}\x00-\x1f]+")
SECRET_SUBSTRINGS = ("token", "secret", "passw", "pwd", "auth", "bearer", "session", "signature", "credential", "assertion",
                     "jwt", "csrf", "xsrf", "ticket", "apikey", "accesskey")
SECRET_WORDS = {"sig", "sid", "key", "code", "pass", "otp", "sas", "saml", "hmac"}


def secret_parameter(name):
    """A query or fragment parameter whose name says its value is a credential: by a whole word (key, sig, code) or a substring (token)."""
    lowered = urllib.parse.unquote(name).lower()
    if any(s in lowered for s in SECRET_SUBSTRINGS):
        return True
    return any(w.lower() in SECRET_WORDS for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", urllib.parse.unquote(name)))


def url_marker(value):
    return "[withheld: %d characters]" % len(value)


def mask_parameters(text, kind, found, url):
    parts = re.split(r"([&;])", text)
    for i, part in enumerate(parts):
        if "=" not in part or part in ("&", ";"):
            continue
        key, value = part.split("=", 1)
        if value and secret_parameter(key):
            found.append((kind, key, value, url))
            parts[i] = key + "=" + url_marker(value)
    return "".join(parts)


def mask_url(url):
    """The URL with its secrets replaced by markers, and what was withheld: [(kind, parameter, value, url)]."""
    found = []
    start = url.index("://") + 3
    rest = url[start:]
    boundary = re.search(r"[/?#]", rest)
    cut = boundary.start() if boundary else len(rest)
    authority, tail = rest[:cut], rest[cut:]
    if "@" in authority:
        userinfo, host = authority.rsplit("@", 1)
        if ":" in userinfo:
            user, password = userinfo.split(":", 1)
            if password:
                found.append(("userinfo_password", None, password, url))
                userinfo = user + ":" + url_marker(password)
        elif len(userinfo) >= 16 and re.fullmatch(r"[A-Za-z0-9_.~%\-]+", userinfo):
            found.append(("userinfo_token", None, userinfo, url))
            userinfo = url_marker(userinfo)
        authority = userinfo + "@" + host
    before_hash, hash_mark, fragment = tail.partition("#")
    path, query_mark, query = before_hash.partition("?")
    if query:
        query = mask_parameters(query, "query_parameter", found, url)
    if "=" in fragment:
        fragment = mask_parameters(fragment, "fragment_parameter", found, url)
    return url[:start] + authority + path + query_mark + query + hash_mark + fragment, found


def mask_text(text):
    """`text` with the secrets of every URL in it withheld, and what was withheld."""
    if "://" not in text:
        return text, []
    found = []

    def one(match):
        masked, withheld = mask_url(match.group(0))
        found.extend(withheld)
        return masked

    return URL_RE.sub(one, text), found


class UrlSecrets:
    """Counts and locates what mask_text withheld; the values themselves go only to `values` (a SecretValues)."""

    def __init__(self, values, tool, key, limit):
        self.values = values
        self.count = 0
        self.by_kind = {}
        self.by_parameter = {}
        self.locators = LosslessPage(tool + "-url-secrets", key, limit)

    def mask(self, text, where):
        masked, found = mask_text(text)
        for kind, parameter, value, url in found:
            self.count += 1
            finding_id = "U%06d" % self.count
            self.by_kind[kind] = self.by_kind.get(kind, 0) + 1
            if parameter is not None:
                self.by_parameter[parameter] = self.by_parameter.get(parameter, 0) + 1
            self.locators.add({"finding_id": finding_id, "kind": kind, "parameter": parameter, "length": len(value), **where})
            self.values.add(finding_id, {"kind": kind, "parameter": parameter, **where, "url": url}, value)
        return masked

    def summary(self):
        page = self.locators.finish()
        return {
            "count": self.count,
            "by_kind": self.by_kind,
            "by_parameter": self.by_parameter,
            "locators": self.locators.page,
            "locators_page": page,
            "marker": "a withheld value is replaced by [withheld: N characters] (N is its length in the URL's own text); "
                      "where it was, its kind and its length are in locators; the value is not in this answer",
            "not_covered": "a secret in a URL's path, in a title, in free text, or in a URL whose scheme is not followed by ://",
        }
# ---- end of URL secrets


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


# The authorizer actions a read needs: SELECT, READ (a column), FUNCTION, RECURSIVE (a recursive
# WITH) and the pragmas that only report. Everything else (INSERT, UPDATE, DELETE, CREATE, DROP,
# ALTER, ATTACH, DETACH, TRANSACTION, SAVEPOINT, ...) is denied.
SQLITE_OK, SQLITE_DENY = 0, 1
A_SELECT, A_READ, A_PRAGMA, A_FUNCTION, A_RECURSIVE = 21, 20, 19, 31, 33
REPORTING_PRAGMAS = {
    "table_info", "table_xinfo", "table_list", "index_list", "index_info", "index_xinfo", "foreign_key_list",
    "database_list", "collation_list", "compile_options", "function_list", "module_list", "pragma_list",
    "schema_version", "user_version", "page_count", "page_size", "freelist_count", "encoding", "journal_mode",
    "integrity_check", "quick_check", "data_version", "application_id",
}
PRAGMAS_WITH_ARGUMENT = {"table_info", "table_xinfo", "index_list", "index_info", "index_xinfo", "foreign_key_list", "integrity_check", "quick_check"}


def read_only_authorizer(action, arg1, arg2, dbname, source):
    if action in (A_SELECT, A_READ, A_FUNCTION, A_RECURSIVE):
        return SQLITE_OK
    if action == A_PRAGMA:
        name = (arg1 or "").lower()
        if name in REPORTING_PRAGMAS and (arg2 is None or name in PRAGMAS_WITH_ARGUMENT):
            return SQLITE_OK
    return SQLITE_DENY


def quote(name):
    return '"' + str(name).replace('"', '""') + '"'


def words(name):
    return {w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", name)}


def sensitive_rule(table, name):
    """Why a column is withheld, or None: `named` (the credential column of a known store), `name` (its
    name says it holds a credential, a card, an IBAN or an SSN) or `table` (its table is about cards or IBANs)."""
    if (table.lower(), name.lower()) in SENSITIVE_COLUMNS:
        return "named"
    if SENSITIVE_NAME.search(name) or CARD_WORDS & words(name):
        return "name"
    if CARD_WORDS & words(table) and not METADATA_COLUMN.search(name):
        return "table"
    return None


def is_card_number(value):
    """1 for a text that is wholly a card number: 13 to 19 digits, spaces or hyphens between groups, passing the Luhn check."""
    if not isinstance(value, str):
        return 0
    text = value.strip()
    if not re.fullmatch(r"[0-9]+(?:[ -][0-9]+)*", text):
        return 0
    digits = re.sub(r"[ -]", "", text)
    if not 13 <= len(digits) <= 19:
        return 0
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return 1 if total % 10 == 0 else 0


def withhold_sensitive(conn):
    """Replace, in the disposable copy and before any query runs, every cell of a sensitive column by a
    marker that holds only its length. Returns (what was withheld, the triggers dropped). If a column
    cannot be withheld the run stops: nothing is queried."""
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        conn.execute("PRAGMA trusted_schema=OFF")
    except sqlite3.Error:
        pass
    # A trigger on the copy runs when a cell is replaced: `AFTER UPDATE OF password_value` could copy the old value
    # to a table nothing withholds. Every trigger goes before the first UPDATE.
    dropped = [name for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'").fetchall()]
    for name in dropped:
        conn.execute("DROP TRIGGER %s" % quote(name))
    try:
        conn.create_function("is_card_number", 1, is_card_number, deterministic=True)
    except (sqlite3.Error, TypeError):
        conn.create_function("is_card_number", 1, is_card_number)
    withheld = []
    tables = conn.execute("SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").fetchall()
    for table, ddl in tables:
        qt = quote(table)
        for col in conn.execute("PRAGMA table_xinfo(%s)" % qt).fetchall():
            name, declared, hidden = col[1], (col[2] or ""), col[6]
            if hidden:
                continue
            q = quote(name)
            rule = sensitive_rule(table, name)
            length = "CASE typeof(%s) WHEN 'blob' THEN length(%s) ELSE length(CAST(%s AS TEXT)) END" % (q, q, q)
            if rule is None:
                # Not a credential column: only a text cell that is wholly a card number goes (`autofill.value`).
                # A column declared INTEGER, REAL or NUMERIC holds no such text.
                if re.search(r"INT|REAL|FLOA|DOUB|NUM|DEC|BOOL|DATE|TIME", declared, re.I):
                    continue
                cursor = conn.execute(
                    "UPDATE %s SET %s = '[withheld: ' || length(%s) || ' characters]' "
                    "WHERE typeof(%s) = 'text' AND length(%s) BETWEEN 13 AND 23 AND is_card_number(%s)" % (qt, q, q, q, q, q))
                if cursor.rowcount:
                    withheld.append({"table": table, "column": name, "rule": "luhn", "cells_withheld": cursor.rowcount,
                                     "cell_types": {"text": cursor.rowcount}, "units": "characters (text)", "total_length": None})
                continue
            numbers = not (rule == "name" and NUMERIC_METADATA.search(name))
            types = "'text', 'blob', 'integer', 'real'" if numbers else "'text', 'blob'"
            cells, total = conn.execute(
                "SELECT count(*), coalesce(sum(%s), 0) FROM %s WHERE typeof(%s) IN (%s)" % (length, qt, q, types)).fetchone()
            kinds = dict(conn.execute("SELECT typeof(%s), count(*) FROM %s WHERE typeof(%s) IN (%s) GROUP BY 1" % (q, qt, q, types)).fetchall())
            replaced_with = "a marker holding only the length"
            if cells:
                marker = "'[withheld: ' || (%s) || ' ' || (CASE typeof(%s) WHEN 'blob' THEN 'bytes' ELSE 'characters' END) || ']'" % (length, q)
                try:
                    conn.execute("UPDATE %s SET %s = %s WHERE typeof(%s) IN (%s)" % (qt, q, marker, q, types))
                except sqlite3.IntegrityError:
                    # A STRICT column that takes no text: the cell is emptied instead.
                    conn.execute("UPDATE %s SET %s = NULL WHERE typeof(%s) IN (%s)" % (qt, q, q, types))
                    replaced_with = "NULL (the column does not take text)"
            withheld.append({"table": table, "column": name, "rule": rule, "cells_withheld": cells, "cell_types": kinds,
                             "units": "bytes (blob), characters (text) or characters of the number", "total_length": total,
                             "replaced_with": replaced_with})
    conn.commit()
    return withheld, dropped


def scratch_parent():
    """Where the disposable copy lives: the job's $OUT, else the agent's own directory, else the system's."""
    out, job = os.environ.get("OUT"), os.environ.get("JOB_ID")
    if job and out:
        base = out
    else:
        base = os.path.join("work", re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"))
    try:
        os.makedirs(base, exist_ok=True)
        return base
    except OSError:
        return None


def jsonable(value):
    if isinstance(value, (bytes, bytearray)):
        return {"blob_hex": bytes(value).hex(), "length": len(value)}
    return value


# ---- The sidecars, read by their formats (https://www.sqlite.org/fileformat2.html: the database header, "Write-Ahead Log",
# "WAL file format", "Checksum Algorithm", and "Rollback Journal Format"). Nothing in a WAL or a journal names the database it
# was written for; what can be compared is compared, and what cannot is said.
WAL_MAGICS = (0x377F0682, 0x377F0683)
JOURNAL_MAGIC = bytes.fromhex("d9d505f920a163d7")
INSPECT_BYTES = 64 * 1024 * 1024


def database_header(head):
    """The fields of the database header the sidecar checks use, or None when `head` is not one."""
    if len(head) < 100 or head[:16] != SQLITE_MAGIC:
        return None
    page_size = struct.unpack_from(">H", head, 16)[0]
    return {
        "page_size": 65536 if page_size == 1 else page_size,
        "write_version": head[18],
        "read_version": head[19],
        "schema_cookie": struct.unpack_from(">I", head, 40)[0],
        "text_encoding": struct.unpack_from(">I", head, 56)[0],
    }


def wal_checksum(data, big_endian, s0, s1):
    """The WAL checksum: 32-bit words of `data` taken in pairs, in the byte order the magic number names."""
    import array
    words_ = array.array("I")
    words_.frombytes(data[:len(data) - len(data) % 8])
    if (sys.byteorder == "big") != big_endian:
        words_.byteswap()
    for i in range(0, len(words_), 2):
        s0 = (s0 + words_[i] + s1) & 0xFFFFFFFF
        s1 = (s1 + words_[i + 1] + s0) & 0xFFFFFFFF
    return s0, s1


def inspect_wal(path, db):
    """Read the WAL's own header and frames: what it says about itself, and what disagrees with the database."""
    size = os.path.getsize(path)
    report = {"bytes": size, "header_valid": False}
    contradictions = []
    with open(path, "rb") as fh:
        head = fh.read(32)
        if len(head) < 32:
            report["problem"] = "shorter than the 32-byte WAL header"
            return report, contradictions
        magic, version, page_size, checkpoint_sequence, salt1, salt2, c1, c2 = struct.unpack(">8I", head)
        big_endian = bool(magic & 1)
        checksum = wal_checksum(head[:24], big_endian, 0, 0) if magic in WAL_MAGICS else None
        report.update({
            "magic": "0x%08x" % magic, "format_version": version, "page_size": page_size, "checkpoint_sequence": checkpoint_sequence,
            "salt_1": salt1, "salt_2": salt2,
            "header_checksum_ok": checksum == (c1, c2),
        })
        sane = magic in WAL_MAGICS and version == 3007000 and 512 <= page_size <= 65536 and page_size & (page_size - 1) == 0
        report["header_valid"] = bool(sane and checksum == (c1, c2))
        if not report["header_valid"]:
            report["problem"] = "the WAL header is not a valid one (magic, version 3007000, a power-of-two page size, its checksum)"
            return report, contradictions
        frame_size = 24 + page_size
        in_file = (size - 32) // frame_size
        report.update({"frames_in_file": in_file, "trailing_bytes": (size - 32) % frame_size})
        s0, s1 = c1, c2
        valid = committed = commits = 0
        committed_dbsize = None
        page1_pending = page1_committed = None
        stop = "end of file" if (size - 32) % frame_size == 0 else "a frame cut short by the end of the file"
        inspected = 0
        for index in range(in_file):
            if inspected + frame_size > INSPECT_BYTES:
                stop = "inspection limit (%d bytes); SQLite reads the rest" % INSPECT_BYTES
                break
            frame = fh.read(frame_size)
            inspected += frame_size
            pgno, dbsize, fs1, fs2, fc1, fc2 = struct.unpack(">6I", frame[:24])
            if (fs1, fs2) != (salt1, salt2):
                stop = "frame %d carries salts that are not the WAL header's (a frame left from before the log was restarted, or another log's)" % (index + 1)
                break
            s0, s1 = wal_checksum(frame[:8], big_endian, s0, s1)
            s0, s1 = wal_checksum(frame[24:], big_endian, s0, s1)
            if (s0, s1) != (fc1, fc2):
                stop = "frame %d fails the cumulative checksum" % (index + 1)
                break
            valid += 1
            if pgno == 1:
                page1_pending = frame[24:24 + 100]
            if dbsize:
                commits += 1
                committed = valid
                committed_dbsize = dbsize
                page1_committed = page1_pending
        complete = not stop.startswith("inspection limit")
        report.update({"frames_valid": valid, "frames_committed": committed, "commit_frames": commits,
                       "frames_valid_after_last_commit": valid - committed,
                       "stopped_because": stop, "database_pages_after_last_commit": committed_dbsize, "inspected_bytes": inspected,
                       "inspection_complete": complete})
    checks = {"page_size": {"wal": page_size, "database": db["page_size"], "agree": page_size == db["page_size"]}}
    if page_size != db["page_size"]:
        contradictions.append("the log's page size is %d and the database's is %d" % (page_size, db["page_size"]))
    if page1_committed is not None:
        wal_head = database_header(page1_committed)
        if wal_head is not None:
            if db["text_encoding"] == 0:
                # The encoding is 0 until the first schema is written: a database whose content is all in the log has not got one yet.
                checks["text_encoding"] = {"wal": wal_head["text_encoding"], "database": 0, "compared": False,
                                           "why": "the database's header holds no encoding yet (its schema is in the log)"}
            else:
                checks["text_encoding"] = {"wal": wal_head["text_encoding"], "database": db["text_encoding"], "agree": wal_head["text_encoding"] == db["text_encoding"]}
            checks["schema_cookie"] = {"wal": wal_head["schema_cookie"], "database": db["schema_cookie"], "wal_not_older": wal_head["schema_cookie"] >= db["schema_cookie"]}
            if db["text_encoding"] != 0 and wal_head["text_encoding"] != db["text_encoding"]:
                contradictions.append("the text encoding of the log's committed page 1 is %d and the database's is %d" % (wal_head["text_encoding"], db["text_encoding"]))
            if wal_head["schema_cookie"] < db["schema_cookie"]:
                contradictions.append("the log's last committed page 1 has schema cookie %d, older than the database's %d (it only grows)" % (wal_head["schema_cookie"], db["schema_cookie"]))
    else:
        checks["page_1"] = "no committed frame holds page 1, so the text encoding and the schema cookie were not compared"
    report["checks"] = checks
    return report, contradictions


def inspect_journal(path, db):
    """The rollback journal's own header: the magic and the page size."""
    with open(path, "rb") as fh:
        head = fh.read(28)
    report = {"bytes": os.path.getsize(path)}
    if len(head) < 28 or head[:8] != JOURNAL_MAGIC:
        # SQLite treats a journal with a zeroed or unrecognised header as not hot.
        report["header"] = "zeroed" if not any(head[:8]) else "not a journal header"
        report["hot_journal"] = False
        return report, []
    report["hot_journal"] = True
    page_size = struct.unpack_from(">I", head, 24)[0]
    report["page_size"] = page_size
    report["records"] = struct.unpack_from(">I", head, 8)[0]
    contradictions = []
    if page_size != db["page_size"]:
        contradictions.append("the journal's page size is %d and the database's is %d" % (page_size, db["page_size"]))
    return report, contradictions


def copy_private(source, destination):
    """A copy of `source` whose mode is the owner's alone: the evidence may be read-only (0444), and the copy must be written."""
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o600)


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
    write_url_secrets = args.get("write_url_secrets", False)
    if not isinstance(write_url_secrets, bool):
        fail("write_url_secrets must be true or false")
    query_note = None
    if sql is None:
        if query in OLD_NAMES:
            query_note = ("%s is the old name of %s: it answers one row per URL (a visit count and the last visit), "
                          "never one row per visit; use %s for visits" % (
                              query, OLD_NAMES[query], "chrome_visits" if query.startswith("chrome") else "firefox_visits"))
            query = OLD_NAMES[query]
        if query not in QUERIES:
            fail("unknown query", query=query, known=sorted(QUERIES) + sorted(OLD_NAMES))
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
    page_size = min(limit, 20000)

    try:
        values = SecretValues(write_url_secrets, "browser_history", "write_url_secrets", "browser_history-url-secrets.jsonl")
    except SecretValuesRefused as exc:
        fail(str(exc))
    url_secrets = UrlSecrets(values, "browser_history", [path, sql], page_size)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))   # so the copy below is removed when the harness stops us
    try:
        scratch = tempfile.mkdtemp(prefix=".browser-scratch-", dir=scratch_parent())
    except OSError as exc:
        values.close()
        fail("the scratch directory for the copy could not be created: nothing was read", reason=describe(exc))
    try:
        copy = os.path.join(scratch, os.path.basename(path))
        try:
            copy_private(path, copy)
            with open(copy, "rb") as fh:
                head = fh.read(100)
        except OSError as exc:
            fail("the database could not be copied for reading: nothing was read", path=path, reason=describe(exc))
        sidecars, not_copied = [], []
        wal_bytes = 0
        wal_seen = False
        wal_report = journal_report = wal_refused = journal_refused = None
        db = database_header(head)
        for suffix in ("-wal", "-shm", "-journal"):
            beside = path + suffix
            if not os.path.isfile(beside):
                continue
            name = os.path.basename(beside)
            try:
                if suffix == "-shm":
                    not_copied.append({"file": name, "why": "the wal-index is a derived index of the log: SQLite rebuilds it from the log, and one from another state could make it read the wrong frames"})
                    continue
                if suffix == "-wal":
                    wal_seen = True
                    wal_bytes = os.path.getsize(beside)
                    if db is None:
                        not_copied.append({"file": name, "why": "the database has no SQLite header, so nothing could be compared with the log"})
                        continue
                    wal_report, wal_contradictions = inspect_wal(beside, db)
                    if not wal_report["header_valid"]:
                        not_copied.append({"file": name, "why": wal_report.get("problem", "not a valid WAL header"), "refused": False})
                        continue
                    if wal_contradictions:
                        wal_refused = {"file": name, "contradictions": wal_contradictions,
                                       "meaning": "the log was not copied and no frame of it was applied; the database is read as it was acquired"}
                        not_copied.append({"file": name, "why": "; ".join(wal_contradictions), "refused": True})
                        continue
                else:
                    if db is None:
                        not_copied.append({"file": name, "why": "the database has no SQLite header, so nothing could be compared with the journal"})
                        continue
                    journal_report, journal_contradictions = inspect_journal(beside, db)
                    if journal_contradictions:
                        journal_refused = {"file": name, "contradictions": journal_contradictions,
                                           "meaning": "the journal was not copied and no page of it was rolled back"}
                        not_copied.append({"file": name, "why": "; ".join(journal_contradictions), "refused": True})
                        continue
                copy_private(beside, copy + suffix)
                sidecars.append(name)
            except OSError as exc:
                fail("a sidecar could not be read or copied: nothing was read", file=name, reason=describe(exc))
        declares_wal = db is not None and db["write_version"] == 2 and db["read_version"] == 2

        # Read-write on the *copy*, so SQLite replays and checkpoints the WAL.
        try:
            conn = sqlite3.connect(copy)
        except sqlite3.Error as exc:
            fail("SQLite could not open the copy; nothing was queried", path=path, reason=str(exc))
        conn.text_factory = lambda b: b.decode("utf-8", errors="backslashreplace")
        results = []
        try:
            try:
                checkpoint = conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
                withheld, triggers_dropped = withhold_sensitive(conn)
                conn.execute("PRAGMA query_only=ON")
            except sqlite3.DatabaseError as exc:
                fail("this is not a SQLite database SQLite can read, or a sensitive column could not be withheld; nothing was queried",
                     path=path, reason=str(exc), sqlite_header=head[:16] == SQLITE_MAGIC, size=os.path.getsize(path))
            conn.set_authorizer(read_only_authorizer)
            wal = {"busy": checkpoint[0], "log_frames": checkpoint[1], "checkpointed_frames": checkpoint[2]}
            for statement_index, s in enumerate(stmts):
                try:
                    cur = conn.execute(s)
                    columns = [d[0] for d in (cur.description or [])]
                    # Two result columns of one name (`SELECT a.id, b.id`) would overwrite each other in a
                    # row; the later ones are numbered and said so.
                    names, seen = [], {}
                    for c in columns:
                        seen[c] = seen.get(c, 0) + 1
                        names.append(c if seen[c] == 1 else "%s_%d" % (c, seen[c]))
                    page = LosslessPage(
                        "browser_history",
                        [path, s, statement_index],
                        page_size,
                    )
                    row_number = 0
                    for row in cur:
                        row_number += 1
                        cells = {}
                        for n, v in zip(names, row):
                            if isinstance(v, str):
                                v = url_secrets.mask(v, {"statement": statement_index, "row": row_number, "column": n})
                            cells[n] = jsonable(v)
                        page.add(cells)
                    kept = page.finish()
                    if names != columns:
                        columns = names
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

        out = {"path": path, "parser": PARSER, "sqlite_version": sqlite3.sqlite_version, "query": None if args.get("sql") else query}
        if query_note:
            out["query_note"] = query_note
        # One statement answers as it always has; several answer each in turn.
        out.update({k: v for k, v in results[0].items() if k != "sql"} if len(results) == 1 else {"results": results})
        frames = wal["checkpointed_frames"]
        out.update({
            "sidecars_copied": sidecars,
            "sidecars_not_copied": not_copied,
            "wal_present": wal_seen and wal_bytes > 0,
            "wal_bytes": wal_bytes,
            "database_declares_wal": declares_wal,
            "wal_checkpoint": wal,
            "wal_frames_replayed": frames if frames and frames > 0 else 0,
            "wal_inspection": wal_report,
            "wal_refused": wal_refused,
            "journal_inspection": journal_report,
            "journal_refused": journal_refused,
            "wal_note": "wal_present says a -wal file was beside the database; wal_frames_replayed is the number of valid frames SQLite "
                        "found in the copy of it and checkpointed into the copy (0 when the log is empty, damaged, or was not copied). It "
                        "does not say which transactions those frames held.",
            "wal_not_established": "no field of a WAL or a journal names the database it was written for, so a log from another database "
                                   "with the same page size, encoding and a schema cookie that is not older cannot be told from this one; "
                                   "wal_inspection.checks says what was compared (page size; text encoding and schema cookie from the last "
                                   "committed page 1, where there is one), and a frame count is not proof of lineage",
            "sensitive_columns_withheld": withheld,
            "triggers_dropped": triggers_dropped,
            "url_secrets_withheld": url_secrets.summary(),
            "secret_values": values.summary("JSON Lines, mode 0600: finding_id, kind, parameter, statement, row, column, url (the whole text), value (the secret)"),
            "read_only": "the statement must start with SELECT, WITH or PRAGMA, and the copy is opened with an authorizer that denies anything else",
        })
        values.close()
        print(json.dumps(out, indent=2, default=str))
    finally:
        values.close()
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    main()
