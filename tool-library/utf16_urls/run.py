#!/usr/bin/env python3
"""String candidates for URLs, `file:` and `Visited:` entries and 192.168.x.x addresses in a file.

This is a STRING SCANNER, not a browser parser. It says where a URL-shaped or history-shaped run of
characters is in the bytes of a file, in two encodings:

  ascii     `http://` or `https://` followed by at least six URL characters, to the first byte that is not
            one. No length is cut off: a URL of any length is returned whole.
  utf16le   a run of at least eight UTF-16LE characters that begins with a printable ASCII character
            (its second byte 0, which also fixes the run's alignment) and contains `http`, `file:`,
            `visited:` or `192.168`. After that first character the run goes on through printable
            ASCII, Latin-1 and the letters of Latin Extended, Greek, Cyrillic, Hebrew, Arabic, Indic and
            Thai (not CJK: its code units are pairs of ASCII letters), so `https://örnek.test/` is one
            candidate; a NUL, a control character, a surrogate or any other code unit ends it.
            The run is everything printable around the anchor, not a parsed URL.

Every occurrence is kept, with its byte offset and its encoding: an offset is where the run starts, and
the same text twice is two candidates. A `groups` view lists each distinct text once with its occurrence
count and first offset (bounded: past `max_distinct` distinct texts the view stops growing and says so; every
occurrence is still in the candidates). A string is a candidate: nothing here says it was visited, typed,
downloaded or opened by anyone.

SENSITIVE OUTPUT. A URL can carry a session token or a password in its query string, its fragment or its
user-info. Every candidate's text is returned with those values replaced by a marker that holds only
their length, `url_secrets_withheld` says how many, of what kind and at which offset, and `contains` is
matched against the text as returned (so it cannot be used to test a guess at a withheld value). The text
is written whole only with `write_url_secrets: true`, in a job run with secret_output: true, to a file under
$OUT of mode 0600; the request is refused anywhere else. A secret in a path or in free text is not found.

The file is read in windows of `chunk` bytes with a carry, never whole, so a match that straddles a window
is found once. A run that touches the end of a window and is longer than the carry is cut there and goes on in
the next window as a piece (`continued: true` on every piece but the last), so the memory is bounded and no
character is lost.
"""
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

PARSER = "utf16_urls/3"
DEFAULT_CHUNK = 8 * 1024 * 1024
CARRY = 64 * 1024
URL_CHARS = rb"[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]"
ASCII_START = re.compile(rb"https?://" + URL_CHARS + rb"{6,}")
ASCII_CONT = re.compile(URL_CHARS + rb"+")
# A UTF-16LE code unit that is printable: ASCII or Latin-1 (second byte 0), or a letter of a script whose block number is a control
# character in ASCII (Latin Extended, Greek, Cyrillic, Hebrew, Arabic, Indic, Thai, Latin Extended Additional), so 8-bit text next to
# a run is not read as such letters. CJK is left out on purpose: its code units are ASCII letter pairs. A run must BEGIN with an ASCII
# unit, which fixes its alignment: a pattern that could begin anywhere would read ASCII text shifted by one byte as such letters.
UTF16_UNIT = rb"(?:[\x20-\x7e\xa0-\xff]\x00|[\x00-\xff][\x01-\x06\x09\x0e\x1e])"
UTF16_START = re.compile(rb"[\x20-\x7e]\x00" + UTF16_UNIT + rb"{7,}")
UTF16_CONT = re.compile(UTF16_UNIT + rb"+")
UTF16_ANCHORS = ("http", "file:", "visited:", "192.168")


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


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


class Spec:
    """One encoding's scanner state: where its first undecided byte is, and whether a run was cut at a window's end."""

    def __init__(self, name, start, cont, width):
        self.name = name
        self.start = start
        self.cont = cont
        self.width = width            # bytes per character
        self.done_to = 0              # absolute offset: everything before it is decided
        self.continuing = False
        self.run_start = None
        self.anchor_ok = False


def window(spec, buf, base, eof, emit):
    """Decide the candidates of `spec` in buf (absolute offset base)."""
    n = len(buf)
    pos = max(spec.done_to - base, 0)
    if spec.continuing and spec.done_to >= base:
        m = spec.cont.match(buf, pos)
        if m and m.end() > pos:
            more = m.end() >= n - (spec.width - 1) and not eof
            emit(spec, base + pos, buf[pos:m.end()], more, True)
            spec.done_to = base + m.end()
            pos = m.end()
            spec.continuing = more
            if more:
                return
        else:
            spec.continuing = False
    while True:
        m = spec.start.search(buf, pos)
        if not m:
            break
        touches = m.end() >= n - (spec.width - 1) and not eof     # a half character at the end is part of the run
        if touches:
            if m.start() >= n - CARRY:
                break                      # undecided: the next window starts at the carry and sees all of it
            emit(spec, base + m.start(), buf[m.start():m.end()], True, False)
            spec.continuing = True
            spec.done_to = base + m.end()
            return
        emit(spec, base + m.start(), buf[m.start():m.end()], False, False)
        spec.done_to = base + m.end()
        pos = m.end()


def main():
    try:
        d = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(d, dict):
        fail("the arguments must be a JSON object")
    path = d.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the file to scan")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    contains = d.get("contains") or ""
    if not isinstance(contains, str):
        fail("contains must be a string")
    contains = contains.lower()
    limit = d.get("limit", 200)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive integer", limit=d.get("limit"))
    chunk = d.get("chunk", DEFAULT_CHUNK)
    if isinstance(chunk, bool) or not isinstance(chunk, int) or not 2 * CARRY <= chunk <= 256 * 1024 * 1024:
        fail("chunk must be a whole number of bytes from %d to 268435456" % (2 * CARRY), chunk=d.get("chunk"))
    max_distinct = d.get("max_distinct", 100000)
    if isinstance(max_distinct, bool) or not isinstance(max_distinct, int) or max_distinct < 1:
        fail("max_distinct must be a positive integer", max_distinct=d.get("max_distinct"))
    write_url_secrets = d.get("write_url_secrets", False)
    if not isinstance(write_url_secrets, bool):
        fail("write_url_secrets must be true or false")
    try:
        values = SecretValues(write_url_secrets, "utf16_urls", "write_url_secrets", "utf16_urls-url-secrets.jsonl")
    except SecretValuesRefused as exc:
        fail(str(exc))
    url_secrets = UrlSecrets(values, "utf16_urls", [path, contains], limit)

    out = LosslessPage("utf16_urls", [path, contains], limit)
    groups = {}
    totals = {"ascii": 0, "utf16le": 0, "filtered_out": 0, "pieces": 0}
    state = {"groups_complete": True}

    def emit(spec, offset, raw, more, is_cont):
        text = raw.decode("ascii", "replace") if spec.width == 1 else raw.decode("utf-16-le", "replace")
        if spec.name == "utf16le":
            present = any(a in text.lower() for a in UTF16_ANCHORS)
            if not is_cont:
                spec.anchor_ok = present          # each run is judged on its own: a stale yes is not carried over
                if not present:
                    return
            elif not spec.anchor_ok:
                if not present:
                    return
                spec.anchor_ok = True
        if contains and contains not in mask_text(text)[0].lower():
            totals["filtered_out"] += 1
            return
        shown = url_secrets.mask(text, {"offset": offset, "encoding": spec.name})
        row = {"encoding": spec.name, "offset": offset, "length_bytes": len(raw), "text": shown}
        if more or is_cont:
            row["continued"] = bool(more)
            row["piece_of_a_longer_run"] = True
            totals["pieces"] += 1
        out.add(row)
        totals[spec.name] += 1
        key = (spec.name, text)
        g = groups.get(key)
        if g is not None:
            g[0] += 1
        elif len(groups) < max_distinct:
            groups[key] = [1, offset, shown]
        else:
            state["groups_complete"] = False

    ascii_spec = Spec("ascii", ASCII_START, ASCII_CONT, 1)
    utf16_spec = Spec("utf16le", UTF16_START, UTF16_CONT, 2)
    scanned = 0
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            carry = b""
            base = 0
            nxt = fh.read(chunk)
            while True:
                data, nxt = nxt, fh.read(chunk) if nxt else b""
                eof = not nxt
                buf = carry + data
                scanned += len(data)
                window(ascii_spec, buf, base, eof, emit)
                window(utf16_spec, buf, base, eof, emit)
                if eof:
                    break
                keep = min(CARRY, len(buf))
                base += len(buf) - keep
                carry = buf[len(buf) - keep:]
    except OSError as exc:
        values.close()
        fail("the file could not be read: nothing was reported as scanned beyond what is named here",
             path=path, status="failed", bytes_scanned=scanned, candidates_found_before=out.total, reason=describe(exc))

    page = out.finish()
    distinct = LosslessPage("utf16_urls-groups", [path, contains, "groups"], limit)
    for (enc, _text), (count, first, shown_text) in sorted(groups.items(), key=lambda kv: kv[1][1]):
        distinct.add({"text": shown_text, "encoding": enc, "occurrences": count, "first_offset": first})
    group_page = distinct.finish()
    answer = {
        "parser": PARSER,
        "status": "complete",
        "path": path,
        "file_bytes": size,
        "bytes_scanned": scanned,
        "candidates": out.page,
        "candidate_count": page["matched"],
        "by_encoding": {"ascii": totals["ascii"], "utf16le": totals["utf16le"]},
        "filtered_out_by_contains": totals["filtered_out"],
        "pieces": totals["pieces"],
        "groups": distinct.page,
        "distinct_count": group_page["matched"],
        "groups_complete": state["groups_complete"],
        "groups_page": group_page,
        "url_secrets_withheld": url_secrets.summary(),
        "secret_values": values.summary("JSON Lines, mode 0600: finding_id, kind, parameter, offset, encoding, url (the whole text), value (the secret)"),
        **page,
        "note": "These are string candidates: where a URL-shaped or history-shaped run of characters is in the bytes, not "
                "a parsed browser record. A string does not say it was visited, typed, downloaded or opened, or by whom. "
                "A UTF-16LE run begins at a printable ASCII character and goes on through printable ASCII, Latin-1 and the letters of Latin "
                "Extended, Greek, Cyrillic, Hebrew, Arabic, Indic and Thai; a run longer than the carry is judged piece by piece. The text of a candidate has the secrets of its URLs "
                "withheld (url_secrets_withheld).",
    }
    values.close()
    print(json.dumps(answer, ensure_ascii=False))


if __name__ == "__main__":
    main()
