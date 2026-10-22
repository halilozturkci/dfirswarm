#!/usr/bin/env python3
"""Copy a SQLite database with its write-ahead log, shared memory file and rollback journal into a new directory, and apply the WAL in the COPY.

A SQLite database on disk is a set: the main file, a -wal that may hold committed changes the main file does not yet have (and older
pages, and an incomplete transaction), a -shm (an index of the WAL, rebuilt from it) and a -journal (a rollback journal, hot when a
write was interrupted). This tool makes one consistent, hashed copy of the set and applies the WAL to a second copy, so that the state
SQLite itself would show can be queried (sqlite_query takes the result) while the evidence is never touched.

  * Nothing is written beside the evidence. Every file is read once, streamed through sha256 into <out_dir>/original/ under a new,
    exclusively created name (database.sqlite, database.sqlite-wal, -shm, -journal), 0600. The source's size and modification time are
    read before and after: a file that changed while it was copied is said (`changed_during_copy`), and so is the fact that the files of
    a live set are copied one after another, not at one instant.
  * The WAL is read from the COPY and checked against the format: the header (magic, version, page size, salts, its own checksum), then
    each frame's salts and its cumulative checksum, in the byte order the magic number gives. The answer says how many frames the file
    holds, how many are valid (salts match this generation and the checksum chain holds), the last commit among them (frames_committed),
    the valid frames after it that no commit covers (never applied), and the first frame that is not valid with the reason: an earlier
    generation's leftover (salt mismatch), a damaged or torn frame (checksum mismatch), a file that ends inside a frame.
  * The WAL is applied by SQLite itself, in a second copy (<out_dir>/applied/database.sqlite): the copy and its -wal are opened and
    checkpointed (PRAGMA wal_checkpoint); the -shm is not used, SQLite rebuilds it. The tool compares the frame count SQLite
    reports with its own reading of the WAL and says when they differ, and counts the pages of the main file the WAL changed. A WAL
    with no valid header or no committed frame is not applied, and the answer says why; `database` is then the copy of the main file.
  * A rollback journal is copied and reported (hot header or not) and is NOT rolled back: the copy of the main file may hold an
    interrupted write.
  * Not measured: deleted records, the freelist and unallocated pages are neither read nor recovered; a frame after the last commit is
    reported, not applied; whether a live set was consistent when copied is not established; and a database encrypted by an extension
    (SQLCipher) is not a SQLite file this tool can read (it is refused with the first bytes and their entropy).

Exit code 0 means the copy was made and the answer is whole about what it did (a WAL that could not be applied is a partial answer, exit 0,
status partial); 1 is a file that cannot be copied or is not SQLite, a refused argument or a place that cannot be written.
"""
import collections
import errno
import hashlib
import json
import math
import os
import re
import signal
import sqlite3
import struct
import sys
import threading
import time
import urllib.parse
from pathlib import Path

TOOL = {"name": "sqlite_snapshot", "version": 2}
CHUNK = 1 << 20
MAX_BYTES_DEFAULT = 8 * 1024 ** 3
MAX_BYTES_CEILING = 1024 ** 4
MAX_SECONDS_DEFAULT = 600
MAX_SECONDS_CEILING = 1700
MAGIC = b"SQLite format 3\x00"
WAL_MAGICS = (0x377F0682, 0x377F0683)
JOURNAL_MAGIC = bytes([0xD9, 0xD5, 0x05, 0xF9, 0x20, 0xA1, 0x63, 0xD7])
SUFFIXES = ("", "-wal", "-shm", "-journal")
NAME = "database.sqlite"

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


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def say(obj, code=0):
    print(json.dumps(obj, ensure_ascii=True))
    sys.stdout.flush()
    raise SystemExit(code)


def fail(message, **extra):
    say({"ok": False, "error": scrub(message), "tool": TOOL, **extra}, 1)


def whole(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s is a whole number from %d to %d" % (key, low, high), **{key: value})
    return value


def resolve_output(out):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself or
    anything under inputs/ is refused, and in a job so is anything outside $OUT, the one place a job writes."""
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("out_dir must stay inside the run directory", out_dir=scrub(str(out)))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("out_dir cannot be under inputs/", out_dir=scrub(str(out)))
    if in_job():
        job_out = Path(os.environ["OUT"]).resolve()
        if dest != job_out and job_out not in dest.parents:
            fail("in a job out_dir is a directory under $OUT, the one place a job writes", out_dir=scrub(str(out)), out=str(job_out),
                 hint="give {OUT}/<name>, or work/extracted/<your id>/<name>, which the harness maps there")
    return dest


def entropy(page):
    counts = collections.Counter(page)
    return -sum(c / len(page) * math.log2(c / len(page)) for c in counts.values())


def private_open(path, mode="wb"):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    return os.fdopen(fd, mode)


def write_json_atomic(path, obj):
    tmp = "%s.tmp.%d" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=True)
        fh.write("\n")
    os.replace(tmp, path)


# ---- the WAL, read from the copy -----------------------------------------------------------------------------------------

def wal_checksum(data, big_endian, s0=0, s1=0):
    """The SQLite WAL checksum over `data` (a multiple of 8 bytes), continuing from (s0, s1)."""
    words = struct.unpack((">" if big_endian else "<") + "%dI" % (len(data) // 4), data)
    for i in range(0, len(words), 2):
        s0 = (s0 + words[i] + s1) & 0xFFFFFFFF
        s1 = (s1 + words[i + 1] + s0) & 0xFFFFFFFF
    return s0, s1


def read_wal(path, db_page_size, deadline):
    """What the WAL file holds, from its header and its frames. Nothing here is applied; this is the reading the answer is checked against."""
    size = os.path.getsize(path)
    info = {"bytes": size}
    if size == 0:
        info.update(state="empty", valid_header=False, frames_in_file=0, frames_valid=0, frames_committed=0, frames_uncommitted_valid=0)
        return info
    if size < 32:
        info.update(state="shorter than its 32-byte header", valid_header=False, frames_in_file=0, frames_valid=0, frames_committed=0, frames_uncommitted_valid=0)
        return info
    with open(path, "rb") as fh:
        head = fh.read(32)
        magic, version, page, seq, salt1, salt2, ck1, ck2 = struct.unpack(">IIIIIIII", head)
        info.update(magic="%08x" % magic, format_version=version, page_size=page, checkpoint_sequence=seq, salt1="%08x" % salt1, salt2="%08x" % salt2)
        if magic not in WAL_MAGICS:
            info.update(state="not a WAL: bad magic %08x" % magic, valid_header=False, frames_in_file=0, frames_valid=0, frames_committed=0, frames_uncommitted_valid=0)
            return info
        big = bool(magic & 1)
        info["checksum_byte_order"] = "big-endian" if big else "little-endian"
        if version != 3007000:
            info.update(state="WAL format version %d, which is not 3007000: not read" % version, valid_header=False, frames_in_file=0, frames_valid=0,
                        frames_committed=0, frames_uncommitted_valid=0)
            return info
        if not 512 <= page <= 65536 or page & (page - 1):
            info.update(state="not a usable page size: %d" % page, valid_header=False, frames_in_file=0, frames_valid=0, frames_committed=0, frames_uncommitted_valid=0)
            return info
        s0, s1 = wal_checksum(head[:24], big)
        if (s0, s1) != (ck1, ck2):
            info.update(state="the header's own checksum does not match: SQLite ignores this WAL", valid_header=False, frames_in_file=0, frames_valid=0,
                        frames_committed=0, frames_uncommitted_valid=0)
            return info
        info["valid_header"] = True
        info["page_size_matches_database"] = (page == db_page_size) if db_page_size else None
        stride = 24 + page
        total, tail = divmod(size - 32, stride)
        info["frames_in_file"] = total
        info["trailing_partial_frame_bytes"] = tail
        valid = committed = 0
        commit_pages = None
        stop = None
        verified_all = True
        for i in range(total):
            if time.monotonic() > deadline:
                verified_all = False
                stop = {"frame": i + 1, "reason": "the time budget ended the check here: frames from this one on were not checked (SQLite still reads them when it applies the WAL)"}
                break
            frame = fh.read(stride)
            if len(frame) < stride:
                stop = {"frame": i + 1, "reason": "the file ends inside this frame"}
                break
            pgno, dbsize, f1, f2, c1, c2 = struct.unpack(">IIIIII", frame[:24])
            if f1 != salt1 or f2 != salt2:
                stop = {"frame": i + 1, "reason": "salt mismatch: a frame of an earlier generation of this WAL (left over after a checkpoint and restart), not part of the current one"}
                break
            if pgno == 0:
                stop = {"frame": i + 1, "reason": "page number 0"}
                break
            s0, s1 = wal_checksum(frame[:8], big, s0, s1)
            s0, s1 = wal_checksum(frame[24:], big, s0, s1)
            if (s0, s1) != (c1, c2):
                stop = {"frame": i + 1, "reason": "checksum mismatch: a damaged or torn frame; it and every frame after it are not valid"}
                break
            valid += 1
            if dbsize:
                committed = valid
                commit_pages = dbsize
        if stop is None and tail:
            stop = {"frame": total + 1, "reason": "the file ends inside this frame (%d of %d bytes)" % (tail, stride)}
        info.update(frames_valid=valid, frames_committed=committed, frames_uncommitted_valid=valid - committed,
                    database_pages_after_last_commit=commit_pages, checksums_verified=verified_all,
                    first_invalid_frame=stop, state=("%d valid frame(s), %d committed" % (valid, committed)) if valid else "no valid frame")
    return info


def journal_state(path):
    with open(path, "rb") as fh:
        head = fh.read(28)
    if head[:8] == JOURNAL_MAGIC:
        return "header present: a rollback journal that was not rolled back (a write was interrupted)"
    if not head.strip(b"\0"):
        return "empty or zeroed header: not a hot journal (a persistent or truncated one left behind)"
    return "a header that is not a rollback journal's; not understood"


# ---- the copy ------------------------------------------------------------------------------------------------------------

def copy_hashing(src, dst_path, deadline, limit_left):
    """Copy src to a new file at dst_path (exclusive, 0600), streamed through sha256. Returns (bytes, sha256)."""
    h = hashlib.sha256()
    n = 0
    with open(src, "rb") as fi, private_open(dst_path) as fo:
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("the time budget ended the copy after %d bytes" % n)
            block = fi.read(CHUNK)
            if not block:
                break
            n += len(block)
            if n > limit_left:
                raise OverflowError("the file grew past the byte budget while it was copied")
            h.update(block)
            fo.write(block)
        fo.flush()
        os.fsync(fo.fileno())
    return n, h.hexdigest()


def pages_changed(a, b, page):
    """How many pages differ between two files, and the page counts of each (streamed)."""
    changed = 0
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            x, y = fa.read(page), fb.read(page)
            if not x and not y:
                break
            if x != y:
                changed += 1
    return changed


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    db = args.get("db_path")
    if not isinstance(db, str) or not db or "\0" in db:
        fail("db_path is required: the SQLite database file (its -wal, -shm and -journal beside it are copied too)")
    try:
        db.encode("utf-8")
    except UnicodeEncodeError:
        fail("db_path holds a lone surrogate and cannot be written in an answer")
    unknown = sorted(set(args) - {"db_path", "out_dir", "apply_wal", "max_bytes", "max_seconds", "quick_check"})
    if unknown:
        fail("unknown parameter: %s" % ", ".join(scrub(str(k)) for k in unknown))
    apply_wal = args.get("apply_wal", True)
    quick = args.get("quick_check", False)
    for key, val in (("apply_wal", apply_wal), ("quick_check", quick)):
        if not isinstance(val, bool):
            fail("%s is true or false" % key)
    max_bytes = whole(args, "max_bytes", MAX_BYTES_DEFAULT, 1, MAX_BYTES_CEILING)
    max_seconds = whole(args, "max_seconds", MAX_SECONDS_DEFAULT, 1, MAX_SECONDS_CEILING)
    if not os.path.exists(db):
        fail("database not found", db_path=scrub(db))
    if not os.path.isfile(db):
        fail("db_path is not a regular file", db_path=scrub(db))
    real = os.path.realpath(db)
    try:
        size = os.path.getsize(real)
        with open(real, "rb") as fh:
            first = fh.read(4096)
    except OSError as exc:
        fail("the database cannot be read: %s" % describe(exc), db_path=scrub(db))
    if size == 0:
        fail("the file is empty (0 bytes): it holds no database", db_path=scrub(db))
    if not first.startswith(MAGIC):
        e = entropy(first)
        fail("not a SQLite file: its first bytes are not the SQLite magic", db_path=scrub(db), header_hex=first[:16].hex(),
             first_page_entropy_bits_per_byte=round(e, 3),
             reading=("random-looking from the first byte, and not identified: an encrypted database (SQLCipher or an app's own) is one explanation, "
                      "compressed or otherwise encoded data another" if e > 7.5 else "another format: identify it from its header (file_type)"))
    if len(first) < 100:
        fail("the file is shorter than SQLite's 100-byte database header", db_path=scrub(db), bytes=size)
    page_size = struct.unpack(">H", first[16:18])[0]
    page_size = 65536 if page_size == 1 else page_size
    header = {"page_size": page_size, "write_version": first[18], "read_version": first[19], "wal_mode": first[18] == 2 or first[19] == 2,
              "page_count_in_header": struct.unpack(">I", first[28:32])[0], "file_change_counter": struct.unpack(">I", first[24:28])[0],
              "version_valid_for": struct.unpack(">I", first[92:96])[0], "text_encoding": {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}.get(struct.unpack(">I", first[56:60])[0], "unknown"),
              "sqlite_version_number": struct.unpack(">I", first[96:100])[0]}
    header["page_count_in_header_valid"] = header["file_change_counter"] == header["version_valid_for"] and header["page_count_in_header"] > 0
    header["pages_by_size"] = size // page_size if page_size else None

    os.umask(0o077)
    st0 = os.stat(real)
    digest = hashlib.sha256(("%s|%d|%d" % (real, size, st0.st_mtime_ns)).encode("utf-8", "surrogateescape")).hexdigest()[:12]
    if args.get("out_dir"):
        if not isinstance(args["out_dir"], str) or "\0" in args["out_dir"]:
            fail("out_dir is a directory path")
        dest = resolve_output(args["out_dir"])
    elif in_job():
        dest = resolve_output(os.path.join(os.environ["OUT"], "sqlite_snapshot-" + digest))
        k = 2
        while dest.exists():
            dest = resolve_output(os.path.join(os.environ["OUT"], "sqlite_snapshot-%s.%d" % (digest, k)))
            k += 1
    else:
        agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
        base = os.path.join("work", agent, "sqlite_snapshot-" + digest)
        dest = resolve_output(base)
        k = 2
        while dest.exists():
            dest = resolve_output("%s.%d" % (base, k))
            k += 1
    if dest.exists():
        fail("out_dir already exists: a snapshot never goes into a directory that is there. Give a new name", out_dir=scrub(str(dest)))
    sources = []
    total = 0
    for suffix in SUFFIXES:
        p = real + suffix
        if os.path.isfile(p) and not os.path.islink(p):      # a link beside the database is listed and not followed, as the entry says
            try:
                sz = os.path.getsize(p)
            except OSError as exc:
                fail("a file of the set cannot be read: %s" % describe(exc), db_path=scrub(db))
            sources.append((suffix, p, sz))
            total += sz
        elif os.path.lexists(p):
            sources.append((suffix, None, 0))
    if total > max_bytes:
        fail("the set is %d bytes, more than max_bytes %d: nothing was copied (raise max_bytes on purpose)" % (total, max_bytes), db_path=scrub(db), set_bytes=total,
             files={(s or "main"): sz for s, _p, sz in sources})
    try:
        dest.mkdir(parents=True, mode=0o700)
        (dest / "original").mkdir(mode=0o700)
        os.chmod(dest, 0o700)
    except OSError as exc:
        fail("the output directory cannot be made: %s" % describe(exc), out_dir=scrub(str(dest)))
    rel_dest = str(dest.relative_to(Path.cwd().resolve())) if Path.cwd().resolve() in dest.parents else str(dest)

    started = time.monotonic()
    deadline = started + max_seconds
    receipt = {
        "tool": TOOL, "status": "running", "ok": True,
        "source": {"db_path": scrub(db), "real_path": scrub(real) if real != os.path.abspath(db) else None, "bytes": size, "database_header": header,
                   "sqlite_library": sqlite3.sqlite_version, "python": sys.version.split()[0]},
        "snapshot_dir": rel_dest, "files": [], "wal": None, "applied": None, "database": None, "problems": [], "notes": [], "not_measured": (
            "deleted records, the freelist and unallocated pages are neither read nor recovered; a WAL frame after the last commit is reported, not applied; "
            "a rollback journal is not rolled back; whether a live set was consistent when its files were copied is not established; "
            "an extension-encrypted database is not read"),
        "set_copy_note": "the files were copied one after another, not at one instant: for a set taken from a running database, compare the sizes and times below with the acquisition record",
    }
    receipt_path = str(dest / "snapshot.json")

    def write_receipt():
        write_json_atomic(receipt_path, receipt)

    def on_signal(signum, _frame):
        receipt["status"] = "interrupted"
        receipt["problems"].append("stopped by signal %d; files named .partial are incomplete" % signum)
        try:
            write_receipt()
        except OSError:
            pass
        os._exit(128 + signum)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, on_signal)
    write_receipt()

    # 1. The copy of the set, hashed as it is read.
    left = max_bytes
    originals = {}
    for suffix, p, sz in sources:
        label = "database.sqlite" + suffix
        entry = {"name": label, "suffix": suffix or None, "source_name": scrub(cell(os.path.basename(real) + suffix))}
        if p is None:
            entry.update(present=True, copied=False, error="listed beside the database but not a regular file (a link or a directory): not followed")
            receipt["files"].append(entry)
            receipt["problems"].append("%s is not a regular file and was not copied" % label)
            continue
        before = os.stat(p)
        target = str(dest / "original" / label)
        partial = target + ".partial"
        try:
            n, sha = copy_hashing(p, partial, deadline, left)
        except (OSError, TimeoutError, OverflowError) as exc:
            try:
                os.unlink(partial)
            except OSError:
                pass
            receipt["status"] = "failed"
            receipt["ok"] = False
            receipt["error"] = "%s could not be copied: %s" % (label, describe(exc) if isinstance(exc, OSError) else scrub(str(exc)))
            write_receipt()
            say(dict(receipt), 1)
        os.rename(partial, target)
        left -= n
        after = os.stat(p)
        changed = (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns) or n != before.st_size
        entry.update(present=True, copied=True, path="original/" + label, bytes=n, sha256=sha, source_size_before=before.st_size, source_size_after=after.st_size,
                     source_mtime_ns_before=before.st_mtime_ns, source_mtime_ns_after=after.st_mtime_ns, changed_during_copy=changed)
        if changed:
            receipt["problems"].append("%s changed while it was copied (size or modification time differ before and after): the copy may mix two states" % label)
        receipt["files"].append(entry)
        originals[suffix] = target
    receipt["source"]["sha256"] = next((f["sha256"] for f in receipt["files"] if f["name"] == "database.sqlite"), None)
    present = {f["suffix"] or "" for f in receipt["files"] if f.get("copied")}
    receipt["sidecars_present"] = sorted(s for s in present if s)
    write_receipt()

    # 2. The WAL, as the format reads it.
    wal_info = None
    if "-wal" in originals:
        try:
            wal_info = read_wal(originals["-wal"], page_size, deadline)
        except (OSError, struct.error) as exc:
            wal_info = {"state": "the copy of the WAL could not be read: %s" % describe(exc), "valid_header": False, "frames_valid": 0, "frames_committed": 0}
            receipt["problems"].append(wal_info["state"])
        receipt["wal"] = wal_info
        bad = wal_info.get("first_invalid_frame") or {}
        reason = bad.get("reason", "")
        if reason.startswith(("checksum", "the file ends", "page number", "the time budget")):
            receipt["problems"].append("frame %d of the WAL: %s" % (bad["frame"], reason))
        elif reason.startswith("salt"):
            receipt["notes"].append("frame %d of the WAL: %s" % (bad["frame"], reason))
        if wal_info.get("frames_uncommitted_valid"):
            receipt["notes"].append("%d valid frame(s) after the last commit belong to a transaction that was not committed: reported, not applied" % wal_info["frames_uncommitted_valid"])
        if not wal_info.get("valid_header") and wal_info.get("bytes", 0) >= 32:
            receipt["problems"].append("the WAL is present (%d bytes) and cannot be read: %s" % (wal_info["bytes"], wal_info.get("state")))
        if wal_info.get("valid_header") and wal_info.get("page_size_matches_database") is False:
            receipt["problems"].append("the WAL's page size (%d) is not the database's (%d): SQLite does not apply it" % (wal_info["page_size"], page_size))
    if "-journal" in originals:
        receipt["rollback_journal"] = {"state": journal_state(originals["-journal"]), "applied": False,
                                       "note": "a rollback journal is copied and reported, never rolled back: the copy of the main file may hold an interrupted write"}
        if receipt["rollback_journal"]["state"].startswith("header present"):
            receipt["problems"].append("a hot rollback journal is beside the database and was not rolled back: the main file may hold an interrupted write")
    write_receipt()

    # 3. The WAL applied, by SQLite, to a second copy.
    database = "original/database.sqlite"
    can_apply = (apply_wal and wal_info is not None and wal_info.get("valid_header") and wal_info.get("frames_committed", 0) > 0
                 and wal_info.get("page_size_matches_database") is not False)
    grown = (wal_info or {}).get("database_pages_after_last_commit")
    if can_apply and grown and grown * page_size > max_bytes:
        # The last commit frame says how many pages the database has: a WAL from hostile input can say billions, and the checkpoint
        # would make a sparse file that large and then be hashed and compared. It is not applied.
        can_apply = False
        receipt["problems"].append("the last commit says the database is %d pages (%d bytes), more than max_bytes %d: the WAL was not applied" % (grown, grown * page_size, max_bytes))
    if not apply_wal:
        receipt["applied"] = {"applied": False, "why": "apply_wal was false: the copies are the set as it was"}
    elif wal_info is None:
        receipt["applied"] = {"applied": False, "why": "there is no -wal beside the database"}
    elif not can_apply:
        why = ("the WAL holds no committed frame that is valid" if wal_info.get("valid_header") else wal_info.get("state", "the WAL is not readable"))
        if wal_info.get("valid_header") and wal_info.get("frames_committed", 0) > 0:
            why = "the WAL was not applied (see problems)"
        receipt["applied"] = {"applied": False, "why": why}
    else:
        applied_dir = dest / "applied"
        applied_dir.mkdir(mode=0o700)
        work_db = str(applied_dir / "database.sqlite")
        try:
            copy_hashing(originals[""], work_db, deadline, max_bytes)
            copy_hashing(originals["-wal"], work_db + "-wal", deadline, max_bytes)
            conn = sqlite3.connect("file:%s?mode=rw" % urllib.parse.quote(work_db), uri=True)
            timer = threading.Timer(max(1.0, deadline - time.monotonic()), conn.interrupt)    # the time budget ends SQLite's work too
            timer.daemon = True
            timer.start()
            try:
                row = conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
                busy, log_frames, checkpointed = row
                mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
                qc = None
                if quick:
                    qc = [r[0] for r in conn.execute("PRAGMA quick_check(20)").fetchall()]
            finally:
                timer.cancel()
                conn.close()
            for extra in (work_db + "-wal", work_db + "-shm", work_db + "-journal"):
                if os.path.exists(extra):
                    if os.path.getsize(extra) == 0:
                        os.unlink(extra)
            leftover = [n for n in os.listdir(applied_dir) if n != "database.sqlite"]
            n_applied = os.path.getsize(work_db)
            if n_applied > max_bytes:
                raise OverflowError("the applied copy is %d bytes, more than max_bytes %d" % (n_applied, max_bytes))
            sha_applied = hashlib.sha256()
            with open(work_db, "rb") as fh:
                for block in iter(lambda: fh.read(CHUNK), b""):
                    sha_applied.update(block)
            changed_pages = pages_changed(originals[""], work_db, page_size)
            agree = log_frames == wal_info["frames_committed"]
            receipt["applied"] = {
                "applied": busy == 0 and checkpointed == log_frames, "by": "SQLite %s: PRAGMA wal_checkpoint on a copy of the main file and a copy of the -wal" % sqlite3.sqlite_version,
                "path": "applied/database.sqlite", "bytes": n_applied, "sha256": sha_applied.hexdigest(), "busy": busy,
                "frames_in_wal_by_sqlite": log_frames, "frames_checkpointed_by_sqlite": checkpointed, "frames_committed_by_this_tool": wal_info["frames_committed"],
                "counts_agree": agree, "pages_of_the_main_file_changed_by_the_wal": changed_pages, "journal_mode_after": mode,
                "files_left_in_applied": leftover,
                "note": "the copy after SQLite's own recovery and checkpoint: the main file's pages with the committed frames written over them; the originals are untouched",
            }
            if qc is not None:
                receipt["applied"]["quick_check"] = qc
            if not agree:
                receipt["problems"].append("SQLite counts %d frame(s) in the WAL and this tool read %d committed: the two readings differ; SQLite's is what the applied copy holds" % (log_frames, wal_info["frames_committed"]))
            if busy != 0 or checkpointed != log_frames:
                receipt["problems"].append("the checkpoint did not move every frame (busy %s, %s of %s): the applied copy may lack committed rows" % (busy, checkpointed, log_frames))
            database = "applied/database.sqlite"
        except (sqlite3.Error, OSError, TimeoutError, OverflowError) as exc:
            receipt["applied"] = {"applied": False, "error": scrub(str(exc)) if not isinstance(exc, OSError) else describe(exc),
                                  "note": "SQLite could not apply the WAL to the copy; the copies of the set are intact in original/"}
            receipt["problems"].append("the WAL could not be applied: %s" % receipt["applied"]["error"])
            leftover_dir = dest / "applied"
            for n in (os.listdir(leftover_dir) if leftover_dir.is_dir() else []):
                try:
                    os.rename(str(leftover_dir / n), str(leftover_dir / (n + ".failed")))
                except OSError:
                    pass
    receipt["database"] = database
    receipt["database_sha256"] = (receipt["applied"] or {}).get("sha256") if database.startswith("applied") else receipt["source"]["sha256"]
    receipt["wal_applied"] = bool(receipt["applied"] and receipt["applied"].get("applied"))
    receipt["state_this_database_shows"] = (
        "the main file with the WAL's committed frames applied in the copy (frames after the last commit and the rollback journal are not applied)" if receipt["wal_applied"]
        else "the main file only, as copied; the WAL, where there is one, is not in it")
    receipt["status"] = "partial" if receipt["problems"] else "complete"
    receipt["status_basis"] = ("every file of the set was copied and hashed, and the WAL was read and applied in the copy" if receipt["status"] == "complete" else
                               "a file of the set was not copied whole, or the WAL or journal could not be read or applied (see problems)")
    receipt["seconds"] = round(time.monotonic() - started, 2)
    write_receipt()
    say(dict(receipt), 0)


if __name__ == "__main__":
    try:
        main()
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:   # noqa: BLE001 - a defect in this tool or a database it did not foresee: said as JSON, never a traceback
        say({"ok": False, "error": "internal error: %s: %s" % (type(exc).__name__, scrub(str(exc))), "tool": TOOL}, 1)
