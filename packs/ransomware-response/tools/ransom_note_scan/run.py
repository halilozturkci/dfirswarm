#!/usr/bin/env python3
"""Find the files whose names look like ransom notes, and say what is in them without reading it out.

A note is the one artefact the adversary wants read, which makes it easy to find. It
is also a place where access-bearing values live: a victim identifier, a "personal
key", a portal address that carries an access token, a wallet. This tool locates
those and counts them. It does not print them.

What it does, in order:

    walks a tree in print order (directories and names ordered by the text the answer prints for
    them; names that are withheld in an order drawn afresh each run, a name withheld for a value its
    note holds among them: a first pass reads the notes for those values before the walk that prints
    is ordered, and takes at most 40% of max_seconds) and follows no link, and takes every regular file
    whose name matches a note-like pattern as a CANDIDATE BY NAME; a name match is
    not a note, and the answer says so for each one;
    reads each candidate once (up to max_size), detects its encoding (byte-order
    mark, then the NUL pattern of UTF-16 without one, else UTF-8) and records the
    decoding errors;
    finds indicator candidates by regular expression: onion addresses, e-mail
    addresses, URLs, bitcoin, monero and ethereum addresses, Tox ids and the value
    that follows a label such as "your personal ID". A bitcoin address's own
    checksum is checked (base58check, bech32); the others are syntactic candidates;
    classifies the candidate: `content_resembles_note` when the content shows at
    least two kinds of note marker (an onion address, a wallet, a Tox id, a
    labelled identifier, note vocabulary), else `filename_only`. Neither is a
    confirmation: a benign project readme and a note are told apart by a person.

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"),
the same as recovery_key_scan's, whose SecretValues class is copied below.

  1. The answer carries presence, kind, location (note id, byte offset), length and a
     validation result. It carries no identifier, wallet, onion address, URL, e-mail
     address, no character of one and no digest of one, and none of the note's text.
     A finding's `finding_id` is a sequence number and is derived from nothing. A note's
     own sha256 is a digest of the whole file, for integrity and for grouping copies; it
     is withheld (sha256 null, and why) for a note shorter than 128 bytes and for one that
     is a single token or a single indicator value, where it would be a digest of the value.
  2. A value is written only when the caller asks (`write_values: true`), only when
     the tool runs as a job (JOB_ID and OUT are set) and only to a file under $OUT.
     The manifest makes a job that sets write_values a secret_output job, and the tool
     checks SECRET_OUTPUT=1 in its environment: outside a job, and in a job that is not
     secret output (its files would be sealed as ordinary output), the request is
     refused and nothing is written.
  3. The values file is JSON Lines, mode 0600, created exclusively before anything is
     scanned; each row names the answer's finding id, the note's real path and the
     byte offset. A preview of each note's first lines goes there too, and nowhere else.
  4. A secret is never on a command line. This tool takes a directory and flags only.
  5. Every path this tool prints (notes, rejected name matches, directories it could not
     list, exclusions, the root) goes through shown(): any component is withheld that holds
     a token shaped like an identifier (see shaped(); the manifest gives the rates at which
     the shape misses and at which it withholds an ordinary name) or a value the note held.
     Some families put the victim's identifier in a name. The shape is a guess, so a
     harmless name can be withheld, and an identifier of another shape is printed as it is;
     list the directory for a name that was withheld. The values file keeps the real path.

`max_seconds` is the tool's own clock (below the manifest's timeout): when it runs out the
walk stops, what was read is written, and the answer says `partial` and how much of the tree
was not examined. The clock runs inside a note too: reading stops at the limit, and so does the
matching, which makes the note `partly scanned` (a counter and a reason, not a silent cut). A stop signal (SIGTERM, SIGINT,
SIGHUP) ends the tool with one JSON answer (status `failed`, `interrupted`), exit code
128 + the signal, after removing the pages it was still writing; a values file already begun
is kept, cut back to its last whole row, and the answer says how many rows it holds. A result
file that is already there is never replaced by another result: the new one takes the next
free name.

What it does not locate: a long token with no label and no known shape (a 64-digit hex
string after the word "Token") is neither located nor counted.
"""
import builtins
import collections
import datetime
import errno
import functools
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import unicodedata
from pathlib import Path

PARSER = "ransom_note_scan/3"
DEFAULT_MAX_SIZE = 200000
MAX_SIZE_CEILING = 16 << 20
DEFAULT_SECONDS, MAX_SECONDS = 480, 540    # the manifest allows 600: the walk stops here so that what it has is written and sealed
FIRST_PASS_SHARE = 0.4                     # of max_seconds, at most, the first pass (the notes read for the values their paths hold) may take
DEFAULT_EXCLUDE_TOP = ["proc", "sys", "dev"]
# Values seen are compared with each other to say "the same value as F000001" without
# saying the value; the comparison is held in memory, and capped.
DUPLICATE_CAP = 50000
# A value longer than this is not held for the comparison: a note can be 16 MiB of one URL.
DUPLICATE_VALUE_CAP = 1024
# The values of one note that are kept to withhold a path that carries one.
NAME_VALUES_CAP = 5000
MAX_WINDOWS = 64                  # the windows of the names of a path that are looked for in a note before it is matched for the values its path holds
# A note shorter than this is not digested: a digest of it is a digest of what it holds.
SHORT_NOTE = 128


# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib


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
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, describe(exc)),
            "status": "failed",
            "status_basis": "the tool stopped with an error (see error); the whole result could not be kept, so there is no answer",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        # ASCII only: U+2028, U+0085, a bidi override and a lone surrogate (a file name that is not UTF-8) are escaped, lose nothing, and a
        # line of the file is always a row.
        text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object, evidence: str | None = None) -> object:
        """Keep a row: read back by the backstop first (`evidence` is the name of a file printed as it is on purpose), then paged. Returns
        the row as kept."""
        row = seal_row(row, evidence)
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return row
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
        return row

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


# BEGIN SHARED PLACE
# The same text is in every windows-forensics tool that keeps a result file (a windows-forensics test holds the copies equal).
# A result file that is there is never replaced by another result: a file of the same bytes is named again, any other result takes the next free
# <stem>-<n><suffix>. The name is taken first, with an exclusive create, so a result written at the same moment cannot be replaced either.
def same_bytes(a, b):
    """Whether two files hold the same bytes (read in blocks, never whole)."""
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


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. The name is taken first, with an exclusive create, so a
    result written at the same moment cannot be replaced either. Returns the path that holds it."""
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        try:
            fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            if not os.path.islink(candidate) and same_bytes(tmp, candidate):
                os.unlink(tmp)
                return candidate
            continue
        os.close(fd)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return candidate
    raise OSError("no free name beside %s" % path)
# END SHARED PLACE


# BEGIN SHARED PAGE
# The same text is in every windows-forensics tool that pages through LosslessPage (held equal by a windows-forensics test): LosslessPage replaces a file of the
# same name; this one places its finished file with place_without_replacing, and registers itself so that a stop can remove its temporary file.
PAGES = []


class NoReplacePage(LosslessPage):
    """LosslessPage whose finished file is placed without replacing an earlier file of the same name (a rerun with other limits, or one
    the time limit stopped, must not leave a smaller file where a larger one was)."""

    def __init__(self, tool, key, limit):
        super().__init__(tool, key, limit)
        PAGES.append(self)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                placed = place_without_replacing(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            self._tmp = None
            self.path = placed
            self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result
# END SHARED PAGE


# BEGIN SHARED STOP
# The same text is in regkv, shellbags and amcache_apps (held equal by a windows-forensics test). SIGTERM, SIGINT and SIGHUP end the tool with JSON (status
# interrupted, exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
import signal
import time

STOP = {"last_word": None, "deadline": None}


def set_deadline(seconds):
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def _on_signal(signum, _frame):
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    last_word = STOP["last_word"]
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def install_signal_handlers(last_word=None):
    STOP["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)
# END SHARED STOP


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The reference implementation of the secret-safe output pattern (recovery_key_scan's,
    copied as LosslessPage is, since standalone tools do not import each other): call
    `add` once per finding with the finding's id, its locator and the value. With
    `enabled` false it writes nothing and `summary()` says so.
    """

    NAME = "ransom-note-values.jsonl"

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=ransom_note_scan with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(
                "write_values is refused in a job that was not run as secret output: its files would "
                "be sealed as ordinary output. The harness sets SECRET_OUTPUT=1 for a secret job's "
                "process and it is not set here. Run this as job_run tool=ransom_note_scan (its "
                "manifest makes a job that sets write_values secret output), or give a command job "
                "secret_output: true; if that is refused the same way, this run's harness does not set "
                "the variable and the values mode is not available in it. Nothing was written."
            )
        self.path = Path(self.out) / self.NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)
        # Created now, before anything is scanned: a file or a link already at that name is
        # refused by name at once (O_EXCL does not follow a link, a dangling one included),
        # instead of failing, or writing through it, after the scan. With nothing found it
        # stays as an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.shown)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.shown, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id: str, locator: dict, value: str) -> None:
        if not self.enabled:
            return
        # One write and a flush per row: a stop signal leaves whole rows on disk, at worst one cut row, which stop() removes.
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=True) + "\n")
        self._fh.flush()
        self.written += 1

    def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def stop(self) -> None:
        """Called when a stop signal ends the tool: close the file, cut it back to its last whole row and count the rows."""
        if self._fh is None or self.path is None:
            return
        try:
            self._fh.close()
        except Exception:  # noqa: BLE001 - a signal can arrive inside a write
            pass
        self._fh = None
        rows = last = at = 0
        try:
            with open(self.path, "rb") as fh:
                while True:
                    chunk = fh.read(1 << 20)
                    if not chunk:
                        break
                    rows += chunk.count(b"\n")
                    cut = chunk.rfind(b"\n")
                    if cut >= 0:
                        last = at + cut + 1
                    at += len(chunk)
            if last < at:
                os.truncate(self.path, last)
            self.written = rows
        except OSError:
            pass

    def summary(self) -> dict:
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": "JSON Lines, mode 0600: finding_id (a note's id for its preview), note_id, file (the real path), "
                      "offset (bytes), kind, encoding, validation, value" if self.enabled else None,
        }


# --- what is looked for -------------------------------------------------------------

NAME_HINTS = re.compile(
    r"(readme|read_me|decrypt|restore|recover|unlock|how[\W_]*to|ransom|help[\W_]*|"
    r"your[\W_]*files|instruction|_note|!!!)", re.I)

# Every repetition is bounded: a long run that nearly matches (a megabyte of "a.a.a." or of
# spaces after a label) costs time in proportion to its length, not to its square. A value
# itself is not cut: it ends where the pattern does, and its length is reported.
ONION = re.compile(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b", re.I)
EMAIL = re.compile(r"\b[\w.+-]{1,64}@[\w-]{1,63}\.[\w.-]{2,253}\b")
URL = re.compile(r"\bhttps?://[^\s<>\"')]{6,}")
BITCOIN = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
MONERO = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
ETHEREUM = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TOX = re.compile(r"\b[A-F0-9]{76}\b", re.I)
IDENTIFIER = re.compile(
    r"(?:your\s{1,8}(?:personal\s{1,8})?(?:id|key|token)|victim\s{0,8}id|company\s{0,8}id|"
    r"identifier|decryption\s{0,8}id)\s{0,32}[:=\-]?\s{0,32}([A-Za-z0-9\-_]{8,})", re.I)

# kind -> (pattern, the group that holds the value). The order is the order rows are written in.
KINDS = [
    ("onion", ONION, 0),
    ("email", EMAIL, 0),
    ("url", URL, 0),
    ("bitcoin", BITCOIN, 0),
    ("monero", MONERO, 0),
    ("ethereum", ETHEREUM, 0),
    ("tox", TOX, 0),
    ("identifier_candidate", IDENTIFIER, 1),
]
WALLET_KINDS = ("bitcoin", "monero", "ethereum")
# A path component has no slash, so a value that has one (a URL) is in no name: it is not one of the values kept to withhold a name.
NAMEABLE = {"onion": True, "email": True, "url": False, "bitcoin": True, "monero": True, "ethereum": True, "tox": True, "identifier_candidate": True}
# Words that make a text read like a note. A list of words, not of values: nothing here is
# secret, and two of them together are a marker, not a finding.
LANGUAGE = ("decrypt", "your files", "encrypted", "ransom", "bitcoin", "private key",
            "tor browser", "restore your", "unlock", "payment")


def fail(message, **extra):
    print(json.dumps(release({"error": message, "status": "failed",
                              "status_basis": "the tool stopped with an error (see error); it scanned no note", **extra})))
    raise SystemExit(1)


PROGRESS = {}


def last_word(signum):
    """What the tool says when a stop signal ends it: one JSON answer, never a clean-looking partial one."""
    values = PROGRESS.get("values")
    held = None
    if values is not None and values.enabled:
        values.stop()
        held = {"values_file": values.shown, "rows_in_values_file": values.written,
                "values_file_is_partial": True,
                "values_file_note": "the file holds the whole rows written before the stop, not every value of the tree; it is secret output"}
    print(json.dumps({"error": "stopped by signal %d before the scan was complete" % signum, "status": "failed",
                      "status_basis": "the tool was stopped by signal %d; the tables it was still writing were removed, so nothing it had "
                                      "read is an answer" % signum,
                      "interrupted": True, "signal": signum, "coverage_so_far": PROGRESS.get("coverage"), **(held or {})}), flush=True)


def drop_temporary_files():
    """Remove the files a page was still writing (a failure, not a stop signal, ended the tool)."""
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def describe(exc):
    """An error without the path it names: type, errno name and the system's own words (never the text of an exception that has none:
    it can name the place of the output)."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    words = getattr(exc, "strerror", None) or ("no free name for a result file" if str(exc).startswith("no free name") else "no system message")
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", words)


def where_it_failed(exc):
    """The line of this tool an unexpected exception was raised on: enough to find it, and no text of the exception (which can name a path)."""
    tb = exc.__traceback__
    line = None
    while tb is not None:
        if tb.tb_frame.f_code.co_filename == __file__:
            line = tb.tb_lineno
        tb = tb.tb_next
    return "line %s of the tool" % line if line else "an unknown line"


# --- time ---------------------------------------------------------------------------

EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def iso_utc(ns):
    """A nanosecond count since 1970-01-01 UTC as ISO 8601 (whole microseconds), or None when
    it is outside what a datetime holds. The raw count is kept beside it wherever it is shown."""
    try:
        when = EPOCH + datetime.timedelta(microseconds=ns // 1000)
    except (OverflowError, ValueError, TypeError):
        return None
    return when.replace(tzinfo=None).isoformat() + "Z"


# --- wallets ------------------------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def base58check(address):
    """A legacy bitcoin address is 25 bytes, the last four the first four of a double sha256 of the rest."""
    number = 0
    for ch in address:
        i = B58.find(ch)
        if i < 0:
            return False
        number = number * 58 + i
    leading = len(address) - len(address.lstrip("1"))
    raw = bytes(leading) + number.to_bytes((number.bit_length() + 7) // 8, "big")
    if len(raw) != 25:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def bech32_polymod(values):
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def bech32_valid(address):
    """BIP-173 (witness version 0) and BIP-350 (later versions): the checksum constant is 1 or 0x2bc830a3."""
    sep = address.rfind("1")
    if sep < 1 or sep + 7 > len(address):
        return False
    hrp, data = address[:sep], address[sep + 1:]
    if any(c not in BECH32 for c in data):
        return False
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + [BECH32.index(c) for c in data]
    return bech32_polymod(values) in (1, 0x2BC830A3)


def validate(kind, value):
    """checksum_valid, checksum_failed, or syntactic_candidate (no checksum this tool checks); None for the rest."""
    if kind == "bitcoin":
        ok = bech32_valid(value) if value.startswith("bc1") else base58check(value)
        return "checksum_valid" if ok else "checksum_failed"
    if kind in ("monero", "ethereum"):
        return "syntactic_candidate"
    return None


# --- decoding and offsets -----------------------------------------------------------

UTF8_ESCAPES = re.compile("[\udc80-\udcff]")
SURROGATES = re.compile("[\ud800-\udfff]")


def decode_note(blob):
    """The text of a note and how it was decoded, or {"binary": True}.

    A byte-order mark decides first. Without one, ASCII text in UTF-16 is NUL in every second
    byte (the odd ones for little-endian), which is told from a binary file's few NULs by how
    many there are in the first 2 KiB; a file with NULs in any other pattern is binary and
    is not read as text. Everything else is read as UTF-8, a byte that is not UTF-8 kept
    as a lone surrogate so that an offset stays a byte offset, and counted.
    """
    if blob.startswith(b"\xef\xbb\xbf"):
        codec, name, basis, base = "utf-8", "UTF-8", "byte-order mark", 3
    elif blob.startswith(b"\xff\xfe"):
        codec, name, basis, base = "utf-16-le", "UTF-16LE", "byte-order mark", 2
    elif blob.startswith(b"\xfe\xff"):
        codec, name, basis, base = "utf-16-be", "UTF-16BE", "byte-order mark", 2
    else:
        sample = blob[:2048]
        half = len(sample) // 2
        odd, even = sample[1::2].count(0), sample[0::2].count(0)
        if half >= 8 and odd >= half * 0.25 and even <= odd * 0.1:
            codec, name, basis, base = "utf-16-le", "UTF-16LE", "NUL byte pattern", 0
        elif half >= 8 and even >= half * 0.25 and odd <= even * 0.1:
            codec, name, basis, base = "utf-16-be", "UTF-16BE", "NUL byte pattern", 0
        elif b"\x00" in sample:
            return {"binary": True, "basis": "NUL bytes in the first 2 KiB, not in a UTF-16 pattern: binary or an encoding this tool does not read"}
        else:
            codec, name, basis, base = "utf-8", "UTF-8", "no byte-order mark and no NUL byte: read as UTF-8", 0
    body = blob[base:]
    if codec != "utf-8":
        trailing = len(body) % 2
        if trailing:
            body = body[:-1]
        text = body.decode(codec, "surrogatepass")
        return {"codec": codec, "errors_mode": "surrogatepass", "name": name, "basis": basis, "base": base,
                "text": text, "decode_errors": len(SURROGATES.findall(text)), "trailing_byte": bool(trailing)}
    text = body.decode("utf-8", "surrogateescape")
    return {"codec": codec, "errors_mode": "surrogateescape", "name": name, "basis": basis, "base": base,
            "text": text, "decode_errors": len(UTF8_ESCAPES.findall(text)), "trailing_byte": False}


class Offsets:
    """The byte offset in the file of a position in the decoded text, for positions that rise.

    Plain ASCII is its own offset; anything else is re-encoded segment by segment between
    the positions asked for, so the whole costs one pass over the text.
    """

    def __init__(self, decoded):
        self.text = decoded["text"]
        self.codec, self.mode, self.base = decoded["codec"], decoded["errors_mode"], decoded["base"]
        self.plain = self.codec == "utf-8" and self.text.isascii()
        self.pos = self.acc = 0

    def reset(self):
        self.pos = self.acc = 0

    def at(self, index):
        if self.plain:
            return self.base + index
        if index < self.pos:
            self.reset()
        self.acc += len(self.text[self.pos:index].encode(self.codec, self.mode))
        self.pos = index
        return self.base + self.acc


def whole_file_digest(blob, text=None, values=()):
    """(sha256 hex, None) of a note, or (None, why) where the digest would be a digest of a secret.

    A note shorter than SHORT_NOTE bytes, or one that is a single token or a single indicator value, is
    not digested: nothing in it hides the value. A longer note's digest is for integrity and for grouping
    copies, and no identifier is digested on its own.
    """
    if len(blob) < SHORT_NOTE:
        return None, "the note is shorter than %d bytes: a digest of it would be a digest of what it holds" % SHORT_NOTE
    if text is not None:
        stripped = text.strip()
        if stripped and (len(stripped.split()) == 1 or stripped in values):
            return None, "the note is a single token or indicator value: a digest of it would be a digest of that value"
    return hashlib.sha256(blob).hexdigest(), None


def count_content(contents, sha, blob, note_id):
    """Group identical notes without printing a digest of one that is withheld: by digest, or in memory."""
    key = sha if sha else (("small", blob) if len(blob) <= 4096 else ("note", note_id))
    entry = contents.setdefault(key, [0, note_id, sha])
    entry[0] += 1


# --- paths --------------------------------------------------------------------------

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



# BEGIN SHARED NAMES
# The same text is in encrypted_survey and ransom_note_scan, so that the two tools judge a name alike (a ransomware-response test holds
# the copies equal). A path is printed only through shown(): every component is judged, and no directory above a file is exempt.
# Everything derived from a name that is withheld (an extension, a stem, a length, the place of the name among its siblings) is withheld
# with it: a name that is withheld is replaced by one constant marker, and the order of a listing never follows the text that was withheld.
WITHHELD = "<identifier-shaped name withheld>"
WITHHELD_PATHS = [0]              # printed paths that had a component withheld (one per call of shown)
_IDRUN = re.compile(r"[A-Za-z0-9]{8,}")
_WORDY = re.compile(r"[A-Z]?[a-z]+(?:[A-Z][a-z]+)*|[A-Z]+")
_PAIR_SEPARATORS = re.compile(r"[^0-9A-Za-z]")
_DIGIT_GROUPS = re.compile(r"(?<![0-9])[0-9]{3,}(?:[ ,][0-9]{3,})+(?![0-9])")
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
SINGLE_CASE_RUN = 16              # a run of letters of one case is a word below this many letters, a random run from here on
HEX_PAIRS = 8                     # this many pairs of hex digits joined by one separator are a byte string
# Directory names every Windows, Linux and ESXi host has, whose letters and digits would otherwise be taken for an identifier, and the names
# of the exceptions Python raises (the tools print the type of an error: IsADirectoryError reads as letters that are not words). A component
# is printed as it is when it is one of these, whole and in any case.
WELL_KNOWN = frozenset((
    "system32", "syswow64", "inetcache", "inetcookies", "inethistory", "msocache", "psreadline", "framework", "framework64",
    "sqlserver", "gpucache", "dawnwebgpucache", "dawngraphitecache", "grshadercache", "indexeddb", "overlay2", "datastore1")
) | frozenset(name.lower() for name, value in vars(builtins).items() if isinstance(value, type) and issubclass(value, BaseException))


# The characters whose NFKC form holds a slash (a full-width solidus, the "a/c", "a/s", "c/o" and "c/u" signs) each read as one backslash, a
# separator that is not a slash: a path is split at the real slashes only, and a folded one would cut a run of pairs into pieces of one.
_SLASH_LIKE = dict.fromkeys((0x2100, 0x2101, 0x2105, 0x2106, 0xFF0F), "\\")
# Characters that show nothing and are not format characters: a combining grapheme joiner, variation selectors, Mongolian free variation
# selectors, hangul and khmer fillers, a braille blank, tag and musical controls, the other default-ignorable code points.
_INVISIBLE = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u2800\u3164"
                        "\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]")


def _unseen(ch):
    """Whether a non-ASCII character shows nothing of its own: a format character, a combining mark, a default-ignorable code point."""
    return unicodedata.category(ch) in ("Cf", "Mn", "Mc", "Me") or _INVISIBLE.match(ch) is not None


def fold(name):
    """The name as the rule reads it: NFKC (a full-width letter or digit is the ASCII one; a full-width solidus is a separator, not a
    slash), every decimal digit of any script as its ASCII digit, and nothing that shows nothing: no format character, no combining mark
    (taken off the letter it sits on before the two are composed), no default-ignorable code point (a zero-width space, a variation
    selector, a filler cannot split a token)."""
    if name.isascii():
        return name
    out = []
    for ch in unicodedata.normalize("NFKC", "".join(c for c in name.translate(_SLASH_LIKE) if c.isascii() or not _unseen(c))):
        if ord(ch) < 128:
            out.append(ch)
        elif unicodedata.category(ch) == "Nd":
            out.append(str(unicodedata.decimal(ch)))
        elif not _unseen(ch):
            out.append(ch)
    return "".join(out)


def _hex_pairs(text):
    """Whether HEX_PAIRS or more pairs of hex digits follow each other, one separator between two. A separator is any character that is not
    an ASCII letter or a digit (the pairs of `id[aa-bb-...-hh]`, `key=aa:bb:...` and `(aa.bb...)` are found: a neighbour of the run that is
    not a letter or a digit does not hide a pair at its end), and only a letter or a digit glued to a pair makes it no pair. A run does not
    cross a slash: a path is read one component at a time (a full-width solidus is not a slash: fold turns it into a separator)."""
    for part in text.split("/"):
        run = 0
        for piece in _PAIR_SEPARATORS.split(part):
            if len(piece) == 2 and piece[0] in HEX_DIGITS and piece[1] in HEX_DIGITS:
                run += 1
                if run >= HEX_PAIRS:
                    return True
            else:
                run = 0
    return False


def _digit_groups(text):
    """Whether groups of three or more digits, joined by a space or a comma, hold ten or more digits together."""
    return any(sum(c.isdigit() for c in m.group(0)) >= 10 for m in _DIGIT_GROUPS.finditer(text))


def shaped(name):
    """Whether a name holds a token shaped like an identifier. The name is folded first (fold). A token is a run of 8 or more ASCII
    letters and digits. It is identifier-shaped when it holds both letters and digits, or is 10 or more digits, or is letters only and is
    not one word, one capitalised word, several capitalised words or all capitals, or is 16 or more letters of one case. So are 8 or more
    pairs of hex digits joined by one separator (any character that is not a letter, a digit or a slash: a colon, a dash, a dot, an underscore,
    a space, a bracket, an equals sign; a letter or a digit glued to a pair at an end of the run makes that pair no pair), and groups of
    digits joined by a space or a comma that hold 10 digits or more. The rule is a shape: a longer or different separator, a different
    grouping and other scripts are not covered (see the manifests)."""
    text = fold(name)
    for m in _IDRUN.finditer(text):
        token = m.group(0)
        if token.isdigit():
            if len(token) >= 10:
                return True
        elif any(c.isdigit() for c in token):
            return True
        elif not _WORDY.fullmatch(token):
            return True
        elif len(token) >= SINGLE_CASE_RUN and (token.islower() or token.isupper()):
            return True
    return len(text) >= 23 and _hex_pairs(text) or len(text) >= 11 and _digit_groups(text)


@functools.lru_cache(maxsize=65536)
def _judge(part):
    """What to print in place of one path component, or None to print it as it is. A component that is judged is withheld whole, by
    one marker that says nothing of its length or its shape."""
    if part.lower() in WELL_KNOWN:
        return None
    if shaped(part):
        return WITHHELD
    return WITHHELD if scrub(part, "names") != part else None


def shown(path, values=(), keep_last=False, count=True):
    """A path as it may be printed: every component that could carry an identifier is withheld.

    A component is withheld when it holds a token shaped like an identifier (shaped), when the shared withholding rules above find a
    token, a key or user-info in it, or when it contains a value the note held (case-insensitive, 8 characters or more). The same rule
    applies to every path a tool prints, so a name is never hidden on one line and printed on the next; a harmless name can be withheld
    with it, and the directory can be listed. keep_last leaves the final component as it is (a name that is itself the evidence).
    """
    if not isinstance(path, str):
        return path
    parts = path.split("/")
    last = len(parts) - 1
    lows = [v.lower() for v in values if len(v) >= 8]
    changed = False
    for i, part in enumerate(parts):
        if not part or (keep_last and i == last):
            continue
        replaced = _judge(part)
        if replaced is None and lows:
            low = part.lower()
            if any(v in low for v in lows):
                replaced = WITHHELD
        if replaced is not None:
            parts[i] = replaced
            changed = True
    if changed and count:
        WITHHELD_PATHS[0] += 1
    return "/".join(parts)


_ORDER_SALT = os.urandom(16)


def print_order(entries, judged, hidden=None):
    """The directory entries in the order an answer prints them: by the text printed for each (the marker for a name that is judged
    and withheld, the name itself otherwise; `judged(entry)` says whether the answer prints the entry's name through the judge;
    `hidden(entry)`, when given, says that a name the first rule lets through is withheld all the same, because the note beneath it holds
    its value: it sorts as the marker does), and the entries that print alike in an order drawn afresh every run (a keyed hash of the whole
    path, the directory above included, under a salt of this run: the same name in two directories has two unrelated ranks). The rank of a
    withheld name among its siblings, the order a directory lists them in and the inode never show in what an answer lists, in the
    order of its rows, in the numbers it hands out or in which entries a limit keeps."""
    texts = []
    for entry in entries:
        name = entry.name
        try:
            if hidden is not None and hidden(entry):
                texts.append(WITHHELD)
            else:
                texts.append((_judge(name) or name) if judged(entry) else name)
        except OSError:
            texts.append(_judge(name) or name)
    order = sorted(range(len(entries)), key=texts.__getitem__)
    out, i = [], 0
    while i < len(order):
        j = i + 1
        while j < len(order) and texts[order[j]] == texts[order[i]]:
            j += 1
        group = order[i:j]
        if len(group) > 1:
            group.sort(key=lambda n: (hashlib.blake2b(entries[n].path.encode("utf-8", "surrogatepass"), key=_ORDER_SALT, digest_size=8).digest(), n))
        out.extend(group)
        i = j
    return [entries[n] for n in out]
# END SHARED NAMES


# BEGIN SHARED BACKSTOP
# The same text is in encrypted_survey and ransom_note_scan (a ransomware-response test holds the copies equal). Every row a page or the census
# keeps and the answer itself pass through here on their way out, whatever the code that made them did: a second check, written apart from
# shown() (it reads a string whole, not component by component, and calls neither the judge, scrub nor any call site's decision), that
# replaces a string holding an identifier-shaped text by a marker, counts it, and makes a complete answer partial. The one exception is on
# purpose: the name of a file that is not named like a note is evidence and is printed as it is (the caller says so with `evidence`, and the
# check refuses that claim for a name that is note-named). Content that is hex by nature (a digest, a tail) is passed by its key.
BOUNDARY = {"replaced": 0, "by": {}, "where": [], "not_listed": 0}
OWN_NAMES = set()                 # the names of the files this run wrote (their digest is the name of the root and of the table)
FREE_KEYS = frozenset(("sha256", "tail_hex", "suffix_hex"))
PROSE_KEYS = frozenset(("reason", "status_basis", "partial_reasons"))    # the tool's own sentences: "(4294967296 bytes)" there is a size, not a name
SERIAL_KEYS = frozenset(("note_id", "finding_id", "first_note_id", "duplicate_of"))      # a sequence number this tool counted: N000001, F1000000
_SERIAL = re.compile(r"[NF][0-9]{6,12}")
MAX_REPLACED_LISTED = 20
MAX_JUDGED = 1 << 16
_SUSPECT = re.compile(r"[A-Za-z0-9]{8}|(?:[0-9A-Fa-f]{2}[^0-9A-Za-z/]){4}|[0-9]{3}[ ,][0-9]{3}")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")
_PAIRS = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{2}(?:[^0-9A-Za-z/][0-9A-Fa-f]{2}){7}(?![0-9A-Za-z])")
_GROUPS = re.compile(r"(?<![0-9])[0-9]{3,}(?:[ ,][0-9]{3,})+(?![0-9])")


class Sealed(dict):
    """A row that has been through the backstop: it is not read again (its evidence name would not pass without the claim made for it)."""


_FOLDS_TO_SLASH = dict.fromkeys((0x2100, 0x2101, 0x2105, 0x2106, 0xFF0F), "\\")      # NFKC turns these into a slash: not a path separator here
_UNSEEN = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u2800\u3164"
                     "\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]")


def _read_as(text):
    """The string as the check reads it: NFKC (a full-width solidus is a separator, not a slash), decimal digits of any script as ASCII
    digits, nothing that shows nothing (no format character, no combining mark, no default-ignorable code point; a mark is taken off the
    character it sits on before the two are composed into one)."""
    if text.isascii():
        return text
    seen = lambda ch: unicodedata.category(ch) in ("Cf", "Mn", "Mc", "Me") or _UNSEEN.match(ch) is not None     # noqa: E731
    kept = []
    for ch in unicodedata.normalize("NFKC", "".join(c for c in text.translate(_FOLDS_TO_SLASH) if c.isascii() or not seen(c))):
        if ch.isascii():
            kept.append(ch)
        elif unicodedata.category(ch) == "Nd":
            kept.append(str(unicodedata.decimal(ch)))
        elif not seen(ch):
            kept.append(ch)
    return "".join(kept)


@functools.lru_cache(maxsize=65536)
def _why(text, prose=False):
    """The reason a string may not be printed (a fixed sentence, never a part of the string), or None. `prose` is a sentence of the tool's
    own (a reason, a status basis): a number of 10 or more digits followed by " bytes" is a size there and is not read as a name."""
    flat = _read_as(text)
    for found in _ALNUM_RUN.finditer(flat):
        run = found.group()
        size = len(run)
        if size < 8 or run.lower() in WELL_KNOWN:
            continue
        digits = sum(1 for c in run if c.isdigit())
        if digits == size:
            if size >= 10 and not (prose and flat.startswith(" bytes", found.end())):
                return "a long run of digits"
        elif digits:
            return "letters and digits in one run"
        elif run.isupper() or run.islower():
            if size >= 16:
                return "a long run of letters of one case"
        elif any(c.isupper() and not (i + 1 < size and run[i + 1].islower()) for i, c in enumerate(run)):
            return "letters that do not read as words"
    if _PAIRS.search(flat):
        return "pairs of hex digits"
    for m in _GROUPS.finditer(flat):
        if sum(c.isdigit() for c in m.group(0)) >= 10:
            return "groups of digits"
    return None


_CLEAN = set()                    # short strings already found clean (keys, repeated words): not read again


def _refuse(text, evidence, prose=False):
    """Why this string may not be printed, or None. `prose` is set for the tool's own sentences (see _why)."""
    size = len(text)
    if size < 8 or text in _CLEAN or text in OWN_NAMES:
        return None
    if size > MAX_JUDGED:
        return "a string too long to check"
    if evidence and not NAME_HINTS.search(evidence):
        if text.lower() in evidence.lower():              # the name itself, or a piece of it (its extension)
            return None
        if text.endswith("/" + evidence):                 # a path whose last component is the evidence
            text = text[:-len(evidence) - 1]
            size = len(text)
            if size < 8:
                return None
    why = None if text.isascii() and not _SUSPECT.search(text) else _why(text, prose)
    if why is None and not prose and size <= 64 and len(_CLEAN) < 20000:
        _CLEAN.add(text)
    return why


def _place(where):
    """The place of a string as text: the keys that are plain words and the indexes above it, never a key that came from a name (a key is a
    word only when it is also one to the second check: a key of letters and digits is not printed, whatever it looks like)."""
    parts = []
    while where is not None:
        where, label = where
        word = not isinstance(label, int) and re.fullmatch(r"[a-z][a-z_0-9]{0,40}", str(label)) and _why(str(label)) is None
        parts.append(label if isinstance(label, int) or word else "*")
    return "/" + "/".join(str(p) for p in reversed(parts))


def _replaced(why, where):
    BOUNDARY["replaced"] += 1
    BOUNDARY["by"][why] = BOUNDARY["by"].get(why, 0) + 1
    if len(BOUNDARY["where"]) < MAX_REPLACED_LISTED:
        BOUNDARY["where"].append({"at": _place(where), "check": why})
    else:
        BOUNDARY["not_listed"] += 1
    return "<withheld at the output: %s>" % why


def _read_back(value, where, key, evidence):
    """`value` with every string checked; the same object when nothing was replaced."""
    if isinstance(value, Sealed):
        return value
    if isinstance(value, str):
        if len(value) < 8 or key in FREE_KEYS or (key in SERIAL_KEYS and _SERIAL.fullmatch(value)):
            return value
        why = _refuse(value, evidence, key in PROSE_KEYS)
        return _replaced(why, where) if why else value
    if isinstance(value, dict):
        pairs, changed = [], False
        for k, v in value.items():
            nk = _read_back(k, (where, "(key)"), None, None) if isinstance(k, str) and len(k) >= 8 else k
            if isinstance(v, (str, dict, list, tuple)):
                nv = _read_back(v, (where, k if nk is k else "(key)"), k if isinstance(k, str) else None, evidence)
            else:
                nv = v
            changed = changed or nk is not k or nv is not v
            pairs.append((nk, nv))
        if not changed:
            return value
        out = {}
        for nk, nv in pairs:
            while nk in out:
                nk = "%s #" % nk
            out[nk] = nv
        return out
    if isinstance(value, (list, tuple)):
        items = [_read_back(v, (where, i), key, evidence) for i, v in enumerate(value)]
        return value if all(a is b for a, b in zip(items, value)) else items
    return value


def seal_row(row, evidence=None):
    """A row on its way to a page or the census: every string read back. `evidence` is the name of the file the row is about when it is
    printed as it is on purpose (a file that is not named like a note)."""
    if isinstance(row, Sealed):
        return row
    out = _read_back(row, None, None, evidence)
    return Sealed(out) if isinstance(out, dict) else out


def release(doc):
    """The answer: every string that was not read back already is read back now. A complete answer that had a string replaced is partial."""
    out = _read_back(doc, None, None, None)
    if BOUNDARY["replaced"] and isinstance(out, dict):
        note = {"strings_replaced_at_the_output": BOUNDARY["replaced"], "by_check": dict(BOUNDARY["by"]), "replaced_at": list(BOUNDARY["where"]),
                "replaced_not_listed": BOUNDARY["not_listed"],
                "note": "every string of this answer and of the files it names was read back by a second check, written apart from the rule "
                        "that withholds names; a string it found identifier-shaped is replaced by a marker and its place is in replaced_at"}
        merged = {}
        for k, v in out.items():
            merged[k] = v
            if k == "status_basis":
                merged["boundary"] = note
        merged.setdefault("boundary", note)
        if merged.get("status") == "complete":
            merged["status"] = "partial"
            if "complete" in merged:
                merged["complete"] = "partial"
            merged["status_basis"] = "%s; %d strings held an identifier-shaped text that the first rule missed and were replaced at the output (see boundary)" % (
                merged.get("status_basis") or "every entry was visited", BOUNDARY["replaced"])
        out = merged
    return out
# END SHARED BACKSTOP


# --- the walk -----------------------------------------------------------------------

def kind_of(mode):
    for test, name in ((stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
                       (stat.S_ISCHR, "a character device"), (stat.S_ISDIR, "a directory")):
        if test(mode):
            return name
    return "a special file"


def judged_entry(entry):
    """Whether the answer prints this entry's name through the judge: a directory always, any other entry when it is named like a note."""
    return entry.is_dir(follow_symlinks=False) or bool(NAME_HINTS.search(entry.name))


def walk(top, exclude_top, exceptions, exclusions, rejected, counters, stopped, hidden=None, dry=False):
    """Yield (path, size, mtime_ns) of the regular files under `top` whose name looks like a note's.

    Directories and entries are taken in print order (print_order; `hidden` names the entries whose name the notes beneath hold the value
    of) and no link is followed. A directory that cannot be listed is an exception; one skipped at the top by name is an exclusion; a name
    match that is a link, a special file or cannot be examined is a rejection with its reason.
    Anything that does not match by name is counted and not listed. When the tool's own clock runs out the
    walk ends and `stopped` says how much of the tree it had not reached. `dry` is the first pass (values_pass): nothing is listed, counted
    or printed, and the entries come in the order the directory lists them.
    """
    stack = [(top, True)]
    while stack:
        if out_of_time():
            stopped.update({"entries_not_examined": 0, "directories_not_entered": len(stack)})
            return
        directory, is_top = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = list(it) if dry else print_order(list(it), judged_entry, hidden)
        except OSError as exc:
            counters["directories_failed"] += 1
            if not dry:
                exceptions.add({"path": shown(directory), "status": "failed", "what": "directory",
                                "reason": "the directory could not be listed", "error": describe(exc)})
            continue
        counters["directories_visited"] += 1
        subdirs = []
        for index, entry in enumerate(entries):
            if out_of_time():
                stopped.update({"entries_not_examined": len(entries) - index, "directories_not_entered": len(stack) + len(subdirs)})
                return
            named = bool(NAME_HINTS.search(entry.name))
            try:
                if entry.is_symlink():
                    counters["links_not_followed"] += 1
                    if named:
                        counters["name_matches"] += 1
                        if not dry:
                            rejected.add({"path": shown(entry.path), "status": "rejected",
                                          "reason": "a symbolic link: links are not followed, so the target was not read"})
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if is_top and entry.name in exclude_top:
                        counters["directories_excluded"] += 1
                        if not dry:
                            exclusions.append(seal_row({"path": shown(entry.path),
                                                        "reason": "named in exclude_top_level_dirs: a top-level %s directory of a Linux root; "
                                                                  "its contents were not read. Name it as the root to read it" % shown(entry.name, count=False)}))
                        continue
                    subdirs.append(entry.path)
                    continue
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                counters["entries_failed"] += 1
                if named:
                    counters["name_matches"] += 1
                if dry:
                    pass
                elif named:
                    rejected.add({"path": shown(entry.path), "status": "rejected",
                                  "reason": "the entry could not be examined", "error": describe(exc)})
                else:
                    exceptions.add({"path": shown(entry.path), "status": "failed",
                                    "reason": "the entry could not be examined", "error": describe(exc)})
                continue
            if not stat.S_ISREG(st.st_mode):
                counters["special_files_skipped"] += 1
                if named:
                    counters["name_matches"] += 1
                    if not dry:
                        rejected.add({"path": shown(entry.path), "status": "rejected",
                                      "reason": "not a regular file (%s)" % kind_of(st.st_mode)})
                continue
            counters["files_visited"] += 1
            if named:
                counters["name_matches"] += 1
                yield entry.path, st.st_size, st.st_mtime_ns
        stack.extend((d, False) for d in reversed(subdirs))


# The longest a match of each pattern can be (with a little to spare). A match of url and identifier_candidate has no bound, but the text
# before the part that runs on has one (HEADS: the label, the white space and the first characters of the value, with a little to spare).
SPANS = {"onion": 72, "email": 400, "bitcoin": 88, "monero": 104, "ethereum": 56, "tox": 88}
HEADS = {"url": 24, "identifier_candidate": 130}
# What a match of these kinds must hold (the same literal, compiled the same way): a note without it is not matched for the kind, which costs a
# search for the literal instead of a pass of the pattern.
GATES = {"onion": re.compile(r"\.onion", re.I), "email": re.compile(r"@"), "ethereum": re.compile(r"0x")}
CHUNK = 1 << 18


def matches(pattern, text, kind):
    """The matches of `pattern` in `text`, exactly the ones pattern.finditer(text) finds and in the same order, with the clock looked at
    between pieces of the text (finditer looks at nothing until a match comes: a megabyte of "a.a.a." has none and takes seconds). Yields
    None, once, when the clock ran out. The text is run piece by piece: a piece is searched with enough text after it that no match
    starting in it is cut (a pattern with no longest match, url and identifier_candidate, is searched with the text its head needs, and a
    match that reaches the end of what was searched is matched again from its start with all the text), and the next piece starts where
    the last match ended or at the end of the piece."""
    span = SPANS.get(kind) or HEADS[kind]
    open_ended = kind in HEADS
    if kind in GATES and not GATES[kind].search(text):
        return
    pos, size = 0, len(text)
    while pos < size:
        if out_of_time():
            yield None
            return
        edge = min(size, pos + CHUNK)
        reach = min(size, edge + span)
        last = pos
        for m in pattern.finditer(text, pos, reach):
            if m.start() >= edge:
                break
            if open_ended and m.end() >= reach and reach < size:
                m = pattern.match(text, m.start()) or m
                last = m.end()
                yield m
                break
            yield m
            last = m.end()
        pos = max(edge, last)


def first_values(text):
    """The values of a note the second pass keeps for withholding names: the same ones in the same order, at most NAME_VALUES_CAP."""
    values = []
    for kind, pattern, group in KINDS:
        if not NAMEABLE[kind]:
            continue
        for m in matches(pattern, text, kind):
            if m is None:
                return values
            values.append(m.group(group))
            if len(values) >= NAME_VALUES_CAP:
                return values
    return values


def can_name(text, names):
    """Whether a value of the note could be inside one of `names` (lower-case path components): a value is 8 characters or more and is
    inside a name, so its first 8 characters are a window of that name, and they are in the note. False means no value of the note is in
    any of the names and the note need not be matched. True is also the answer when there are many windows to look for."""
    windows = set()
    for name in names:
        key = name.casefold()
        windows.update(key[i:i + 8] for i in range(len(key) - 7))
        if len(windows) > MAX_WINDOWS:
            return True
    key = text.casefold()
    return any(window in key for window in windows)


def values_pass(top, exclude_top, max_size):
    """The first pass: the paths below `top` whose name holds a value of the note beneath them (case-insensitive, 8 characters or more, the
    rule shown() applies), or None when the pass did not finish. The notes are read before the walk that prints is ordered, so that a name
    withheld for a value sorts as every withheld name does and not by its text."""
    matched = set()
    base = top.rstrip(os.sep) or os.sep
    for path, _size, _mtime in walk(top, exclude_top, None, None, None, collections.Counter(), {}, dry=True):
        names, where = [], path
        while len(where) > len(base) and where != base:
            names.append((where, os.path.basename(where).lower()))
            where = os.path.dirname(where)
        if all(len(name) < 8 for _, name in names):       # a value is 8 characters or more: no name here can hold one
            continue
        try:
            decoded = decode_note(read_note(path, max_size))
        except Unreadable:
            continue
        if decoded.get("binary") or not can_name(decoded["text"], [name for _, name in names]):
            continue
        lows = {v.lower() for v in first_values(decoded["text"]) if len(v) >= 8}
        for where, low in names:
            if any(v in low for v in lows):
                matched.add(where)
    return None if out_of_time() else matched


class Unreadable(Exception):
    def __init__(self, reason, **extra):
        super().__init__(reason)
        self.reason, self.extra = reason, extra


def read_note(path, max_size):
    """The bytes of a regular file of at most max_size, opened without following a link.

    The size is taken from the open file, not from the directory entry, and a file that grew
    past max_size since the walk saw it is refused rather than cut.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise Unreadable("a symbolic link: links are not followed, so the target was not read")
        raise Unreadable("the file could not be read", error=describe(exc))
    try:
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise Unreadable("not a regular file (%s)" % kind_of(st.st_mode))
            if st.st_size == 0:
                raise Unreadable("the file is empty", bytes=0)
            if st.st_size > max_size:
                raise Unreadable("larger than max_size (%d bytes, max_size is %d): not read" % (st.st_size, max_size), bytes=st.st_size)
            chunks, got = [], 0
            while got <= max_size:
                if out_of_time():
                    raise Unreadable("not read: the time limit (max_seconds) was reached while it was being read")
                chunk = os.read(fd, min(1 << 20, max_size + 1 - got))
                if not chunk:
                    break
                chunks.append(chunk)
                got += len(chunk)
        except OSError as exc:
            raise Unreadable("the file could not be read", error=describe(exc))
        if got > max_size:
            raise Unreadable("larger than max_size (it grew past %d bytes since it was listed): not read" % max_size, bytes=got)
        return b"".join(chunks)
    finally:
        os.close(fd)


def format_hint(text):
    head = text[:1024].lstrip().lower()
    if head.startswith(("<!doctype html", "<html", "<head", "<body", "<hta:application")) or "<html" in head[:512]:
        return "html"
    if head.startswith("{\\rtf"):
        return "rtf"
    return "text"


# --- arguments ----------------------------------------------------------------------

KNOWN_PARAMS = {"root", "max_size", "limit", "write_values", "exclude_top_level_dirs", "max_seconds"}


def int_param(args, key, default, low, high=None):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        fail("%s must be an integer" % key)
    if value < low:
        fail("%s must be at least %d" % (key, low))
    if high is not None and value > high:
        fail("%s must be at most %d (a note is read whole into memory)" % (key, high))
    return value


def main():
    install_signal_handlers(last_word)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    root = args.get("root")
    if not isinstance(root, str) or not root:
        fail("root is required: a directory to sweep")
    if not os.path.isdir(root):
        fail("no such directory", root=shown(root, count=False))
    max_size = int_param(args, "max_size", DEFAULT_MAX_SIZE, 16, MAX_SIZE_CEILING)
    limit = int_param(args, "limit", 100, 1)
    max_seconds = int_param(args, "max_seconds", DEFAULT_SECONDS, 1, MAX_SECONDS)
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    exclude_top = args.get("exclude_top_level_dirs", DEFAULT_EXCLUDE_TOP)
    if not isinstance(exclude_top, list) or not all(isinstance(x, str) and x and "/" not in x for x in exclude_top):
        fail("exclude_top_level_dirs must be a list of directory names (no slash); [] excludes nothing")
    unknown = sorted(k for k in args if k not in KNOWN_PARAMS)
    try:
        values = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)
    PROGRESS["values"] = values
    started = time.monotonic()

    real = os.path.realpath(root)
    notes = NoReplacePage("ransom_note_scan", [real, "notes"], limit)
    occurrences = NoReplacePage("ransom_note_scan", [real, "occurrences"], limit)
    rejected = NoReplacePage("ransom_note_scan", [real, "name matches not read"], limit)
    exceptions = NoReplacePage("ransom_note_scan", [real, "directories and entries not read"], limit)
    exclusions = []
    counters = {"directories_visited": 0, "directories_failed": 0, "directories_excluded": 0, "entries_failed": 0,
                "files_visited": 0, "name_matches": 0, "links_not_followed": 0, "special_files_skipped": 0, "notes_partly_scanned": 0}
    by_class = {}
    empty_files = 0
    totals = {}
    seen = {}
    capped = False
    distinct = {}
    contents = {}
    earliest = None
    note_serial = finding_serial = 0
    bytes_read = 0
    stopped = {}
    PROGRESS["coverage"] = counters

    # The first pass takes at most FIRST_PASS_SHARE of the time; the clock the rest of the run keeps is the one the caller set.
    STOP["deadline"] = started + max_seconds * FIRST_PASS_SHARE
    matched = values_pass(root, set(exclude_top), max_size)
    STOP["deadline"] = started + max_seconds
    # Unfinished, any name of 8 characters or more could be a value of a note not read yet: those are ordered like withheld names.
    hidden = (lambda entry: entry.path in matched) if matched is not None else (lambda entry: len(entry.name) >= 8)

    try:
        for path, size, mtime_ns in walk(root, set(exclude_top), exceptions, exclusions, rejected, counters, stopped, hidden):
            try:
                blob = read_note(path, max_size)
            except Unreadable as exc:
                row = {"path": shown(path), "status": "rejected", "reason": exc.reason}
                row.update({k: v for k, v in exc.extra.items() if k in ("bytes", "error")})
                rejected.add(row)
                if exc.reason == "the file is empty":
                    empty_files += 1
                continue
            bytes_read += len(blob)
            note_serial += 1
            note_id = "N%06d" % note_serial
            modified = iso_utc(mtime_ns)
            row = {"note_id": note_id, "bytes": len(blob), "mtime_ns": mtime_ns, "modified_utc": modified,
                   "parser": PARSER}
            if modified is None:
                row["mtime_error"] = "the modification time is outside what a datetime holds"
            elif earliest is None or mtime_ns < earliest[0]:
                earliest = (mtime_ns, note_id, modified)

            decoded = decode_note(blob)
            if decoded.get("binary"):
                sha, why = whole_file_digest(blob)
                count_content(contents, sha, blob, note_id)
                row.update({"sha256": sha, **({"sha256_withheld": why} if why else {})})
                row.update({"file": shown(path), "class": "binary_not_scanned", "class_basis": [],
                            "encoding": None, "encoding_basis": decoded["basis"], "decode_errors": None,
                            "format_hint": "binary", "indicator_counts": {}})
                by_class["binary_not_scanned"] = by_class.get("binary_not_scanned", 0) + 1
                notes.add(row)
                continue

            text = decoded["text"]
            offsets = Offsets(decoded)
            counts, note_values = {}, []
            cut = False
            for kind, pattern, group in KINDS:
                if cut:
                    break
                offsets.reset()
                for m in matches(pattern, text, kind):
                    if m is None or out_of_time():        # the clock runs inside a note too: a 16 MiB note holds millions of matches, or none
                        cut = True
                        break
                    value = m.group(group)
                    finding_serial += 1
                    finding_id = "F%06d" % finding_serial
                    offset = offsets.at(m.start(group))
                    validation = validate(kind, value)
                    counts[kind] = counts.get(kind, 0) + 1
                    stats = totals.setdefault(kind, {"occurrences": 0, "notes": 0})
                    stats["occurrences"] += 1
                    if counts[kind] == 1:
                        stats["notes"] += 1
                    if validation:
                        stats[validation] = stats.get(validation, 0) + 1
                    occ = {"finding_id": finding_id, "note_id": note_id, "kind": kind, "offset": offset,
                           "length": len(value), "encoding": decoded["name"]}
                    if validation:
                        occ["validation"] = validation
                    earlier = seen.get((kind, value))
                    if earlier:
                        occ["duplicate_of"] = earlier
                    elif len(seen) < DUPLICATE_CAP and len(value) <= DUPLICATE_VALUE_CAP:
                        seen[(kind, value)] = finding_id
                        distinct[kind] = distinct.get(kind, 0) + 1
                    else:
                        capped = True
                    occurrences.add(occ)
                    values.add(finding_id, {"note_id": note_id, "file": path, "offset": offset, "kind": kind,
                                            "encoding": decoded["name"], "validation": validation}, value)
                    if NAMEABLE[kind] and len(note_values) < NAME_VALUES_CAP:
                        note_values.append(value)

            lowered = text.lower()
            language = [w for w in LANGUAGE if w in lowered]
            basis = []
            if counts.get("onion"):
                basis.append("onion")
            if any(counts.get(k) for k in WALLET_KINDS):
                basis.append("wallet")
            if counts.get("tox"):
                basis.append("tox")
            if counts.get("identifier_candidate"):
                basis.append("identifier_candidate")
            if len(language) >= 2:
                basis.append("language")
            cls = "content_resembles_note" if len(basis) >= 2 else "filename_only"
            by_class[cls] = by_class.get(cls, 0) + 1
            if values.enabled:
                lines = [line.strip() for line in text.splitlines() if line.strip()][:4]
                values.add(note_id, {"note_id": note_id, "file": path, "offset": 0, "kind": "note_preview",
                                     "encoding": decoded["name"], "validation": None}, "\n".join(lines))
            sha, why = whole_file_digest(blob, text, set(note_values))
            count_content(contents, sha, blob, note_id)
            row.update({"sha256": sha, **({"sha256_withheld": why} if why else {})})
            row.update({"file": shown(path, note_values), "class": cls, "class_basis": basis,
                        "encoding": decoded["name"], "encoding_basis": decoded["basis"],
                        "decode_errors": decoded["decode_errors"], "format_hint": format_hint(text),
                        "indicator_counts": counts})
            if decoded["trailing_byte"]:
                row["trailing_byte"] = "an odd number of bytes: the last byte is not part of the decoded text"
            if cut:
                counters["notes_partly_scanned"] += 1
                row["scan_stopped"] = ("the time limit (max_seconds) was reached while this note was being scanned: the indicators after the "
                                       "ones counted here were not looked for")
            notes.add(row)
    finally:
        values.close()

    variants = NoReplacePage("ransom_note_scan", [real, "distinct note contents"], limit)
    for copies, first, sha in sorted(contents.values(), key=lambda e: (-e[0], e[1])):
        variants.add({"sha256": sha, "copies": copies, "first_note_id": first,
                      **({} if sha else {"digest_withheld": True})})
    for kind, n in distinct.items():
        totals[kind]["distinct_values"] = n

    pages = {"notes": notes.finish(), "occurrences": occurrences.finish(), "name_matches_not_read": rejected.finish(),
             "exceptions": exceptions.finish(), "distinct_note_contents": variants.finish()}
    OWN_NAMES.update(page["all_results"] for page in pages.values() if page.get("all_results"))
    if values.shown:
        OWN_NAMES.add(values.shown)
    unread = pages["name_matches_not_read"]["matched"]
    # An empty file has nothing in it to have missed; every other name match that was not read could.
    lost = unread - empty_files
    reasons = []
    if counters["directories_failed"] or counters["entries_failed"]:
        reasons.append("%d directories and %d entries could not be listed or examined" % (counters["directories_failed"], counters["entries_failed"]))
    if counters["directories_excluded"]:
        reasons.append("%d top-level directories were not read (exclude_top_level_dirs)" % counters["directories_excluded"])
    if lost:
        reasons.append("%d name matches were not read (larger than max_size, unreadable, a link or a special file, or the time limit was reached while "
                       "reading one)" % lost)
    if counters["notes_partly_scanned"]:
        reasons.append("%d notes were only partly scanned: the time limit (max_seconds %d) was reached while they were being scanned"
                       % (counters["notes_partly_scanned"], max_seconds))
    if stopped:
        reasons.append("the time limit (max_seconds %d) was reached: %d entries of the directory being read and at least %d directories were "
                       "not examined, so a note under them was not looked for" % (max_seconds, stopped["entries_not_examined"], stopped["directories_not_entered"]))
    if BOUNDARY["replaced"]:
        reasons.append("%d strings held an identifier-shaped text that the first rule missed and were replaced at the output (see boundary)"
                       % BOUNDARY["replaced"])
    candidate_count = sum(by_class.values())
    status = "partial" if reasons else "complete"
    basis = ("; ".join(reasons) if reasons else
             "every directory was listed and every file whose name matched was read or is listed as not read with its reason; "
             "the time limit was not reached")
    if status == "complete" and matched is None:
        basis += "; the first pass stopped by its share of the time limit (see first_pass): only the order of names that print alike is affected"
    print(json.dumps(release({
        "root": shown(root),
        "parser": PARSER,
        "complete": status,
        "status": status,
        "status_basis": basis,
        "partial_reasons": reasons,
        "candidate_count": candidate_count,
        "candidates_by_class": dict(sorted(by_class.items())),
        "rejected_count": unread,
        "notes": notes.page,
        "indicator_counts": {k: totals[k] for k in sorted(totals)},
        "duplicate_check": "capped: at most %d distinct values of %d characters or fewer are compared, others are not" % (DUPLICATE_CAP, DUPLICATE_VALUE_CAP) if capped else "complete",
        "occurrences": occurrences.page,
        "rejected": rejected.page,
        "distinct_note_contents": variants.page,
        "earliest_observed_note_mtime": (
            {"note_id": earliest[1], "modified_utc": earliest[2], "mtime_ns": earliest[0],
             "clock": "filesystem modification time as collected, UTC; extraction, copying and a restore change it",
             "caveat": "the least modification time among the candidates read: not the time the run started, not the "
                       "time any program executed, and not tied to the clock setting of any machine"}
            if earliest else None),
        "coverage": {**counters, "name_matches_read": candidate_count, "bytes_read": bytes_read, "max_size": max_size},
        "time_limit": {"max_seconds": max_seconds, "reached": bool(stopped), **stopped},
        "first_pass": ("complete: the notes were read for the values their paths hold before the walk was ordered" if matched is not None else
                       "stopped by its share of the time limit: names of 8 characters or more are ordered by the keyed hash alone, as withheld names are"),
        "exclusions": exclusions,
        "exceptions": exceptions.page,
        "pages": pages,
        "secret_values": values.summary(),
        "paths_withheld": WITHHELD_PATHS[0],
        **({"paths_note": "A name component that holds a token shaped like an identifier (the manifest gives the rates at which the shape "
                          "misses and at which it withholds an ordinary name), or a value the note held, is withheld "
                          "from every path in this answer and in the files it names, in notes, rejected name matches, directories "
                          "not listed and exclusions alike, once per printed path counted here; a harmless name can go with it. The real path is in the values file "
                          "when write_values was asked for; otherwise list the directory."}
           if WITHHELD_PATHS[0] else {}),
        "truncated": any(p["truncated"] for p in pages.values()),
        **({"unrecognised_parameters": unknown} if unknown else {}),
        "note": "Locator output: no identifier, wallet, onion address, URL, contact address or note text is in this answer or in "
                "any file it names, except the values file when write_values was asked for in a secret_output job. A name match "
                "is not a ransom note: `class` says whether the content also shows two kinds of note marker "
                "(content_resembles_note) or not (filename_only), and neither confirms anything. An indicator is a pattern "
                "match: checksum_valid says a bitcoin address's own checksum holds, not whose it is or that anyone paid it; "
                "syntactic_candidate is a match with no checksum this tool checks. name_matches_not_read lists every name "
                "match that was not read, with the reason; a note named otherwise, an image of a note and an encoding this tool "
                "does not detect are not found. Do NOT open any link found in a note from the examination host: visiting a leak "
                "site or a portal can identify the victim to the adversary and is a decision for the organisation, not for the "
                "examiner. Record in the report WHERE each indicator is (note id, offset, sealed job output), and hand a value "
                "over through the channel the operator named.",
    }), indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit as exc:
        if exc.code not in (0, None):
            drop_temporary_files()
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        drop_temporary_files()
        detail = describe(exc) if isinstance(exc, OSError) else "%s at %s" % (type(exc).__name__, where_it_failed(exc))
        fail("unexpected failure: %s" % detail)
