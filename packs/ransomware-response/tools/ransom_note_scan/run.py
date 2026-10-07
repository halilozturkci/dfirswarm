#!/usr/bin/env python3
"""Find the files whose names look like ransom notes, and say what is in them without reading it out.

A note is the one artefact the adversary wants read, which makes it easy to find. It
is also a place where access-bearing values live: a victim identifier, a "personal
key", a portal address that carries an access token, a wallet. This tool locates
those and counts them. It does not print them.

What it does, in order:

    walks a tree in name order and follows no link, and takes every regular file
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
     The skill says the job runs with `secret_output: true`. Outside a job the
     request is refused and nothing is written.
  3. The values file is JSON Lines, mode 0600, created exclusively before anything is
     scanned; each row names the answer's finding id, the note's real path and the
     byte offset. A preview of each note's first lines goes there too, and nowhere else.
  4. A secret is never on a command line. This tool takes a directory and flags only.
  5. Every path this tool prints (notes, rejected name matches, directories it could not
     list, exclusions, the root) has any component withheld that holds a token shaped like
     an identifier (eight or more letters and digits, both kinds present) or a value the
     note held. Some families put the victim's identifier in a name. The shape is a guess,
     so a harmless name can be withheld, and an identifier of another shape is printed as
     it is; list the directory for a name that was withheld. The values file keeps the
     real path.

What it does not locate: a long token with no label and no known shape (a 64-digit hex
string after the word "Token") is neither located nor counted.
"""
import datetime
import errno
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

PARSER = "ransom_note_scan/2"
DEFAULT_MAX_SIZE = 200000
MAX_SIZE_CEILING = 16 << 20
DEFAULT_EXCLUDE_TOP = ["proc", "sys", "dev"]
# Values seen are compared with each other to say "the same value as F000001" without
# saying the value; the comparison is held in memory, and capped.
DUPLICATE_CAP = 50000
# A value longer than this is not held for the comparison: a note can be 16 MiB of one URL.
DUPLICATE_VALUE_CAP = 1024
# The values of one note that are kept to withhold a path that carries one.
NAME_VALUES_CAP = 5000
# A note shorter than this is not digested: a digest of it is a digest of what it holds.
SHORT_NOTE = 128


# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output (in a job, $OUT/tool-output)
# and named. The file name is a digest of the page's key (a path), never of a value.
# Rows are written with ensure_ascii: a file name that is not UTF-8 reaches Python as lone
# surrogates, which a UTF-8 file cannot hold and a JSON escape can.
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

    def _write(self, row: object) -> None:
        assert self._out is not None
        self._out.write(json.dumps(row, ensure_ascii=True, default=str))
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
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


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
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id: str, locator: dict, value: str) -> None:
        if not self.enabled:
            return
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=True))
        self._fh.write("\n")
        self.written += 1

    def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

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
# Words that make a text read like a note. A list of words, not of values: nothing here is
# secret, and two of them together are a marker, not a finding.
LANGUAGE = ("decrypt", "your files", "encrypted", "ransom", "bitcoin", "private key",
            "tor browser", "restore your", "unlock", "payment")


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def describe(exc):
    """An error without the path it names: type, errno name and the system's own words."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


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

WITHHELD = "<identifier-shaped name withheld>"
PATHS_WITHHELD = [0]
TOKEN = re.compile(r"[A-Za-z0-9]{8,}")


def shaped(name):
    """A token of eight or more letters and digits with both kinds present: the shape of many identifiers."""
    for m in TOKEN.finditer(name):
        token = m.group(0)
        if any(c.isdigit() for c in token) and any(c.isalpha() for c in token):
            return True
    return False


def shown(path, values=()):
    """A path as it may be printed: every component that could carry an identifier is withheld.

    A component is withheld when it holds a token shaped like an identifier, or contains a value this
    note held (case-insensitive, eight characters or more). The same rule applies to every path this
    tool prints, so a name is never hidden on one line and printed on the next; a harmless directory
    name can be withheld with it, and the directory can be listed. The real path is in the values file.
    """
    if not isinstance(path, str):
        return path
    parts = path.split("/")
    for i, part in enumerate(parts):
        if not part:
            continue
        low = part.lower()
        if shaped(part) or any(len(v) >= 8 and v.lower() in low for v in values):
            parts[i] = WITHHELD
            PATHS_WITHHELD[0] += 1
    return "/".join(parts)


# --- the walk -----------------------------------------------------------------------

def kind_of(mode):
    for test, name in ((stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
                       (stat.S_ISCHR, "a character device"), (stat.S_ISDIR, "a directory")):
        if test(mode):
            return name
    return "a special file"


def walk(top, exclude_top, exceptions, exclusions, rejected, counters):
    """Yield (path, size, mtime_ns) of the regular files under `top` whose name looks like a note's.

    Directories and entries are taken in name order and no link is followed. A directory that
    cannot be listed is an exception; one skipped at the top by name is an exclusion; a name
    match that is a link, a special file or cannot be examined is a rejection with its reason.
    Anything that does not match by name is counted and not listed.
    """
    stack = [(top, True)]
    while stack:
        directory, is_top = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            counters["directories_failed"] += 1
            exceptions.add({"path": shown(directory), "status": "failed", "what": "directory",
                            "reason": "the directory could not be listed", "error": describe(exc)})
            continue
        counters["directories_visited"] += 1
        subdirs = []
        for entry in entries:
            named = bool(NAME_HINTS.search(entry.name))
            try:
                if entry.is_symlink():
                    counters["links_not_followed"] += 1
                    if named:
                        counters["name_matches"] += 1
                        rejected.add({"path": shown(entry.path), "status": "rejected",
                                      "reason": "a symbolic link: links are not followed, so the target was not read"})
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if is_top and entry.name in exclude_top:
                        counters["directories_excluded"] += 1
                        exclusions.append({"path": shown(entry.path),
                                           "reason": "named in exclude_top_level_dirs: a top-level %s directory of a Linux root; "
                                                     "its contents were not read. Name it as the root to read it" % shown(entry.name)})
                        continue
                    subdirs.append(entry.path)
                    continue
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                counters["entries_failed"] += 1
                if named:
                    counters["name_matches"] += 1
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
                    rejected.add({"path": shown(entry.path), "status": "rejected",
                                  "reason": "not a regular file (%s)" % kind_of(st.st_mode)})
                continue
            counters["files_visited"] += 1
            if named:
                counters["name_matches"] += 1
                yield entry.path, st.st_size, st.st_mtime_ns
        stack.extend((d, False) for d in reversed(subdirs))


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

KNOWN_PARAMS = {"root", "max_size", "limit", "write_values", "exclude_top_level_dirs"}


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
        fail("no such directory", root=root)
    max_size = int_param(args, "max_size", DEFAULT_MAX_SIZE, 16, MAX_SIZE_CEILING)
    limit = int_param(args, "limit", 100, 1)
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

    real = os.path.realpath(root)
    notes = LosslessPage("ransom_note_scan", [real, "notes"], limit)
    occurrences = LosslessPage("ransom_note_scan", [real, "occurrences"], limit)
    rejected = LosslessPage("ransom_note_scan", [real, "name matches not read"], limit)
    exceptions = LosslessPage("ransom_note_scan", [real, "directories and entries not read"], limit)
    exclusions = []
    counters = {"directories_visited": 0, "directories_failed": 0, "directories_excluded": 0, "entries_failed": 0,
                "files_visited": 0, "name_matches": 0, "links_not_followed": 0, "special_files_skipped": 0}
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

    try:
        for path, size, mtime_ns in walk(root, set(exclude_top), exceptions, exclusions, rejected, counters):
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
            for kind, pattern, group in KINDS:
                offsets.reset()
                for m in pattern.finditer(text):
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
                    if len(note_values) < NAME_VALUES_CAP:
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
            notes.add(row)
    finally:
        values.close()

    variants = LosslessPage("ransom_note_scan", [real, "distinct note contents"], limit)
    for copies, first, sha in sorted(contents.values(), key=lambda e: (-e[0], e[1])):
        variants.add({"sha256": sha, "copies": copies, "first_note_id": first,
                      **({} if sha else {"digest_withheld": True})})
    for kind, n in distinct.items():
        totals[kind]["distinct_values"] = n

    pages = {"notes": notes.finish(), "occurrences": occurrences.finish(), "name_matches_not_read": rejected.finish(),
             "exceptions": exceptions.finish(), "distinct_note_contents": variants.finish()}
    unread = pages["name_matches_not_read"]["matched"]
    # An empty file has nothing in it to have missed; every other name match that was not read could.
    lost = unread - empty_files
    reasons = []
    if counters["directories_failed"] or counters["entries_failed"]:
        reasons.append("%d directories and %d entries could not be listed or examined" % (counters["directories_failed"], counters["entries_failed"]))
    if counters["directories_excluded"]:
        reasons.append("%d top-level directories were not read (exclude_top_level_dirs)" % counters["directories_excluded"])
    if lost:
        reasons.append("%d name matches were not read (larger than max_size, unreadable, a link or a special file)" % lost)
    candidate_count = sum(by_class.values())
    print(json.dumps({
        "root": shown(root),
        "parser": PARSER,
        "complete": "partial" if reasons else "complete",
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
        "exclusions": exclusions,
        "exceptions": exceptions.page,
        "pages": pages,
        "secret_values": values.summary(),
        "paths_withheld": PATHS_WITHHELD[0],
        **({"paths_note": "A name component that holds a token shaped like an identifier, or a value the note held, is withheld "
                          "from every path in this answer and in the files it names, in notes, rejected name matches, directories "
                          "not listed and exclusions alike; a harmless name can go with it. The real path is in the values file "
                          "when write_values was asked for; otherwise list the directory."}
           if PATHS_WITHHELD[0] else {}),
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
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s: %s" % (type(exc).__name__, exc))
