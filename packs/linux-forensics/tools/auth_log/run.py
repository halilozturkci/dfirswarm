#!/usr/bin/env python3
"""Read auth.log and secure as records rather than as text.

What this exists to get right, because doing it by hand with grep is where the mistakes are.

Rotation. The current file usually covers days, and an intrusion usually is not in it. auth.log.1,
auth.log.2.gz and the rest hold the rest. They are read oldest first by the suffix the rotation scheme
wrote (a number, a date, or none for the live file); the answer says which basis ordered each file and
whether the files' own time ranges agree with that order.

The missing year and the missing zone. A traditional syslog line carries a month, a day and a time and
no year and no zone, so every date is an inference until something supplies one. The year applied comes
from the file's modification time (which is the time of extraction on a copied tree) or from the
caller's `year`; the answer says which, per file, and each record carries its stamp as written
(`time_raw`), the year applied and `time_zone: "unknown"`. A year is counted only where the months wrap
forward through the year end; a line out of order by months is flagged `reordered` and placed by its
nearness to the lines around it, never counted as a second year end. An RFC 3339 stamp keeps its own
offset and its fraction of a second.

The shape of each line. "Accepted publickey for deploy from 10.0.0.5 ... ssh2: ED25519 SHA256:..."
names a key, not a person: the fingerprint maps to an entry in some authorized_keys file and says
nothing about when that entry was made. A PAM session is the named service's session (sshd, sudo, cron
and others), not necessarily a login. A line that matches no rule stays `other`, with its text.

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"). A sudo line carries a
whole command line, and a name typed at a prompt can be a password typed into the wrong field. The answer
therefore carries fields and locators (file, physical line, byte offset), the length of the text and never
the text: `raw` and `command` are in a file under $OUT only when `write_text: true` is asked, in a job, and
in the answer only with `preview_text: true`, in a job. The skill says the job runs with secret_output:
true. Nothing is hashed, and a secret never goes on a command line: this tool takes a path and flags.

A tool that fails loudly: a file it cannot open or read to its end is a named, partial file and not an
empty one; a line no rule places is counted, located and kept; `all_lines_parsed` is true only when every
line matched a syslog shape and every file was read through.
"""
import array
import datetime
import gzip
import ipaddress
import json
import math
import os
import re
import secrets
import stat
import sys
import tempfile
import time
import zlib
from pathlib import Path

TOOL = "auth_log"
PARSER = "auth_log/4"
DEFAULT_LIMIT = 200
FIRST_FAILURES = 20
MAX_LINE = 64 << 10         # a physical line longer than this is located, not parsed
DEFAULT_EXPANDED = 1 << 30  # a gzip stream is read to at most this many decompressed bytes
DEFAULT_SECONDS = 100.0     # the manifest allows 120
MAX_SECONDS = 105.0           # the most a caller may ask for (the manifest allows 120)
ZONE_SLACK = datetime.timedelta(hours=26)   # the log's zone is unknown: UTC-12 to UTC+14 is 26 hours
TEXT_NAME = "auth-text.jsonl"

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


# ---- The parts every tool of this pack that pages or keeps text copies (a tool is standalone; none imports another) ----


def fail(message, **extra):
    """An error answer: JSON, exit 1, and the same `status` every answer of this pack carries."""
    print(json.dumps({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def read_args():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def want_str(args, key, required=None):
    value = args.get(key)
    if value is None:
        if required:
            fail(required)
        return None
    if not isinstance(value, str):
        fail("%s must be a string" % key)
    if required and not value:
        fail(required)
    return value


def want_str_list(args, key):
    value = args.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        fail("%s must be a list of strings" % key)
    return value


def want_seconds(args, key, default, maximum=3600):
    """A time budget: a finite number above zero and no more than `maximum` (NaN and Infinity are not budgets)."""
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 or value > maximum:
        fail("%s must be a number of seconds above 0 and at most %d" % (key, maximum))
    return float(value)


def decode(data):
    """Bytes as text with no byte lost: an undecodable byte is a lone surrogate, which the text file writes as an escape
    and which encodes back to the byte (`blen` counts the bytes the original had)."""
    return data.decode("utf-8", "surrogateescape")


def blen(text):
    return len(text.encode("utf-8", "surrogateescape"))


def bound(value, limit=1024):
    """(shown, bytes or None): a string longer than `limit` characters is shown cut, with its whole length. The
    whole is kept where the record's text is kept (the text file, the evidence at the record's locator)."""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit], blen(value)
    return value, None


def want_flag(args, key):
    value = args.get(key, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_limit(args):
    limit = args.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive integer")
    return limit


def status_of(complete, failed, basis_complete, basis_partial, basis_failed):
    """The `status` every answer of this pack carries, with the reason for it: complete (everything the request asked
    for was read and nothing was left out), partial (some of it was, and the answer names what was not) or failed."""
    if failed:
        return {"status": "failed", "status_basis": basis_failed}
    if complete:
        return {"status": "complete", "status_basis": basis_complete}
    return {"status": "partial", "status_basis": basis_partial}


def touches_withheld_text(has_filter):
    """A filter that matches the text of a record is a search over text the answer withholds: it is honoured only in a job
    (whose output is sealed), and the answer says it was used."""
    return bool(has_filter) and in_job()


# Lossless paging (the same in every library tool that pages): the page an agent reads stays small, and when
# there are more rows the whole result is written as JSON Lines under work/<agent>/tool-output (in a job,
# $OUT/tool-output) and named. The file name is random: it is never a digest of anything asked for. A write
# that fails is an error answer naming the file, never a traceback and never a silent loss.
class LosslessPage:
    def __init__(self, tool, key, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page = []
        self.total = 0
        self._out = None
        self._tmp = None
        name = "%s-%s.jsonl" % (self.tool, secrets.token_hex(8))
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        try:
            self._out.write(json.dumps(row, ensure_ascii=False, default=str))
            self._out.write("\n")
        except OSError as exc:
            fail("the whole result could not be written to %s: %s" % (self.path, describe(exc)), paging_file=str(self.path))

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace")
            except OSError as exc:
                fail("the whole result could not be written: %s cannot be created (%s)" % (self.path, describe(exc)), paging_file=str(self.path))
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                os.replace(self._tmp, self.path)
            except OSError as exc:
                fail("the whole result could not be written to %s: %s" % (self.path, describe(exc)), paging_file=str(self.path))
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


def require_job(flag):
    """What leaves a record's text is held to the secret-safe output pattern (docs/packs.md, "Secrets and
    sensitive output"): the text goes into the answer or into a file only in a job, whose output the skill
    says to seal with secret_output: true. Outside a job the request is refused and nothing is written."""
    if not in_job():
        fail("%s is refused outside a job: a command line, a message or an environment value written or "
             "printed here would be an ordinary file or an ordinary answer, not a sealed output. Run this as "
             "job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, TOOL))


class TextRefused(Exception):
    pass


class TextFile:
    """Where the text of a tool's records goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan's SecretValues, for rows. With `enabled` false it
    writes nothing and `summary()` says so. Enabled, it is refused outside a job; inside one the file is
    created before anything is read (mode 0600, exclusively: a file or a link already at that name is
    refused by name) under $OUT, and the answer names it and says it may hold secrets. A byte that is not
    UTF-8 is written as a JSON escape of its lone surrogate and reads back as the byte: the file keeps the whole.
    """

    def __init__(self, name, enabled, what, flag="write_text"):
        self.enabled = enabled
        self.written = 0
        self.what = what
        self.flag = flag
        self._fh = None
        self.path = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise TextRefused("%s is refused outside a job: the text of the records written here would be an "
                              "ordinary file, not a sealed output. Run this as job_run tool=%s with secret_output: "
                              "true, and ask again there. Nothing was written." % (flag, TOOL))
        self.path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise TextRefused("the text file already exists: %s" % self.path)
        except OSError as exc:
            raise TextRefused("the text file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "wb")

    def _put(self, data):
        try:
            self._fh.write(data)
        except OSError as exc:
            fail("the text file could not be written: %s (%s)" % (self.path, describe(exc)), text_file=str(self.path))

    def add(self, row):
        if self._fh is None:
            return
        self._put(json.dumps(row, ensure_ascii=False, default=str).encode("utf-8", "backslashreplace") + b"\n")
        self.written += 1

    def add_bytes_raw(self, data):
        """A piece of a source's own bytes, written as it came; the record it belongs to is counted by count_record."""
        if self._fh is not None:
            self._put(data)

    def count_record(self):
        if self._fh is not None:
            self.written += 1

    def add_bytes(self, data):
        """One record exactly as its source wrote it (a native export's line, newline included)."""
        if self._fh is None:
            return
        self._put(data)
        self.written += 1

    def close(self):
        if self._fh is not None:
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()
            except OSError as exc:
                fail("the text file could not be closed: %s (%s)" % (self.path, describe(exc)), text_file=str(self.path))
            self._fh = None

    def summary(self, preview=False):
        """What the answer says about text. `preview` is true when the answer itself carries it (preview_text)."""
        shown = {"answer_contains_text_that_may_hold_secrets": bool(preview)}
        if not self.enabled:
            hint = ("No text of any record is in a file." if not preview else
                    "The answer's records carry their text (preview); no file of it was written, and the paging file, if there is one, holds none.")
            return {"requested": False, "written": 0, "file": None, "contains_text_that_may_hold_secrets": False, **shown,
                    "hint": hint + " %s: true, in a job run with secret_output: true, keeps the whole of each record in a private file under $OUT." % self.flag}
        return {"requested": True, "written": self.written, "file": self.shown,
                "contains_text_that_may_hold_secrets": self.written > 0, **shown, "format": self.what}


TRADITIONAL = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d{1,10})\])?:\s*(?P<msg>.*)$")
ISO = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d{1,10})\])?:\s*(?P<msg>.*)$")
ISO_PARTS = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")

# The ssh key that follows "ssh2:" in an acceptance: "TYPE FINGERPRINT", or for a certificate
# "TYPE-CERT FINGERPRINT ID <key id> (serial N) CA TYPE FINGERPRINT".
KEY_CERT = re.compile(
    r"^(?P<keytype>\S+)\s+(?P<fingerprint>\S+)\s+ID\s(?P<cert_id>.*)\s\(serial\s(?P<cert_serial>\d{1,20})\)\s"
    r"CA\s(?P<ca_keytype>\S+)\s(?P<ca_fingerprint>\S+)\s*$")
KEY_PLAIN = re.compile(r"^(?P<keytype>\S+)\s+(?P<fingerprint>\S+)\s*$")

# Explicit variants, one per message form. Fields are named for what the line says; a value that is not an
# address is never a `source`.
RULES = [
    ("ssh_accepted", re.compile(
        r"^Accepted (?P<method>\S+) for (?P<user>.+?) from (?P<source>\S+) port (?P<port>\d+)(?: ssh2)?"
        r"(?::\s*(?P<key>.*))?")),
    ("ssh_failed", re.compile(
        r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.+?) from (?P<source>\S+) "
        r"port (?P<port>\d+)(?: ssh2)?(?::\s*(?P<key>.*))?")),
    ("ssh_invalid_user", re.compile(r"^Invalid user (?P<user>.*?) from (?P<source>\S+)(?: port (?P<port>\d+))?")),
    ("ssh_disconnect", re.compile(
        r"^Received disconnect from (?P<source>\S+) port (?P<port>\d+):(?P<disconnect_code>\d{1,6}):\s*(?P<reason>.*)$")),
    ("ssh_disconnect", re.compile(
        r"^Disconnected from (?:(?P<role>authenticating user|invalid user|user) (?P<user>.+?) )?"
        r"(?P<source>\S+)(?: port (?P<port>\d+))?(?P<stage>.*)$")),
    ("key_observed_authentication", re.compile(
        r"^Accepted key (?P<keytype>\S+) (?P<fingerprint>\S+)"
        r"(?: found at (?P<authorized_keys_file>.+?):(?P<authorized_keys_line>\d+))?")),
    ("sudo", re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.*)$")),
    ("sudo_failed", re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*(?:\d+ incorrect password attempts?|user NOT in sudoers|command not allowed)")),
    ("su", re.compile(r"^(?:\(to (?P<target>\S+)\) (?P<user>\S+)(?: on (?P<tty>\S+))?|"
                      r"Successful su for (?P<target2>\S+) by (?P<user2>\S+))")),
    ("su_failed", re.compile(r"^FAILED su for (?P<target>\S+) by (?P<user>\S+)")),
    ("session_opened", re.compile(
        r"^pam_unix\((?P<pam_service>[^:)]*):session\): session opened for user (?P<user>[^\s(]+)"
        r"(?:\(uid=(?P<uid>-?\d+)\))?(?: by (?P<by>[^\s(]*)(?:\(uid=(?P<by_uid>-?\d+)\))?)?")),
    ("session_closed", re.compile(
        r"^pam_unix\((?P<pam_service>[^:)]*):session\): session closed for user (?P<user>[^\s(]+)(?:\(uid=(?P<uid>-?\d+)\))?")),
    ("auth_failure", re.compile(r"^pam_unix\((?P<pam_service>[^:)]*):auth\): authentication failure;(?P<kv>.*)$")),
    ("account_added", re.compile(
        r"^new (?P<what>user|group): name=(?P<name>[^,]+)(?:, UID=(?P<uid>\d+))?(?:, GID=(?P<gid>\d+))?"
        r"(?:, home=(?P<home>[^,]*))?(?:, shell=(?P<shell>[^,]*))?")),
    ("account_changed", re.compile(
        r"^(?:pam_unix\([^)]*:chauthtok\): )?(?:changed password|password changed) for (?P<user>\S+)")),
]
KINDS = sorted({k for k, _ in RULES} | {"other"})
INT_FIELDS = ("port", "uid", "by_uid", "gid", "cert_serial", "authorized_keys_line", "disconnect_code")
# The key=value pairs of a pam_unix authentication failure that become fields. Any other key in the line is the
# line's own text (a typed user name can contain "key=value"), and a key can never overwrite a locator field.
PAM_KEYS = ("logname", "uid", "euid", "tty", "ruser", "rhost", "user")
# Fields a line's text can never set: they are the tool's own.
RESERVED = {"user_bytes", "user_withheld", "id", "parser", "file", "line", "byte_offset", "time", "time_raw", "time_zone", "time_utc", "year", "host",
            "process", "pid", "kind", "reordered", "time_error", "text_bytes", "command_bytes", "raw", "line_text"}
# What is the text of a line and not a field of it: held back from the answer, kept in the text file.
TEXT_FIELDS = ("raw", "command")


def address_ok(text):
    try:
        ipaddress.ip_address(text.split("%", 1)[0])
        return True
    except ValueError:
        return False


def finish(kind, fields):
    """(fields, typed): the fields a line gives, and the names among them that are text someone typed at a prompt,
    where the log itself says there is no such account (an invalid user) or the form does not say (a PAM `user=`)."""
    typed = []
    if kind in ("ssh_accepted", "ssh_failed"):
        key = fields.pop("key", None)
        if key:
            found = KEY_CERT.match(key) or KEY_PLAIN.match(key)
            if found:
                fields.update({k: v for k, v in found.groupdict().items() if v})
            else:
                fields["key_text_unparsed"] = True
    if kind == "ssh_failed":
        if fields.pop("invalid", None):
            fields["invalid_user"] = True
            typed.append("user")
    if kind == "ssh_invalid_user":
        typed.append("user")
    if kind == "ssh_disconnect":
        role = fields.pop("role", None)
        if role:
            fields["user_role"] = role
            if role == "invalid user":
                typed.append("user")
        stage = (fields.pop("stage", "") or "").strip()
        if stage:
            fields["stage"] = stage
    if kind == "auth_failure":
        # One pass, linear: split on whitespace and read `key=value` tokens. (A pattern for them was quadratic.)
        for token in (fields.pop("kv", "") or "").split():
            key, eq, value = token.partition("=")
            if not eq or value == "" or key not in PAM_KEYS:
                continue
            fields["source" if key == "rhost" else key] = value
        if "user" in fields:
            typed.append("user")
    if kind == "su":
        for plain in ("target", "user"):
            if plain + "2" in fields:
                fields[plain] = fields.pop(plain + "2")
    if "source" in fields and not address_ok(fields["source"]):
        fields["source_unvalidated"] = fields.pop("source")
    for key in INT_FIELDS:
        if key in fields:
            try:
                fields[key] = int(fields[key])
            except ValueError:
                fields.pop(key)
    return {k: v for k, v in fields.items() if k not in RESERVED}, typed


def classify(message):
    for kind, pattern in RULES:
        found = pattern.match(message)
        if found:
            fields = {k: v for k, v in found.groupdict().items() if v not in (None, "")}
            return (kind,) + finish(kind, fields)
    return "other", {}, []


# --- the files and their order ---------------------------------------------------------------------

def rotation_basis(path):
    """(rank, key, basis): oldest first. A number is a rotation count (a higher one is older), a date is
    that day, and the live file is the newest. Anything else is ordered by name, and said so."""
    name = os.path.basename(path)
    found = re.search(r"[-.]((?:19|20)\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))(?:\.gz)?$", name)
    if found:
        return 1, int(found.group(1)), "date suffix"
    found = re.search(r"\.(\d{1,6})(?:\.gz)?$", name)
    if found:
        return 1, -int(found.group(1)), "numeric rotation suffix"
    if re.fullmatch(r"(?:auth\.log|secure)", name):
        return 2, 0, "current file"
    return 0, 0, "name only"


class FileState:
    def __init__(self, path):
        self.path = path
        self.errors = []
        self.compression = "none"
        self.lines_before_error = 0


def open_binary(path, state):
    raw = open(path, "rb")
    magic = raw.read(2)
    raw.seek(0)
    if magic == b"\x1f\x8b":
        state.compression = "gzip"
        return gzip.GzipFile(fileobj=raw)
    raw.seek(0)
    head = raw.read(6)
    raw.seek(0)
    for name, signature in (("bzip2", b"BZh"), ("xz", b"\xfd7zXZ\x00"), ("zstd", b"\x28\xb5\x2f\xfd")):
        if head.startswith(signature):
            raw.close()
            raise OSError("this file is %s-compressed: only gzip is read here; decompress a copy with the tool that made it and read that" % name)
    return raw


def physical_lines(path, state, expanded_cap=None):
    """(line number, byte offset, bytes or None when over MAX_LINE, bytes in the line) for each physical line.

    A read or a decompression error ends the iteration, is recorded in state.errors with where it
    happened, and is not raised: what was read before it is kept. The offset is into the stream as it
    comes out (the decompressed one for a gzip file); a gzip stream that expands past `expanded_cap`
    bytes ends there as a recorded error, so a compression bomb costs a bounded amount of work."""
    try:
        handle = open_binary(path, state)
    except OSError as exc:
        state.errors.append({"file": path, "error": describe(exc), "line": 0, "byte_offset": 0})
        return
    offset, number = 0, 0
    try:
        with handle:
            while True:
                chunk = handle.readline(MAX_LINE + 1)
                if not chunk:
                    return
                length = len(chunk)
                if expanded_cap is not None and state.compression == "gzip" and offset + length > expanded_cap:
                    state.errors.append({"file": path, "error": "the decompressed stream passed max_expanded_bytes (%d): not read past it" % expanded_cap,
                                         "line": number, "byte_offset": offset})
                    return
                if length > MAX_LINE and not chunk.endswith(b"\n"):
                    # Read on to the end of the line without holding it.
                    while True:
                        more = handle.readline(MAX_LINE + 1)
                        length += len(more)
                        if expanded_cap is not None and state.compression == "gzip" and offset + length > expanded_cap:
                            state.errors.append({"file": path, "error": "the decompressed stream passed max_expanded_bytes (%d): not read past it" % expanded_cap,
                                                 "line": number + 1, "byte_offset": offset})
                            return
                        if not more or more.endswith(b"\n"):
                            break
                    number += 1
                    yield number, offset, None, length
                    offset += length
                    continue
                number += 1
                yield number, offset, chunk, length
                offset += length
    except (OSError, EOFError, zlib.error) as exc:
        state.errors.append({"file": path, "error": describe(exc), "line": number, "byte_offset": offset})


# --- months, years, zones ---------------------------------------------------------------------------

FIRST, SAME, FORWARD, ROLLOVER, REORDERED = range(5)


def circular(a, b):
    return min((a - b) % 12, (b - a) % 12)


def classify_months(months):
    """How each line's month relates to the lines before and after it: (a bytearray of FIRST, SAME, FORWARD, ROLLOVER or
    REORDERED, the number of rollovers, the indexes of the first few).

    A month that goes up is the log moving on, however long the gap (a machine that was off for eight months wrote
    January and then September of one year). A month that goes down is a year end when it comes within six months
    after the last one (Dec to Jan), and a step back in time otherwise. And a line that the next line contradicts is
    out of order whichever way it points: one that is further from the last in-order month than the line after it is
    (January, March, January: the March line is the stray; January, December, January: the December one). The last
    line has no next line, so a downward step of more than six months is all it can show.

    A line out of order does not move the place the next one is compared with. Only lines whose date and clock exist
    are given to this."""
    n = len(months)
    out = bytearray(n)
    prev, rollovers, where = None, 0, []
    for i in range(n):
        m = months[i]
        if prev is None:
            out[i], prev = FIRST, m
            continue
        if m == prev:
            out[i] = SAME
            continue
        if i + 1 < n:
            nx = months[i + 1]
            stray = nx != m and circular(prev, nx) < circular(prev, m)
        else:
            stray = m < prev and (m - prev) % 12 > 6
        if stray or (m < prev and (m - prev) % 12 > 6):
            out[i] = REORDERED
            continue
        if m < prev:
            out[i] = ROLLOVER
            rollovers += 1
            if len(where) < 20:
                where.append(i)
        else:
            out[i] = FORWARD
        prev = m
    return out, rollovers, where


def valid_clock(day_time):
    h, m, s = (int(x) for x in day_time.split(":"))
    return h < 24 and m < 60 and s < 61


def anchor_year(last, mtime):
    """The year of the last in-order line: the latest year in which that date is no later than the file's
    modification time plus the 26 hours the log's unknown zone allows."""
    limit = mtime + ZONE_SLACK
    year = limit.year
    for _ in range(8):
        try:
            when = datetime.datetime(year, *last)
        except ValueError:
            year -= 1
            continue
        if when <= limit:
            return year
        year -= 1
    return None


def traditional_time(year, month, day, clock):
    try:
        h, m, s = (int(x) for x in clock.split(":"))
        return datetime.datetime(year, month, day, h, m, min(s, 59)), None
    except ValueError:
        return None, "no such date or time: month %d day %d %s in %d" % (month, day, clock, year)


def iso_time(stamp):
    """(time, time_utc, time_zone, error, notes) for an RFC 3339 stamp, its fraction kept. `time` is the clock reading as
    written, with no zone designator; `time_utc` is the same instant in UTC and exists only where the stamp carries
    its zone."""
    found = ISO_PARTS.match(stamp)
    if not found:
        return None, None, "unknown", "stamp does not match RFC 3339", []
    y, mo, d, h, mi, s, frac, zone = found.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    note = []
    if frac and len(frac) > 6:
        note.append("the fraction has %d digits and is kept to 6" % len(frac))
    second = int(s)
    if second == 60:
        second = 59
        note.append("second 60 (a leap second) is shown as 59")
    try:
        naive = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), second, micro)
    except ValueError:
        return None, None, zone or "unknown", "no such date or time in the stamp", note
    shown = naive.isoformat()
    if zone is None:
        return shown, None, "unknown", None, note
    if zone == "Z":
        offset, kept = datetime.timedelta(0), "Z"
    else:
        digits = zone[1:].replace(":", "")
        hours, minutes = int(digits[:2]), int(digits[2:])
        if hours > 23 or minutes > 59:
            return shown, None, zone, "the zone offset %s is not a valid offset" % zone, note
        offset = datetime.timedelta(hours=hours, minutes=minutes)
        offset = offset if zone[0] == "+" else -offset
        kept = "%s%02d:%02d" % (zone[0], hours, minutes)
    try:
        utc = (naive - offset).isoformat() + "Z"
    except OverflowError:
        return shown, None, kept, "the stamp in UTC is outside the range of a date", note
    return shown, utc, kept, None, note


# --- the run -----------------------------------------------------------------------------------------

def short_fields(fields):
    """The fields as the answer shows them: a long free-text value is cut at 256 characters and its whole length said.
    The whole is in the text file (write_text) and in the evidence at the record's locator."""
    shown, cut = {}, {}
    for key, value in fields.items():
        value, whole = bound(value, 256)
        shown[key] = value
        if whole is not None:
            cut[key] = whole
    if cut:
        shown["truncated_fields"] = cut
    return shown


def shown_text(row):
    """What `contains` may match outside a job: the fields the answer shows, and nothing it withholds."""
    return " ".join(str(v) for k, v in row.items() if v is not None and k not in ("id", "parser", "byte_offset", "text_bytes"))


class Overtime(Exception):
    pass


def main():
    args = read_args()
    path = want_str(args, "path", "path is required: an auth.log or secure file, or a directory holding them")
    if os.path.islink(path):
        fail("refusing a symlink: pass the log file or directory inside the evidence", path=path,
             target=os.readlink(path))
    limit = want_limit(args)
    write_text, preview_text = want_flag(args, "write_text"), want_flag(args, "preview_text")
    if preview_text:
        require_job("preview_text")
    year_arg = args.get("year")
    if year_arg is not None and (isinstance(year_arg, bool) or not isinstance(year_arg, int) or not 1970 <= year_arg <= 2200):
        fail("year must be a whole year between 1970 and 2200")
    wanted = set(want_str_list(args, "kinds"))
    if "key_added" in wanted:
        fail("key_added was renamed key_observed_authentication: an `Accepted key` line is sshd matching a "
             "login against an authorized_keys entry, not a key being installed", known=KINDS)
    unknown = sorted(wanted - set(KINDS))
    if unknown:
        fail("unknown kinds: %s" % ", ".join(unknown), known=KINDS)
    needle = (want_str(args, "contains") or "").lower()
    expand_cap = args.get("max_expanded_bytes", DEFAULT_EXPANDED)
    if isinstance(expand_cap, bool) or not isinstance(expand_cap, int) or expand_cap < 1:
        fail("max_expanded_bytes must be a positive integer")
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    deadline = time.monotonic() + seconds

    walk_errors, skipped_symlinks, skipped_special, targets = [], [], [], []

    def regular(candidate):
        try:
            if os.path.islink(candidate):
                skipped_symlinks.append({"file": candidate, "target": os.readlink(candidate)})
                return False
            if not stat.S_ISREG(os.lstat(candidate).st_mode):
                skipped_special.append({"file": candidate, "reason": "not a regular file (a pipe, a socket or a device): never opened"})
                return False
        except OSError as exc:
            walk_errors.append({"path": candidate, "error": describe(exc)})
            return False
        return True

    try:
        is_dir = os.path.isdir(path)
        exists_ = os.path.lexists(path)
    except OSError as exc:
        fail("the path cannot be examined", path=path, reason=describe(exc))
    if is_dir:
        def on_error(exc):
            walk_errors.append({"path": getattr(exc, "filename", None), "error": describe(exc)})
        for root, dirs, names in os.walk(path, onerror=on_error):
            for name in list(dirs):
                if os.path.islink(os.path.join(root, name)):
                    skipped_symlinks.append({"file": os.path.join(root, name), "target": os.readlink(os.path.join(root, name))})
                    dirs.remove(name)
            for name in names:
                if re.match(r"^(auth\.log|secure)", name):
                    candidate = os.path.join(root, name)
                    if regular(candidate):
                        targets.append(candidate)
    elif exists_:
        try:
            special = not stat.S_ISREG(os.lstat(path).st_mode)
        except OSError as exc:
            fail("the path cannot be examined", path=path, reason=describe(exc))
        if special:
            fail("not a regular file or a directory: a pipe, a socket or a device is never opened", path=path)
        targets = [path]
    else:
        fail("no such file or directory", path=path)
    if not targets:
        fail("no auth.log or secure file found there", path=path, skipped_symlinks=skipped_symlinks,
             skipped_special=skipped_special, walk_errors=walk_errors)
    ranked = sorted(((rotation_basis(t), t) for t in targets), key=lambda row: (row[0][0], row[0][1], row[1]))
    schemes = {basis for (rank, _k, basis), _t in ranked if rank == 1}

    try:
        text = TextFile(TEXT_NAME, write_text, "JSON Lines, mode 0600: the record's id, locator and fields as in the answer, "
                        "with `raw` (the message), `command` (a sudo command line), a typed `user` and `line_text` (the physical line)")
    except TextRefused as exc:
        fail(str(exc))
    page = LosslessPage(TOOL, "records", limit)
    unparsed_page = LosslessPage(TOOL, "unparsed", limit)
    preview_rows = []

    files, read_errors, by_kind = [], [], {}
    counts = {"physical": 0, "blank": 0, "read": 0, "unparsed": 0, "time_errors": 0, "invalid_utf8": 0}
    seq = 0
    not_reached = []
    hit_deadline = False

    def tick(n):
        if n % 4096 == 0 and time.monotonic() > deadline:
            raise Overtime()

    for (rank, _key, basis), target in ranked:
        if hit_deadline:
            not_reached.append(target)
            continue
        state = FileState(target)
        info = {"path": target, "order_basis": basis, "compression": "none", "size": None, "modified": None,
                "physical_lines": 0, "unparsed_lines": 0, "records": 0, "formats": {}, "year_basis": None,
                "first_year": None, "last_year": None, "rollovers": 0, "rollover_lines": [], "reordered_lines": 0,
                "first_time": None, "last_time": None, "partial": False}
        try:
            info["size"] = os.path.getsize(target)
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(target), datetime.timezone.utc).replace(tzinfo=None)
            info["modified"] = mtime.isoformat() + "Z"
        except (OSError, ValueError, OverflowError):
            mtime = None
        # Pass one: the months of every line whose date exists, and the packed date of each, so that the year of the
        # last in-order line can be worked back through the year ends the months show.
        months, packed, numbers = array.array("b"), array.array("q"), array.array("q")
        try:
            for n, (_n, _o, chunk, _l) in enumerate(physical_lines(target, state, expand_cap)):
                tick(n)
                if chunk is None:
                    continue
                found = TRADITIONAL.match(decode(chunk).rstrip("\r\n"))
                if not found or found.group("mon") not in MONTHS:
                    continue
                month, day = MONTHS[found.group("mon")], int(found.group("day"))
                try:
                    datetime.datetime(2000, month, day)
                    valid = valid_clock(found.group("time"))
                except ValueError:
                    valid = False
                if not valid:
                    continue            # a date that does not exist says nothing about which way the months run
                h, m, sec = (int(x) for x in found.group("time").split(":"))
                months.append(month)
                numbers.append(_n)
                packed.append((((month * 32 + day) * 24 + h) * 60 + m) * 61 + sec)
        except Overtime:
            hit_deadline = True
            read_errors.append({"file": target, "error": "max_seconds (%s) passed while reading this file: it was not read further" % seconds, "line": None, "byte_offset": None})
            info["partial"] = True
            files.append(info)
            continue
        classes, rollovers, where = classify_months(months)
        info["rollovers"], info["rollover_lines"] = rollovers, [numbers[i] for i in where]
        info["reordered_lines"] = sum(1 for c in classes if c == REORDERED)
        last_valid = None
        for i in range(len(classes) - 1, -1, -1):
            if classes[i] != REORDERED:
                v = packed[i]
                v, sec = divmod(v, 61)
                v, m = divmod(v, 60)
                v, h = divmod(v, 24)
                month, day = divmod(v, 32)
                last_valid = (month, day, h, m, sec)
                break
        if year_arg is not None:
            first_year, info["year_basis"] = year_arg, "argument"
            info["year_argument_spans_rollover"] = rollovers > 0
        elif mtime is not None and last_valid is not None:
            anchor = anchor_year(last_valid, mtime)
            first_year = None if anchor is None else anchor - rollovers
            info["year_basis"] = "file mtime (UTC, with 26 hours allowed for the log's unknown zone; on a copied tree it is the time of the copy)"
        else:
            first_year, info["year_basis"] = None, "none: no readable modification time or no dated line"
        # Pass two: the records.
        state = FileState(target)
        year, cursor, valid_index = first_year, None, 0
        try:
            for number, offset, chunk, length in physical_lines(target, state, expand_cap):
                tick(number)
                counts["physical"] += 1
                info["physical_lines"] += 1
                if chunk is None:
                    counts["unparsed"] += 1
                    info["unparsed_lines"] += 1
                    row = {"file": target, "line": number, "byte_offset": offset, "bytes": length, "reason": "line longer than %d bytes: located, not parsed" % MAX_LINE}
                    unparsed_page.add(row)
                    text.add({"record_type": "unparsed", **row, "line_text": None})
                    continue
                if b"\xff" in chunk or not chunk.isascii():
                    try:
                        chunk.decode("utf-8")
                    except UnicodeDecodeError:
                        counts["invalid_utf8"] += 1
                line = decode(chunk)
                if line.endswith("\n"):
                    line = line[:-1]
                if line.endswith("\r"):
                    line = line[:-1]
                if not line.strip():
                    counts["blank"] += 1
                    continue
                counts["read"] += 1
                found = TRADITIONAL.match(line)
                iso = None if found else ISO.match(line)
                reason = None
                if found and found.group("mon") not in MONTHS:
                    reason, found = "unknown month %r: not placed in any year" % found.group("mon"), None
                elif not found and not iso:
                    reason = "not a syslog line"
                if reason:
                    counts["unparsed"] += 1
                    info["unparsed_lines"] += 1
                    row = {"file": target, "line": number, "byte_offset": offset, "bytes": length, "reason": reason}
                    unparsed_page.add(row)
                    text.add({"record_type": "unparsed", **row, "line_text": line})
                    continue
                parts = (found or iso).groupdict()
                time_fields, range_key = {}, None
                if found:
                    info["formats"]["traditional"] = info["formats"].get("traditional", 0) + 1
                    month, day = MONTHS[parts["mon"]], int(parts["day"])
                    try:
                        datetime.datetime(2000, month, day)
                        exists = valid_clock(parts["time"])
                    except ValueError:
                        exists = False
                    cls = None
                    if exists:
                        cls = classes[valid_index] if valid_index < len(classes) else SAME
                        valid_index += 1
                    reordered = cls == REORDERED
                    when, error, use = None, None, None
                    if year_arg is not None:
                        use = year_arg
                        when, error = traditional_time(use, month, day, parts["time"])
                    else:
                        if cls == ROLLOVER and year is not None:
                            year += 1
                        if year is None:
                            error = "no year could be applied (%s)" % info["year_basis"]
                        elif not exists:
                            use = year
                            when, error = traditional_time(use, month, day, parts["time"])
                        elif reordered and cursor is not None:
                            # Out of order: the year that puts it nearest the lines around it.
                            best = None
                            for candidate in (year - 1, year, year + 1):
                                dt, _err = traditional_time(candidate, month, day, parts["time"])
                                if dt is not None and (best is None or abs(dt - cursor) < abs(best[0] - cursor)):
                                    best = (dt, candidate)
                            if best:
                                when, use = best
                            else:
                                error = "no such date or time: month %d day %d %s" % (month, day, parts["time"])
                        else:
                            use = year
                            when, error = traditional_time(use, month, day, parts["time"])
                    if when is not None and not reordered:
                        cursor = when
                        range_key = when.isoformat()
                        info["first_year"] = info["first_year"] or when.year
                        info["last_year"] = when.year
                    time_fields = {"time": when.isoformat() if when else None,
                                   "time_raw": line[:found.start("host")].rstrip(),
                                   "time_zone": "unknown", "time_utc": None, "year": use if when else None}
                    if error:
                        time_fields["time_error"] = error
                    if parts["time"].endswith(":60") and when is not None:
                        time_fields["time_note"] = "second 60 (a leap second) is shown as 59"
                    if reordered:
                        time_fields["reordered"] = True
                else:
                    info["formats"]["rfc3339"] = info["formats"].get("rfc3339", 0) + 1
                    shown, utc, zone, error, notes = iso_time(parts["stamp"])
                    time_fields = {"time": shown, "time_raw": parts["stamp"], "time_zone": zone, "time_utc": utc}
                    if error:
                        time_fields["time_error"] = error
                    if notes:
                        time_fields["time_note"] = "; ".join(notes)
                    range_key = utc.rstrip("Z") if utc else shown
                if range_key:
                    info["first_time"] = info["first_time"] or range_key
                    info["last_time"] = range_key
                if time_fields.get("time_error"):
                    counts["time_errors"] += 1
                kind, fields, typed = classify(parts["msg"])
                by_kind[kind] = by_kind.get(kind, 0) + 1
                if wanted and kind not in wanted:
                    continue
                texts = {"raw": parts["msg"]}
                if "command" in fields:
                    texts["command"] = fields.pop("command")
                withheld = {}
                for name in typed:
                    if name in fields:
                        texts[name] = fields.pop(name)
                        withheld[name + "_bytes"] = blen(texts[name])
                        withheld[name + "_withheld"] = True
                row_core = {**time_fields, "host": parts.get("host"), "process": parts.get("proc"), "kind": kind, **short_fields(fields), **withheld}
                if needle:
                    # Outside a job `contains` matches the fields the answer shows; in a job it matches the whole line.
                    if needle not in (line.lower() if in_job() else shown_text(row_core).lower()):
                        continue
                seq += 1
                info["records"] += 1
                record_id = "A%06d" % seq
                row = {"id": record_id, "parser": PARSER, "file": target, "line": number, "byte_offset": offset,
                       **row_core, "pid": int(parts["pid"]) if parts.get("pid") else None,
                       "text_bytes": blen(parts["msg"])}
                if "command" in texts:
                    row["command_bytes"] = blen(texts["command"])
                text.add({**row, **fields, **texts, "line_text": line})
                page.add(row)
                if preview_text and len(preview_rows) < limit:
                    preview_rows.append({**row, **texts})
        except Overtime:
            hit_deadline = True
            read_errors.append({"file": target, "error": "max_seconds (%s) passed while reading this file: it was not read further" % seconds, "line": None, "byte_offset": None})
            info["partial"] = True
        info["compression"] = state.compression
        for err in state.errors:
            read_errors.append(err)
            info["partial"] = True
        files.append(info)
    text.close()

    # Do the files' own time ranges agree with the order they were read in?
    overlaps = []
    for earlier, later in zip(files, files[1:]):
        if earlier["last_time"] and later["first_time"] and later["first_time"] < earlier["last_time"]:
            overlaps.append({"earlier": earlier["path"], "later": later["path"], "earlier_last": earlier["last_time"], "later_first": later["first_time"]})
    pages = {"records": page.finish(), "unparsed": unparsed_page.finish()}
    all_parsed = counts["unparsed"] == 0 and not read_errors and not walk_errors and not skipped_special and not not_reached
    outcome = status_of(
        all_parsed, not files or all(f["partial"] and f["physical_lines"] == 0 for f in files),
        "every line of every file matched a syslog shape and every file was read through",
        "%d line(s) matched no syslog shape, %d read error(s), %d walk error(s), %d special file(s) not opened, %d file(s) not reached: "
        "the answer names each" % (counts["unparsed"], len(read_errors), len(walk_errors), len(skipped_special), len(not_reached)),
        "no file could be read")
    print(json.dumps({
        "parser": PARSER,
        **outcome,
        "path": path,
        "files": files,
        "file_count": len(files),
        "files_not_reached": not_reached,
        "mixed_rotation_schemes": len(schemes) > 1,
        "cross_file_order": "consistent" if not overlaps and len(schemes) <= 1 else ("overlap" if overlaps else "not established: more than one rotation scheme"),
        "cross_file_order_overlaps": overlaps,
        "physical_lines": counts["physical"],
        "blank_lines": counts["blank"],
        "lines_read": counts["read"],
        "unparsed_lines": counts["unparsed"],
        "lines_with_time_errors": counts["time_errors"],
        "lines_with_invalid_utf8": counts["invalid_utf8"],
        "by_kind": by_kind,
        "contains_scope": None if not needle else ("the whole line, in a job" if in_job() else "the fields the answer shows (outside a job the text is not matched)"),
        "filter_touched_withheld_text": touches_withheld_text(needle),
        "record_count": pages["records"]["matched"],
        "records": preview_rows if preview_text else page.page,
        "unparsed": unparsed_page.page,
        "pages": pages,
        "text": text.summary(preview_text),
        "all_lines_parsed": all_parsed,
        "read_errors": read_errors,
        "walk_errors": walk_errors,
        "skipped_symlinks": skipped_symlinks,
        "skipped_special": skipped_special,
        "truncated": any(p["truncated"] for p in pages.values()),
        "note": "A traditional syslog stamp carries no year and no zone: each file says the year basis applied "
                "(its modification time, which on a copied tree is the time of the copy, or your `year`) and each "
                "record keeps its stamp as written in time_raw, with `time` the clock reading as written and "
                "`time_utc` set only where the stamp carries its zone. A month that goes up is the log moving on "
                "however long the gap; a month that goes down is a year end only within six months after the last one, "
                "and a line the next line contradicts is flagged reordered and placed by nearness; rollover_lines "
                "names each year end that was read. all_lines_parsed says that every line matched a syslog shape "
                "and every file was read through; it is not coverage of the host's authentication events. An "
                "ssh_accepted line says sshd accepted an authentication: its fingerprint names a key, not a person, "
                "and not when the key was installed. A PAM session is the named service's, not necessarily a login. A "
                "user name typed at a prompt (an invalid user, a PAM user=) can be a password: it is not in the answer, "
                "only its length (user_bytes), and is in the text file. Text files are editable by root: compare the "
                "sessions that matter with wtmp (utmp_parse) and the journal, and treat a disagreement as a question to "
                "explain (rotation, forwarding, filtering, a damaged file and an edit all produce one), not as an answer.",
    }, indent=2))


if __name__ == "__main__":
    main()
