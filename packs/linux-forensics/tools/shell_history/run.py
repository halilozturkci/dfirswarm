#!/usr/bin/env python3
"""Collect the shell and client history files under a tree, record by record, in the order the program wrote them.

A history file is not a log. It is written by the shell into the user's own home directory, so clearing
/var/log does nothing to it. It is also not a record of what ran: it holds what the program saved, when it
saved it (a killed shell may never have written its last session; concurrent sessions interleave and
overwrite; HISTCONTROL, HISTIGNORE and an unset HISTFILE leave nothing). Each record says how its
boundaries were found, because they are not the same everywhere:

    bash   with HISTTIMEFORMAT: a `#<epoch>` line, then the entry up to the next such line (a command that
           spans lines is one record). Without it each physical line is a record and a line that ends in
           a backslash is flagged: whether the next line continues it is not in the file.
    zsh    EXTENDED_HISTORY: `: <epoch>:<elapsed>;<command>`; a trailing backslash is read as zsh's
           escape for a newline inside the command, so a command that really ended in a backslash cannot
           be told from one that continues. A line with no header is a plain entry of that file. Bytes zsh
           stores in its Meta encoding (0x83 then the byte xor 0x20) are decoded and flagged.
    fish   `- cmd: <command>` with `when: <epoch>` and an optional `paths:` list; fish writes a newline in
           a command as the two characters \\n and a backslash as \\\\, both decoded.
    plain  every other client history (python, mysql, psql, redis-cli, node, sh, ash): one entry per
           physical line, no time. A client may escape characters its own way (the mysql client writes a
           space as \\040); the line is kept as written.

The directory a file is in is not the account that owns it. `user` is `unknown` unless the evidence's own
etc/passwd (read from the root given, when it holds one, or from `passwd`) says that exactly one account has
that home; the directory's name is `home_basename`, and is said to be only that.

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"). A command line can hold a
password, a token or a key (mysql -p..., curl -H "Authorization: ...", an export of a secret). The answer
therefore carries locators (file, physical lines, byte offset), the time, the program and the length of each
command, and never the command: `write_commands: true` writes every record's text to a file under $OUT
(mode 0600) and `preview_commands: true` puts it in the answer, each only in a job, which the skill says to
run with secret_output: true. Outside a job both are refused. No command is hashed or shortened.

A tool that fails loudly: a directory it could not open, a file it could not read to its end, a link it did
not follow, a top-level directory it left out and a file it knows and does not parse are each named; one
bad file never stops the sweep and never becomes an empty result.
"""
import datetime
import json
import math
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from pathlib import Path

TOOL = "shell_history"
PARSER = "shell_history/4"
DEFAULT_LIMIT = 200
FIRST_FAILURES = 20
MAX_PIECE = 8 << 20          # a physical line longer than this is read in pieces, none dropped
MAX_RECORD = 8 << 20         # a record longer than this is continued in the next one, none dropped
DEFAULT_SECONDS = 100.0
MAX_SECONDS = 105.0           # the most a caller may ask for (the manifest allows 120)
TEXT_NAME = "shell-history-commands.jsonl"

# file name -> (format, the program that writes it)
NAMES = {
    ".bash_history": ("bash", "bash"), ".zsh_history": ("zsh", "zsh"), "fish_history": ("fish", "fish"),
    ".sh_history": ("plain", "sh"), ".ash_history": ("plain", "ash"), ".history": ("plain", "shell or client"),
    ".python_history": ("plain", "python"), ".mysql_history": ("plain", "mysql"), ".psql_history": ("plain", "psql"),
    ".rediscli_history": ("plain", "redis-cli"), ".node_repl_history": ("plain", "node"),
}
# Known files that are not command histories: named, not read as if they were.
NOT_PARSED = {".lesshst": "less's own state file (search patterns, shell commands, marks): not a command history"}
ZSH = re.compile(rb"^:\s*(\d+):(\d+);(.*)$", re.S)
BASH_STAMP = re.compile(rb"^#(\d{9,})$")
FISH_CMD = re.compile(rb"^- cmd: ?(.*)$", re.S)
FISH_WHEN = re.compile(rb"^  when: ?(\d+)\s*$")
SKIP_TOP = ("proc", "sys", "dev")


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


def when(epoch):
    """(ISO 8601 UTC time, error) for an epoch-seconds string; the raw value is kept beside it by the caller."""
    try:
        value = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=int(epoch))
        return value.isoformat() + "Z", None
    except (ValueError, OverflowError):
        return None, "epoch %s is outside the range of a date" % epoch


def unmetafy(data):
    """zsh stores a byte it treats specially as 0x83 followed by the byte xor 0x20."""
    if b"\x83" not in data:
        return data, False
    out, i, changed = bytearray(), 0, False
    while i < len(data):
        if data[i] == 0x83 and i + 1 < len(data):
            out.append(data[i + 1] ^ 0x20)
            i += 2
            changed = True
        else:
            out.append(data[i])
            i += 1
    return bytes(out), changed


def text_of(data):
    return decode(data)


def physical(path):
    """(line number, byte offset, bytes without the newline, more, first) for each physical line or piece of one.

    A line longer than MAX_PIECE comes in pieces that share its number: `first` is true on the first piece and
    `more` on every piece but the last; nothing is dropped. A read error is raised to the caller, which has the
    records so far."""
    with open(path, "rb") as fh:
        number, offset, first = 1, 0, True
        while True:
            chunk = fh.readline(MAX_PIECE)
            if not chunk:
                return
            ended = chunk.endswith(b"\n")
            more = not ended and len(chunk) == MAX_PIECE
            if ended:
                chunk = chunk[:-1]
                if chunk.endswith(b"\r"):
                    chunk = chunk[:-1]
            yield number, offset, chunk, more, first
            offset += len(chunk)
            first = ended
            if ended:
                number += 1


def scan(path, counters):
    """physical(), with the file's physical and blank lines counted: (number, offset, data, piece, blank) where
    `piece` says this is part of a line that was read in pieces."""
    for number, offset, data, more, first in physical(path):
        if first:
            counters["physical"] += 1
        blank = not data.strip()
        if blank and first:
            counters["blank"] += 1
        yield number, offset, data, (more or not first), blank


class Record:
    __slots__ = ("start", "end", "offset", "lines", "nbytes", "time_raw", "time", "time_error", "elapsed", "basis",
                 "time_basis", "uncertain", "meta", "split", "continues_previous")

    def __init__(self, start, offset, basis):
        self.start, self.end, self.offset, self.basis = start, start, offset, basis
        self.lines, self.nbytes = [], 0
        self.time_raw, self.time, self.time_error, self.elapsed = None, None, None, None
        self.time_basis, self.uncertain, self.meta, self.split, self.continues_previous = None, False, False, False, False

    def add(self, data):
        self.lines.append(data)
        self.nbytes += len(data)

    def size(self):
        return self.nbytes


def stamp(rec, raw, basis):
    rec.time_raw = raw
    rec.time, rec.time_error = when(raw)
    rec.time_basis = basis


def cont(rec, number, offset, basis):
    """The record that carries on where `rec` stopped at the size cap."""
    nxt = Record(number, offset, basis)
    nxt.continues_previous, nxt.split = True, True
    return nxt


def bash_records(path, counters):
    """Bash: stamped entries run to the next stamp; with no stamp, each physical line is a record."""
    rec, blanks = None, 0
    for number, offset, data, piece, blank in scan(path, counters):
        if blank:
            if rec is not None and rec.basis == "bash timestamp line":
                blanks += 1                        # inside a stamped entry only if a command line follows
                if blanks + rec.size() >= MAX_RECORD:
                    # A run of blank lines as long as a record may be: the record ends here, and the run is
                    # counted as blank lines and belongs to no record.
                    yield rec
                    rec, blanks = None, 0
                    counters["blank_beyond_cap"] += 1
            continue
        if ZSH.match(data):
            counters["other_format"]["zsh extended history"] = counters["other_format"].get("zsh extended history", 0) + 1
        found = BASH_STAMP.match(data)
        if found and not piece:
            if rec is not None:
                yield rec
            blanks = 0
            rec = Record(number, offset, "bash timestamp line")
            rec.add(data)
            stamp(rec, text_of(found.group(1)), "bash timestamp line")
            rec.meta = True            # no command line yet
            continue
        if rec is not None and rec.basis == "bash timestamp line":
            if rec.size() >= MAX_RECORD:
                yield rec
                rec = cont(rec, number, offset, "bash timestamp line")
            rec.lines.extend([b""] * blanks)
            rec.nbytes += blanks
            blanks = 0
            rec.add(data)
            rec.end = number
            rec.meta = False
            rec.split = rec.split or piece
            continue
        if rec is not None:
            yield rec
        rec = Record(number, offset, "physical line")
        rec.add(data)
        rec.uncertain = data.endswith(b"\\")
        rec.split = piece
        yield rec
        rec = None
    if rec is not None:
        yield rec


def zsh_records(path, counters):
    rec = None
    for number, offset, data, piece, blank in scan(path, counters):
        if rec is not None and rec.lines and rec.lines[-1].endswith(b"\\"):
            # zsh writes a newline inside a command after a backslash, and an empty line inside a command is one too.
            if rec.size() >= MAX_RECORD:
                yield rec
                rec = cont(rec, number, offset, rec.basis)
            rec.add(data)
            rec.end = number
            rec.split = rec.split or piece
            continue
        if blank:
            continue
        if rec is not None:
            yield rec
            rec = None
        found = ZSH.match(data)
        if found:
            rec = Record(number, offset, "zsh extended header")
            rec.add(data)
            stamp(rec, text_of(found.group(1)), "zsh extended header")
            digits = found.group(2)
            if len(digits) <= 15:
                rec.elapsed = int(digits)
            else:
                rec.time_error = "elapsed seconds %s... is not a plausible duration" % text_of(digits[:15])
        else:
            rec = Record(number, offset, "physical line (no zsh header)")
            rec.add(data)
        rec.split = rec.split or piece
    if rec is not None:
        yield rec


def fish_records(path, counters):
    rec = None
    for number, offset, data, piece, blank in scan(path, counters):
        if blank:
            continue
        found = FISH_CMD.match(data)
        if found and not piece:
            if rec is not None:
                yield rec
            rec = Record(number, offset, "fish entry")
            rec.add(data)
            continue
        if rec is None:
            counters["other_lines"] += 1
            continue
        if rec.size() >= MAX_RECORD:
            yield rec
            rec = cont(rec, number, offset, "fish entry")
        rec.add(data)
        rec.end = number
        rec.split = rec.split or piece
        when_line = FISH_WHEN.match(data)
        if when_line and not piece:
            stamp(rec, text_of(when_line.group(1)), "fish when")
    if rec is not None:
        yield rec


def plain_records(path, counters):
    for number, offset, data, piece, blank in scan(path, counters):
        if blank:
            continue
        rec = Record(number, offset, "physical line")
        rec.add(data)
        rec.split = piece
        yield rec


READERS = {"bash": bash_records, "zsh": zsh_records, "fish": fish_records, "plain": plain_records}


def command_of(fmt, rec):
    """The command a record holds, decoded as its format says, and whether bytes were decoded."""
    changed = False
    if fmt == "bash":
        lines = [x for x in rec.lines if not (rec.basis == "bash timestamp line" and BASH_STAMP.match(x))]
        return "\n".join(text_of(x) for x in lines), False
    if fmt == "zsh":
        first = rec.lines[0]
        found = ZSH.match(first)
        parts = [found.group(3) if found else first] + rec.lines[1:]
        parts = [p[:-1] if i < len(parts) - 1 and p.endswith(b"\\") else p for i, p in enumerate(parts)]
        joined, changed = unmetafy(b"\n".join(parts))
        return text_of(joined), changed
    if fmt == "fish":
        found = FISH_CMD.match(rec.lines[0])
        raw = text_of(found.group(1)) if found else text_of(rec.lines[0])
        return re.sub(r"\\(n|\\)", lambda m: "\n" if m.group(1) == "n" else "\\", raw), False
    return text_of(rec.lines[0]), False


def command_line_count(fmt, command):
    return command.count("\n") + 1 if command else 0


def shown_fields_text(info, rec):
    """What `contains` may match outside a job: the fields the answer shows of a record, never its command."""
    return " ".join(str(v) for v in (info["file"], info["program"], info["format"], info["home"], info["home_basename"], info["user"],
                                      rec.time_raw, rec.time, rec.basis) if v is not None)


def home_of(dirpath):
    suffix = os.sep + os.path.join(".local", "share", "fish")
    return dirpath[: -len(suffix)] if dirpath.endswith(suffix) else dirpath


def read_passwd(path):
    """{home: [(name, line number)]} from a passwd file."""
    homes = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for number, line in enumerate(fh, 1):
            fields = line.rstrip("\n").split(":")
            if len(fields) >= 6 and fields[0] and not line.startswith("#"):
                homes.setdefault(fields[5].rstrip("/") or "/", []).append((fields[0], number))
    return homes


def main():
    args = read_args()
    root = want_str(args, "root", "root is required: a home directory or an extracted file system root")
    if os.path.islink(root):
        fail("refusing a symlink root: pass the extracted evidence directory", root=root, target=os.readlink(root))
    if not os.path.isdir(root):
        fail("no such directory", root=root)
    limit = want_limit(args)
    write_text, preview = want_flag(args, "write_commands"), want_flag(args, "preview_commands")
    if preview:
        require_job("preview_commands")
    pattern = None
    if want_str(args, "contains"):
        try:
            pattern = re.compile(args["contains"], re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))
    only_user = want_str(args, "user")
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    deadline = time.monotonic() + seconds
    declared_fs_root = args.get("root_is_file_system_root")
    if declared_fs_root is not None and not isinstance(declared_fs_root, bool):
        fail("root_is_file_system_root must be true or false")

    # The evidence's own account database, when there is one to read. A root is read as a file system root (a home
    # directory's path in it is then a home in the evidence) when it has an etc/ directory, or when the caller says so.
    passwd_notes, homes, passwd_path, passwd_name = [], {}, None, None
    explicit = want_str(args, "passwd")
    try:
        fs_root = declared_fs_root if declared_fs_root is not None else os.path.isdir(os.path.join(root, "etc"))
    except OSError:
        fs_root = bool(declared_fs_root)
    candidate = explicit or os.path.join(root, "etc", "passwd")
    try:
        exists_ = os.path.lexists(candidate)
        is_link = os.path.islink(candidate)
        is_file = os.path.isfile(candidate)
    except OSError as exc:
        exists_, is_link, is_file = False, False, False
        passwd_notes.append("%s could not be examined: %s" % (candidate, describe(exc)))
    if exists_:
        if is_link:
            passwd_notes.append("%s is a link and was not followed" % candidate)
        elif not is_file:
            passwd_notes.append("%s is not a regular file" % candidate)
        elif not fs_root:
            passwd_notes.append("a passwd file exists but root is not read as a file system root (it has no etc/ directory; say "
                                "root_is_file_system_root: true if it is one): a home directory's path in the tree cannot be mapped "
                                "to a home in the evidence, so no owner is named")
        else:
            try:
                homes, passwd_path = read_passwd(candidate), candidate
                passwd_name = explicit or "etc/passwd"
            except OSError as exc:
                passwd_notes.append("%s could not be read: %s" % (candidate, describe(exc)))
    elif explicit is not None:
        passwd_notes.append("%s does not exist" % explicit)
    elif fs_root:
        passwd_notes.append("the root has no etc/passwd: no owner is named")
    if passwd_path is None:
        fs_root = False

    try:
        text = TextFile(TEXT_NAME, write_text, "JSON Lines, mode 0600: the record's id and locator as in the answer, "
                        "with `command` (decoded as its format says) and `record_lines` (the physical lines exactly)",
                        flag="write_commands")
    except TextRefused as exc:
        fail(str(exc))
    page = LosslessPage(TOOL, "records", limit)
    preview_rows = []
    special = []

    files, walk_errors, skipped_symlinks, excluded, not_parsed, read_failures = [], [], [], [], [], []
    seen, seq, matched, with_time, partial_reason = 0, 0, 0, 0, None

    def on_error(exc):
        walk_errors.append({"path": getattr(exc, "filename", None), "error": describe(exc)})

    for dirpath, dirs, names in os.walk(root, onerror=on_error):
        if time.monotonic() > deadline:
            partial_reason = partial_reason or "the walk stopped at max_seconds (%s); directories after %s were not visited" % (seconds, dirpath)
            break
        for name in list(dirs):
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                skipped_symlinks.append({"file": full, "target": os.readlink(full)})
                dirs.remove(name)
            elif dirpath == root and name in SKIP_TOP:
                excluded.append({"path": full, "reason": "the top of the tree's %s: a mounted root's, not evidence (only the top is left out; "
                                                          "a directory of that name deeper in the tree is read)" % name})
                dirs.remove(name)
        for name in sorted(names):
            full = os.path.join(dirpath, name)
            if name in NOT_PARSED:
                not_parsed.append({"file": full, "reason": NOT_PARSED[name]})
                continue
            if name not in NAMES:
                continue
            if os.path.islink(full):
                skipped_symlinks.append({"file": full, "target": os.readlink(full)})
                continue
            try:
                regular = stat.S_ISREG(os.lstat(full).st_mode)
            except OSError as exc:
                walk_errors.append({"path": full, "error": describe(exc)})
                continue
            if not regular:
                special.append({"file": full, "reason": "not a regular file (a pipe, a socket or a device): never opened"})
                continue
            fmt, program = NAMES[name]
            home = home_of(dirpath)
            owners = homes.get("/" + os.path.relpath(home, root).replace(os.sep, "/") if home != root else "/", []) if fs_root else []
            if len(owners) == 1:
                user, user_source = owners[0][0], "%s:%d" % (passwd_name, owners[0][1])
            elif len(owners) > 1:
                user, user_source = "ambiguous", "%d accounts have this home: %s" % (len(owners), ", ".join(o[0] for o in owners))
            else:
                user, user_source = "unknown", None
            base = os.path.basename(home) or home
            if only_user and only_user != (user if user not in ("unknown", "ambiguous") else base):
                continue
            seen += 1
            try:
                st = os.stat(full)
                size, last = st.st_size, datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            except (OSError, ValueError, OverflowError):
                size, last = None, None
            info = {"file": full, "program": program, "format": fmt, "home": home, "home_basename": base, "user": user,
                    "user_source": user_source, "size": size, "last_written": last, "records": 0, "physical_lines": 0,
                    "blank_lines": 0, "with_timestamps": 0, "timestamps_out_of_order": 0, "partial": False}
            counters = {"physical": 0, "blank": 0, "other_lines": 0, "other_format": {}, "blank_beyond_cap": 0}
            previous, index = None, 0
            try:
                ticks = 0
                for rec in READERS[fmt](full, counters):
                    ticks += 1
                    if ticks % 1024 == 0 and time.monotonic() > deadline:
                        partial_reason = partial_reason or "the read stopped at max_seconds (%s) inside %s; later records of it and later files were not read" % (seconds, full)
                        info["partial"] = True
                        break
                    if fmt == "bash" and rec.meta:
                        info["stamps_without_command"] = info.get("stamps_without_command", 0) + 1
                        continue
                    command, decoded = command_of(fmt, rec)
                    index += 1
                    info["records"] += 1
                    if rec.time:
                        info["with_timestamps"] += 1
                        if previous is not None and rec.time < previous:
                            info["timestamps_out_of_order"] += 1
                        previous = rec.time
                    if pattern and not pattern.search(command if in_job() else shown_fields_text(info, rec)):
                        continue
                    seq += 1
                    matched += 1
                    if rec.time:
                        with_time += 1
                    command_bytes = blen(command)
                    row = {"id": "H%06d" % seq, "parser": PARSER, "file": full, "program": program, "format": fmt,
                           "home": home, "home_basename": base, "user": user, "index": index,
                           "line_start": rec.start, "line_end": rec.end, "byte_offset": rec.offset,
                           "time_raw": rec.time_raw, "time": rec.time, "time_basis": rec.time_basis,
                           "boundary_basis": rec.basis, "command_bytes": command_bytes,
                           "command_lines": command_line_count(fmt, command)}
                    if user_source:
                        row["user_source"] = user_source
                    if rec.elapsed is not None:
                        row["elapsed_seconds"] = rec.elapsed
                    if rec.time_error:
                        row["time_error"] = rec.time_error
                    if rec.uncertain:
                        row["continuation_uncertain"] = True
                    if decoded:
                        row["unmetafied"] = True
                    if rec.split:
                        row["split_at_cap"] = True
                    text.add({**row, "command": command, "record_lines": [text_of(x) for x in rec.lines]})
                    page.add(row)
                    if preview and len(preview_rows) < limit:
                        preview_rows.append({**row, "command": command})
            except OSError as exc:
                info["error"] = describe(exc)
                info["partial"] = True
                read_failures.append({"file": full, "error": describe(exc)})
            info["physical_lines"], info["blank_lines"] = counters["physical"], counters["blank"]
            if counters["other_lines"]:
                info["lines_outside_an_entry"] = counters["other_lines"]
            wrong = [k for k, v in counters["other_format"].items() if v]
            if wrong and fmt != "zsh":
                info["looks_like_other_format"] = wrong[0]
            files.append(info)
    text.close()
    pages = {"records": page.finish()}
    all_read = not read_failures and not walk_errors and partial_reason is None and not special
    outcome = status_of(
        all_read, bool(files) is False and bool(walk_errors or read_failures),
        "every history file found was read through, no directory could not be opened and nothing was left unopened",
        "%d read failure(s), %d walk error(s), %d special file(s) not opened%s: the answer names each" % (
            len(read_failures), len(walk_errors), len(special), "; the read stopped at max_seconds" if partial_reason else ""),
        "no history file could be read")
    print(json.dumps({
        "parser": PARSER,
        **outcome,
        "root": root,
        "files": files,
        "file_count": len(files),
        "passwd": {"file": passwd_path, "read_as_file_system_root": fs_root, "notes": passwd_notes},
        "contains_scope": None if pattern is None else ("the decoded command, in a job" if in_job() else "the fields the answer shows (outside a job a command is not matched)"),
        "filter_touched_withheld_text": touches_withheld_text(pattern is not None),
        "records_in_files": sum(f["records"] for f in files),
        "record_count": matched,
        "with_timestamps": with_time,
        "records": preview_rows if preview else page.page,
        "pages": pages,
        "text": text.summary(preview),
        "all_files_read": all_read,
        "skipped_special": special,
        "partial_reason": partial_reason,
        "read_failures": read_failures,
        "walk_errors": walk_errors,
        "excluded_dirs": excluded,
        "skipped_symlinks": skipped_symlinks,
        "not_parsed_files": not_parsed,
        "truncated": pages["records"]["truncated"],
        "note": "Records are in the order the program wrote them, and each says how its boundaries were found "
                "(boundary_basis). A record with no time has order only: say so, and do not imply a sequence in time; "
                "stamps need not rise from one record to the next (concurrent sessions, a merge or a changed clock; "
                "timestamps_out_of_order counts them). A history file is what the program saved, not a record of what "
                "ran: a killed session may never have been written, HISTCONTROL and HISTIGNORE drop entries, and the "
                "file's last_written is when it last changed, which is an extraction time on a copied tree. `user` is "
                "an account only when the evidence's passwd says one account has that home; home_basename is a "
                "directory's name. The answer carries no command: write_commands or preview_commands, in a job run "
                "with secret_output: true, is how the text is read.",
    }, indent=2))


if __name__ == "__main__":
    main()
