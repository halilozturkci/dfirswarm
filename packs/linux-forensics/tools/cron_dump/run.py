#!/usr/bin/env python3
"""List the scheduling artefacts of a Linux root: cron tables and systemd timers, as candidates.

Scheduling on Linux is scattered across several places and two subsystems, and an agent that checks the
obvious one has checked a fraction of it. This reads the places below, from an extracted root, and says
what it looked in, what it did not look in, and what it could not read. It is an inventory of candidates:
not every scheduling mechanism (at jobs, anacron and a user manager's runtime units are among what it does
not read, and the answer says so), and not the effective systemd configuration (a drop-in is listed and not
merged, an alias or a mask is a link that is listed and not followed, an enablement is not rebuilt). A
listed job is not evidence that it ran.

    /etc/crontab                     system table, with a user field
    /etc/cron.d/*                    drop-ins, also with a user field
    /etc/cron.{hourly,daily,weekly,monthly}/   scripts a run-parts-style runner may start
    /var/spool/cron/crontabs/<user>  per-user tables, no user field (the file's name is the owner)
    /var/spool/cron/<user>           the same, on the Red Hat family
    *.timer                          systemd timers in the system and the user unit directories, and in each
                                     account's ~/.config/systemd/user and ~/.local/share/systemd/user

Each entry carries the file it was in, its physical line, that file's modification time and mode: a
modification time is set by an install, a copy and a restore as well as by an edit, so it is a lead to
explain and not an answer. A cron line keeps the line as written and the command as the exact substring
after the schedule (and user) fields. A timer keeps every assignment in the file in order, each with its
section and line, the empty ones included (an empty `OnCalendar=` resets the list in systemd, and the
reading that skips it is wrong).

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"). A cron command can hold a
password or a token, and cron environment values and a unit's Environment= can hold secrets. The answer
carries the schedule, the user, the locators and the length of the command and the names (not the values) of
the environment variables in force; the command, the environment values and the raw line are in a file under
$OUT only when `write_text: true` is asked, in a job, and in the answer only with `preview_text: true`, in a
job. The skill says the job runs with secret_output: true. A timer's assignments under [Unit], [Timer] and
[Install] are shown; a value under any other section is not.

A tool that fails loudly: coverage is computed over everything looked at before `contains` filters
anything, so a filtered-out error still shows; a file or directory that could not be read, a link that was
not followed, a cron line that matches no table shape and a place that does not exist are each named.
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

TOOL = "cron_dump"
PARSER = "cron_dump/5"
DEFAULT_LIMIT = 200
MAX_CONTINUED = 1 << 20      # a unit line continued with backslashes is joined up to this many bytes
MAX_FILE_BYTES = 64 << 20    # a cron table larger than this is named as unread (a table is read a line at a time)
MAX_UNIT_BYTES = 8 << 20     # a unit file or a passwd file larger than this is named as unread, not read whole
MAX_CRON_LINE = 1 << 20      # a cron line longer than this is located, not parsed
MAX_NAMED = 500              # how many errors, links and special files are named inline (all are counted)
MAX_LOCATIONS = 200          # how many places of the census are shown inline (the whole is paged)
DEFAULT_SECONDS = 50.0       # the manifest allows 60
MAX_SECONDS = 50.0           # the most a caller may ask for (the manifest allows 60)
TEXT_NAME = "cron-text.jsonl"

SPECIALS = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}
SYSTEM_TABLES = ["etc/crontab"]
SYSTEM_DIRS = ["etc/cron.d"]
RUN_PARTS = ["etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly"]
SPOOLS = ["var/spool/cron/crontabs", "var/spool/cron"]
# Where systemd looks for system units and for user units (systemd.unit(5)), as locations to look in. Which of
# them a given boot used is not known from the files.
SYSTEM_UNIT_DIRS = ["etc/systemd/system", "usr/local/lib/systemd/system", "usr/lib/systemd/system",
                    "lib/systemd/system", "run/systemd/system", "run/systemd/transient", "run/systemd/generator",
                    "run/systemd/generator.early", "run/systemd/generator.late"]
USER_UNIT_DIRS = ["etc/systemd/user", "usr/local/lib/systemd/user", "usr/lib/systemd/user", "run/systemd/user"]
HOME_UNIT_DIRS = [".config/systemd/user", ".local/share/systemd/user"]
RUN_USER_DIRS = ["systemd/user", "systemd/transient", "systemd/generator"]
TIMER_KEYS = ("OnCalendar", "OnBootSec", "OnStartupSec", "OnActiveSec", "OnUnitActiveSec", "OnUnitInactiveSec")
STARTUP_KEYS = ("OnBootSec", "OnStartupSec")
SHOWN_SECTIONS = {"unit", "timer", "install"}
# The keys whose value is shown: those with scheduling semantics. Any other key (Description=, Environment=, ...) can say anything.
SHOWN_KEYS = {"OnCalendar", "OnBootSec", "OnStartupSec", "OnActiveSec", "OnUnitActiveSec", "OnUnitInactiveSec", "OnClockChange",
              "OnTimezoneChange", "AccuracySec", "RandomizedDelaySec", "FixedRandomDelay", "Persistent", "WakeSystem",
              "RemainAfterElapse", "Unit", "WantedBy", "RequiredBy", "Also", "Alias", "DefaultInstance"}
UNSUPPORTED = [
    "systemd drop-ins (<unit>.timer.d/*.conf) are listed in unmerged_dropins and not applied; an empty assignment "
    "that resets a list, an override of Unit= and the unit's enablement are not rebuilt",
    "unit aliases, masks (a link to /dev/null) and enablement links (*.wants/, *.requires/) are links: they are "
    "listed in skipped_symlinks and not followed",
    ".service units are not read: a timer names its unit, and what runs is in that unit's ExecStart, which this "
    "tool does not show",
    "units a generator makes at boot, and a user manager's runtime directory, are in the evidence only if /run was "
    "captured; run/ is looked in as listed and may be empty",
    "at jobs (var/spool/at, var/spool/cron/atjobs), anacron (etc/anacrontab), cron.allow and cron.deny, and which cron "
    "implementation ran, are not read",
    "run-parts selection (the executable bit, the name rules of the runner that was installed) is not applied; mode is shown",
    "no time zone or daylight-saving rule is applied to a calendar expression, and an expression is not expanded to a time",
]

CRON_NUM = r"[*0-9][*0-9/,\-]{0,63}"
CRON_NAMED = r"[*0-9A-Za-z][*0-9A-Za-z/,\-]{0,63}"
FIVE = re.compile(r"^(\s*)((?:%s)\s+(?:%s)\s+(?:%s)\s+(?:%s)\s+(?:%s))(\s+)(.*)$" % (CRON_NUM, CRON_NUM, CRON_NUM, CRON_NAMED, CRON_NAMED), re.S)
SPECIAL = re.compile(r"^(\s*)(@[A-Za-z]+)(\s+)(.*)$", re.S)
USER_COMMAND = re.compile(r"^(\S+)(\s+)(.*)$", re.S)
ENV_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", re.S)


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


def mtime_of(path):
    try:
        return datetime.datetime.fromtimestamp(os.path.getmtime(path), datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OSError, ValueError, OverflowError):
        return None


def mode_of(path):
    try:
        return "%04o" % (os.lstat(path).st_mode & 0o7777)
    except OSError:
        return None


def inside(root, path):
    """False when an absolute evidence symlink would resolve into this VM."""
    try:
        return os.path.commonpath((os.path.realpath(root), os.path.realpath(path))) == os.path.realpath(root)
    except (OSError, ValueError):
        return False


class Overtime(Exception):
    pass


def shown_hay(row):
    """What `contains` may match outside a job: the fields the answer shows of an entry, never a command."""
    return " ".join(str(row.get(k)) for k in ("source", "manager", "file", "schedule", "user", "unit", "script", "persistent") if row.get(k) is not None)


class Run:
    """What was looked at, entry by entry as it is met: nothing is kept but the first page, so memory does not follow the
    size of the evidence, and coverage is counted before any filter."""

    def __init__(self, root, text, page, unparsed_page, pattern, preview, limit, deadline):
        self.root, self.text, self.page, self.unparsed_page = root, text, page, unparsed_page
        self.pattern, self.preview, self.limit, self.deadline = pattern, preview, limit, deadline
        self.need_text = text.enabled or preview
        self.need_command = self.need_text or (pattern is not None and in_job())
        self.preview_rows = []
        self.total = self.matched = self.at_reboot = self.unparsed_count = self.seq = self.nested = 0
        self.locations, self.read_errors, self.walk_errors = [], [], []
        self.skipped_symlinks, self.special, self.dropins = [], [], []
        self.counts = {"read_errors": 0, "walk_errors": 0, "skipped_symlinks": 0, "special": 0}
        self.seen_real = {}
        self.partial_reason = None

    def check(self):
        if time.monotonic() > self.deadline:
            raise Overtime()

    def keep(self, which, item):
        self.counts[which] += 1
        target = getattr(self, which)
        if len(target) < MAX_NAMED:
            target.append(item)

    def census(self, rel, state, **extra):
        self.locations.append({"path": rel, "state": state, **extra})

    def error(self, path, exc):
        self.keep("read_errors", {"file": path, "error": describe(exc)})

    def not_regular(self, path):
        self.keep("special", {"file": path, "reason": "not a regular file (a pipe, a socket or a device): never opened"})

    def emit(self, row, texts):
        """One entry: counted, filtered, paged and written the moment it is read."""
        self.total += 1
        if self.pattern is not None:
            hay = ("%s %s %s" % (texts.get("command") or "", row.get("unit") or "", row.get("script") or "")) if in_job() else shown_hay(row)
            if not self.pattern.search(hay):
                return
        self.matched += 1
        self.at_reboot += 1 if row.get("at_reboot") else 0
        self.text.add({**row, **texts})
        self.page.add(row)
        if self.preview and len(self.preview_rows) < self.limit:
            self.preview_rows.append({**row, **{k: v for k, v in texts.items() if k != "assignments"}} if row["source"] == "cron" else row)

    def unparsed_line(self, path, number, offset, reason, line):
        self.unparsed_count += 1
        row = {"file": path, "line": number, "byte_offset": offset, "reason": reason}
        self.unparsed_page.add(row)
        self.text.add({"record_type": "unparsed", **row, "text": line})


def cron_entries(run, path, has_user, owner):
    """A cron table, a line at a time (a table of 64 MiB costs no more memory than one line)."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            run.not_regular(path)
            return
        size = os.path.getsize(path)
        if size > MAX_FILE_BYTES:
            raise OSError("a cron table of %d bytes is larger than the %d this tool reads: read it with another tool" % (size, MAX_FILE_BYTES))
        fh = open(path, "rb")
    except OSError as exc:
        run.error(path, exc)
        return
    stamp, mode = mtime_of(path), mode_of(path)
    environment, ordered_names = {}, []
    offset, number = 0, 0
    with fh:
        while True:
            rawb = fh.readline(MAX_CRON_LINE + 1)
            if not rawb:
                break
            number += 1
            start = offset
            offset += len(rawb)
            if number % 2048 == 0:
                run.check()
            if len(rawb) > MAX_CRON_LINE and not rawb.endswith(b"\n"):
                while True:                          # read on to the end of the line without holding it
                    more = fh.readline(MAX_CRON_LINE + 1)
                    offset += len(more)
                    if not more or more.endswith(b"\n"):
                        break
                run.unparsed_line(path, number, start, "a line over %d bytes: located, not parsed" % MAX_CRON_LINE, None)
                continue
            line = decode(rawb)
            if line.endswith("\n"):
                line = line[:-1]
            if line.endswith("\r"):
                line = line[:-1]
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            assignment = ENV_LINE.match(stripped)
            if assignment:
                name, value = assignment.group(1), assignment.group(2).strip()
                if name not in environment:
                    ordered_names.append(name)
                environment[name] = value
                if run.text.enabled:
                    run.text.add({"record_type": "environment", "file": path, "line": number, "byte_offset": start, "name": name, "value": value})
                continue
            found = SPECIAL.match(line)
            if found:
                if found.group(2).lower() not in SPECIALS:
                    found = None
                else:
                    schedule, rest = found.group(2), found.group(4)
            if not found:
                found = FIVE.match(line)
                if not found:
                    run.unparsed_line(path, number, start, "not a cron table line (no schedule that cron reads)", line)
                    continue
                schedule, rest = " ".join(found.group(2).split()), found.group(4)
            user, command = owner, rest
            user_basis = "spool file name" if owner else None
            if has_user:
                split = USER_COMMAND.match(rest)
                if not split or not split.group(3).strip():
                    run.unparsed_line(path, number, start, "a user field and no command", line)
                    continue
                user, command, user_basis = split.group(1), split.group(3), "user field"
            run.seq += 1
            user_shown, user_whole = bound(user, 256)
            row = {"id": "C%06d" % run.seq, "parser": PARSER, "source": "cron", "file": path, "line": number, "byte_offset": start,
                   "file_modified": stamp, "mode": mode, "schedule": schedule, "user": user_shown, "user_basis": user_basis,
                   "at_reboot": schedule.lower() == "@reboot", "command_bytes": blen(command),
                   "environment_count": len(ordered_names), "environment_keys": ordered_names[:50]}
            if user_whole is not None:
                row["user_bytes"] = user_whole
            if len(ordered_names) > 50:
                row["environment_keys_truncated"] = True
            texts = {}
            if run.need_command:
                texts = {"raw_line": line, "command": command}
                # The environment in force is kept with the entry up to 100 variables; past that every assignment is in the
                # file's environment rows (the text file), and the entry says so.
                if run.need_text:
                    if len(environment) <= 100:
                        texts["environment"] = dict(environment)
                    else:
                        texts["environment_in_rows"] = True
            run.emit(row, texts)


def unit_assignments(text):
    """(every `key=value` of a unit file in order, with its section and the number of the line it began on; the
    number of lines that were neither an assignment, a section header nor a comment)."""
    if text.startswith("﻿"):
        text = text[1:]
    lines = text.split("\n")
    out, section, i, other = [], None, 0, 0
    while i < len(lines):
        start = i + 1
        parts = [lines[i].rstrip("\r")]
        size = len(parts[0])
        # A comment line is one line: a backslash at its end is not read as a continuation here (whether systemd
        # continues a comment was not checked, and reading it as one would hide the assignment that follows).
        while (parts[-1].endswith("\\") and not parts[0].lstrip().startswith(("#", ";"))
               and i + 1 < len(lines) and size < MAX_CONTINUED):
            parts[-1] = parts[-1][:-1]
            i += 1
            parts.append(lines[i].rstrip("\r"))
            size += len(parts[-1])
        i += 1
        stripped = " ".join(parts).strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        key, sep, value = stripped.partition("=")
        if sep:
            out.append({"line": start, "section": section, "key": key.strip(), "value": value.strip()})
        else:
            other += 1
    return out, other


def timer_entry(run, path, manager):
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            run.not_regular(path)
            return
        size = os.path.getsize(path)
        if size > MAX_UNIT_BYTES:
            raise OSError("a unit file of %d bytes is larger than the %d this tool reads: read it with another tool" % (size, MAX_UNIT_BYTES))
        with open(path, "rb") as fh:
            data = decode(fh.read())
    except OSError as exc:
        run.error(path, exc)
        return
    assignments, other = unit_assignments(data)

    def shown_value(a):
        # A value is shown only where its key has scheduling semantics and sits in a section a timer has: a
        # Description=, an Environment= or anything else can say anything.
        return a["key"] in SHOWN_KEYS and (a["section"] or "").lower() in SHOWN_SECTIONS

    nonempty = [a for a in assignments if a["value"] and shown_value(a)]
    calendars = [a["value"] for a in nonempty if a["key"] in TIMER_KEYS]
    units = [a["value"] for a in nonempty if a["key"] == "Unit"]
    persistent = [a["value"] for a in nonempty if a["key"] == "Persistent"]
    shown = []
    for a in assignments:
        if shown_value(a):
            value, whole = bound(a["value"], 1024)
            item = {"line": a["line"], "section": a["section"], "key": a["key"], "value": value}
            if whole is not None:
                item["value_bytes"] = whole
            shown.append(item)
        else:
            shown.append({"line": a["line"], "section": a["section"], "key": a["key"],
                          "value_bytes": blen(a["value"]), "value_withheld": True})

    def one(value):
        return bound(value, 1024)[0]
    run.seq += 1
    row = {"id": "C%06d" % run.seq, "parser": PARSER, "source": "systemd", "manager": manager, "file": path,
           "file_modified": mtime_of(path), "mode": mode_of(path), "assignments": shown,
           "assignment_count": len(assignments), "lines_without_assignment": other,
           "schedule": one(calendars[0]) if calendars else None,
           "schedules": [one(c) for c in calendars],
           "unit": one(units[-1]) if units else os.path.basename(path)[: -len(".timer")] + ".service",
           "unit_basis": "last non-empty Unit=" if units else "no Unit=: the service of the same name",
           "persistent": one(persistent[-1]) if persistent else None,
           "at_reboot": any(a["key"] in STARTUP_KEYS for a in nonempty),
           "derived_basis": "schedule, schedules, unit and persistent are read naively from the assignments in file order, from the "
                            "keys with scheduling semantics only: an empty assignment that resets a list, drop-ins and other "
                            "overrides are not applied"}
    run.emit(row, {"assignments": assignments})


def scan_dir(run, rel, handle):
    """Visit the files of one location, recording what the place is; `handle(dirpath, name)` takes each file. A place that
    is the same directory as one already read (a merged-/usr link in the path) is read once, and named."""
    run.check()
    full = os.path.join(run.root, rel)
    try:
        if not os.path.lexists(full):
            run.census(rel, "missing")
            return
        if os.path.islink(full) or not inside(run.root, full):
            run.keep("skipped_symlinks", {"file": full, "target": os.readlink(full) if os.path.islink(full) else "outside the root"})
            run.census(rel, "link or outside the root: not followed")
            return
        if not os.path.isdir(full):
            run.census(rel, "not a directory")
            return
        real = os.path.realpath(full)
    except OSError as exc:
        run.keep("walk_errors", {"path": full, "error": describe(exc)})
        run.census(rel, "error: %s" % describe(exc))
        return
    if real in run.seen_real:
        run.census(rel, "alias of %s (the same directory reached through a link in its path): read once, there" % run.seen_real[real])
        return
    run.seen_real[real] = rel
    before = run.total

    def on_error(exc):
        run.keep("walk_errors", {"path": getattr(exc, "filename", None), "error": describe(exc)})

    for dirpath, dirs, names in os.walk(full, onerror=on_error):
        for name in list(dirs):
            sub = os.path.join(dirpath, name)
            if os.path.islink(sub):
                run.keep("skipped_symlinks", {"file": sub, "target": os.readlink(sub)})
                dirs.remove(name)
        for name in sorted(names):
            handle(dirpath, name)
    run.census(rel, "read", entries=run.total - before)


def handle_timer_dir(run, manager):
    def handle(dirpath, name):
        target = os.path.join(dirpath, name)
        if name.endswith(".timer"):
            if os.path.islink(target):
                run.keep("skipped_symlinks", {"file": target, "target": os.readlink(target)})
            else:
                timer_entry(run, target, manager)
        elif name.endswith(".conf") and dirpath.endswith(".timer.d"):
            run.dropins.append({"file": target, "timer": os.path.basename(dirpath)[: -len(".d")]})
    return handle


def homes_of(run):
    """(homes relative to the root, where the list came from, how many the account database does not list, the home
    paths it gave that were not used): the accounts' homes from the evidence's etc/passwd, and every directory under home/
    and root, because an account that was deleted leaves its home behind."""
    homes, source, from_passwd, ignored = [], [], 0, []
    passwd = os.path.join(run.root, "etc", "passwd")
    try:
        usable = os.path.isfile(passwd) and not os.path.islink(passwd) and inside(run.root, passwd)
    except OSError:
        usable = False
    if usable:
        try:
            if os.path.getsize(passwd) > MAX_UNIT_BYTES:
                raise OSError("etc/passwd is larger than the %d this tool reads" % MAX_UNIT_BYTES)
            with open(passwd, "rb") as fh:
                data = decode(fh.read())
        except OSError as exc:
            run.error(passwd, exc)
            data = None
        if data is not None:
            for line in data.split("\n"):
                fields = line.split(":")
                if len(fields) >= 6 and fields[5].startswith("/") and fields[5] not in ("/", "/nonexistent"):
                    parts = [p for p in fields[5].split("/") if p]
                    if ".." in parts or "." in parts or "\0" in fields[5]:
                        if len(ignored) < MAX_NAMED:
                            ignored.append(fields[5])
                        continue
                    homes.append("/".join(parts))
            from_passwd = len(homes)
            source.append("etc/passwd")
    home_dir = os.path.join(run.root, "home")
    try:
        if os.path.isdir(home_dir) and not os.path.islink(home_dir):
            homes += ["home/" + n for n in sorted(os.listdir(home_dir))]
    except OSError as exc:
        run.error(home_dir, exc)
    homes.append("root")
    source.append("directory listing (home/*, root)")
    seen, unique = set(), []
    for h in homes:
        if h and h not in seen:
            seen.add(h)
            unique.append(h)
    return unique, " and ".join(source), (max(0, len(unique) - from_passwd) if from_passwd else None), ignored


def main():
    args = read_args()
    root = want_str(args, "root", "root is required: an extracted file system root")
    if os.path.islink(root):
        fail("refusing a symlink root: pass the extracted evidence directory", root=root, target=os.readlink(root))
    if not os.path.isdir(root):
        fail("no such directory", root=root)
    limit = want_limit(args)
    write_text, preview_text = want_flag(args, "write_text"), want_flag(args, "preview_text")
    if preview_text:
        require_job("preview_text")
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    pattern = None
    if want_str(args, "contains"):
        try:
            pattern = re.compile(args["contains"], re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))
    try:
        text = TextFile(TEXT_NAME, write_text, "JSON Lines, mode 0600: the entry's id and fields as in the answer, with `raw_line`, "
                        "`command` and `environment` for a cron line (every environment assignment once, as its own row) and the "
                        "unit's complete `assignments` for a timer")
    except TextRefused as exc:
        fail(str(exc))
    page = LosslessPage(TOOL, "entries", limit)
    unparsed_page = LosslessPage(TOOL, "unparsed", limit)
    run = Run(root, text, page, unparsed_page, pattern, preview_text, limit, time.monotonic() + seconds)
    homes_info = ([], "not reached", None, [])
    try:
        for rel in SYSTEM_TABLES:
            run.check()
            full = os.path.join(root, rel)
            if not os.path.lexists(full):
                run.census(rel, "missing")
            elif os.path.islink(full) or not inside(root, full):
                run.keep("skipped_symlinks", {"file": full, "target": os.readlink(full) if os.path.islink(full) else "outside the root"})
                run.census(rel, "link or outside the root: not followed")
            elif os.path.isfile(full):
                before = run.total
                cron_entries(run, full, True, None)
                run.census(rel, "read", entries=run.total - before)
            else:
                run.census(rel, "not a file")

        def table(has_user, owner_from_name):
            def handle(dirpath, name):
                target = os.path.join(dirpath, name)
                if os.path.islink(target):
                    run.keep("skipped_symlinks", {"file": target, "target": os.readlink(target)})
                elif os.path.isfile(target):
                    cron_entries(run, target, has_user, name if owner_from_name else None)
                elif os.path.lexists(target):
                    run.not_regular(target)
            return handle

        for rel in SYSTEM_DIRS:
            scan_dir(run, rel, table(True, False))
        for rel in RUN_PARTS:
            def run_parts(dirpath, name, rel=rel):
                target = os.path.join(dirpath, name)
                if os.path.islink(target):
                    run.keep("skipped_symlinks", {"file": target, "target": os.readlink(target)})
                elif os.path.lexists(target) and not os.path.isfile(target):
                    run.not_regular(target)
                elif os.path.isfile(target) and dirpath != os.path.join(root, rel):
                    run.nested += 1                       # run-parts does not enter a subdirectory
                elif os.path.isfile(target):
                    run.seq += 1
                    mode = mode_of(target)
                    run.emit({"id": "C%06d" % run.seq, "parser": PARSER, "source": "run-parts", "file": target,
                              "file_modified": mtime_of(target), "mode": mode, "schedule": os.path.basename(rel).replace("cron.", "@"),
                              "user": "root", "user_basis": "assumed from the usual run-parts lines of /etc/crontab, which are listed on their own and are the evidence",
                              "script": target, "executable": bool(int(mode or "0", 8) & 0o111) if mode else None,
                              "at_reboot": False}, {})
            scan_dir(run, rel, run_parts)
        for rel in SPOOLS:
            def spool(dirpath, name, rel=rel):
                if dirpath != os.path.join(root, rel):
                    return
                table(False, True)(dirpath, name)
            scan_dir(run, rel, spool)
        for rel in SYSTEM_UNIT_DIRS:
            scan_dir(run, rel, handle_timer_dir(run, "system"))
        for rel in USER_UNIT_DIRS:
            scan_dir(run, rel, handle_timer_dir(run, "user"))
        homes_info = homes_of(run)
        for home in homes_info[0]:
            for sub in HOME_UNIT_DIRS:
                scan_dir(run, "%s/%s" % (home, sub), handle_timer_dir(run, "user"))
        run_user = os.path.join(root, "run", "user")
        if os.path.isdir(run_user) and not os.path.islink(run_user):
            try:
                for uid in sorted(os.listdir(run_user)):
                    for sub in RUN_USER_DIRS:
                        scan_dir(run, "run/user/%s/%s" % (uid, sub), handle_timer_dir(run, "user"))
            except OSError as exc:
                run.error(run_user, exc)
    except Overtime:
        run.partial_reason = "the inventory stopped at max_seconds (%s): the places after the last one in locations were not looked in" % seconds
    homes, home_source, homes_beyond_passwd, homes_ignored = homes_info
    text.close()
    locations_page = LosslessPage(TOOL, "locations", MAX_LOCATIONS)
    by_state = {}
    for loc in run.locations:
        locations_page.add(loc)
        key = loc["state"].split(":")[0].split(" (")[0]
        by_state[key] = by_state.get(key, 0) + 1
    pages = {"entries": page.finish(), "unparsed": unparsed_page.finish(), "locations": locations_page.finish()}
    all_read = (not run.counts["read_errors"] and not run.counts["walk_errors"] and not run.counts["skipped_symlinks"]
                and not run.counts["special"] and run.partial_reason is None)
    looked = sum(1 for loc in run.locations if loc["state"] == "read")
    outcome = status_of(
        all_read, bool(run.counts["read_errors"] or run.counts["walk_errors"]) and looked == 0,
        "every place listed in locations was looked in and read, none was left unread",
        "%d read error(s), %d walk error(s), %d link(s) not followed, %d special file(s) not opened%s: the answer names each" % (
            run.counts["read_errors"], run.counts["walk_errors"], run.counts["skipped_symlinks"], run.counts["special"],
            "; the inventory stopped at max_seconds" if run.partial_reason else ""),
        "no scheduling place could be read")
    print(json.dumps({
        "parser": PARSER,
        **outcome,
        "root": root,
        "locations": locations_page.page,
        "locations_by_state": by_state,
        "home_source": home_source,
        "homes_beyond_passwd": homes_beyond_passwd,
        "homes_ignored": homes_ignored,
        "entries": run.preview_rows if preview_text else page.page,
        "pages": pages,
        "contains_scope": None if pattern is None else ("the command, the unit and the script path, in a job" if in_job() else "the fields the answer shows (outside a job a command is not matched)"),
        "filter_touched_withheld_text": touches_withheld_text(pattern is not None),
        "entries_total": run.total,
        "entries_matched": run.matched,
        "at_reboot": run.at_reboot,
        "unparsed_lines": run.unparsed_count,
        "unparsed": unparsed_page.page,
        "text": text.summary(preview_text),
        "all_checked_locations_read": all_read,
        "partial_reason": run.partial_reason,
        "run_parts_files_in_subdirectories_not_listed": run.nested,
        "read_errors": run.read_errors,
        "walk_errors": run.walk_errors,
        "skipped_symlinks": run.skipped_symlinks,
        "skipped_special": run.special,
        "error_counts": run.counts,
        "unmerged_dropins": run.dropins,
        "unsupported": UNSUPPORTED,
        "truncated": any(p["truncated"] for p in pages.values()),
        "coverage_note": "A candidate inventory of the places listed in locations, counted before `contains` filtered anything: "
                         "it is not every scheduling mechanism (see unsupported) and not the effective systemd configuration.",
        "note": "file_modified is a lead to explain, not a conclusion: an install, a copy and a restore set it as well as an edit, "
                "and it says nothing about what ran. Corroborate a candidate with the package database, the journal or audit "
                "records of the job running, and the account's own history before calling it added or changed. An @reboot entry "
                "runs when the cron daemon starts, and a timer with OnBootSec or OnStartupSec is set relative to the boot or the "
                "manager's start, not to a calendar; neither is evidence that anything ran. A systemd timer says when: the unit "
                "it names says what runs, and that unit is not read here.",
    }, indent=2))


if __name__ == "__main__":
    main()
