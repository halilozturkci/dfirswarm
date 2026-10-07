#!/usr/bin/env python3
"""Read the evidence's journal, and never your own; keep every field of every entry.

journalctl with no arguments reads the journal of the machine you are sitting at. That is the easiest
mistake to make here, and its output looks entirely plausible in a report, so this tool refuses to run
without a path, passes it to `--file` or `--directory`, and puts the argv it ran (as an array) in its
answer. The journal carries what /var/log/auth.log does not: _EXE and _CMDLINE for the process that logged,
_SYSTEMD_UNIT for the service, _AUDIT_SESSION for the login session, and two clocks.

The two clocks are the point. __REALTIME_TIMESTAMP is the wall clock, which can be set, stepped, corrected by
NTP and wrong; __MONOTONIC_TIMESTAMP counts from the boot and is the order within it. A boot id names a boot
and orders nothing, so grouping by boot does not remove a clock step inside a boot, and across boots the two
clocks must be anchored independently. Both are kept raw, with the cursor (which names the entry and holds
the boot, the monotonic and the realtime values it was taken from) and the machine id.

What is kept. The complete native export (`journalctl -o json --all`) is written exactly as journalctl
produced it, one entry per line, to $OUT/journal-native.jsonl when `write_text: true` is asked in a job: it is
the lossless result, and it holds messages and command lines. The answer carries a projection of each entry:
the cursor, both clocks (raw and decoded), the boot and the machine, and the identity fields; a value that
journalctl wrote as a byte array or as null is named as such and never turned into text. It carries the
length of the message and of the command line, not their text.

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"). A journal holds command lines
(_CMDLINE, sudo and mount messages) and application messages that can hold a password or a token. The answer
never carries `message` or `cmdline`; `preview_text: true` (in a job) adds them to the projection, and
`write_text: true` (in a job) writes the native entries to a private file. Both are refused outside a job; the
skill says the job runs with secret_output: true. Nothing is hashed or shortened.

A tool that fails loudly: journalctl's stderr is kept whole in a file; a deadline (`max_seconds`) ends the read
and returns what was read with `export_status: partial`; a line that is not JSON is counted and located; a
journalctl that failed and wrote nothing is an error, not an empty export. `mode: verify` runs journalctl
--verify on its own, keeps its whole output, and claims only what that command checks.
"""
import datetime
import json
import math
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

TOOL = "journal_export"
PARSER = "journal_export/4"
DEFAULT_LIMIT = 200
DEFAULT_SECONDS = 240.0
MAX_SECONDS = 270.0           # the most a caller may ask for (the manifest allows 300)
FIRST_FAILURES = 20
MAX_BOOTS = 5000
MAX_LINE = 32 << 20       # an entry longer than this is counted and located, not parsed
PREVIEW_CHARS = 65536     # a previewed message or command line is shown to this many characters, with its whole length
OWN_JOURNALS = ("/var/log/journal", "/run/log/journal")
MAX_FIELD_NAMES = 500
TEXT_NAME = "journal-native.jsonl"
VERIFY_NAME = "journal-verify.txt"
STDERR_NAME = "journalctl.stderr"
EPOCH = datetime.datetime(1970, 1, 1)
# A time bound is read by journalctl in the zone of the machine running it, which is not the evidence's: only a
# bound that carries its own zone is passed on (the UTC suffix, or seconds since the epoch).
BOUND = re.compile(r"^(?:@\d+(?:\.\d+)?|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?\s+UTC)$")


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


def decoded_time(micro):
    try:
        return (EPOCH + datetime.timedelta(microseconds=int(micro))).isoformat() + "Z", None
    except (ValueError, TypeError, OverflowError):
        return None, "__REALTIME_TIMESTAMP %r is not a count of microseconds in the range of a date" % (micro,)


def sized(value):
    """(bytes, encoding) of a field journalctl wrote as a string, a byte array, a list of values or null."""
    if value is None:
        return 0, "null"
    if isinstance(value, str):
        return blen(value), "text"
    if isinstance(value, list) and all(isinstance(x, int) for x in value):
        return len(value), "bytes"
    if isinstance(value, list):
        return sum(blen(str(x)) for x in value), "several values"
    return blen(str(value)), "other"


IDENTITY = (("_PID", "pid"), ("_UID", "uid"), ("_GID", "gid"), ("_COMM", "comm"), ("_EXE", "exe"),
            ("_SYSTEMD_UNIT", "unit"), ("_SYSTEMD_USER_UNIT", "user_unit"), ("_AUDIT_SESSION", "audit_session"),
            ("_AUDIT_LOGINUID", "audit_loginuid"), ("SYSLOG_IDENTIFIER", "syslog_identifier"), ("PRIORITY", "priority"),
            ("_TRANSPORT", "transport"), ("_HOSTNAME", "hostname"), ("_MACHINE_ID", "machine_id"))


def project(entry, number, seq):
    realtime = entry.get("__REALTIME_TIMESTAMP")
    shown, error = decoded_time(realtime) if realtime is not None else (None, "no __REALTIME_TIMESTAMP")
    msg_bytes, msg_enc = sized(entry.get("MESSAGE"))
    cmd_bytes, cmd_enc = sized(entry.get("_CMDLINE"))
    row = {"id": "J%06d" % seq, "parser": PARSER, "native_line": number, "cursor": entry.get("__CURSOR"),
           "realtime_us": realtime, "time": shown, "monotonic_us": entry.get("__MONOTONIC_TIMESTAMP"),
           "boot_id": entry.get("_BOOT_ID")}
    if error:
        row["time_error"] = error
    cut = {}

    def put(name, value):
        shown, whole = bound(value, 1024)
        row[name] = shown
        if whole is not None:
            cut[name] = whole
    for field, name in (("_SOURCE_REALTIME_TIMESTAMP", "source_realtime_us"), ("_SOURCE_MONOTONIC_TIMESTAMP", "source_monotonic_us"),
                        ("__SEQNUM", "seqnum"), ("__SEQNUM_ID", "seqnum_id")):
        if field in entry:
            put(name, entry[field])
    for field, name in IDENTITY:
        if field in entry:
            put(name, entry[field])
    if cut:
        row["truncated_fields"] = cut
    row.update({"message_bytes": msg_bytes, "message_encoding": msg_enc})
    if "_CMDLINE" in entry:
        row.update({"cmdline_bytes": cmd_bytes, "cmdline_encoding": cmd_enc})
    return row


def output_file(name):
    """Where a whole output of this tool is kept: $OUT in a job, work/<agent>/tool-output otherwise. A name already taken
    (a second call in one job) is never overwritten: it gets a number before its extension."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        base = Path(out)
        shown_dir = "store/jobs/%s/out" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
    else:
        agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
        base = Path("work") / agent / "tool-output"
        shown_dir = str(base)
        name = "%s-%s-%s" % (TOOL, secrets.token_hex(8), name)
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fail("the output directory %s cannot be created: %s" % (base, describe(exc)))
    stem, dot, ext = name.partition(".")
    for n in range(0, 1000):
        candidate = name if n == 0 else "%s.%d%s%s" % (stem, n + 1, dot, ext)
        try:
            fd = os.open(str(base / candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            continue
        except OSError as exc:
            fail("the output file %s cannot be created: %s" % (base / candidate, describe(exc)))
        os.close(fd)
        return base / candidate, "%s/%s" % (shown_dir, candidate)
    fail("no free name for %s in %s" % (name, base))


CURRENT = {"proc": None}


def on_term(signum, _frame):
    """Told to stop from outside: end journalctl and what it started, so nothing keeps running after the tool."""
    proc = CURRENT["proc"]
    if proc is not None and proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                proc.kill()
            except OSError:
                pass
    raise SystemExit(128 + signum)


def run_journalctl(argv, raw_sink, line_sink, oversized_sink, stderr_path, seconds):
    """Run journalctl in a process group of its own, with a deadline that ends the whole group. Every byte of stdout
    goes to `raw_sink` in order; each line within MAX_LINE goes whole to `line_sink`, and a longer one is counted by
    `oversized_sink` and not held, so one huge entry costs no more memory than the cap."""
    state = {"timed_out": False}
    with open(stderr_path, "wb") as err:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=err, start_new_session=True)
        CURRENT["proc"] = proc

        def kill():
            state["timed_out"] = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                try:
                    proc.kill()
                except OSError:
                    pass
        timer = threading.Timer(seconds, kill)
        timer.start()
        try:
            pending, size = [], 0
            while True:
                piece = proc.stdout.readline(1 << 20)
                if not piece:
                    break
                raw_sink(piece)
                size += len(piece)
                if pending is not None and size <= MAX_LINE:
                    pending.append(piece)
                else:
                    pending = None
                if piece.endswith(b"\n"):
                    if pending is None:
                        oversized_sink(size)
                    else:
                        line_sink(b"".join(pending))
                    pending, size = [], 0
            if size:
                if pending is None:
                    oversized_sink(size)
                else:
                    line_sink(b"".join(pending))
        finally:
            timer.cancel()
            proc.stdout.close()
            proc.wait()
            CURRENT["proc"] = None
    return proc.returncode, state["timed_out"]


def first_lines(path, count=20):
    try:
        with open(path, "rb") as fh:
            return [l.decode("utf-8", "replace").rstrip("\n") for _, l in zip(range(count), fh)]
    except OSError:
        return []


def main():
    args = read_args()
    path = want_str(args, "path", "path is required: journalctl with no path reads this machine's own journal, which is never the evidence")
    try:
        present = os.path.lexists(path)
        if present and os.path.islink(path):
            fail("refusing a symlink: pass the journal file or directory inside the evidence", path=path, target=os.readlink(path))
        mode_bits = os.stat(path).st_mode if present else 0
    except OSError as exc:
        fail("the path cannot be examined", path=path, reason=describe(exc))
    if not present:
        fail("no such file or directory", path=path)
    if not (stat.S_ISREG(mode_bits) or stat.S_ISDIR(mode_bits)):
        fail("not a journal file or a directory: a pipe, a socket or a device is never passed to journalctl", path=path)
    absolute = os.path.abspath(path)
    here = os.getcwd()
    inside_run = absolute == here or absolute.startswith(here + os.sep)
    if not inside_run and any(absolute == own or absolute.startswith(own + os.sep) for own in OWN_JOURNALS):
        fail("this path is where this machine keeps its own journal, which is never the evidence: pass the journal under inputs/ or work/", path=path)
    if inside_run:
        # Every component under the run directory must be a real directory or file: a link in the middle of the path can lead out of the evidence.
        walked = here
        for part in os.path.relpath(absolute, here).split(os.sep):
            if part in (".", ""):
                continue
            walked = os.path.join(walked, part)
            if os.path.islink(walked):
                fail("refusing a path that goes through a link (%s): pass the journal's real location inside the evidence" % walked, path=path, link=walked)
    mode = args.get("mode", "export")
    if mode not in ("export", "verify"):
        fail("mode must be export or verify")
    limit = want_limit(args)
    write_text, preview_text = want_flag(args, "write_text"), want_flag(args, "preview_text")
    if preview_text:
        require_job("preview_text")
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    if args.get("grep") and not in_job():
        fail("grep is refused outside a job: it matches the text of the messages, which this answer withholds, so a count of what "
             "it matched would be an oracle on that text. Run this as job_run tool=journal_export with secret_output: true, and ask again there.")
    for name in ("unit", "grep", "priority", "since", "until"):
        want_str(args, name)
    bounds = {}
    for key in ("since", "until"):
        if args.get(key):
            if not BOUND.match(args[key].strip()):
                fail("%s must carry its own zone: journalctl reads a bare time in the zone of the machine it runs on, which is "
                     "not the evidence's. Write it as 'YYYY-MM-DD HH:MM:SS UTC' or as seconds since the epoch, '@1771100000'." % key,
                     given=args[key])
            bounds[key] = args[key].strip()
    binary = shutil.which("journalctl")
    if not binary:
        fail("journalctl is not on PATH",
             install="apt-get install -y systemd; the journal is a binary format that journalctl reads",
             note="On macOS there is no journalctl at all: copy the journal to a Linux host.")
    if os.path.isdir(path):
        links = []
        for root_, dirs_, names_ in os.walk(path):
            for entry_ in dirs_ + names_:
                if os.path.islink(os.path.join(root_, entry_)):
                    links.append(os.path.join(root_, entry_))
        if links:
            fail("refusing a journal directory that holds links: journalctl --directory may follow them out of the evidence. "
                 "Pass each real journal file as path instead.", links=links[:FIRST_FAILURES], link_count=len(links))
    where = ["--directory" if os.path.isdir(path) else "--file", path]

    if mode == "verify":
        argv = [binary, "--verify"] + where
        out_path, out_shown = output_file(VERIFY_NAME)
        err_path, err_shown = output_file(STDERR_NAME)
        signal.signal(signal.SIGTERM, on_term)
        try:
            with open(out_path, "wb") as sink:
                code, timed_out = run_journalctl(argv, sink.write, lambda raw: None, lambda size: None, err_path, seconds)
        except OSError as exc:
            fail("journalctl could not be run: %s" % describe(exc), argv=argv)
        outcome = status_of(not timed_out, False,
                            "journalctl --verify ran to its end; its exit code and whole output are kept (a clean result is not a complete journal)",
                            "journalctl --verify did not finish within max_seconds: the output so far is kept", "")
        print(json.dumps({
            "parser": PARSER, "mode": "verify", **outcome, "path": path, "argv": argv, "exit_code": code, "timed_out": timed_out,
            "verify": {"output_file": out_shown, "output_bytes": os.path.getsize(out_path), "stderr_file": err_shown,
                       "stderr_bytes": os.path.getsize(err_path), "stderr_first_lines": first_lines(err_path)},
            "claims": "journalctl --verify checks the internal, structural consistency of the journal files it was given, and, "
                      "for a sealed journal with the verification key, the seal. The exit code and the whole output are kept.",
            "does_not_show": "that no journal file or entry is missing or was removed, that the host kept a persistent journal, "
                             "that an unsealed journal is authentic, or that the entries say what happened: a clean result is "
                             "not a complete one. Read the output for each file, and judge gaps against rotation, retention, "
                             "the boundaries of what was collected and any remote copy.",
        }, indent=2))
        return

    try:
        text = TextFile(TEXT_NAME, write_text, "the native `journalctl -o json --all` output, exactly as journalctl wrote it, one entry per line")
    except TextRefused as exc:
        fail(str(exc))
    argv = [binary] + where + ["-o", "json", "--no-pager", "--all", "--quiet"]
    for flag, name in (("--unit", "unit"), ("--since", "since"), ("--until", "until"), ("--grep", "grep"), ("--priority", "priority")):
        value = bounds.get(name) if name in ("since", "until") else args.get(name)
        if value:
            argv += [flag, str(value)]
    err_path, err_shown = output_file(STDERR_NAME)
    page = LosslessPage(TOOL, "records", limit)
    preview_rows = []
    census, boots = {}, {}
    st = {"lines": 0, "entries": 0, "bad": [], "bad_count": 0, "census_truncated": False, "boots_truncated": False,
          "oversized": 0, "boot_not_text": 0}

    def oversized(size):
        text.count_record()
        st["lines"] += 1
        st["oversized"] += 1
        st["bad_count"] += 1
        if len(st["bad"]) < FIRST_FAILURES:
            st["bad"].append({"native_line": st["lines"], "bytes": size,
                              "error": "a line over %d bytes: counted and located, not parsed (its bytes are in the native file when write_text was asked)" % MAX_LINE})

    def sink(raw):
        text.count_record()
        st["lines"] += 1
        number = st["lines"]
        if raw.strip() in (b"-- No entries --", b"-- No entries --\r"):
            st["no_entries"] = st.get("no_entries", 0) + 1     # journalctl's own notice for an empty selection: no entry, no error
            return
        try:
            entry = json.loads(raw)
            if not isinstance(entry, dict):
                raise ValueError("an entry is a JSON object")
        except ValueError as exc:
            st["bad_count"] += 1
            if len(st["bad"]) < FIRST_FAILURES:
                st["bad"].append({"native_line": number, "bytes": len(raw), "error": str(exc)})
            return
        st["entries"] += 1
        for name in entry:
            if name in census or len(census) < MAX_FIELD_NAMES:
                census[name] = census.get(name, 0) + 1
            else:
                st["census_truncated"] = True
        row = project(entry, number, st["entries"])
        boot = row.get("boot_id")
        if boot is not None and not isinstance(boot, str):
            st["boot_not_text"] += 1     # a repeated _BOOT_ID comes as a list: it is not one boot, and is not grouped
            boot = None
        if boot is not None:
            b = boots.get(boot)
            if b is None and len(boots) < MAX_BOOTS:
                b = boots[boot] = {"boot_id": boot, "entries": 0, "first_realtime_us": row["realtime_us"],
                                   "first_monotonic_us": row["monotonic_us"], "first_cursor": row["cursor"]}
            elif b is None:
                st["boots_truncated"] = True
            if b is not None:
                b["entries"] += 1
                b["last_realtime_us"], b["last_monotonic_us"], b["last_cursor"] = row["realtime_us"], row["monotonic_us"], row["cursor"]
        page.add(row)
        if preview_text and len(preview_rows) < limit:
            msg, msg_whole = bound(entry.get("MESSAGE"), PREVIEW_CHARS)
            cmd, cmd_whole = bound(entry.get("_CMDLINE"), PREVIEW_CHARS)
            extra = {"preview_truncated": {k: v for k, v in (("message", msg_whole), ("cmdline", cmd_whole)) if v is not None}} if (msg_whole or cmd_whole) else {}
            preview_rows.append({**row, "message": msg, "cmdline": cmd, **extra})

    signal.signal(signal.SIGTERM, on_term)
    try:
        code, timed_out = run_journalctl(argv, text.add_bytes_raw, sink, oversized, err_path, seconds)
    except OSError as exc:
        text.close()
        fail("journalctl could not be run: %s" % describe(exc), argv=argv)
    text.close()
    stderr_bytes = os.path.getsize(err_path)
    if code != 0 and not timed_out and st["entries"] == 0:
        fail("journalctl refused this journal", exit_code=code, stderr_file=err_shown, stderr_first_lines=first_lines(err_path), argv=argv)
    pages = {"records": page.finish()}
    complete = code == 0 and not timed_out and st["bad_count"] == 0
    outcome = status_of(
        complete, False,
        "journalctl exited 0 within the deadline and every line it wrote parsed; this says nothing about journal files that were not in "
        "what you collected, or entries rotated away or never written",
        "journalctl exited %s%s and %d line(s) did not parse: what was read is kept and the files are named" % (code, " after the deadline" if timed_out else "", st["bad_count"]), "")
    print(json.dumps({
        "parser": PARSER,
        "mode": "export",
        "path": path,
        "argv": argv,
        "time_bounds": {**bounds, "interpretation": "as written, with its own zone"} if bounds else None,
        "exit_code": code,
        "timed_out": timed_out,
        **outcome,
        "no_entries_notices": st.get("no_entries", 0),
        "grep_scope": None if not args.get("grep") else "the message text, in a job",
        "filter_touched_withheld_text": touches_withheld_text(bool(args.get("grep"))),
        "entry_count": st["entries"],
        "lines_read": st["lines"],
        "boots_seen": len(boots),
        "boots": list(boots.values()),
        "boots_truncated": st["boots_truncated"],
        "field_census": census,
        "field_census_truncated": st["census_truncated"],
        "parse_errors": {"count": st["bad_count"], "first": st["bad"], "oversized_lines": st["oversized"]},
        "entries_with_a_boot_id_that_is_not_text": st["boot_not_text"],
        "stderr": {"file": err_shown, "bytes": stderr_bytes, "first_lines": first_lines(err_path)},
        "records": preview_rows if preview_text else page.page,
        "record_count": pages["records"]["matched"],
        "pages": pages,
        "text": text.summary(preview_text),
        "truncated": pages["records"]["truncated"],
        "note": "Within a boot, order entries by monotonic_us: the wall clock (realtime_us) can step inside a boot, and neither a boot "
                "id nor the order journalctl printed removes that. A boot id names a boot and does not order it; across boots, anchor "
                "the two clocks independently. The projection keeps the cursor and both clocks raw, and the whole entry is in the "
                "native file when write_text was asked. That no journal directory is in what you collected shows only that this path "
                "was not collected: it does not show that the host never kept a persistent journal or that earlier boots were never "
                "written, so read the journald configuration and the machine's other journals before saying so. mode: verify checks "
                "the structure of the files it is given and says nothing about files or entries that are not there.",
    }, indent=2))


if __name__ == "__main__":
    main()
