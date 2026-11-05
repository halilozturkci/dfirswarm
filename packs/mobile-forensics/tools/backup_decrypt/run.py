#!/usr/bin/env python3
"""Decrypt an encrypted iOS backup with iphone_backup_decrypt, from a password in a file the job was given.

A backup made with "Encrypt local backup" keeps its blobs as ciphertext and its Manifest.db as ciphertext too; the keys that open them are in
Manifest.plist (BackupKeyBag, ManifestKey) and are unlocked by the password. This tool opens the backup with the approved library
(iphone_backup_decrypt, pinned with hashes in requires/), writes the decrypted Manifest.db and every decrypted file under the output
directory, and tells for every row of the map what became of it. It implements no cryptography of its own and guesses nothing about the
key bag: the library does the work, in a child process of this tool.

    decrypted/Manifest.db                the decrypted map (mode 0600)
    decrypted/<first two hex digits>/<file id>   one decrypted file per Manifest row of a file (mode 0600), under the id the backup gave it
    decrypted/DECRYPTED.json             the banner: a decrypted copy of what a backup kept, not the phone and not an acquisition
    tool-output/backup_decrypt-<digest>.jsonl    one line per Manifest row: the whole account, whatever the answer shows inline

THE PASSWORD. It comes only from `password_ref`, a path to a regular file of mode 0600 (no access for group or other; a link, a pipe, a
device or a directory is refused; at most 4096 bytes; one trailing newline is dropped) that the job was given as an input. This process
never reads the file: it checks that the file is there and looks like one, and a child process of this tool opens it again (it must be the
same file), reads it, and hands the text to the library in memory. The password is not on any command line (the child is started with a
fixed command line and is told its paths on its standard input, which are not secret), not in any environment variable, not on standard
output or standard error (both of the child go nowhere), not in a path, a JSON key, an error message or a file; an exception of the library
is reported by its class name only. The tool runs only in a job run as secret output (SECRET_OUTPUT=1; the manifest's `secret_output:
"required"` makes every job of the tool one): elsewhere it is refused as JSON before anything is made, because what it writes is the
content of a phone.

THE OUTCOMES, told apart in `outcome` (and in `status`, complete / partial / failed, with the basis):
    verified             the decrypted Manifest.db opens as SQLite, and every row of a file was decrypted and the length of what was
                         written is the Size the Manifest records for it (a directory or a link row has no blob and is counted as such)
    partial              the above for some rows only; the rows that are not are listed by outcome (a blob the backup does not hold, a
                         length that is not the recorded Size, a name the backend could not select with certainty, a limit, the time)
    wrong_secret         the backup is of a shape this tool knows (Manifest.plist says it is encrypted and holds a key bag and a manifest
                         key) and the backend did not unlock it with this password. The backend does not say whether the password is wrong
                         or the key bag is of a kind it does not read; the two are not told apart
    secret_unavailable   the password file is missing, is not a regular file of mode 0600, is empty, is over 4096 bytes, is not UTF-8,
                         or changed between the two looks
    unsupported_format   the backup is not one this tool opens: Manifest.plist is missing or unreadable, does not say IsEncrypted is
                         true, holds no BackupKeyBag or ManifestKey, or Manifest.db is a plain SQLite file; nothing is attempted
    backend_unavailable  the library is not installed in this image

"Verified" means those two checks. It is not a claim that a file's content is the file the phone held: a file id is a locator, and the
Manifest records no digest of a file's content. The tool does not print or write a key bag, a class key or a manifest key; the answer says
whether Manifest.plist holds them and how long they are, and nothing more.

The backend selects a file by `relativePath = ? AND domain LIKE ? AND flags = 1 ORDER BY domain, relativePath LIMIT 1`, so a row can be
decrypted from another row's blob (two domains equal up to case, a `_` or `%` in a domain, a collation that equates two paths, a pattern
over SQLite's length limit). Before every file the child runs that query, with LIMIT 2, on a copy of the decrypted map; a row it does not
return alone (or whose query fails) is not decrypted and is listed as ambiguous_selection. The library's own naming of its output files is not used: it writes each file to a name this tool chose in a
private directory, and the tool then links it under the file id without replacing anything.
"""
import base64
import datetime
import errno
import hashlib
import json
import math
import os
import plistlib
import re
import select
import shutil
import signal
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
from pathlib import Path
from urllib.parse import quote

PARSER = "backup_decrypt/3"
TOOL = "backup_decrypt"
VALUES_NAME = "backup-decrypt-values.jsonl"        # unused: the tool has no values mode, the shared block names it
VALUES_FORMAT = "unused"


# --- shared with the pack's other tools: begin ---------------------------------------------
# The three tools of this pack carry this block byte for byte (a test holds the copies equal),
# so that they withhold the same strings, write the same files the same way and refuse in the
# same words. Standalone tools do not import each other: the block is copied.
#
# THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"), as the
# encrypted-containers pack's recovery_key_scan introduced it and the macOS pack's plist_read
# copied it:
#   1. The answer carries presence, kind, location (file and offset or path), length and counts.
#      It carries no value, no characters of one, no masked shape and no digest of one.
#   2. A value is written only on `write_values: true`, only when the tool runs as a job
#      (JOB_ID and OUT are set) that the harness ran as secret output (SECRET_OUTPUT=1, which the
#      manifest's `secret_output` declaration makes the job service set), and only to a file under
#      $OUT: JSON Lines, mode 0600, created exclusively before anything is read. Outside such a job
#      the request is refused as JSON and nothing is written.
#   3. A secret is never on a command line: these tools take a path and flags only.
#   4. A printed path component shaped like a recovery password is withheld on every output
#      channel (the answer, the files it names, an error message); the values file keeps the
#      real path.
#   5. The harness shows the requester a sealed file's size and digest, so neither may answer a
#      question about text nobody can see: a filter marks rows and never drops them, a window or an
#      expression that is not accepted writes a file of the same size as one that is, and every row
#      carries a random per-run `run`, so that no two runs share a digest.
#   6. One document is written, whole: from the moment the answer is being written a stop signal is
#      ignored, so a reader that is slow never gets a truncated answer followed by a failure. A reader that
#      takes nothing for WRITE_STALL_SECONDS is given up on: the tool exits (141) instead of waiting for ever.

# A stop that arrives while the rest of this module is still being read (the definitions below, the tool's own code after
# the block) is answered here, by one JSON document and exit 128 + the signal, as run_main answers it later. The handlers are
# installed as the module reaches this point, not when main() starts, so the window left is the interpreter's own start-up and
# the imports above the block, which no code in this file can close and which this tool does not claim: a stop there ends the
# process with no answer, before anything was read or written. run_main replaces these handlers.
EARLY_SIGNALS = [getattr(signal, name) for name in ("SIGTERM", "SIGINT", "SIGHUP") if hasattr(signal, name)]


def early_stop(signum, frame):
    for number in EARLY_SIGNALS:
        signal.signal(number, signal.SIG_IGN)
    name = signal.Signals(signum).name
    text = json.dumps({"error": "the tool was stopped by %s before it finished: this is not an answer to the question" % name,
                       "status": "failed", "status_basis": "stopped by %s before the tool had started to read anything" % name,
                       "interrupted": name}) + "\n"
    try:
        os.write(1, text.encode("utf-8"))
    except OSError:
        pass
    os._exit(128 + signum)


for early_number in EARLY_SIGNALS:
    signal.signal(early_number, early_stop)

WITHHELD = "<recovery-password-shaped name withheld>"
WITHHELD_LONG = "<name too long to judge withheld>"
PATHS_WITHHELD = [0]
# A BitLocker recovery password is eight groups of six digits: 48 digits. People save a key under its own name, and not
# only in the dashed form: with spaces, underscores or dots between the groups, with no separator at all, with another
# dash, comma, colon, bracket or quote mark, in full-width or Arabic-Indic digits, with a zero-width character or an accent
# inside, and a name can carry part of it or be split across two path components. A text is shaped like one when it holds
# RECOVERY_DIGITS (seven groups of six) or more decimal digits in a run that allows at most three characters that are neither
# a letter nor a digit between two digits (a run of white space counts as one, and `/` is such a character), after NFKC
# folding (which turns full-width digits, superscripts and circled digits into ASCII ones). Fewer digits are a timestamp, a
# phone number or an id.
# The judgment is linear in the text: the maximal runs of digits and separators are found in one pass, and only a run long
# enough to hold RECOVERY_DIGITS digits is looked at again, at its start (a pattern tried from every digit costs 41 steps per
# character on "41 digits and a letter", repeated). A path is judged only up to JUDGE_CHARS characters: nothing a file system
# holds is longer, and a longer text is withheld whole instead of being read, so that the cost of one hostile cell stays small.
RECOVERY_DIGITS = 42
JUDGE_CHARS = 8192
SEPARATOR = r"[\W_]"
DIGIT_RUN = re.compile(r"\d(?:%s{0,3}\d)*" % SEPARATOR)
KEY_START = re.compile(r"\d(?:%s{0,3}\d){%d}" % (SEPARATOR, RECOVERY_DIGITS - 1))
SPACES = re.compile(r"\s+")


def folded(text):
    """NFKC, with every run of white space as one space."""
    return SPACES.sub(" ", unicodedata.normalize("NFKC", text))


def key_spans(text):
    """(start, end) of every run of `text` (already folded) that holds RECOVERY_DIGITS or more digits."""
    return [run.span() for run in DIGIT_RUN.finditer(text)
            if run.end() - run.start() >= RECOVERY_DIGITS and KEY_START.match(text, run.start())]


def key_shaped(text):
    return bool(key_spans(folded(text)))


def shown(path, count=True):
    """A path as it may be printed: a component that holds digits of a text shaped like a recovery password (a key split
    across components included) is withheld, and a path too long to judge is withheld whole."""
    if not isinstance(path, str):
        return path
    if len(path) > JUDGE_CHARS:
        if count:
            PATHS_WITHHELD[0] += 1
        return WITHHELD_LONG
    parts = path.split("/")
    texts = [folded(part) for part in parts]
    spans = key_spans("/".join(texts))
    if not spans:
        return path
    at, hidden = 0, []
    for i, text in enumerate(texts):
        if any(start < at + len(text) and end > at for start, end in spans):
            hidden.append(i)
        at += len(text) + 1
    for i in hidden:
        parts[i] = WITHHELD
        if count:
            PATHS_WITHHELD[0] += 1
    return "/".join(parts)


def scrub(text):
    """Text that may quote a path, with anything shaped like a recovery password withheld."""
    text = DIGIT_RUN.sub(lambda run: WITHHELD if run.end() - run.start() >= RECOVERY_DIGITS and KEY_START.match(run.string, run.start())
                         else run.group(), text)
    if key_shaped(text):      # digits only NFKC folds (superscripts, circled digits): the text is not printed at all
        return WITHHELD
    return text


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def clean(value):
    """The value as strict JSON: a float that is not finite (JSON has no NaN or Infinity) is its text."""
    if isinstance(value, float) and not math.isfinite(value):
        return {"_float": repr(value)}
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    return value


def dumps(value, **kwargs):
    return json.dumps(clean(value), allow_nan=False, default=str, **kwargs)


# What is open when a run fails: the pages and the values file are closed and named in the error, so a
# result read before the failure is kept, whole, and never left as a hidden temporary file.
OPEN_PAGES = []
OPEN_VALUES = []
NONCE = "%d-%d" % (os.getpid(), time.time_ns())


# Things the run made that a failure or a stop must not leave behind (a working copy of an evidence file). Each is a
# callable that removes what the tool itself created; it is run once, by fail() and by a stop signal.
CLEANUP = []


def run_cleanup():
    while CLEANUP:
        step = CLEANUP.pop()
        try:
            step()
        except Exception:
            pass


def wrap_up(answer):
    """What an answer that ends the run early carries: the pages already written are closed and named, the values
    file is closed and counted, and what the tool made as scratch is removed."""
    kept = []
    for page in OPEN_PAGES:
        if page._out is not None:
            try:
                kept.append(page.finish().get("all_results"))
            except Exception:
                pass
    if kept:
        answer["rows_read_before_the_failure_kept_in"] = kept
    for values in OPEN_VALUES:
        values.close()
        if values.written:
            answer["values_written_before_the_failure"] = {"file": values.shown, "rows": values.written}
    run_cleanup()
    return answer


WRITE_STALL_SECONDS = 30
WRITE_CHUNK = 4096


def write_stalled(signum, frame):
    sys.stderr.write("the reader took nothing for %d seconds: the answer is not delivered\n" % WRITE_STALL_SECONDS)
    raise SystemExit(141)


def emit(text):
    """Write one document to standard output, whole. From here a stop signal is ignored: the answer is written in one piece
    (a reader that is slow, or has not started, sees all of it) and never as a truncated document followed by a failure.
    A reader that takes nothing for WRITE_STALL_SECONDS is given up on (exit 141): without that, a pipe nobody reads could
    be ended only by SIGKILL."""
    for number in STOP_SIGNALS:
        signal.signal(number, signal.SIG_IGN)
    data = memoryview((text + "\n").encode("utf-8"))
    # One os.write on a blocking pipe returns only when everything it was given has gone in, however slowly the reader takes it,
    # so a single call for the whole document would restart the clock once. A write of at most WRITE_CHUNK bytes (a pipe takes
    # up to PIPE_BUF bytes in one piece) returns when that much has been taken, so the clock restarts on every chunk the reader
    # takes and only a reader that takes nothing for WRITE_STALL_SECONDS is given up on.
    timed = hasattr(signal, "setitimer")
    if timed:
        try:
            signal.signal(signal.SIGALRM, write_stalled)
        except ValueError:      # not the main thread: no deadline
            timed = False
    try:
        sys.stdout.flush()
        descriptor = sys.stdout.fileno()
        while len(data):
            if timed:
                signal.setitimer(signal.ITIMER_REAL, WRITE_STALL_SECONDS)       # progress restarts the wait
            try:
                data = data[os.write(descriptor, data[:WRITE_CHUNK]):]
            except BlockingIOError:      # a pipe set non-blocking by its owner and full: wait until it can take more
                select.select([], [descriptor], [], 1.0)
    except OSError:       # the reader went away: there is nobody to answer
        raise SystemExit(1)
    finally:
        if timed:
            signal.setitimer(signal.ITIMER_REAL, 0)


def fail(message, **extra):
    answer = {"error": scrub(str(message)), "status": "failed", "status_basis": "the tool stopped with an error: %s" % scrub(str(message)),
              **{k: (scrub(v) if isinstance(v, str) else v) for k, v in extra.items()}}
    emit(dumps(wrap_up(answer)))
    raise SystemExit(1)


class Interrupted(BaseException):
    """A stop signal (SIGTERM, SIGINT or SIGHUP) arrived. A BaseException, so that no `except Exception` of a tool
    swallows it; run_main answers for it once, at the top."""

    def __init__(self, signum):
        BaseException.__init__(self, signum)
        self.signum = signum


STOP_SIGNALS = [getattr(signal, name) for name in ("SIGTERM", "SIGINT", "SIGHUP") if hasattr(signal, name)]


def stop_handler(signum, frame):
    # The answer to the first signal is written once: a second signal while it is written changes nothing.
    for number in STOP_SIGNALS:
        signal.signal(number, signal.SIG_IGN)
    raise Interrupted(signum)


def stopped(signum):
    """One JSON answer for a run a signal ended, then exit 128 + the signal. The pages and the values file are closed
    and named, the scratch the tool made is removed, and nothing is said about what the tool had read."""
    name = signal.Signals(signum).name
    answer = wrap_up({"error": "the tool was stopped by %s before it finished: this is not an answer to the question" % name,
                      "status": "failed", "status_basis": "stopped by %s before the answer was complete" % name,
                      "interrupted": name})
    emit(dumps(answer))
    raise SystemExit(128 + signum)


class Timeout(Exception):
    pass


def alarm_handler(signum, frame):
    raise Timeout()


def timed_search(pattern, text, seconds):
    """pattern.search(text), stopped after `seconds` where the platform can: a pattern the caller
    wrote can backtrack without end."""
    if not hasattr(signal, "setitimer"):
        return pattern.search(text)
    old = signal.signal(signal.SIGALRM, alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return pattern.search(text)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)


class LosslessPage:
    """A page an agent reads, and the whole result in a file the answer names.

    The page stays small (rows, and bytes when a byte limit is given); when there are more rows
    the whole result is written as JSON Lines under work/<agent>/tool-output (in a job,
    $OUT/tool-output) and named: nothing is cut. The file name is a digest of the page's key (a
    path), never of a value. Rows are written with ensure_ascii on: a path the filesystem gave as
    bytes that are not UTF-8 reaches Python as lone surrogates, which a UTF-8 file cannot hold
    and an escape can. A rerun that would replace a larger earlier file of the same name writes a
    new name and says which earlier file it kept.
    """

    def __init__(self, tool, key, limit, byte_limit=None):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = safe_name(tool)
        self.limit = limit
        self.byte_limit = byte_limit
        self.page = []
        self.page_bytes = 0
        self.full = False
        self.bytes_bound_hit = False
        self.total = 0
        self._out = None
        self._tmp = None
        OPEN_PAGES.append(self)
        # The key is the question (a path as it may be printed, a filter), plus this call's own nonce: two
        # questions that print alike (two files in directories whose names are withheld, two messages passed
        # in the call) never share a file, and a rerun never replaces an earlier result.
        digest = hashlib.sha256(dumps([key, NONCE], sort_keys=True).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's output: the whole
            # result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (safe_name(job), name)
        else:
            agent = safe_name(os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(dumps(row))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if not self.full and len(self.page) < self.limit:
            size = len(dumps(row)) if self.byte_limit is not None else 0
            if self.byte_limit is None or self.page_bytes + size <= self.byte_limit:
                self.page.append(row)
                self.page_bytes += size
                return
            self.bytes_bound_hit = True
        # From the first row that does not fit, every later row goes to the file only: the page
        # is a prefix.
        self.full = True
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.byte_limit is not None:
            result["inline_byte_limit"] = self.byte_limit
            if self.bytes_bound_hit:
                result["inline_bounded_by_bytes"] = True
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            target, shown_as = self.path, self.shown
            if target.exists() and target.stat().st_size > os.path.getsize(self._tmp):
                n = 2
                while target.with_name("%s-%d%s" % (target.stem, n, target.suffix)).exists():
                    n += 1
                target = target.with_name("%s-%d%s" % (target.stem, n, target.suffix))
                shown_as = self.shown.rsplit("/", 1)[0] + "/" + target.name
                result["kept_earlier_larger_result"] = self.shown
            os.replace(self._tmp, target)
            result["all_results"] = shown_as
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The pattern of recovery_key_scan (encrypted-containers), copied: call `add` once per finding
    with its id, its locator and the value. With `enabled` false it writes nothing and
    `summary()` says so.
    """

    def __init__(self, enabled):
        self.enabled = enabled
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        self.run = os.urandom(8).hex()      # in every row: the file's digest is different in every run, whatever it holds
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % TOOL
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(
                "write_values is refused in a job that is not run as secret output (SECRET_OUTPUT is not 1): the values file would "
                "be sealed as ordinary output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. "
                "Run this as job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % TOOL
            )
        self.path = Path(self.out) / VALUES_NAME
        self.shown = "store/jobs/%s/out/%s" % (safe_name(self.job), VALUES_NAME)
        # Created now, before anything is read: a file or a link already at that name is refused
        # by name at once (O_EXCL does not follow a link, a dangling one included), instead of
        # failing, or writing through it, after the scan. With nothing found it stays an empty
        # file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")
        OPEN_VALUES.append(self)

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        # ensure_ascii: a file name that is not UTF-8 is a lone surrogate to Python; an escape
        # reads back, a raw write cannot.
        self._fh.write(dumps({"finding_id": finding_id, **locator, "run": self.run, "value": value}))
        self._fh.write("\n")
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": VALUES_FORMAT if self.enabled else None,
        }


def open_values(args):
    """The values file, or a refusal as JSON: write_values must be true or false."""
    wanted = args.get("write_values", False)
    if not isinstance(wanted, bool):
        fail("write_values must be true or false")
    try:
        return SecretValues(wanted)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)


def positive(args, name, default, maximum=None):
    value = args.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        fail("%s must be a positive integer" % name, **{name: value})
    if maximum is not None and value > maximum:
        fail("%s is at most %d" % (name, maximum), **{name: value})
    return value


def seconds(args, name, default, cap):
    """A time limit: finite, positive and at most `cap` (the tool's own limit less a margin, so that the
    answer is written before the harness stops the tool; NaN and Infinity would switch the clock off)."""
    value = args.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        fail("%s must be a positive finite number of seconds" % name, **{name: str(value)})
    if value > cap:
        fail("%s is at most %s seconds (the tool's own limit less the margin it needs to write its answer)" % (name, cap), **{name: value})
    return float(value)


def read_args():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def send(result):
    emit(dumps(result, indent=2))


def run_main(main):
    for number in STOP_SIGNALS:
        signal.signal(number, stop_handler)
    try:
        try:
            main()
        except SystemExit:
            raise
        except Exception as exc:  # never an empty or clean answer for a failure, and never a traceback
            fail("unexpected failure: " + (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
    except Interrupted as stop:
        stopped(stop.signum)
# --- shared with the pack's other tools: end -----------------------------------------------

# BEGIN SHARED PLACE
# The same text is in every windows-forensics tool that keeps a result file (a windows-forensics test holds the copies equal).
# A result file that is there is never replaced by another result: a file of the same bytes is named again, any other result takes the next free
# <stem>-<n><suffix>. A result written at the same moment cannot be replaced either: taking a name fails when it is there.
# Only regular files are ever compared: both names are opened with O_NONBLOCK and O_NOFOLLOW and looked at with fstat before a byte is
# read, so a FIFO, a device, a directory or a link at a name (the caller's own results_to, say) is another result's and cannot hold the
# tool. The comparing of one call has PLACE_COMPARE_SECONDS in all; past it an earlier result is taken as different and this one takes
# the next free name (nothing is replaced, but an identical rerun may then be named anew).
# The name is taken with a hard link of the finished file, so it never holds an empty file, whatever stops the tool and when (SIGKILL
# included). Where the file system refuses the link, the name is taken with an exclusive create and the file is moved over it: a stop
# that unwinds (an exception) takes the empty name back while it is still the empty file this call made; a stop that ends the process
# without unwinding (SIGKILL, the handlers of the STOP block) between the create and the move leaves the empty name, and the next run takes -2.
PLACE_COMPARE_SECONDS = 5   # all the comparing one call to place_without_replacing does; past it an earlier result is taken as different


def same_bytes(a, b, deadline=None):
    """Whether two files hold the same bytes (read in blocks, never whole). Each is opened without waiting and without following a link
    (O_NONBLOCK, O_NOFOLLOW) and looked at with fstat first: only two regular files of one size are read, so a FIFO, a device, a
    directory or a link at either name is never read (a FIFO would hold the tool for ever). Past `deadline` (a monotonic time) the
    answer is False."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fa = fb = None
    try:
        fa = os.fdopen(os.open(str(a), flags), "rb")
        fb = os.fdopen(os.open(str(b), flags), "rb")
        sa, sb = os.fstat(fa.fileno()), os.fstat(fb.fileno())
        if (sa.st_mode & 0o170000) != 0o100000 or (sb.st_mode & 0o170000) != 0o100000 or sa.st_size != sb.st_size:
            return False
        while True:
            if deadline is not None and time.monotonic() > deadline:
                return False
            x, y = fa.read(1 << 20), fb.read(1 << 20)
            if x != y:
                return False
            if not x:
                return True
    except OSError:
        return False
    finally:
        for fh in (fa, fb):
            if fh is not None:
                fh.close()


def _take_name(tmp, candidate):
    """Give the finished `tmp` the name `candidate` if it is free, and say whether it now has it (False: the name is taken, by a file, a
    link, a FIFO or a directory). The name is taken with a hard link, so it never holds an empty file; where the file system refuses the
    link it is taken with an exclusive create and the file is moved over it, and a stop that unwinds in between takes the empty name back."""
    try:
        os.link(tmp, candidate)
    except FileExistsError:
        return False
    except OSError:
        pass                                   # no hard links here: the older way, below
    else:
        try:
            os.unlink(tmp)
        except OSError:
            pass                               # the hidden name stays beside the placed file; the stop path of the page removes it
        return True
    fd = made = None
    try:
        fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        made = os.fstat(fd)
        closing, fd = fd, None
        os.close(closing)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return True
    except FileExistsError:
        return False
    except BaseException:
        try:
            if made is None and fd is not None:
                made = os.fstat(fd)
        except OSError:
            pass
        try:
            if fd is not None:
                os.close(fd)
        except OSError:
            pass
        try:
            now = os.lstat(candidate)
            if made is not None and (now.st_mode & 0o170000) == 0o100000 and now.st_size == 0 and (now.st_dev, now.st_ino) == (made.st_dev, made.st_ino):
                os.unlink(candidate)           # the empty name this call took is not left behind
        except OSError:
            pass
        raise


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. A name that is taken (by a file, a link, a FIFO or a directory) is
    left as it is: a regular file of the same bytes is named again, any other result takes the next free <stem>-<n><suffix>. Returns the
    path that holds it. The comparing with earlier results has PLACE_COMPARE_SECONDS in all: past it an earlier result is taken as
    different and this one takes the next free name."""
    deadline = time.monotonic() + PLACE_COMPARE_SECONDS
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        if _take_name(tmp, candidate):
            return candidate
        if not os.path.islink(candidate) and same_bytes(tmp, candidate, deadline):
            os.unlink(tmp)
            return candidate
    raise OSError("no free name beside %s" % path)
# END SHARED PLACE

# BEGIN SHARED PROCESS
# The same text is in pcap_extract, zeek_run, suricata_run, the network-capture recipe and computer-forensics-base's
# archive_extract; tests/pack-network-withholding.test.ts holds the four network copies equal and tests/pack-base-shared.test.ts
# holds archive_extract's to them. A program an engine tool runs is started in THIS tool's process group, never in a session of
# its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid,
# SIGKILL)), and an engine in a group of its own goes on writing into the output directory after the tool is gone. On
# Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it started by
# walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word. Only what is
# below a program this tool started and has not yet waited for is ever signalled: the walk starts at that program's pid
# and nowhere else, and a program that has been waited for (its pid may be another process's by now) is left alone. The
# walk is bounded (MAX_ROUNDS and WALK_SECONDS, below). A stop signal is the one case that reaches further: it also
# ends everything below the tool itself (a program that was forked a moment before it was entered in ACTIVE is among it) and what
# the tool started and lost (reap_orphans): a process that was seen below the tool, in the tool's own group, and whose parent has since
# ended. Nothing else is ever ended: a process the tool never saw in its tree (the next stage of a pipeline the tool heads, a process a
# launcher put in the group) is left alone, whoever leads the group. A program that has ended while something it started still
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds (and POST_EXIT_BYTES bytes) and goes on without them.
# The walk below a program is bounded: MAX_ROUNDS rounds and WALK_SECONDS seconds. Each process is stopped (SIGSTOP) as the walk finds it,
# so one that forks fast cannot outrun the walk; the walk is repeated for what the stopped ones had already forked, and the stopped set is
# then killed. A tree that is still growing at the bound is left, and process_notes() says so.
# Before a pid other than the program itself is signalled, its identity is read again (same_process(pid, ident)): the start time, from
# /proc/<pid>/stat (field 22, counted after the last ")") on Linux, from libproc's PROC_PIDTBSDINFO (pbi_start_tvsec, pbi_start_tvusec;
# written from <sys/proc_info.h>, not run on macOS in this repository's tests) on macOS, and from `ps -o lstart=` (to the second: coarse)
# where neither answers. The parent is no part of it: a child is re-parented when its parent ends, and is still the process that was
# listed. A pid that is gone, or whose start time is not the listed one, is left alone; a pid whose start time could not be read when it
# was listed is signalled only if it can be read now and is in the tool's own group; a ps listing that gave no start time (a minimal ps) is
# checked only for the pid still being there.
# A tree that cannot be listed (ps fails, lists nothing or needs more than PS_WAIT seconds, /proc cannot be read or takes more than
# TABLE_SECONDS) is never taken as an empty one: list_descendants raises TreeNotListed, the program itself is still ended, and a sentence
# in process_notes() says that the tree could not be listed (communicate_bounded also appends it to the stderr bytes it returns when it
# ended the program at its deadline). descendants() is list_descendants for a caller that cannot take an exception (a signal handler): its
# list is empty and has not_listed = True when the tree could not be listed.
# Open: a pid that ends and is reused between the identity check and the signal (two calls) is signalled; the Linux rule that a member of
# the tool's own group that holds the tool's pipe is ended; on macOS a daemon that holds the pipes of a finished program is not found (no
# /proc/<pid>/fd); a tool SIGKILLed between the stop and the kill leaves the program and the stopped set stopped (the harness ends the
# tool's group, and with it the stopped ones that are in it); a carrier's answer carries program_group (process_verdict, process_notes)
# only where that carrier's own code calls process_apply (without the call a program's leftovers are ended but not reported); the start of the interpreter, before any handler is in, is a window a signal can land in.
# What a program leaves behind (settle). A program can exit by itself and leave a process that goes on writing a file the answer then reports:
# one in a session of its own, or one that holds none of the tool's descriptors, which neither the walk nor the pipes reach. On Linux spawn()
# makes the tool a subreaper (become_subreaper, PR_SET_CHILD_SUBREAPER): such a process is adopted by the tool, so it is a direct child of the
# tool, and settle() ends it: when a program leaves ACTIVE after it has ended or been killed (ACTIVE is a list whose remove() does it), and at
# the end of communicate_bounded and inside kill_all. It ends only a child of the tool that is no program's own: not a program spawn() started
# (SPAWNED: Popen reaps those, their returncode is never taken), not one kept (KEEP, process_keep(pid), spawn(argv, leaves=True) for a
# program that leaves a process on purpose) and not a child the tool already had (PRE_KIDS). It stops each one, what it started with it (the
# walk above), kills and reaps them, for at most LEFTOVER_SECONDS, reading the clock for every process. While another program is running in
# ACTIVE nothing is ended and the answer says it is unproven. process_verdict() says what was found; process_apply(answer) puts it into an
# answer as program_group and turns a complete answer partial when a program left something or that could not be ruled out: a carrier
# calls it once where it prints its answer. Where nothing is adopted (not Linux, or the kernel refuses) settle() ends only what the tool saw
# below a program whose parent is gone, and the answer is unproven (NONLINUX_UNPROVEN_DOWNGRADE below is the one line that decides whether
# that alone makes a complete answer partial on a host that is not Linux). Not reached by any of this: a process that is not a descendant of
# a program (started through a service manager, a socket, another PID namespace), and the tool itself being killed (the harness ends its group).
# What a program's pipes deliver after it ended (the byte cap). communicate_bounded reads the pipes itself (a selector, not
# Popen.communicate) and looks at the program after every read. From the moment the program has ended, or been killed at its deadline, it
# takes at most POST_EXIT_BYTES (1 MiB) more bytes from its two pipes together and at most PIPE_GRACE seconds, whichever comes first; a
# program's own last words are in the pipe already (a pipe holds far less than the cap), so only what a process that went on holding the
# pipe wrote can be cut. At the cap the tool stops reading, ends the holder (reap_orphans, settle) and lets the pipes go: PIPE_CUT["cut"]
# counts the calls cut that way, process_notes() says so, and process_apply turns a complete answer partial. The bytes kept are the ones
# read, not a whole stream: a caller that parses the output sees the program's output and at most 1 MiB of what a leftover wrote. While the
# program is still alive nothing is capped here (a program's own output is its caller's to bound); the timing is unchanged.
import select as _select
import selectors as _selectors
import time

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
class _Active(list):
    """The programs running now. A program that leaves the list after it has ended or been killed (a carrier removes it when it has waited
    for it) is followed by settle(): what it left behind is ended before the carrier reads what the program wrote. One that is still
    running when it is removed is not looked at."""

    def remove(self, proc):
        list.remove(self, proc)
        if proc.poll() is not None:
            settle()


ACTIVE = _Active()             # the programs running now
SPAWNED = {}                   # the programs spawn() started: pid -> identity (Popen reaps them, settle() never does)
KEEP = {}                      # the processes left on purpose: pid -> identity (settle() leaves them)
PRE_KIDS = {}                  # the children the tool already had when the first program was spawned: pid -> identity
LEAVES = {}                    # the programs started with leaves=True that have not ended yet: pid -> Popen
LEFT = {"left_behind": 0, "unproven": []}   # how many live processes settle() ended, and why nothing-left-behind cannot be proven
SUB = {"tried": False, "on": False, "note": None}        # whether the subreaper was asked for, and is on
SETTLING = [False]             # settle() is running (the stop signal's own call goes through)
LEFTOVER_SECONDS = 3              # the most one settle() works, in seconds; the clock is read for every process it ends, not once per pass
SETTLE_LOOK = 0.05             # the pause before the look that follows an ending: a fork that was under way when the first process died
# The one line the owner decides: on a host that cannot adopt orphaned processes (not Linux) a program may have left a process nobody can find.
# True: that alone is `unproven`, and process_apply turns a complete answer partial. False: the answer only carries a note.
NONLINUX_UNPROVEN_DOWNGRADE = True
SEEN = set()                   # the pids seen below a program this tool started: the only ones reap_orphans may end once their parent is gone
SEEN_IDENT = {}                # what each pid in SEEN was (its start time) when it was seen below the tool: a pid that ended and was reused does not match
NOTES = []                     # what this block could not do, as sentences for an answer (process_notes())
MAX_ROUNDS, WALK_SECONDS = 8, 15   # the bound of the walk below a program: rounds, and seconds
TABLE_SECONDS = 10             # the longest reading of /proc (or of a process table) is given
SEEN_MAX = 1 << 16             # the most pids SEEN holds

def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, leaves=False, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    become_subreaper()
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    proc = subprocess.Popen(argv, **kwargs)
    SEEN.add(proc.pid)
    started = _read_ident(proc.pid, "proc" if os.path.isdir("/proc/self") else "libproc")
    if started is not None:
        SEEN_IDENT[proc.pid] = started
    SPAWNED[proc.pid] = started
    if leaves:
        LEAVES[proc.pid] = proc     # what this program leaves behind stays (settle() keeps it)
    return proc


class TreeNotListed(Exception):
    """The processes could not be listed: ps failed, listed nothing or needed more than PS_WAIT seconds, /proc could not be read, or reading
    it took more than TABLE_SECONDS. It is never to be read as a tree with nothing below it."""


class _Listing(list):
    """The pids below a process, as a list; .ident holds each pid's identity from the same reading, .not_listed says the tree could not be listed."""
    ident = None
    not_listed = False


class _Table(dict):
    """{pid: (parent pid, process group)}; .ident holds each pid's identity from the same reading."""
    ident = None


def _note(text):
    """Record a sentence about what this block could not do (once, at most 20) and return it."""
    if text not in NOTES and len(NOTES) < 20:
        NOTES.append(text)
    return text


def process_notes():
    """What this block could not do so far, as sentences (a tree that could not be listed, a walk that was cut), for an answer."""
    return list(NOTES)


def _libproc_start(pid):
    """(seconds, microseconds) of the start of `pid` from libproc's PROC_PIDTBSDINFO (macOS), or None. Written from <sys/proc_info.h>
    (struct proc_bsdinfo, 136 bytes, flavor 3); not run on macOS in this repository's tests."""
    try:
        import ctypes.util

        class BsdInfo(ctypes.Structure):
            _fields_ = [("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32), ("pbi_xstatus", ctypes.c_uint32),
                        ("pbi_pid", ctypes.c_uint32), ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
                        ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32), ("pbi_rgid", ctypes.c_uint32),
                        ("pbi_svuid", ctypes.c_uint32), ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
                        ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32), ("pbi_nfiles", ctypes.c_uint32),
                        ("pbi_pgid", ctypes.c_uint32), ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
                        ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32), ("pbi_start_tvsec", ctypes.c_uint64),
                        ("pbi_start_tvusec", ctypes.c_uint64)]

        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        lib.proc_pidinfo.restype = ctypes.c_int
        info = BsdInfo()
        if lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
            return None
        return (int(info.pbi_start_tvsec), int(info.pbi_start_tvusec))
    except Exception:  # noqa: BLE001 - no library, no symbol, a sandbox: the caller falls back
        return None


def _ps_start(pid):
    """The start time `ps -o lstart= -p <pid>` prints, to the second (coarse), or None when ps fails, takes more than PS_WAIT seconds or prints none."""
    try:
        done = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True, timeout=PS_WAIT)
    except (OSError, subprocess.SubprocessError):
        return None
    text = " ".join(done.stdout.split())
    return text if done.returncode == 0 and text else None


def _read_ident(pid, kind):
    """The identity of `pid` read the way `kind` ("proc", "libproc" or "ps") says, or None when the process is gone or the way fails."""
    if kind == "proc":
        try:
            with open("/proc/%d/stat" % pid, "rb") as fh:
                data = fh.read()
            return ("proc", int(data[data.rindex(b")") + 2:].split()[19]))   # field 22, counted after the last ")": the name may hold one
        except (OSError, ValueError, IndexError):
            return None
    if kind == "libproc":
        started = _libproc_start(pid)
        return None if started is None else ("libproc", started)
    started = _ps_start(pid)
    return None if started is None else ("ps", started)


def process_ident(pid):
    """What tells the process that has `pid` now from a later one that gets the same pid: its start time. Linux: field 22 of /proc/<pid>/stat;
    macOS: libproc's pbi_start_tvsec and pbi_start_tvusec; where neither answers, the start time ps prints (to the second). The parent is no
    part of it: a child is re-parented when its parent ends, and is still the process that was listed. None where the process is gone or
    cannot be read."""
    if os.path.isdir("/proc/self"):
        return _read_ident(pid, "proc")
    return _read_ident(pid, "libproc") or _read_ident(pid, "ps")


def same_process(pid, ident):
    """Whether `pid` is still the process `ident` was read from (process_ident, or the listing a walk made): a pid that is gone, or that
    another process has taken since (another start time), is not. An `ident` of None (it could not be read when the process was listed) is
    not vouched for either: the pid is signalled only if it can be read now and is in this process's own group. A listing by plain ps that
    gave no start time ("listed") can only be checked for the pid still being there."""
    if ident is None:
        try:
            return process_ident(pid) is not None and os.getpgid(pid) == os.getpgrp()
        except OSError:
            return False
    if ident[0] == "listed":
        try:
            os.kill(pid, 0)
        except PermissionError:
            return True
        except OSError:
            return False
        return True
    return _read_ident(pid, ident[0]) == ident


def _seen_below(pids, ident):
    """Enter pids seen below the tool in SEEN, with the identity the listing that showed them gave."""
    for pid in pids:
        if pid in SEEN or len(SEEN) < SEEN_MAX:
            SEEN.add(pid)
            if ident.get(pid) is not None:
                SEEN_IDENT[pid] = ident[pid]


def _ps_rows(columns):
    """The rows of `ps -A -o <columns>` as lists of fields. Raises TreeNotListed when ps cannot be run, fails, takes more than PS_WAIT seconds
    or lists nothing."""
    try:
        done = subprocess.run(["ps", "-A", "-o", columns], capture_output=True, text=True, timeout=PS_WAIT)
    except subprocess.TimeoutExpired as exc:
        raise TreeNotListed("ps took more than %d seconds" % PS_WAIT) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise TreeNotListed("ps could not be run: %s" % type(exc).__name__) from exc
    rows = [line.split() for line in done.stdout.splitlines() if line.split()]
    if done.returncode != 0 or not rows:
        raise TreeNotListed("ps %s" % ("exited %d" % done.returncode if done.returncode != 0 else "listed nothing"))
    return rows


def _children_libproc(pid):
    """The direct children of `pid` on macOS, from libproc (macOS only: proc_listchildpids is not a symbol of the other
    BSDs; a library call, so no program is started and nothing can be slow); None when the library, the symbol or the
    call is not there."""
    try:
        import ctypes.util
        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        lib.proc_listchildpids.restype = ctypes.c_int
        size = 256
        while size <= 1 << 16:
            buf = (ctypes.c_int * size)()
            if lib.proc_listchildpids(pid, buf, ctypes.sizeof(buf)) < 0:
                return None
            found = []
            for value in buf:
                if value <= 0:
                    break
                found.append(int(value))
            if len(found) < size:
                return found
            size *= 4
        return found
    except Exception:  # noqa: BLE001 - no library, no symbol: the caller falls back
        return None


PS_WAIT = 10    # seconds the ps fallback is given: ps is slow on a heavily loaded host, and a tree that is not found is a program left running


def _below(kids, pid):
    """Every process below `pid` in `kids` ({parent: [children]}), a parent before its children."""
    found, seen, queue = [], {pid}, [pid]
    for parent in queue:
        for child in kids.get(parent, []):
            if child not in seen:
                seen.add(child)
                found.append(child)
                queue.append(child)
    return found


def _libproc_works(pid):
    """Whether an empty libproc answer for `pid` can be believed: libproc has just listed `pid` as this tool's own child, or, when `pid`
    is the tool itself, has just listed the tool as its parent's child. A library that lists nothing for a live process is not working
    (as in a sandbox that denies it)."""
    if pid in (_children_libproc(os.getpid()) or []):
        return True
    return pid == os.getpid() and os.getpid() in (_children_libproc(os.getppid()) or [])


def list_descendants(pid):
    """Every process below `pid` (never one beside it): from /proc where there is one, else from libproc, else from ps (given PS_WAIT
    seconds). libproc is believed when it lists a child; an empty answer is believed only when libproc has just listed this tool's own child
    `pid` (a library that answers nothing for a live child is not working, as in a sandbox that denies it), and otherwise ps is asked. The
    list carries .ident, the identity of each pid from the same reading. Raises TreeNotListed when the processes cannot be listed: that is
    never an empty list."""
    kids, ident = {}, {}
    try:
        if os.path.isdir("/proc/self"):
            started = time.monotonic()
            for entry in os.listdir("/proc"):
                if time.monotonic() - started > TABLE_SECONDS:
                    raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        kids.setdefault(int(fields[1]), []).append(int(entry))
                        ident[int(entry)] = ("proc", int(fields[19]))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            first = _children_libproc(pid)
            if first:
                found, seen, stack = list(first), {pid, *first}, list(first)
                while stack:
                    for child in _children_libproc(stack.pop()) or []:
                        if child not in seen:
                            seen.add(child)
                            found.append(child)
                            stack.append(child)
                listing = _Listing(found)
                listing.ident = {}
                for child in found:
                    started = _libproc_start(child)
                    if started is not None:
                        listing.ident[child] = ("libproc", started)
                return listing
            if first is not None and _libproc_works(pid):
                listing = _Listing()
                listing.ident = {}
                return listing
            for row in _ps_rows("pid=,ppid=,lstart="):
                if len(row) >= 2 and row[0].isdigit() and row[1].isdigit():
                    kids.setdefault(int(row[1]), []).append(int(row[0]))
                    ident[int(row[0])] = ("ps", " ".join(row[2:])) if len(row) >= 6 else ("listed", None)
    except OSError as exc:
        raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    listing = _Listing(_below(kids, pid))
    listing.ident = {child: ident[child] for child in listing if child in ident}
    return listing


def descendants(pid):
    """list_descendants for a caller that cannot take an exception (a signal handler): the same list, but when the tree cannot be listed the
    list is empty, has not_listed = True, and process_notes() says so."""
    try:
        return list_descendants(pid)
    except TreeNotListed as exc:
        _note("the processes below pid %d could not be listed (%s)" % (pid, exc))
        listing = _Listing()
        listing.ident = {}
        listing.not_listed = True
        return listing


def _process_table():
    """{pid: (parent pid, process group)} for every process, from /proc where there is one, else from ps (given PS_WAIT seconds); .ident holds
    each pid's identity from the same reading. Raises TreeNotListed when neither answers."""
    table, ident = _Table(), {}
    try:
        if os.path.isdir("/proc/self"):
            started = time.monotonic()
            for entry in os.listdir("/proc"):
                if time.monotonic() - started > TABLE_SECONDS:
                    raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        table[int(entry)] = (int(fields[1]), int(fields[2]))
                        ident[int(entry)] = ("proc", int(fields[19]))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            for row in _ps_rows("pid=,ppid=,pgid=,lstart="):
                if len(row) >= 3 and all(part.isdigit() for part in row[:3]):
                    table[int(row[0])] = (int(row[1]), int(row[2]))
                    ident[int(row[0])] = ("ps", " ".join(row[3:])) if len(row) >= 8 else ("listed", None)
    except OSError as exc:
        raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    table.ident = ident
    return table


def _sample(pid):
    """Remember what is below `pid` now, by the cheap routes only (/proc, or libproc on macOS; never a program): a process that is seen
    here and later loses its parent is the tool's to end, and one that was never seen is not."""
    try:
        if os.path.isdir("/proc/self"):
            table = _process_table()
            kids = {}
            for child, (parent, _group) in table.items():
                kids.setdefault(parent, []).append(child)
            _seen_below(_below(kids, pid), table.ident)
        else:
            seen, stack = {pid}, [pid]
            while stack:
                for child in _children_libproc(stack.pop()) or []:
                    if child not in seen:
                        seen.add(child)
                        stack.append(child)
            idents = {child: ("libproc", started) for child in seen - {pid} for started in [_libproc_start(child)] if started is not None}
            _seen_below(seen - {pid}, idents)
    except Exception:  # noqa: BLE001 - a sample is best effort
        pass


def _pipe_inodes(proc):
    """The inodes of the pipes the tool holds with `proc` (Linux: /proc names a pipe by it; elsewhere the answer is not used)."""
    found = set()
    for handle in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if handle is not None:
                found.add(os.fstat(handle.fileno()).st_ino)
        except (OSError, ValueError):
            pass
    return found


def _holds_pipe(pid, inodes):
    """Whether `pid` holds one of the pipes (Linux only, from /proc/<pid>/fd): the pipes are private to the tool and what it started."""
    try:
        for name in os.listdir("/proc/%d/fd" % pid):
            try:
                link = os.readlink("/proc/%d/fd/%s" % (pid, name))
            except OSError:
                continue
            if link.startswith("pipe:[") and link.endswith("]") and int(link[6:-1]) in inodes:
                return True
    except (OSError, ValueError):
        pass
    return False


def reap_orphans(inodes=None):
    """Kill what this tool started and lost: a process of the tool's own group that is no longer below the tool (its parent ended and
    init adopted it, so the walk from a program's pid cannot find it) and that the tool knows to be its own: it was seen below the tool
    (SEEN: the programs it started, the trees it listed, the samples taken while it waited), or, on Linux, it holds one of `inodes`,
    the pipes the tool made. A process the tool never saw in its tree is not touched, whoever leads the group: the next stage of a
    pipeline the tool heads, or a process a launcher put in the group, is not the tool's. A process outside the group is never looked
    at, and a pid is checked against the group, and against the identity it had when it was seen (same_process), at the moment it is
    signalled. Returns the pids signalled; when the processes cannot be listed it signals none and process_notes() says so."""
    me = os.getpid()
    try:
        if os.getpgrp() != me:
            return []
    except OSError:
        return []
    try:
        table = _process_table()
    except TreeNotListed as exc:
        _note("what the tool started and lost could not be looked for: the processes could not be listed (%s)" % exc)
        return []
    kids = {}
    for pid, (parent, _group) in table.items():
        kids.setdefault(parent, []).append(pid)
    below = set(_below(kids, me))
    on_linux = os.path.isdir("/proc/self")
    killed = []
    started = time.monotonic()
    for pid, (_parent, group) in table.items():
        if time.monotonic() - started > TABLE_SECONDS:
            _note("the look for what the tool started and lost was cut after %d seconds" % TABLE_SECONDS)
            break
        if group != me or pid == me or pid in below:
            continue
        listed = table.ident.get(pid)
        holder = False
        if pid in SEEN:
            before = SEEN_IDENT.get(pid)
            if before is not None and listed is not None and before != listed:
                continue                           # the pid is another process's now: one the tool never saw
        elif inodes and on_linux and _holds_pipe(pid, inodes):
            holder = True
        else:
            continue
        try:
            if os.getpgid(pid) != me:
                continue
            if not same_process(pid, listed) or (holder and not _holds_pipe(pid, inodes)):
                continue
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except OSError:
            pass
    return killed


def _stop_below(root, stopped):
    """Stop (SIGSTOP) every process below `root` as the walk finds it, so one that forks fast cannot outrun the walk, and repeat the walk
    for what the stopped ones had already forked, for at most MAX_ROUNDS rounds and WALK_SECONDS seconds. `stopped` gets {pid: identity}.
    Returns None, or the sentence that says the tree could not be listed or that the walk was cut."""
    began = time.monotonic()
    for _round in range(MAX_ROUNDS):
        try:
            found = list_descendants(root)
        except TreeNotListed as exc:
            return _note("the processes below pid %d could not be listed (%s): the program itself was ended, nothing below it" % (root, exc))
        listed = getattr(found, "ident", None) or {}
        _seen_below(found, listed)
        fresh = [pid for pid in found if pid not in stopped]
        if not fresh:
            return None
        for pid in fresh:
            if not same_process(pid, listed.get(pid)):
                continue
            try:
                os.kill(pid, signal.SIGSTOP)
                stopped[pid] = listed.get(pid)
            except OSError:
                pass
        if time.monotonic() - began > WALK_SECONDS:
            break
    return _note("the walk below pid %d was cut at %d rounds or %d seconds: a process started after it may be running" % (root, MAX_ROUNDS, WALK_SECONDS))


def _end(stopped):
    """Kill the stopped set, each pid only if it is still the process that was stopped."""
    for pid, ident in list(stopped.items()):
        if same_process(pid, ident):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def kill_tree(proc):
    """Kill the program and everything it started. The program is stopped first and then each process below it as the walk finds it
    (_stop_below), so the tree does not grow while it is listed; the stopped set is killed after the program. A pid is killed only if it
    is still the process that was listed (same_process). A program already waited for is not touched: its pid is free to be another
    process's, and the walk below it would be that process's children. Returns None, or a sentence when the tree could not be listed or
    the walk was cut."""
    if proc.poll() is not None:
        return None
    try:
        proc.send_signal(signal.SIGSTOP)    # a program that is stopped forks nothing more while its tree is listed
    except OSError:
        pass
    stopped, note = {}, None
    try:
        note = _stop_below(proc.pid, stopped)
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        _end(stopped)
    return note


def _stat_row(pid):
    """(state letter, parent pid, identity) of `pid` from /proc/<pid>/stat, or None when it is gone or cannot be read. The identity is the one
    process_ident gives (field 22, counted after the last ")")."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as fh:
            data = fh.read()
        rest = data[data.rindex(b")") + 2:].split()
        return rest[0].decode("ascii", "replace"), int(rest[1]), ("proc", int(rest[19]))
    except (OSError, ValueError, IndexError):
        return None


def _children_of_me():
    """{pid: (state, identity)} of the direct children of this process (Linux). The kernel's own list of each thread's children is read where
    there is one (no scan of every process), and every pid it names is checked against /proc/<pid>/stat; where there is none, /proc is
    scanned. Raises TreeNotListed when /proc cannot be read or takes more than TABLE_SECONDS."""
    me = os.getpid()
    pids = None
    try:
        named = set()
        for tid in os.listdir("/proc/%d/task" % me):
            with open("/proc/%d/task/%s/children" % (me, tid)) as fh:
                named.update(int(part) for part in fh.read().split())
        pids = sorted(named)
    except (OSError, ValueError):
        pids = None
    if pids is None:
        try:
            pids = [int(entry) for entry in os.listdir("/proc") if entry.isdigit()]
        except OSError as exc:
            raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    found, started = {}, time.monotonic()
    for pid in pids:
        if time.monotonic() - started > TABLE_SECONDS:
            raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
        row = _stat_row(pid)
        if row is not None and row[1] == me:
            found[pid] = (row[0], row[2])
    return found


def _unproven(text):
    """Record why this block cannot say that no program left a process behind (once, at most 20) and return it."""
    if text not in LEFT["unproven"] and len(LEFT["unproven"]) < 20:
        LEFT["unproven"].append(text)
    return text


def become_subreaper():
    """On Linux ask the kernel to make this process the parent of every process a program leaves behind (PR_SET_CHILD_SUBREAPER = 36), so that
    one that left the tool's group or session, or holds none of its descriptors, is a child of the tool and settle() can find it. Called by
    spawn() before the first program; once. PRE_KIDS records the children the tool already had (pid and start time): they are not a program's
    and settle() leaves them. Where the kernel refuses, or the host is not Linux, nothing is adopted: settle() falls back to what the tool
    saw below a program (SEEN), and the answer cannot prove that nothing was left (process_verdict()['unproven']). Returns whether it is on."""
    if SUB["tried"]:
        return SUB["on"]
    SUB["tried"] = True
    if sys.platform.startswith("linux") and ctypes is not None:
        try:
            SUB["on"] = ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
        except Exception:  # noqa: BLE001 - no libc symbol, a sandbox: the caller falls back
            SUB["on"] = False
        if SUB["on"]:
            try:
                PRE_KIDS.update({pid: ident for pid, (_state, ident) in _children_of_me().items()})
            except TreeNotListed as exc:
                _unproven(_note("the children the tool already had could not be listed (%s): one of them may be taken for a program's" % exc))
        else:
            _unproven("this host refused PR_SET_CHILD_SUBREAPER: a process a program left behind outside the walk is not adopted and may not be found")
    else:
        reason = "this host cannot adopt orphaned processes (no PR_SET_CHILD_SUBREAPER): a process a program left behind may not be found"
        SUB["note"] = reason              # in process_verdict()["notes"], never in process_notes(): a tool that reads only what a program printed is not made partial by it
        if NONLINUX_UNPROVEN_DOWNGRADE:
            _unproven(reason)
    return SUB["on"]


def process_keep(pid):
    """Let `pid` stay: settle() does not end it. For a process a program leaves on purpose (a daemon the tool stops itself); spawn(argv,
    leaves=True) does it for what that program leaves. A kept process is still ended by a stop signal (kill_all)."""
    ident = process_ident(pid)
    if ident is not None:
        KEEP[pid] = ident


def _exempt(pid, ident, active):
    """Whether the process `pid` (identity `ident`) is the tool's own and not a program's leftover: a program spawn() started (Popen owns it
    and reaps it), one in ACTIVE (`active`, their pids), one kept (KEEP) or one the tool already had (PRE_KIDS). A pid whose identity differs is
    another process that has the number now."""
    if pid in active:
        return True
    for table in (SPAWNED, KEEP, PRE_KIDS):
        if pid in table and (table[pid] is None or table[pid] == ident):
            return True
    return False


def _victims_children(active):
    """[(pid, state, identity)]: the children of this tool that are no program's own (Linux, with the subreaper on)."""
    return [(pid, state, ident) for pid, (state, ident) in sorted(_children_of_me().items()) if not _exempt(pid, ident, active)]


def _victims_seen(active):
    """[(pid, state, identity)]: where nothing is adopted, the processes that were seen below a program, are still the ones that were seen, and
    have lost their parent (the parent is not the tool and is not a live process the tool saw). Raises TreeNotListed."""
    me = os.getpid()
    candidates = [pid for pid in list(SEEN) if pid != me and SEEN_IDENT.get(pid) is not None and not _exempt(pid, SEEN_IDENT[pid], active)]
    if not candidates:
        return []
    table = _process_table()
    found = []
    for pid in candidates:
        row, listed = table.get(pid), table.ident.get(pid)
        if row is None or listed != SEEN_IDENT[pid] or row[0] == me:
            continue
        parent = row[0]
        if parent in table and SEEN_IDENT.get(parent) is not None and table.ident.get(parent) == SEEN_IDENT[parent]:
            continue                               # its parent is a live process of a program's tree: the program has not ended
        found.append((pid, "S", listed))
    return found


def _stop_under(roots, stopped, deadline):
    """_stop_below for several roots at once with one reading of the processes per round (a program may leave thousands): stop (SIGSTOP)
    every process below any of `roots` as the walk finds it, for at most MAX_ROUNDS rounds, WALK_SECONDS seconds and until `deadline`.
    `stopped` gets {pid: identity}. Returns None, or the sentence that says the tree could not be listed or that the walk was cut."""
    began = time.monotonic()
    for _round in range(MAX_ROUNDS):
        try:
            table = _process_table()
        except TreeNotListed as exc:
            return _unproven(_note("the processes below what a program left behind could not be listed (%s): the leftovers were ended, nothing below them" % exc))
        kids = {}
        for child, (parent, _group) in table.items():
            kids.setdefault(parent, []).append(child)
        fresh = []
        for root in roots:
            fresh.extend(pid for pid in _below(kids, root) if pid not in stopped)
        if not fresh:
            return None
        for pid in fresh:
            ident = table.ident.get(pid)
            if pid not in stopped and same_process(pid, ident):
                try:
                    os.kill(pid, signal.SIGSTOP)
                    stopped[pid] = ident
                except OSError:
                    pass
        if time.monotonic() > min(deadline, began + WALK_SECONDS):
            break
    return _unproven(_note("the walk below what a program left behind was cut at %d rounds or %d seconds: a process started after it may be running" % (MAX_ROUNDS, WALK_SECONDS)))


def _end_counting(stopped):
    """Kill the stopped set, each pid only if it is still the process that was stopped. How many were alive (a zombie was not left running)."""
    alive = 0
    for pid, ident in list(stopped.items()):
        row = _stat_row(pid)
        if not same_process(pid, ident):
            continue
        try:
            os.kill(pid, signal.SIGKILL)
            if row is None or row[0] not in ("Z", "X"):
                alive += 1
        except OSError:
            pass
    return alive


def _end_children(victims, deadline):
    """End the leftovers that are this tool's children: each is stopped (its identity and parent read again first), what it started is stopped
    with it (_stop_under), the set is killed, and the children are reaped (waitpid WNOHANG: the tool is their parent). The clock is read for
    every one, so a program that left thousands is cut at `deadline`, not after a pass. Returns how many live processes were killed."""
    me = os.getpid()
    stopped, reap, cut = {}, [], False
    try:
        for pid, _state, ident in victims:
            if time.monotonic() >= deadline:
                cut = True
                break
            row = _stat_row(pid)
            if row is None or row[1] != me or row[2] != ident:
                continue                           # gone, or not this tool's child any more
            if row[0] in ("Z", "X"):
                reap.append(pid)
                continue
            try:
                os.kill(pid, signal.SIGSTOP)
            except OSError:
                continue
            stopped[pid] = ident
            reap.append(pid)
        _stop_under(list(stopped), stopped, deadline)
    finally:
        alive = _end_counting(stopped)
    pending = set(reap)
    while pending:
        for pid in list(pending):
            try:
                done, _status = os.waitpid(pid, os.WNOHANG)
            except OSError:
                pending.discard(pid)               # not this tool's child (any more): nothing to reap
                continue
            if done:
                pending.discard(pid)
        if not pending:
            break
        if time.monotonic() >= deadline:
            _unproven(_note("%d processes a program left behind did not end within %d seconds" % (len(pending), LEFTOVER_SECONDS)))
            break
        time.sleep(0.005)
    if cut:
        _unproven(_note("a program left more processes than could be ended within %d seconds: some are still running" % LEFTOVER_SECONDS))
    return alive


def _end_seen(victims, deadline):
    """End the leftovers where nothing is adopted: stopped, what they started stopped with them, then killed (each only if it is still the
    process that was seen). Returns how many live processes were killed."""
    stopped = {}
    try:
        for pid, _state, ident in victims:
            if time.monotonic() >= deadline:
                _unproven(_note("a program left more processes than could be ended within %d seconds: some are still running" % LEFTOVER_SECONDS))
                break
            if same_process(pid, ident):
                try:
                    os.kill(pid, signal.SIGSTOP)
                    stopped[pid] = ident
                except OSError:
                    pass
        _stop_under(list(stopped), stopped, deadline)
    finally:
        alive = _end_counting(stopped)
    return alive


def _settle(final):
    active = {proc.pid for proc in list(ACTIVE)}
    if not final and any(proc.poll() is None for proc in list(ACTIVE)):
        _unproven(_note("a program was still running when another one ended: what is left behind cannot be told from what that program started, so nothing was ended"))
        return 0
    deadline = time.monotonic() + LEFTOVER_SECONDS
    victims = _victims_children if SUB["on"] else _victims_seen
    ended, looked = 0, False
    ready = [proc for proc in list(LEAVES.values()) if proc.poll() is not None]
    if ready:
        for proc in ready:                         # a program that leaves a process on purpose: what it left stays
            LEAVES.pop(proc.pid, None)
        for pid, state, ident in victims(active):
            if state not in ("Z", "X"):
                KEEP[pid] = ident
    while True:
        found = victims(active)
        if not found:
            if ended and not looked:
                looked = True                      # one more look after a short pause: a fork that was under way when the first one died
                time.sleep(SETTLE_LOOK)
                continue
            return ended
        if time.monotonic() >= deadline:
            _unproven(_note("%d processes a program left behind were still there after %d seconds: they were not all ended" % (len(found), LEFTOVER_SECONDS)))
            return ended
        ended += (_end_children if SUB["on"] else _end_seen)(found, deadline)
        if not SUB["on"]:
            return ended                           # nothing is adopted: one pass, the processes are not this tool's to reap


def settle(final=False):
    """Look for what the programs this tool ran have left behind, and end it: the processes that are the tool's children and no program's own
    (the subreaper adopted them) are stopped, what they started with them, killed and reaped, for at most LEFTOVER_SECONDS (the clock is read for
    every process, and one more look follows an ending). Never a process of another program: while another program is running in ACTIVE nothing
    is ended and process_verdict() says it is unproven. Never a program spawn() started (Popen owns its exit status: its returncode is never
    taken), nor KEEP, PRE_KIDS or a process outside the tool's own children. final=True is the stop signal's own call (kill_all). Runs on the
    caller's thread, joins none and never raises. Returns how many live processes it ended; process_verdict() holds the totals."""
    if SETTLING[0] and not final:
        return 0
    SETTLING[0] = True
    try:
        ended = _settle(final)
        LEFT["left_behind"] += ended
        return ended
    except Exception as exc:  # noqa: BLE001 - never into the finally of a carrier: say it could not be proven
        _unproven(_note("the look for what a program left behind failed (%s)" % type(exc).__name__))
        return 0
    finally:
        SETTLING[0] = False


def process_verdict():
    """What an answer says about the programs the tool ran: {"subreaper": whether orphans were adopted, "left_behind": how many live processes
    settle() ended, "unproven": why 'nothing was left behind' cannot be claimed (empty when it can), "notes": process_notes()}."""
    return {"subreaper": SUB["on"], "left_behind": LEFT["left_behind"], "unproven": list(LEFT["unproven"]), "notes": process_notes() + ([SUB["note"]] if SUB["note"] else [])}


def process_apply(answer):
    """Put process_verdict() into `answer` as answer["program_group"] and, when a program left a process behind or that cannot be ruled out,
    turn a complete answer into a partial one (status "partial", the ok and complete flags that are there false, a sentence in status_basis;
    a call of communicate_bounded that was cut at POST_EXIT_BYTES counts, PIPE_CUT):
    what a program wrote while the tool read it is not a complete result. A carrier calls it once where it prints its answer. Returns `answer`."""
    verdict = process_verdict()
    answer["program_group"] = verdict
    if (verdict["left_behind"] > 0 or verdict["unproven"] or PIPE_CUT["cut"]) and answer.get("status") == "complete":
        answer["status"] = "partial"
        for flag in ("ok", "complete"):
            if flag in answer:
                answer[flag] = False
        if verdict["left_behind"] > 0:
            sentence = "a program left %d process%s running after it ended; the tool ended them, and what they wrote before that is in the files named here" % (
                verdict["left_behind"], "" if verdict["left_behind"] == 1 else "es")
        elif PIPE_CUT["cut"]:
            sentence = "a process that held a program's pipe after it ended went on writing; the tool read no more than %d bytes of it and let the pipe go" % POST_EXIT_BYTES
        else:
            sentence = "the tool cannot prove that no program left a process behind (see program_group.unproven)"
        basis = answer.get("status_basis")
        answer["status_basis"] = "%s; %s" % (basis, sentence) if isinstance(basis, str) and basis else sentence
    return answer


PIPE_GRACE = 1.0    # seconds the pipes of a program that has ended are given to reach end of file
POST_EXIT_BYTES = 1 << 20    # the most bytes (both pipes together) read from the pipes of a program that has ended
PIPE_CUT = {"cut": 0}        # how many calls stopped reading at POST_EXIT_BYTES because a process still held the pipes and went on writing


def communicate_bounded(proc, seconds, input=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes. At `seconds` the program and what it started
    are killed (timed out). A program that has ended while something it started still holds its pipes (a daemon, a helper that
    inherited them) does not hold the tool: from the moment the program has ended (or was killed) the pipes are given PIPE_GRACE seconds
    and POST_EXIT_BYTES bytes, whichever is used up first; what the program wrote is kept, what the tool lost is killed (reap_orphans,
    settle), and the pipes are let go. A cut at the byte cap is counted in PIPE_CUT and noted (process_notes()); the return shape is the
    same. The pipes are read here and by nothing else (not by Popen.communicate), so letting them go is safe. `input` is written while
    the program runs and is dropped once it has ended."""
    deadline = time.monotonic() + max(0.1, seconds)
    bufs = (bytearray(), bytearray())
    sel = _selectors.DefaultSelector()
    pending = memoryview(input) if input and proc.stdin is not None else None
    for index, stream in enumerate((proc.stdout, proc.stderr)):
        if stream is not None:
            sel.register(stream, _selectors.EVENT_READ, index)
    if proc.stdin is not None:
        if pending:
            sel.register(proc.stdin, _selectors.EVENT_WRITE, 2)
        else:
            _close_pipe(proc.stdin)
    timed_out, note, ended, extra, cut, sampled = False, None, None, 0, False, 0.0
    try:
        while True:
            now = time.monotonic()
            if ended is None:
                if proc.poll() is not None:
                    ended = now
                elif now >= deadline:
                    timed_out = True
                    note = kill_tree(proc)
                    ended = time.monotonic()
                elif now - sampled >= 0.2:
                    sampled = now
                    _sample(proc.pid)
            if ended is not None:
                if pending is not None:
                    sel.unregister(proc.stdin)
                    _close_pipe(proc.stdin)
                    pending = None
                if not any(key.data != 2 for key in sel.get_map().values()) or extra >= POST_EXIT_BYTES or now - ended >= PIPE_GRACE:
                    cut = extra >= POST_EXIT_BYTES and any(key.data != 2 for key in sel.get_map().values())
                    break
            wait = max(0.01, min(0.2, (deadline if ended is None else ended + PIPE_GRACE) - now))
            if not sel.get_map():
                try:
                    proc.wait(timeout=wait)
                except subprocess.TimeoutExpired:
                    pass
                continue
            for key, _mask in sel.select(wait):
                if key.data == 2:
                    try:
                        pending = pending[os.write(key.fd, pending[:_select.PIPE_BUF]):]
                    except OSError:
                        pending = None
                    if not pending:
                        sel.unregister(proc.stdin)
                        _close_pipe(proc.stdin)
                        pending = None
                    continue
                if ended is not None and extra >= POST_EXIT_BYTES:
                    break
                try:
                    data = os.read(key.fd, 65536 if ended is None else min(65536, POST_EXIT_BYTES - extra))
                except OSError:
                    data = b""
                if not data:
                    sel.unregister(key.fileobj)
                    continue
                bufs[key.data].extend(data)
                if ended is not None:
                    extra += len(data)
        if any(key.data != 2 for key in sel.get_map().values()):
            reap_orphans(_pipe_inodes(proc))
            settle()
    finally:
        sel.close()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            _close_pipe(pipe)
    if cut:
        PIPE_CUT["cut"] += 1
        _note("a process that held a program's pipe after the program ended went on writing: the tool read %d bytes more and let the pipe go" % POST_EXIT_BYTES)
    try:
        proc.wait(timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired:
        pass
    settle()
    err = bytes(bufs[1])
    if note:
        err = err + (b"\n" if err else b"") + note.encode("utf-8", "replace")
    return bytes(bufs[0]), err, timed_out


def _close_pipe(pipe):
    try:
        if pipe is not None:
            pipe.close()
    except (OSError, ValueError):
        pass


def kill_all():
    """End every program the tool has running, with what each started. Then everything below the tool itself, which is the tool's own: a
    program forked a moment before it was entered in ACTIVE is among it. Then what an earlier program started and lost (reap_orphans).
    Returns the sentences for what could not be done (also in process_notes())."""
    notes = []
    for proc in list(ACTIVE):
        note = kill_tree(proc)
        if note:
            notes.append(note)
    stopped = {}
    try:
        note = _stop_below(os.getpid(), stopped)
        if note:
            notes.append(note)
    finally:
        _end(stopped)
    reap_orphans()
    settle(True)     # what the stop ended below the tool is reaped (bounded; settle never raises)
    return notes


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)     # the first signal counts: a second one starts no second answer
    kill_all()
    last_word = STATE.get("last_word")
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def preflight(argv, seconds):
    """Run a short program, bounded; (exit code or None, stdout bytes, stderr bytes, timed out)."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, b"", describe(exc).encode("utf-8", "replace"), False
    ACTIVE.append(proc)
    try:
        out, err, timed_out = communicate_bounded(proc, max(1.0, seconds))
        return (None if timed_out else proc.returncode), out, err, timed_out
    finally:
        ACTIVE.remove(proc)


def run_to_files(argv, stdout_path, stderr_path, seconds, cwd=None):
    """One program with its output in files, killed with what it started at `seconds`. (exit code, timed out)."""
    with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
        proc = spawn(argv, stdout=stdout, stderr=stderr, cwd=cwd)
        ACTIVE.append(proc)
        try:
            return proc.wait(timeout=max(0.1, seconds)), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            proc.wait()
            return None, True
        finally:
            ACTIVE.remove(proc)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


# --- backup_decrypt ---------------------------------------------------------------------------------------------------------

SQLITE_MAGIC = b"SQLite format 3\x00"
FILE_ID = re.compile(r"[0-9a-fA-F]{40}")
DEFAULT_LIMIT = 200
INLINE_BYTES = 1 << 20
DEFAULT_MAX_SECONDS = 480
MAX_SECONDS_CAP = 540       # manifest.json timeout_seconds (600) less the work after the child and the time to write the answer
CHILD_SHARE = 0.78          # the child (key derivation, then the files) has this share of max_seconds; the tool reads the result with the rest
DEFAULT_MAX_FILES = 200000
MAX_FILES_CAP = 2000000
DEFAULT_MAX_BYTES = 4 << 30
MAX_BYTES_CAP = 1 << 42
SECRET_MAX_BYTES = 4096
MAX_PLIST_BYTES = 4 << 20
MAX_REF_DEPTH = 12
MAX_ROWS = 4000000          # rows of the map that are read; past it the run is partial and says so
CELL_CHARS = JUDGE_CHARS + 1
FILE_CELL_BYTES = 1 << 20
LOOK_EVERY = 1000
EVENT_LINE_BYTES = 4096
ARGUMENTS = ("backup", "password_ref", "max_files", "max_bytes", "max_seconds", "limit")
KINDS = {1: "file", 2: "directory", 4: "symlink"}
OUTCOMES_NOT_DECRYPTED = ("blob_missing", "backend_error", "ambiguous_selection", "refused_id", "duplicate_id",
                          "not_copied_max_bytes", "not_attempted_max_files", "not_attempted", "write_failed")
BANNER = {"kind": "ios-backup-decrypted-copy", "tool": TOOL, "parser": PARSER,
          "layout": "Manifest.db, decrypted, and one decrypted file per Manifest row of a file at <first two digits of its id>/<id>",
          "is_not": "the phone's file system, an acquisition of the phone, a backup directory (Manifest.plist is not carried over), or proof "
                    "that a file's content is what the phone held (a file id is a locator)"}


class OutOfTime(Exception):
    pass


class NotRegular(Exception):
    pass


def fd_flags(extra=0):
    return os.O_RDONLY | extra | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def open_regular(path, dir_fd=None):
    """(fd, fstat) of a regular file, opened without waiting and without following a link: a FIFO, a device or a link at the name
    is never read (a FIFO would hold the tool for ever)."""
    fd = os.open(path, fd_flags(), dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
    except OSError:
        os.close(fd)
        raise
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise NotRegular(stat.S_IFMT(info.st_mode))
    return fd, info


def read_plist(path):
    """(status, tree, reason): a backup's plain plist, read without following a link."""
    try:
        fd, info = open_regular(path)
    except FileNotFoundError:
        return "missing", None, None
    except NotRegular:
        return "unreadable", None, "not a regular file"
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return "link", None, "a symbolic link: not followed"
        return "unreadable", None, describe(exc)
    with os.fdopen(fd, "rb") as fh:
        if info.st_size > MAX_PLIST_BYTES:
            return "too_large", None, "%d bytes, over %d" % (info.st_size, MAX_PLIST_BYTES)
        try:
            data = fh.read(MAX_PLIST_BYTES + 1)
            if len(data) > MAX_PLIST_BYTES:
                return "too_large", None, "over %d bytes" % MAX_PLIST_BYTES
            return "ok", plistlib.loads(data), None
        except Exception as exc:  # a parser fault on hostile input is that file's status, not a crash
            return "unreadable", None, describe(exc)


class Archive:
    """An NSKeyedArchiver graph: the root object, and values followed through UID references with a depth bound and a cycle check
    (manifest_db's reader, copied)."""

    def __init__(self, tree):
        self.objects = None
        self.root = None
        self.reason = None
        self.status = "ok"
        if not isinstance(tree, dict) or tree.get("$archiver") != "NSKeyedArchiver":
            self.status, self.reason = "not_keyed_archive", "no $archiver of NSKeyedArchiver at the top"
            return
        objects, top = tree.get("$objects"), tree.get("$top")
        if not isinstance(objects, list) or not isinstance(top, dict):
            self.status, self.reason = "malformed", "$objects is not a list or $top is not a dictionary"
            return
        self.objects = objects
        ref = top.get("root")
        if ref is None:
            if len(top) != 1:
                self.status, self.reason = "malformed", "$top has no root and more or fewer than one entry"
                return
            ref = next(iter(top.values()))
        try:
            root = self.deref(ref)
        except ValueError as exc:
            self.status, self.reason = "malformed", str(exc)
            return
        if not isinstance(root, dict):
            self.status, self.reason = "malformed", "the root object is a %s, not a dictionary" % type(root).__name__
            return
        self.root = root

    def deref(self, value):
        seen = set()
        while isinstance(value, plistlib.UID):
            index = value.data
            if index in seen:
                raise ValueError("a reference cycle at object %d" % index)
            if len(seen) >= MAX_REF_DEPTH:
                raise ValueError("references deeper than %d" % MAX_REF_DEPTH)
            if not 0 <= index < len(self.objects):
                raise ValueError("a reference to object %d, and the archive has %d" % (index, len(self.objects)))
            seen.add(index)
            value = self.objects[index]
        return value

    def get(self, key):
        if key not in self.root:
            return None, False
        return self.deref(self.root[key]), True


def manifest_size_mode(blob):
    """(status, size, mode) from the keyed archive of a `file` cell: what the Manifest says the file was."""
    if not isinstance(blob, (bytes, bytearray)):
        return "absent", None, None
    try:
        archive = Archive(plistlib.loads(bytes(blob)))
    except Exception:
        return "unreadable", None, None
    if archive.root is None:
        return archive.status, None, None
    try:
        size, found_size = archive.get("Size")
        mode, found_mode = archive.get("Mode")
    except ValueError:
        return "malformed", None, None
    size = size if found_size and isinstance(size, int) and not isinstance(size, bool) else None
    mode = mode if found_mode and isinstance(mode, int) and not isinstance(mode, bool) else None
    return "ok", size, mode



def class_word(exc):
    """The class name of an exception and nothing else: the library's text may quote what it was given."""
    return re.sub(r"[^A-Za-z0-9_]", "_", type(exc).__name__)[:64]


# --- the child: the only process that holds the password ------------------------------------------------------------------------
# It is this same file started with --child. It is told its paths on its standard input (none of them secret), reads the password file
# itself, and reports to events.jsonl in the work directory. Its standard output and standard error go nowhere.

def child_event(handle, **fields):
    handle.write(json.dumps(fields, sort_keys=True) + "\n")
    handle.flush()


def read_secret(path, ident):
    """(text, why): the password, or the reason it could not be had, as a fixed word."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None, "not_readable"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, "not_a_regular_file"
        if [info.st_dev, info.st_ino] != list(ident):
            return None, "changed_between_looks"
        if info.st_mode & 0o077:
            return None, "mode_not_0600"
        if info.st_size < 1 or info.st_size > SECRET_MAX_BYTES:
            return None, "size_out_of_range"
        data = b""
        while len(data) <= SECRET_MAX_BYTES:
            chunk = os.read(fd, SECRET_MAX_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
    except OSError:
        return None, "not_readable"
    finally:
        os.close(fd)
    if len(data) > SECRET_MAX_BYTES:
        return None, "size_out_of_range"
    if data.endswith(b"\n"):
        data = data[:-1]
    if not data:
        return None, "empty"
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "not_utf8"


def selects_only(lookup, rowid, file_id, domain, rel):
    """Whether the backend's own query, run on the decrypted map, returns exactly this row. The backend selects a file by
    `relativePath = ? AND domain LIKE ? AND flags = 1 ORDER BY domain, relativePath LIMIT 1` (iphone_backup_decrypt 0.11.2), so a row
    whose query returns another row too, or none, or raises (a LIKE pattern over SQLite's length limit, a collation that equates two
    paths) would be decrypted from some other row's blob: it is not decrypted."""
    try:
        rows = lookup.execute("SELECT rowid, fileID FROM Files WHERE relativePath = ? AND domain LIKE ? AND flags = 1 ORDER BY domain, relativePath LIMIT 2",
                              (rel, domain)).fetchall()
    except Exception:  # noqa: BLE001  a lookup that fails is not a lookup that found this row alone
        return False
    return len(rows) == 1 and rows[0][0] == rowid and rows[0][1] == file_id


def source_size(backup, file_id):
    """The size of the encrypted blob the backup holds for an id, or None: sharded (ab/abcdef...) first, flat second, no link followed."""
    for candidate in (os.path.join(backup, file_id[:2], file_id), os.path.join(backup, file_id)):
        try:
            info = os.lstat(candidate)
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode):
            return info.st_size
    return None


def child_main():
    os.umask(0o077)
    try:
        config = json.loads(sys.stdin.read(1 << 16))
    except ValueError:
        os._exit(2)
    work, dest, backup = config["work"], config["dest"], config["backup"]
    until = config["until"]
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    events = os.fdopen(os.open(os.path.join(work, "events.jsonl"), flags, 0o600), "w", encoding="utf-8")
    tmp = os.path.join(work, "tmp")
    os.environ["TMPDIR"] = tmp
    tempfile.tempdir = tmp
    secret, why = read_secret(config["password_ref"], config["password_ident"])
    if secret is None:
        child_event(events, e="secret_unavailable", why=why)
        return 0
    try:
        from iphone_backup_decrypt import EncryptedBackup
    except Exception as exc:  # noqa: BLE001
        child_event(events, e="backend_unavailable", c=class_word(exc))
        return 0
    manifest = os.path.join(work, "Manifest.db")
    try:
        opened = EncryptedBackup(backup_directory=backup, passphrase=secret)
    except Exception as exc:  # noqa: BLE001  the text of the library's exception is never kept
        child_event(events, e="unlock_failed", stage="open", c=class_word(exc))
        return 0
    child_event(events, e="opened")
    try:
        opened.save_manifest_file(manifest)
    except Exception as exc:  # noqa: BLE001
        child_event(events, e="unlock_failed", stage="manifest", c=class_word(exc))
        return 0
    try:
        info = os.lstat(manifest)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        os.chmod(manifest, 0o600)
        conn = sqlite3.connect("file:%s?mode=ro&immutable=1" % quote(os.path.abspath(manifest)), uri=True)
        conn.set_progress_handler(lambda: 1 if time.time() > until else 0, 20000)
        conn.text_factory = lambda b: b.decode("utf-8", "surrogateescape")
        total = conn.execute("SELECT count(*) FROM Files").fetchone()[0]
    except Exception as exc:  # noqa: BLE001
        child_event(events, e="manifest_unusable", c=class_word(exc))
        return 0
    final = os.path.join(dest, "Manifest.db")
    try:
        os.link(manifest, final)
        child_event(events, e="manifest", bytes=info.st_size, rows=total)
    except OSError as exc:
        child_event(events, e="manifest_unusable", c=class_word(exc))
        return 0
    # The lookup is a copy of the decrypted map (with an index on relativePath, which changes no result): the backend's own query is run on it
    # before every file, so that no row is decrypted from another row's blob.
    try:
        lookup_path = os.path.join(work, "lookup.db")
        shutil.copyfile(manifest, lookup_path)
        lookup = sqlite3.connect(lookup_path)
        lookup.set_progress_handler(lambda: 1 if time.time() > until else 0, 20000)
        lookup.text_factory = lambda b: b.decode("utf-8", "surrogateescape")
        try:
            lookup.execute("CREATE INDEX IF NOT EXISTS bd_rel ON Files(relativePath)")
        except Exception:  # noqa: BLE001  slower, not different
            pass
    except Exception as exc:  # noqa: BLE001
        child_event(events, e="manifest_unusable", c=class_word(exc))
        return 0
    done_files, done_bytes, stage_n = 0, 0, 0
    max_files, max_bytes = config["max_files"], config["max_bytes"]
    cursor = conn.execute("SELECT rowid, fileID, domain, relativePath FROM Files WHERE flags = 1 ORDER BY rowid")
    cut = None
    try:
        for rowid, file_id, domain, rel in cursor:
            if time.time() > until:
                cut = "time"
                break
            if not isinstance(file_id, str) or not FILE_ID.fullmatch(file_id):
                child_event(events, e="row", r=rowid, o="refused_id")
                continue
            if not selects_only(lookup, rowid, file_id, domain, rel):
                child_event(events, e="row", r=rowid, o="ambiguous_selection")
                continue
            if done_files >= max_files:
                child_event(events, e="row", r=rowid, o="not_attempted_max_files")
                continue
            file_id = file_id.lower()
            size = source_size(backup, file_id)
            if size is None:
                child_event(events, e="row", r=rowid, o="blob_missing")
                continue
            if done_bytes + size > max_bytes:
                child_event(events, e="row", r=rowid, o="not_copied_max_bytes")
                continue
            stage_n += 1
            stage = os.path.join(work, "stage-%d" % stage_n)
            try:
                opened.extract_file(relative_path=rel, domain_like=domain, output_filename=stage)
            except FileNotFoundError:
                child_event(events, e="row", r=rowid, o="blob_missing")
                continue
            except Exception as exc:  # noqa: BLE001
                child_event(events, e="row", r=rowid, o="backend_error", c=class_word(exc))
                continue
            try:
                made = os.lstat(stage)
                if not stat.S_ISREG(made.st_mode):
                    raise OSError("not a regular file")
                os.chmod(stage, 0o600)
                shard = os.path.join(dest, file_id[:2])
                os.makedirs(shard, mode=0o700, exist_ok=True)
                os.link(stage, os.path.join(shard, file_id))
            except FileExistsError:
                child_event(events, e="row", r=rowid, o="duplicate_id")
                continue
            except OSError as exc:
                child_event(events, e="row", r=rowid, o="write_failed", c=class_word(exc))
                continue
            finally:
                try:
                    os.unlink(stage)
                except OSError:
                    pass
            done_files += 1
            done_bytes += made.st_size
            child_event(events, e="row", r=rowid, o="ok", b=made.st_size)
    except sqlite3.OperationalError:
        cut = "time"
    child_event(events, e="done", cut=cut, files=done_files, bytes=done_bytes)
    return 0


# --- the tool: what the parent checks, runs and reads ----------------------------------------------------------------------------

def output_base():
    """(Path, shown prefix): $OUT in a job."""
    out = os.environ["OUT"]
    return Path(out), "store/jobs/%s/out" % safe_name(os.environ["JOB_ID"])


def b64(text):
    return base64.b64encode(text.encode("utf-8", "surrogateescape")).decode("ascii")


def check_secret_file(ref):
    """(device and inode, why): the password file looked at, never read. A fixed word for why."""
    try:
        info = os.lstat(ref)
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "not_readable"
    if stat.S_ISLNK(info.st_mode):
        return None, "a_link"
    if not stat.S_ISREG(info.st_mode):
        return None, "not_a_regular_file"
    if info.st_mode & 0o077:
        return None, "mode_not_0600"
    if info.st_size < 1 or info.st_size > SECRET_MAX_BYTES:
        return None, "size_out_of_range"
    return [info.st_dev, info.st_ino], None


def format_check(backup):
    """(ok, why, facts): whether the backup is one this tool opens. facts carry presence and lengths of the key material, never a byte of it."""
    status, plist, reason = read_plist(os.path.join(backup, "Manifest.plist"))
    facts = {"manifest_plist": status}
    if status == "ok" and not isinstance(plist, dict):
        return False, "Manifest.plist is not a dictionary", facts
    if status != "ok":
        return False, "Manifest.plist is %s%s" % (status, ": " + reason if reason else ""), facts
    flag = plist.get("IsEncrypted", "absent")
    facts["is_encrypted"] = flag if isinstance(flag, bool) else str(type(flag).__name__) if flag != "absent" else "absent"
    for key in ("BackupKeyBag", "ManifestKey"):
        value = plist.get(key)
        facts[key] = {"present": isinstance(value, (bytes, bytearray)), "bytes": len(value) if isinstance(value, (bytes, bytearray)) else 0}
    if flag is not True:
        return False, "Manifest.plist does not say IsEncrypted is true: there is nothing to decrypt (use manifest_db and backup_materialise)", facts
    for key in ("BackupKeyBag", "ManifestKey"):
        if not facts[key]["present"] or facts[key]["bytes"] < 1:
            return False, "Manifest.plist holds no %s" % key, facts
    try:
        fd, info = open_regular(os.path.join(backup, "Manifest.db"))
    except FileNotFoundError:
        return False, "no Manifest.db there", facts
    except (NotRegular, OSError):
        return False, "Manifest.db is not a regular file", facts
    with os.fdopen(fd, "rb") as handle:
        head = handle.read(16)
    facts["manifest_db"] = {"bytes": info.st_size, "plain_sqlite": head == SQLITE_MAGIC}
    if head == SQLITE_MAGIC:
        return False, "Manifest.db is a plain SQLite file although Manifest.plist says the backup is encrypted", facts
    return True, None, facts


class ResultFile:
    """One line per row, written as the row is known and flushed at once, so that the count the answer gives is the lines the file
    holds, whatever ends the run. The inline page is a prefix. The file takes its name without replacing an earlier one (PLACE); the
    hidden temporary is registered for removal before it exists and is removed by a failure and by a stop."""

    def __init__(self, base, shown_base, key, limit, byte_limit):
        self.limit, self.byte_limit = limit, byte_limit
        self.page, self.page_bytes, self.rows, self.bytes_bound_hit = [], 0, 0, False
        digest = hashlib.sha256(dumps([key, NONCE], sort_keys=True).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (TOOL, digest)
        self.dir = base / "tool-output"
        self.target = self.dir / name
        self.shown_dir = shown_base + "/tool-output/"
        self.shown = self.shown_dir + name
        self._out = None
        self._tmp = None
        self._cleanup = None
        OPEN_PAGES.append(self)

    def open(self):
        if self._out is not None:
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=str(self.dir), prefix=".%s-" % TOOL)
        self._tmp = Path(name)
        tmp = self._tmp
        self._cleanup = lambda: tmp.unlink() if tmp.exists() or tmp.is_symlink() else None
        CLEANUP.append(self._cleanup)
        self._out = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, row):
        self.open()
        text = dumps(row)
        self._out.write(text)
        self._out.write("\n")
        self._out.flush()
        self.rows += 1
        if len(self.page) < self.limit and self.page_bytes + len(text) <= self.byte_limit:
            self.page.append(row)
            self.page_bytes += len(text)
        elif len(self.page) < self.limit:
            self.bytes_bound_hit = True

    def finish(self):
        self.open()
        out, self._out = self._out, None
        out.flush()
        os.fsync(out.fileno())
        out.close()
        placed = place_without_replacing(self._tmp, self.target)
        if self._cleanup in CLEANUP:
            CLEANUP.remove(self._cleanup)
        result = {"rows": self.rows, "returned": len(self.page), "truncated": self.rows > len(self.page),
                  "inline_byte_limit": self.byte_limit, "all_results": self.shown_dir + placed.name,
                  "all_results_format": "JSON Lines, one row of the backup's map per line, with what became of it"}
        if self.bytes_bound_hit:
            result["inline_bounded_by_bytes"] = True
        if placed != self.target:
            result["earlier_result_kept"] = self.shown
        return result


def run_child(run_dir, config, seconds_left):
    """Start the child in this tool's process group, give it its paths, and wait for it: (exit code or None, why it was ended or None).
    It is ended with whatever it started when the time given to it is out, and by a stop signal (the BaseException below)."""
    env = dict(os.environ)
    env["TMPDIR"] = os.path.join(config["work"], "tmp")
    proc = spawn([sys.executable, os.path.abspath(__file__), "--child"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                 cwd=config["work"], env=env)
    ACTIVE.append(proc)
    began = time.monotonic()
    ended = None
    try:
        try:
            proc.stdin.write(json.dumps(config).encode("utf-8"))
            proc.stdin.close()
        except OSError:
            pass
        while True:
            try:
                code = proc.wait(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                pass
            _sample(proc.pid)
            if time.monotonic() - began > seconds_left:
                ended = "the time given to it ran out"
                kill_tree(proc)
                proc.wait()
                code = None
                break
    except BaseException:
        kill_tree(proc)
        raise
    finally:
        ACTIVE.remove(proc)
    reap_orphans()
    return code, ended


def read_events(path, limit_lines):
    """(events by kind, rows by rowid, lines read, whether a line was longer than allowed): the child's account, read to a bound."""
    marks, rows, lines, bad = {}, {}, 0, False
    try:
        fd, info = open_regular(path)
    except (OSError, NotRegular):
        return marks, rows, 0, False
    with os.fdopen(fd, "rb") as handle:
        while lines < limit_lines:
            raw = handle.readline(EVENT_LINE_BYTES + 1)
            if not raw:
                break
            if len(raw) > EVENT_LINE_BYTES:
                bad = True
                break
            lines += 1
            try:
                event = json.loads(raw)
            except ValueError:
                bad = True
                continue
            if not isinstance(event, dict):
                continue
            kind = event.get("e")
            if kind == "row" and isinstance(event.get("r"), int):
                rows[event["r"]] = (event.get("o"), event.get("b"), event.get("c"))
            elif isinstance(kind, str):
                marks[kind] = event
    return marks, rows, lines, bad


def remove_tree(path):
    shutil.rmtree(path, ignore_errors=True)


def capped(column):
    return "substr(CAST(%s AS TEXT), 1, %d)" % (column, CELL_CHARS)


RUN = {}


def main():
    try:
        main_inner()
    except Interrupted as stop:
        if "shown" not in RUN:
            raise
        name = signal.Signals(stop.signum).name
        emit(dumps(wrap_up({"error": "the tool was stopped by %s before it finished: this is not an answer to the question" % name, "status": "failed",
                            "status_basis": "stopped by %s before the answer was complete; files the child had written are in the output directory named here, without a DECRYPTED.json" % name,
                            "interrupted": name, "output_directory": RUN["shown"]})))
        raise SystemExit(128 + stop.signum)


def main_inner():
    started = time.monotonic()
    args = read_args()
    unknown = sorted(str(k) for k in args if k not in ARGUMENTS)
    if unknown:
        fail("the tool has no such argument: %s" % ", ".join(scrub(k) for k in unknown[:10]), arguments=list(ARGUMENTS))
    backup, secret_ref = args.get("backup"), args.get("password_ref")
    if not isinstance(backup, str) or not backup:
        fail("backup is required: the encrypted backup directory")
    if not isinstance(secret_ref, str) or not secret_ref:
        fail("password_ref is required: the path of the file that holds the password (given to the job as an input; never the password itself)")
    max_files = positive(args, "max_files", DEFAULT_MAX_FILES, MAX_FILES_CAP)
    max_bytes = positive(args, "max_bytes", DEFAULT_MAX_BYTES, MAX_BYTES_CAP)
    limit = positive(args, "limit", DEFAULT_LIMIT, 1 << 20)
    max_seconds = seconds(args, "max_seconds", DEFAULT_MAX_SECONDS, MAX_SECONDS_CAP)
    if not (os.environ.get("JOB_ID") and os.environ.get("OUT")):
        fail("backup_decrypt is refused outside a job: what it writes is the content of a phone, and outside a job it would be an ordinary file, "
             "not a sealed secret output. Run this as job_run tool=%s (the manifest makes every job of it secret output). Nothing was written." % TOOL,
             decrypt="refused", written=False)
    if os.environ.get("SECRET_OUTPUT") != "1":
        fail("backup_decrypt is refused in a job that is not run as secret output (SECRET_OUTPUT is not 1). Nothing was written.", decrypt="refused", written=False)
    if not os.path.isdir(backup):
        fail("backup is not a directory", backup=shown(backup, False))

    def refused(outcome, basis, **more):
        answer = {"tool": TOOL, "parser": PARSER, "status": "failed", "status_basis": basis, "outcome": outcome, "written": False,
                  "note": "Nothing was decrypted and nothing was written. The password is never printed, and the tool read none of it in this process.", **more}
        emit(dumps(wrap_up(answer), indent=2))
        raise SystemExit(1)

    ident, why = check_secret_file(secret_ref)
    if ident is None:
        refused("secret_unavailable", "the password file cannot be used: %s (it must be a regular file of mode 0600 given to the job, 1 to %d bytes)" % (why.replace("_", " "), SECRET_MAX_BYTES),
                password_file={"usable": False, "why": why})
    ok, why_format, facts = format_check(backup)
    if not ok:
        refused("unsupported_format", "the backup is not one this tool opens: %s" % scrub(why_format), backup_facts=facts)

    base, shown_base = output_base()
    nonce = os.urandom(4).hex()
    run_dir = base / ("backup_decrypt-%s" % nonce)
    work, dest = run_dir / "work", run_dir / "decrypted"
    try:
        os.mkdir(run_dir, 0o700)
        os.mkdir(work, 0o700)
        os.mkdir(work / "tmp", 0o700)
        os.mkdir(dest, 0o700)
    except OSError as exc:
        fail("the output directory could not be made: %s" % describe(exc), written=False)
    CLEANUP.append(lambda: remove_tree(str(work)))
    shown_run = "%s/%s" % (shown_base, run_dir.name)
    RUN["shown"] = shown_run
    child_until = started + max_seconds * CHILD_SHARE
    config = {"work": str(work), "dest": str(dest), "backup": os.path.abspath(backup), "password_ref": os.path.abspath(secret_ref), "password_ident": ident,
              "until": time.time() + (child_until - time.monotonic()), "max_files": max_files, "max_bytes": max_bytes}
    code, ended = run_child(run_dir, config, max(1.0, child_until - time.monotonic()))
    marks, rows, lines, bad_line = read_events(str(work / "events.jsonl"), MAX_ROWS + 1000)
    note_tree = process_notes()

    def stop_with(outcome, basis, **more):
        remove_tree(str(work))
        CLEANUP.clear()
        answer = {"tool": TOOL, "parser": PARSER, "status": "failed", "status_basis": basis, "outcome": outcome, "written": False,
                  "backup_facts": facts, "output_directory": shown_run,
                  "note": "Nothing was decrypted that is kept. The password is never printed, and the tool read none of it in this process.", **more}
        shutil.rmtree(str(run_dir), ignore_errors=True)
        emit(dumps(wrap_up(answer), indent=2))
        raise SystemExit(1)

    if "secret_unavailable" in marks:
        stop_with("secret_unavailable", "the password file cannot be used: %s" % str(marks["secret_unavailable"].get("why", "")).replace("_", " "),
                  password_file={"usable": False, "why": marks["secret_unavailable"].get("why")})
    if "backend_unavailable" in marks:
        stop_with("backend_unavailable", "the backend (iphone_backup_decrypt) is not installed in this image: %s" % marks["backend_unavailable"].get("c"))
    if "unlock_failed" in marks and marks["unlock_failed"].get("c") != "IncorrectPassphraseError":
        stop_with("failed", "the backend failed at the %s step with %s, which is not its wrong-password error: the tool does not read it as a wrong password"
                  % (marks["unlock_failed"].get("stage"), marks["unlock_failed"].get("c")),
                  unlock={"stage": marks["unlock_failed"].get("stage"), "exception_class": marks["unlock_failed"].get("c")})
    if "unlock_failed" in marks:
        stop_with("wrong_secret", "the backend raised IncorrectPassphraseError at the %s step: the password is not the backup's (%s)" % (marks["unlock_failed"].get("stage"), marks["unlock_failed"].get("c")),
                  unlock={"stage": marks["unlock_failed"].get("stage"), "exception_class": marks["unlock_failed"].get("c")})
    if "manifest_unusable" in marks or "manifest" not in marks:
        basis = ("the decrypted Manifest.db could not be used (%s)" % marks["manifest_unusable"].get("c")) if "manifest_unusable" in marks else (
            "the child ended before the decrypted Manifest.db was written (%s)" % (ended or ("exit code %s" % code)))
        stop_with("failed", basis, child={"exit_code": code, "ended": ended})

    # --- verify: the decrypted map, read here, against the files the child placed --------------------------------------------------
    read_deadline = started + max_seconds * 0.97
    results = ResultFile(base, shown_base, [shown_run], limit, INLINE_BYTES)
    manifest_path = dest / "Manifest.db"
    counts = {}
    problems = []
    manifest_ok, manifest_rows = False, 0
    try:
        conn = sqlite3.connect("file:%s?mode=ro&immutable=1" % quote(str(manifest_path)), uri=True)
        conn.text_factory = lambda b: b.decode("utf-8", "surrogateescape")

        def guard():
            if time.monotonic() > read_deadline:
                return 1
            return 0
        conn.set_progress_handler(guard, 20000)
        conn.execute("SELECT count(*) FROM Files").fetchone()
        manifest_ok = True
    except Exception as exc:  # noqa: BLE001
        problems.append("the decrypted Manifest.db did not open as SQLite here: %s" % class_word(exc))
    cut = None
    if manifest_ok:
        try:
            cursor = conn.execute("SELECT rowid, %s, %s, %s, flags, CASE WHEN length(file) <= %d THEN file END FROM Files ORDER BY rowid"
                                  % (capped("fileID"), capped("domain"), capped("relativePath"), FILE_CELL_BYTES))
            for rowid, file_id, domain, rel, flag, blob in cursor:
                manifest_rows += 1
                if manifest_rows > MAX_ROWS:
                    cut = "rows"
                    break
                if manifest_rows % LOOK_EVERY == 0 and time.monotonic() > read_deadline:
                    cut = "time"
                    problems.append("the decrypted map could not be read to its end in the time left")
                    break
                kind = KINDS.get(flag, "other")
                size_status, size, _mode = manifest_size_mode(blob)
                row = {"row": rowid, "file_id": file_id if isinstance(file_id, str) and FILE_ID.fullmatch(file_id) else None,
                       "domain": scrub(domain) if isinstance(domain, str) else None, "relative_path": shown(rel, False) if isinstance(rel, str) else None,
                       "kind": kind, "manifest_size": size, "manifest_size_status": size_status}
                if kind in ("directory", "symlink"):
                    row["outcome"] = "no_blob_expected"
                elif kind != "file":
                    row["outcome"] = "unknown_kind_not_decrypted"
                else:
                    event = rows.get(rowid)
                    if event is None:
                        row["outcome"] = "not_attempted"
                    elif event[0] == "ok":
                        placed = None
                        if row["file_id"]:
                            try:
                                info = os.lstat(os.path.join(str(dest), row["file_id"][:2].lower(), row["file_id"].lower()))
                                placed = info.st_size if stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 else None
                            except OSError:
                                placed = None
                        row["decrypted_bytes"] = placed
                        if placed is None:
                            row["outcome"] = "write_failed"
                        elif size is None:
                            row["outcome"] = "decrypted_size_unknown"
                        elif placed == size:
                            row["outcome"] = "decrypted_verified"
                        else:
                            row["outcome"] = "size_mismatch"
                    else:
                        row["outcome"] = str(event[0]) if event[0] in OUTCOMES_NOT_DECRYPTED else "not_attempted"
                        if event[2]:
                            row["backend_exception_class"] = event[2]
                counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
                results.add(row)
        except sqlite3.OperationalError:
            cut = "time"
            problems.append("the decrypted map could not be read to its end in the time left")
        except Exception as exc:  # noqa: BLE001
            cut = "read"
            problems.append("the decrypted map could not be read to its end: %s" % class_word(exc))
    page = results.finish()
    remove_tree(str(work))
    if CLEANUP:
        CLEANUP.clear()
    cut_child = marks.get("done", {}).get("cut") if "done" in marks else None
    if "done" not in marks:
        problems.append("the child ended before its end line (%s): rows it had not reached are not_attempted" % (ended or "exit code %s" % code))
    if cut_child:
        problems.append("the child stopped for the %s limit; rows it had not reached are not_attempted" % cut_child)
    if cut == "rows":
        problems.append("the map holds more than %d rows: the rest is not read" % MAX_ROWS)
    if bad_line:
        problems.append("the child's account held a line that was too long or not JSON")
    expected = {"decrypted_verified", "no_blob_expected"}
    short = sum(n for k, n in counts.items() if k not in expected)
    if short:
        problems.append("%d row(s) are not decrypted and verified: %s" % (short, ", ".join("%s %d" % (k, n) for k, n in sorted(counts.items()) if k not in expected)))
    verified = manifest_ok and not problems and counts.get("decrypted_verified", 0) + counts.get("no_blob_expected", 0) == manifest_rows
    status = "complete" if verified else "partial"
    if verified:
        basis = ("the decrypted Manifest.db opens as SQLite and each of its %d file row(s) was decrypted to the length the Manifest records (%d row(s) are directories or links with no blob)"
                 % (counts.get("decrypted_verified", 0), counts.get("no_blob_expected", 0)))
    else:
        basis = "partial because " + "; ".join(problems[:4]) + (" (and %d more in `problems`)" % (len(problems) - 4) if len(problems) > 4 else "")
    banner = json.dumps(BANNER, sort_keys=True, indent=2) + "\n"
    fd, banner_tmp = tempfile.mkstemp(dir=str(dest), prefix=".bd-banner-")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(banner)
    place_without_replacing(Path(banner_tmp), dest / "DECRYPTED.json")
    answer = {
        "tool": TOOL, "parser": PARSER, "status": status, "status_basis": basis,
        "outcome": "verified" if verified else "partial",
        "backup_facts": facts,
        "password_file": {"usable": True, "note": "read by the child process only, as text in memory; it is on no command line, in no environment variable, on no output channel and in no file"},
        "decrypted": {"root": shown_run + "/decrypted", "manifest": shown_run + "/decrypted/Manifest.db", "manifest_opens_as_sqlite": manifest_ok,
                      "manifest_rows": manifest_rows, "mode": "0600", "banner": shown_run + "/decrypted/DECRYPTED.json",
                      "layout": "decrypted/<first two digits of the file id>/<file id>"},
        "counts": counts,
        "verification": "decrypted_verified: the decrypted length is the Size the Manifest records for the row. It is not a claim that the content is what the phone held (a file id is a locator; the Manifest records no digest of content).",
        "problems": problems, "child": {"exit_code": code, "ended": ended, "events": lines, "seconds_limit": round(max_seconds * CHILD_SHARE, 1)},
        "rows": results.page, "pages": {"rows": page}, "truncated": page["truncated"] or cut is not None or bool(cut_child),
        "process_notes": note_tree,
        "note": "This is a decrypted copy of what a backup kept, written by the library iphone_backup_decrypt in a child process of this tool: not the phone, not an acquisition, "
                "and not a backup directory (Manifest.plist is not carried over). No key bag, class key or manifest key is printed: Manifest.plist's key material is a presence and a length. "
                "The password is never in this answer. The files are sealed sensitive output of this secret job.",
    }
    send(answer)


if __name__ == "__main__":
    if sys.argv[1:] == ["--child"]:
        sys.exit(child_main())
    run_main(main)
