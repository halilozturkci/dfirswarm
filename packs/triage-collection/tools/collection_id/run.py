#!/usr/bin/env python3
"""Say what a delivered directory holds, which collectors left records in it, and what those records say was not copied.

This is a survey of names, a few first bytes and the collectors' own logs. It is a hypothesis about the delivery, not an
audit of it. What it measures:

  - every object it walks, classified one by one: a signature in the first bytes where there is one, the extension
    otherwise, and each says which. A name that says image or raw with no signature is `unknown`, not a physical image: a
    raw memory capture has no signature either. The delivery is `mixed` when more than one kind of object is present (copied
    files below the top level count as one kind; a note or a log beside an image does not). Nothing is opened but the first
    4 KiB of the objects named in `reads_first_bytes_of`; an archive or a container is not opened and its members are not
    listed;
  - the collector markers found, by their paths (more than one collector may have left records in one delivery, and one
    collector may have run more than once): KAPE `*_CopyLog.csv`, `*_SkipLog.csv` and `*_ConsoleLog.txt`, UAC `uac.log`
    and a `[root]` directory, Velociraptor `uploads.json` or `collection_context.json`. A top-level directory named C, C$ or
    Windows is a layout clue only: KAPE targets, CyLR output and a hand copy all look like it, and nothing here names CyLR.
    A log found inside collected data (below `[root]` or `uploads`) belongs to the source host and is not read;
  - what each recognised log records, read whole and streamed. KAPE: the columns and rows of a copy or skip log, and the
    levelled lines of a console log. UAC: the lines that start with a date, a time and a level word, in both forms the
    sources of UAC 3.4.0 (DBG, INF, ERR, CMD) and 2.9.1 (DEBUG, INFO, WARNING, ERROR, COMMAND) write; a line that matches
    nothing is counted and kept unlabelled. Velociraptor (checked against the source of 0.77.2): the rows of `uploads.json`,
    and, because that version never writes a failed upload to `uploads.json`, the rows of `results/*.json` whose upload record
    carries an Error and the ERROR lines of `log.json`. A log whose columns or lines are not recognised, or that is binary or
    UTF-16, is `partial` or `unsupported`.

The failure count is `null`, never 0, unless every failure-source log was read whole (`parsed`), the walk was complete, and no
archive went unopened; `failed_targets_seen` is how many rows were read all the same. What it does not measure: that the
collector finished, what it was asked to copy (the profile, targets and artefacts are not read), whether a recorded failure
matters, whether a digest in a log matches the delivered file, the original path of a file (collection_index), the
collector's version, or what a log omits. A skip-log row is a recorded skip with the collector's own words; whether it is a
failure is the collector's meaning, not this tool's. "No failure recorded" is a statement about the rows read, not about the
acquisition.

SECRET-SAFE OUTPUT (docs/packs.md, "Secrets and sensitive output"). Paths and log text are printed through the shared
withholding block: a string shaped like a recovery password, an access key, a token, a private-key block, the user-info of a
URL, or the value after a credential header, key name or password option is replaced by its kind, its length and a finding
id, in every channel (a path, a log line, a dictionary key, an error). The shapes are few and exact, so a secret of no
recognisable shape can still appear in a collector's log: the skill says to run this as a job with `secret_output: true`.
`write_values: true` (a job only) writes the real strings to `$OUT/collection-id-values.jsonl`, mode 0600, created before
anything is read.
"""
# ---- BEGIN SHARED BLOCK ----------------------------------------------------------------------------------------------
# Identical in every tool of this pack that prints a path or a log line (collection_id, collection_index, collection_manifest_parse,
# collection_manifest_verify, collection_path_map, collection_coverage). A tool is standalone, so what they share is copied, as
# LosslessPage is in every pack tool, and tests/pack-triage-shared.test.ts holds the copies equal. Edit it in all, never in
# one. It holds: the error form, typed arguments, where an output may be written and published without replacing another,
# the lossless table, the secret-safe values file (the SecretValues of recovery_key_scan), the withholding of strings
# shaped like a credential, the head-of-file classifier for what a delivery may hold besides copied files, and a deadline.
import atexit
import errno
import hashlib
import json
import os
import re
import secrets
import signal
import stat
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

DEFAULT_LIMIT = 200
FIRST_PROBLEMS = 25               # how many problems of a kind an answer names inline; every one is a row of the problems table
INLINE_BUDGET = 32 << 10          # bytes of rows an inline page carries (the model reads the first 64 KiB of an answer); the rest is in the table's file
CHUNK = 1 << 20
HEAD_BYTES = 4096
MIN_RAW_BYTES = 1 << 20           # a file smaller than this is not read for a volume signature ($Boot is a boot sector, not a disk)
DEADLINE = [None]


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def secret_job():
    """Whether the job service ran this job as secret output (it sets SECRET_OUTPUT=1 for a job the agent flagged and for a job the
    tool's manifest declares, `write_values` here): a values file is written only then."""
    return os.environ.get("SECRET_OUTPUT") == "1"


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def fail(message, **extra):
    """An error answer: JSON, exit 1, never a traceback. A name in it that is shaped like a credential is withheld."""
    write_answer({"error": scrub(str(message)), "status": "failed", **extra})
    raise SystemExit(1)


def scrub_all(value):
    """Every string of a structure through scrub, keys included (a key can be the credential, and is a name: it gets the floor of a name)."""
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, dict):
        return {shown(k) if isinstance(k, str) else k: scrub_all(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub_all(v) for v in value]
    return value


def _stopped_by_signal(signum, frame):
    """A kill leaves no half-written file (atexit runs on SystemExit) and no empty answer."""
    print(json.dumps({"error": "the tool was stopped by signal %d before it finished; nothing it was writing was published" % signum,
                      "status": "failed"}))
    raise SystemExit(128 + signum)


def install_signal_handlers():
    for name in ("SIGTERM", "SIGHUP", "SIGINT"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _stopped_by_signal)


def ignored_parameters(args, known):
    """The names a caller passed that this tool does not read, so a typo is seen and not silently the default."""
    return sorted(scrub(str(k)) for k in args if k not in known)


def read_args():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=type(exc).__name__)
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def want_str(args, key, required=None):
    value = args.get(key)
    if value is None:
        if required:
            fail(required)
        return None
    if not isinstance(value, str) or not value or "\0" in value:
        fail("%s must be a non-empty string" % key)
    return value


def want_bool(args, key, default=False):
    value = args.get(key, default)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_int(args, key, default, minimum=1, maximum=None):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or (maximum is not None and value > maximum):
        fail("%s must be an integer of at least %d%s" % (key, minimum, "" if maximum is None else " and at most %d" % maximum))
    return value


def start_clock(seconds):
    DEADLINE[0] = time.monotonic() + seconds
    SCRUB_DEADLINE[0] = DEADLINE[0] + 10


def out_of_time():
    return DEADLINE[0] is not None and time.monotonic() > DEADLINE[0]


# ---- where an output may be written ------------------------------------------------------------------------------


def same_file(a, b):
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def is_inside(path, ancestor):
    """Whether `path` is `ancestor` or below it, decided by identity (device and inode) of the existing places, not by how the
    names are spelled: on a case-insensitive file system work/COLL and work/coll are one directory."""
    p = Path(path)
    return any(same_file(candidate, ancestor) for candidate in (p, *p.parents) if os.path.lexists(candidate))


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself, or
    anything under inputs/ is refused. A string check is not enough: `work/../inputs/x`, an absolute path, a symlink that
    points out and a case-variant spelling on a case-insensitive file system all name a place the tool must not write, so the
    path is resolved first and places are compared by identity. In a job the run directory is read-only and only $OUT is
    written, so a place outside $OUT is refused with the way to name one (work/<your agent id>/..., which the harness maps to
    $OUT), not left to fail on a read-only file system."""
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if same_file(dest, root) or not is_inside(dest, root):
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if is_inside(dest, inputs):
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    if in_job():
        base = Path(os.environ["OUT"]).resolve()
        if same_file(dest, base) or not is_inside(dest, base):
            fail("%s is not under this job's output directory: a job writes only $OUT, and the run directory is read-only. "
                 "Name a place under work/<your agent id>/ and the harness maps it there, or leave %s out." % (what, what),
                 **{what: str(out)})
    try:
        return str(dest.relative_to(root))
    except ValueError:
        return os.path.relpath(dest, root)


def shown_output(path):
    """How an output is named in an answer: a job's $OUT is sealed as store/jobs/<job>/out, so a place under it is shown
    as it will be cited."""
    try:
        rel = Path(path).resolve().relative_to(Path(os.environ["OUT"]).resolve())
        return "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ["JOB_ID"]), rel.as_posix())
    except (KeyError, ValueError, OSError):
        return str(path)


def same_bytes(a, b):
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(CHUNK), fb.read(CHUNK)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


def publish(tmp, path):
    """Move a finished file to `path` without replacing what is there: a file at the name is an earlier answer (a complete
    one, perhaps, where this run was cut short by a lower limit) and stays; this one is kept beside it as name.2.ext,
    unless it holds the same bytes, when the file already there is it. Returns the path it has."""
    stem, ext = os.path.splitext(str(path))
    k = 1
    while True:
        candidate = Path(stem + ("" if k == 1 else ".%d" % k) + ext)
        try:
            os.link(tmp, candidate)
        except FileExistsError:
            if same_bytes(tmp, candidate):
                os.unlink(tmp)
                return candidate
            k += 1
            continue
        except OSError:                                   # a file system with no hard links: a look, then a rename
            if os.path.lexists(candidate):
                if same_bytes(tmp, candidate):
                    os.unlink(tmp)
                    return candidate
                k += 1
                continue
            os.rename(tmp, candidate)
            return candidate
        os.unlink(tmp)
        return candidate


_TEMPS = set()


def _drop_unpublished():
    """A refused or failed run leaves no half-written result behind: only a finished file is published."""
    for path in list(_TEMPS):
        try:
            os.unlink(path)
        except OSError:
            pass


atexit.register(_drop_unpublished)


OWN_NAMES = set()
OWN_PATHS = set()


def register_own(path):
    """A file this run creates (a table, its temporary file, the values file): a walk whose root contains it must not list it."""
    OWN_NAMES.add(os.path.basename(str(path)))
    OWN_PATHS.add(os.path.realpath(str(path)))


def is_own(entry):
    return entry.name in OWN_NAMES and os.path.realpath(entry.path) in OWN_PATHS


class Table:
    """The rows an answer carries inline, and the whole in a JSON Lines file it names. Rows past `limit` (or past the
    inline byte budget) go to the file, so nothing is cut: under $OUT/tool-output in a job, work/<agent>/tool-output
    otherwise, with a random name (never a digest of the request). With `dest` or `always` the whole is written even when
    it fits; with `dest` it goes there, and never over a file that is already there: that one is kept and this one is
    named beside it. Rows are written with ASCII escapes, so a lone surrogate from a non-UTF-8 name survives and no row can
    raise."""

    def __init__(self, tool, limit, dest=None, always=False, budget=INLINE_BUDGET):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit, self.budget, self.dest, self.always = limit, budget, dest, always
        self.page, self.total, self.bytes = [], 0, 0
        self._out = self._tmp = None
        if dest:
            self.path = Path(dest)
        else:
            name = "%s-%s.jsonl" % (self.tool, secrets.token_hex(8))
            job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
            if job and out:
                self.path = Path(out) / "tool-output" / name
            else:
                agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
                self.path = Path("work") / agent / "tool-output" / name
        register_own(self.path)
        if dest or always:
            self._open_tmp()

    def _open_tmp(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.tool)
            self._tmp = Path(name)
            _TEMPS.add(name)
            register_own(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace")
        except OSError as exc:
            fail("the whole result could not be written: %s cannot be created (%s)" % (shown_output(self.path.parent), describe(exc)))

    def open_now(self):
        """Create the file now (a table whose file would lie inside the tree being walked must be known before the walk)."""
        if self._out is None:
            self._open_tmp()

    def _write(self, text):
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            fail("the whole result could not be written to %s: %s" % (shown_output(self.path), describe(exc)))

    def add(self, row):
        row = row_out(row, "%s row %d" % (self.tool, self.total + 1))
        text = json.dumps(row, default=str)
        self.total += 1
        if self._out is None and (len(self.page) >= self.limit or self.bytes + len(text) > self.budget):
            self._open_tmp()
            for kept in self.page:
                self._write(json.dumps(kept, default=str))
        if self._out is not None:
            self._write(text)
        if len(self.page) < self.limit and self.bytes + len(text) <= self.budget:
            self.page.append(row)
            self.bytes += len(text)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                final = publish(self._tmp, self.path)
                _TEMPS.discard(str(self._tmp))
            except OSError as exc:
                fail("the whole result could not be written to %s: %s" % (shown_output(self.path), describe(exc)))
            result["all_results"] = shown_output(final)
            OWN_SHOWN.add(result["all_results"])
            result["all_results_format"] = "JSON Lines, one complete result per line"
            if str(final) != str(self.path):
                OWN_SHOWN.add(shown_output(self.path))
                result["all_results_note"] = "a different file was already at %s and was kept; this result is beside it" % shown_output(self.path)
        return result


class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan (docs/packs.md, "Secrets and sensitive output"), copied unchanged
    but for the file's name and the tool named in the refusal. With `enabled` false it writes nothing and `summary()` says
    so. Enabled, it is refused outside a job; inside one the file is created at once, before anything is read (mode 0600,
    O_EXCL and O_NOFOLLOW: a file or a link already at that name is refused by name, a dangling link included), so with
    nothing withheld it stays an empty file and the answer says written: 0.
    """

    def __init__(self, enabled, name, tool):
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
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % tool
            )
        if not secret_job():
            raise SecretValuesRefused(
                "write_values is refused in a job that is not run as secret output (SECRET_OUTPUT is not 1): the values file would be an "
                "ordinary output, not a sealed one. Run this as job_run tool=%s with secret_output: true. Nothing was written." % tool
            )
        self.path = Path(self.out) / name
        register_own(self.path)
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), name)
        OWN_SHOWN.add(self.shown)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.shown)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.shown, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace")

    def add(self, finding_id, locator, value):
        if not self.enabled or self._fh is None:
            return
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}, default=str))
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
            "format": "JSON Lines, mode 0600: finding_id, where, value (the real string)" if self.enabled else None,
        }


# ---- withholding: nothing shaped like a credential is printed ------------------------------------------------------
# [Local to this pack, with the boundary and the independent check below it: one clearly marked block, identical in every tool. The
# pack-wide reference block of the shared-withholding task is meant to replace it; until then every tool keeps this one.]
# A path or a line of a collector's log can carry a string that is a secret. What is judged here is its SHAPE, and the shapes
# are rules, not a proof: a secret of no recognisable shape (a plain password alone in a name, a passphrase, a UUID-shaped key,
# a lower-case token of 24 letters) is printed, and the skill says to run the tool as a job with secret_output: true. What is
# caught is withheld in every channel (a path, a log line, an error, a dictionary key) and the same strings in both tools of the
# pack; the real string goes to the values file when write_values is asked, in a job. Each withheld text carries a finding id,
# the finding_id of its row in the values file.
#
# What is judged: (1) the text as a reader sees it, not as its bytes are: a copy without NUL, zero-width, bidi and other format
# characters, combining marks and variation selectors, with spaces of every kind one space, compatibility forms folded (full-width
# letters) and the NULs of UTF-16 read as 8-bit gone, and the rules run on that copy, so a token split by an invisible character
# is found and the span withheld is the span of the original; (2) named shapes: key ids, token families (the prefixes of the
# vendors' public formats, in any case), web tokens, private-key blocks, URL user-info, connection strings, the value after a name
# that says it is a secret (read back from the `=` or `:`, so DB_PASSWORD=, adminPassword= and X-Api-Key: count), the options of
# the clients that take a password on the command line, recovery passwords; (3) random-looking text: a run of letters and digits
# that changes class the way random text does (and a `/`-joined key, which is several pieces), in a name or path of 16
# characters or more and in a token of 20 or more in a line of text. Hex is evidence (a digest), a GUID or a SID is a typed id,
# and a name below 16 characters is shown whatever it looks like.
#
# Linear time: a text over 16 KiB is judged in windows of 8 KiB that overlap by 1 KiB (no rule matches more than 1 KiB), every
# regular expression has bounded repetition, user-info and the client options are found by hand from their `@` or their program
# name, the clock is read between windows, and a text the run has no time left to judge is withheld whole (it fails closed).

SCRUB_DEADLINE = [None]            # the withholding's own clock: the run's deadline plus a grace; release() gives the final answer its own
WINDOW, OVERLAP, SINGLE = 8192, 1024, 16384
MAX_CANDIDATES = 4096              # `@` signs and program names examined in one text; past it the rest of the text is withheld
KIND_RANDOM = "random-looking text"
MAX_PIECES = 12                    # pieces in one window: a key of 64 characters has a few `/ - _ +`, a run of one-letter pieces is not a key
_NO_EXT = "png|jpe?g|gif|svg|webp|ico|bmp|tiff?|heic|plist|json|txt|log|db|dat|xml|html?|css|js|py|exe|dll|lnk"
_FILE_EXT = re.compile(r"(?:%s)\Z" % _NO_EXT, re.I)
# rules that withhold their whole match: (kind, pattern); a rule with a `secret` group withholds that part only
SHAPES = [
    ("recovery-password-shaped text", re.compile(r"(?<![0-9])[0-9]{6}(?P<s>[-_. ]?)(?:[0-9]{6}(?P=s)){6}[0-9]{6}(?![0-9])")),
    ("access-key-shaped text", re.compile(r"(?i:(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA|ABIA|ACCA)[0-9A-Z]{16})")),
    ("token-shaped text", re.compile(r"(?i:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}"
                                    r"|xapp-[A-Za-z0-9-]{10,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}|dop_v1_[A-Za-z0-9]{40,}|AIza[A-Za-z0-9_-]{30,}"
                                    r"|ya29\.[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{16,}(?:\.[A-Za-z0-9_-]{16,})?|npm_[A-Za-z0-9]{30,}|shpat_[A-Za-z0-9]{30,}"
                                    r"|pypi-[A-Za-z0-9_-]{50,}|hf_[A-Za-z]{30,}|1//0[A-Za-z0-9_-]{30,}|SK[0-9a-f]{32})")),
    ("token-shaped text", re.compile(r"(?<![A-Za-z0-9])sk-(?=[A-Za-z0-9_-]{0,47}[0-9])[A-Za-z0-9_-]{20,}")),
    ("web-token-shaped text", re.compile(r"eyJ[A-Za-z0-9_=-]{8,}(?:\.[A-Za-z0-9_=-]*){2,4}")),
    ("base64-shaped text", re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{15,}={1,2}(?![A-Za-z0-9+=])")),
    ("webhook URL", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("credential after a header", re.compile(r"(?i:(?:proxy-)?authorization[ \t]{0,3}[:=][ \t]{0,3}(?:basic|bearer|token|negotiate|digest)[ \t]{1,8})(?P<secret>[^\s'\",;]{1,2048})")),
    ("credential after a header", re.compile(r"(?i:(?:set-)?cookie[ \t]{0,3}:[ \t]{0,3})(?P<secret>[^\r\n]{1,1024})")),
    ("credential after a key name", re.compile(r"(?i:[?&]sig=)(?P<secret>[A-Za-z0-9%+/=]{16,})")),
    ("credential after a key name", re.compile(r"(?i:\bConvertTo-SecureString[ \t]{1,8}(?:-String[ \t]{1,8})?)(?P<secret>'[^'\r\n]{1,512}'|\"[^\"\r\n]{1,512}\"|[^\s;|]{1,512})")),
]
_ANY_CHEAP = re.compile(r"[0-9]{6}[-_. ]?[0-9]{6}|[A-Za-z0-9_-]{16}|[=:@]|-----|eyJ|(?i:authorization|cookie|ConvertTo)|\s--?[a-zA-Z]")
# the name of a secret, read before an `=` or a `:` (the word may be glued to a prefix with `_` `-` `.` or by CamelCase)
_NAME = re.compile(r"(?i:pass(?:word|wd|phrase)?|pwd|secret(?:[_-]?(?:access[_-]?)?key)?|token|credential|api[_-]?key|access[_-]?key|account[_-]?key|"
                   r"private[_-]?key|master[_-]?key|signing[_-]?key|shared[_-]?key|auth|sig|sas|pw)s?(?=[\"']?[ \t]{0,3}[=:])")
_WEAK_NAMES = ("pass", "pw", "auth", "sig", "sas")
_NOT_WEAK = re.compile(r"(?i:by|com|over|under|tres|sur|im|en|encom|tres|by|out|sub)pass\Z")
_VALUE = re.compile(r"[\"']?[ \t]{0,3}[=:][ \t]{0,3}(?:(?P<q>[\"'])(?P<quoted>[^\"'\r\n]{1,512})(?P=q)|(?P<plain>[^\s\"'&,;<>]{1,512}))")
_CLIENT_WORD = re.compile(r"(?i)(mysql\w*|mariadb\w*|sshpass|curl|wget|smbclient|7za?|7zr|unrar|rar|zip|unzip|redis-cli|ldapsearch|ldapmodify|ldapadd|openssl)(?![A-Za-z0-9])")
_CLIENT_OPT = {
    "mysql": re.compile(r"\s-p(?P<secret>\S+)"), "mariadb": re.compile(r"\s-p(?P<secret>\S+)"), "sshpass": re.compile(r"\s-p[ \t]*(?P<secret>\S+)"),
    "curl": re.compile(r"\s(?:-u|--user|--proxy-user)(?:=|[ \t]+)[^\s:]{1,64}:(?P<secret>\S+)"), "wget": re.compile(r"\s--(?:http-|ftp-|proxy-)?password(?:=|[ \t]+)(?P<secret>\S+)"),
    "smbclient": re.compile(r"\s-U[ \t]*[^\s%]{1,64}%(?P<secret>\S+)"), "7z": re.compile(r"\s-p(?P<secret>\S+)"), "unrar": re.compile(r"\s-p(?P<secret>\S+)"),
    "rar": re.compile(r"\s-p(?P<secret>\S+)"), "zip": re.compile(r"\s-P[ \t]*(?P<secret>\S+)"), "unzip": re.compile(r"\s-P[ \t]*(?P<secret>\S+)"),
    "redis-cli": re.compile(r"\s-a[ \t]+(?P<secret>\S+)"), "ldapsearch": re.compile(r"\s-w[ \t]+(?P<secret>\S+)"), "ldapmodify": re.compile(r"\s-w[ \t]+(?P<secret>\S+)"),
    "ldapadd": re.compile(r"\s-w[ \t]+(?P<secret>\S+)"), "openssl": re.compile(r"\s-pass(?:in|out)?[ \t]+(?:pass|env|file):(?P<secret>\S+)"),
}
_OPTION = re.compile(r"(?i:(?<![\w-])--?(?:pass(?:word|wd|phrase)?|pwd|secret|token|api-?key|client-secret|access-?key)(?:=|[ \t]{1,3}))(?P<secret>[^\s=<>-][^\s<>]{0,511})")
_PEM_HEAD = re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-[0-9]+:")
_PUTTY_END = re.compile(r"Private-MAC:\s*[0-9A-Fa-f]+")
_MARKER = re.compile(r"<[A-Za-z][A-Za-z -]{2,60} withheld, [0-9]+ characters(?:, W[0-9]{6})?>|<withheld: [0-9]+ bytes>|<text over the scan budget withheld, [0-9]+ characters>")
_FOLD_DROP = frozenset(("Cc", "Cf", "Mn", "Me", "Cs", "Co", "Cn", "Zl", "Zp"))
_PLAIN_ASCII = re.compile(r"[\x20-\x7e\n]*")
WITHHELD = {"count": 0}
VALUES = [None]
_SEEN = {}
_SEEN_CHARS = [0]


def fold_view(text):
    """(the text as a reader sees it, the original index of each of its characters or None when they are the same)."""
    if _PLAIN_ASCII.fullmatch(text):
        return text, None
    out, index = [], []
    for i, ch in enumerate(text):
        if ch == "\n":
            out.append(ch)
            index.append(i)
            continue
        if ch < " " or ch == "\x7f":
            if ch in "\t\r":
                out.append(" ")
                index.append(i)
            continue
        category = unicodedata.category(ch)
        if category in _FOLD_DROP:
            continue
        if category == "Zs":
            out.append(" ")
            index.append(i)
        elif ord(ch) > 127:
            for c in unicodedata.normalize("NFKC", ch):
                out.append(c)
                index.append(i)
        else:
            out.append(ch)
            index.append(i)
    return "".join(out), index


_MAC_USER_FOLDER = re.compile(r"(?<=/var/folders/)[a-z0-9_]{2}/[a-z0-9_]{30}(?=/|\Z)")      # the per-user temporary folder of a Mac: a typed id with `_` in it


def _blank_known(f):
    """Markers this tool wrote and the names of files it made are not judged again (they are blanked, so every index stays)."""
    if "withheld" in f:
        f = _MARKER.sub(lambda m: " " * len(m.group()), f)
    for name in OWN_SHOWN:
        if name in f:
            f = f.replace(name, " " * len(name))
    if "/folders/" in f:
        f = _MAC_USER_FOLDER.sub(lambda m: " " * len(m.group()), f)
    return f


def _user_info_spans(f, budget):
    """Spans of user-info: for each `@` that a host follows, the text before it back to the last `//` (the whole of it, so a
    password that holds / ? # or @ goes with it), or, without a scheme, a `name:password` token whose host is an address or a dotted
    name that is not a file extension (icon@2x.png is a file name). `budget` is a one-item list: the `@` signs left to examine."""
    spans, pos, size = [], 0, len(f)
    while True:
        at = f.find("@", pos)
        if at < 0:
            return spans
        pos = at + 1
        if at + 1 >= size or f[at + 1] in " \t\r\n@/?#'\"<>":
            continue
        lo = max(0, at - 768)
        start = max(f.rfind(c, lo, at) for c in " \t\r\n'\"<>") + 1
        budget[0] -= 1
        if budget[0] < 0:
            # the secret of user-info stands BEFORE the `@`: past the budget the withheld span starts at the segment, not at the `@`
            spans.append((start, size, "user-info of a URL"))
            return spans
        seg = f[start:at]
        slash = seg.rfind("//")
        if slash >= 0:
            cand = seg[slash + 2:]
            colon = cand.find(":")
            head = cand if colon < 0 else cand[:colon]
            if cand and not any(c in head for c in "/?#") and not (colon >= 0 and re.match(r"[0-9]+(?:[/?#]|\Z)", cand[colon + 1:])):
                spans.append((start + slash + 2, at, "user-info of a URL"))
                continue
        colon = seg.rfind(":")
        if colon <= 0 or colon + 1 >= len(seg):
            continue
        secret = seg[colon + 1:]
        if any(c in secret for c in "/\\:'\"<>"):
            continue
        name_start = colon
        while name_start > 0 and colon - name_start < 64 and (seg[name_start - 1].isalnum() or seg[name_start - 1] in "._%+-"):
            name_start -= 1
        if name_start == colon:
            continue
        before = seg[name_start - 1] if name_start > 0 else ""
        if before and (before.isalnum() or before in "_@.:\\-"):
            continue
        host = re.match(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*", f[at + 1:at + 256])
        if not host:
            continue
        labels = host.group().split(".")
        is_ip = len(labels) == 4 and all(x.isdigit() and len(x) <= 3 for x in labels)
        named = len(labels) > 1 and any(x.isalpha() and len(x) >= 2 and not _FILE_EXT.match(x) for x in labels[1:])
        if is_ip or named:
            spans.append((start + name_start, at, "user-info of a URL"))
    return spans


def _named_spans(f):
    """The value after a name that says it is a secret, read from the name: DB_PASSWORD=x, adminPassword: x, "password": "x"."""
    spans = []
    for m in _NAME.finditer(f):
        word = m.group().lower().rstrip("s")
        if word in _WEAK_NAMES:
            before = f[m.start() - 1] if m.start() else ""
            if before.isalpha() and not (m.group()[0].isupper() and before.islower()):
                continue
            if _NOT_WEAK.search(f[max(0, m.start() - 6):m.end()]):
                continue
        v = _VALUE.match(f, m.end())
        if not v:
            continue
        if v.group("quoted") is not None:
            spans.append((v.start("quoted"), v.end("quoted"), "credential after a key name"))
        else:
            value = v.group("plain")
            if value.startswith("//") or value.startswith("<"):
                continue
            spans.append((v.start("plain"), v.end("plain"), "credential after a key name"))
    return spans


def _client_spans(f, budget):
    spans = []
    for m in _CLIENT_WORD.finditer(f):
        budget[0] -= 1
        if budget[0] < 0:
            spans.append((m.end(), len(f), "password option"))
            return spans
        word = m.group(1).lower()
        key = "mysql" if word.startswith("mysql") else "mariadb" if word.startswith("mariadb") else "7z" if word.startswith("7z") else word
        option = _CLIENT_OPT.get(key)
        if option is None:
            continue
        seg = f[m.end():m.end() + 300]
        for stop in "\n|;&":
            cut = seg.find(stop)
            if cut >= 0:
                seg = seg[:cut]
        o = option.search(seg)
        if o:
            spans.append((m.end() + o.start("secret"), m.end() + o.end("secret"), "password option"))
    return spans


def _option_spans(f):
    return [(m.start("secret"), m.end("secret"), "password option") for m in _OPTION.finditer(f)]


def _block_spans(f):
    """Private-key blocks (PEM, PuTTY): from the header to the END line, or to the end of the text when there is none."""
    spans, pos = [], 0
    while True:
        m = _PEM_HEAD.search(f, pos)
        if not m:
            return spans
        if m.group().startswith("PuTTY"):
            end = _PUTTY_END.search(f, m.end())
            stop = end.end() if end else len(f)
        else:
            e = f.find("-----END", m.end())
            if e < 0:
                stop = len(f)
            else:
                close = f.find("-----", e + 8)
                stop = close + 5 if close >= 0 else len(f)
        spans.append((m.start(), stop, "private-key block"))
        pos = max(stop, m.end())


# ---- random-looking text -----------------------------------------------------------------------------------------------
_HEX_ONLY = re.compile(r"[0-9A-Fa-f]+\Z")
_UNITS = re.compile(r"[A-Z][a-z]+|[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
_PLAIN_WORD = re.compile(r"[A-Za-z][a-z]*\Z")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")
_TOKEN = re.compile(r"\S+")
_JOINERS = frozenset("/\\-_+")


def _class_of(c):
    return 0 if c.isdigit() else 1 if c.isupper() else 2


def random_text(body):
    """Whether letters and digits change class the way random text does and words do not: at least two classes, a class change
    in three characters of ten, and fewer than three characters to a word (a run of capitals, of small letters or of digits).
    Hex is a digest and left alone."""
    if _HEX_ONLY.match(body):
        return False
    classes = [_class_of(c) for c in body]
    if len(set(classes)) < 2:
        return False
    changes = sum(1 for a, b in zip(classes, classes[1:]) if a != b)
    return changes >= 0.3 * (len(body) - 1) and len(body) <= 3.0 * len(_UNITS.findall(body))


_SHORT_WORDS = frozenset("""usr lib bin etc var tmp opt dev src doc log web net app run mnt sys proc home root boot data temp user users local cache apps
    java node npm pip tar zip dll exe png jpg gif xml json html text file files info logs mail work test demo base core main test jump list db sql
    ntuser sam iis rpm deb sbin share man wine snap flat gnu msi cab ini cfg conf init""".split())


def _word(piece):
    """A plain word: letters with at most a leading capital, five or more of them, or three or four of a short list of the names
    directories have (random small letters of three or four are not a word)."""
    if _PLAIN_WORD.match(piece) is None:
        return False
    return len(piece) >= 5 or (len(piece) >= 3 and piece.lower() in _SHORT_WORDS)


def random_spans(f, minimum):
    """Spans of text that reads as random: a stretch of letters and digits of `minimum` or more (16 in a name or a path, 20 in a
    line of text), alone or as a window of the pieces between `/ \\ - _ +` (up to 64 letters and digits, none of them a plain word, so
    a key with a `/` in it is found and a path of words is not). A hit grows over its neighbours that are not words. Typed ids (a
    GUID, a package publisher id, the user folder of a Mac) are not judged."""
    spans = []
    for token in _TOKEN.finditer(f):
        text = token.group()
        if len(text) < minimum:
            continue
        runs = list(_ALNUM_RUN.finditer(text))
        if not runs or max(len(m.group()) for m in runs) < 4:
            continue                                              # a key is not made of pieces of one to three characters
        pieces = []                                              # (start, end, body) with body "" for a typed id
        for k, m in enumerate(runs):
            raw = m.group()
            gap_before = text[runs[k - 1].end():m.start()] if k else ""
            typed = (len(raw) == 13 and gap_before in ("_", "__") and re.fullmatch(r"[a-z0-9]{13}", raw) is not None
                     or len(raw) == 30 and k >= 2 and runs[k - 2].group() == "folders" and re.fullmatch(r"[a-z0-9]{30}", raw) is not None)
            pieces.append((m.start(), m.end(), "" if typed else raw))

        joins = [set(text[pieces[x][1]:pieces[x + 1][0]]) <= _JOINERS and pieces[x + 1][0] - pieces[x][1] <= 2 for x in range(len(pieces) - 1)]

        def joined(a, b):
            return all(joins[a:b])

        i = 0
        while i < len(pieces):
            body = pieces[i][2]
            hit = None
            if len(body) >= minimum and random_text(body):
                hit = i
            elif body and not _word(body):
                total, whole, j = len(body), body, i
                while j + 1 < len(pieces) and j - i < MAX_PIECES and joins[j]:
                    nxt = pieces[j + 1][2]
                    if not nxt or _word(nxt):
                        break
                    j += 1
                    total += len(nxt)
                    whole += nxt
                    if total > 64:
                        break
                    if total >= minimum and random_text(whole):
                        hit = j
                        break
            if hit is None:
                i += 1
                continue
            lo, hi = i, hit
            while lo > 0 and pieces[lo - 1][2] and not _word(pieces[lo - 1][2]) and joined(lo - 1, lo):
                lo -= 1
            while hi + 1 < len(pieces) and pieces[hi + 1][2] and not _word(pieces[hi + 1][2]) and joined(hi, hi + 1):
                hi += 1
            spans.append((token.start() + pieces[lo][0], token.start() + pieces[hi][1], KIND_RANDOM))
            i = hi + 1
    return spans


def _spans(f, allow, budget):
    """Every span of the (folded) text f that is withheld, as (start, end, kind)."""
    spans = []
    if _ANY_CHEAP.search(f):
        for kind, rx in SHAPES:
            has_secret = "secret" in rx.groupindex
            for m in rx.finditer(f):
                spans.append((m.start("secret"), m.end("secret"), kind) if has_secret else (m.start(), m.end(), kind))
        spans += _block_spans(f)
        if "@" in f:
            spans += _user_info_spans(f, budget)
        if "=" in f or ":" in f:
            spans += _named_spans(f)
        spans += _client_spans(f, budget)
        if "-" in f:
            spans += _option_spans(f)
    spans += random_spans(f, 16 if allow else 20)
    return spans


def _merge(spans):
    spans.sort()
    merged = []
    for s, e, kind in spans:
        if e <= s:
            continue
        if merged and s <= merged[-1][1]:
            if e > merged[-1][1]:
                merged[-1] = (merged[-1][0], e, merged[-1][2])
        else:
            merged.append((s, e, kind))
    return merged


def _scrub_out_of_time():
    return SCRUB_DEADLINE[0] is not None and time.monotonic() > SCRUB_DEADLINE[0]


def find_spans(text, allow):
    """The spans of `text` to withhold, in the coordinates of `text`. A text over SINGLE is judged in overlapping windows."""
    folded, index = fold_view(text)
    f = _blank_known(folded)
    budget = [MAX_CANDIDATES]
    found = []
    if len(f) <= SINGLE:
        found = _spans(f, allow, budget)
    else:
        found = _block_spans(f)
        pos = 0
        while pos < len(f):
            if _scrub_out_of_time():
                found.append((pos, len(f), "text over the scan budget"))
                break
            piece = f[pos:pos + WINDOW + OVERLAP]
            found += [(s + pos, e + pos, k) for s, e, k in _spans(piece, allow, budget)]
            pos += WINDOW
    found = _merge(found)
    if index is None:
        return found
    return _merge([(index[s], index[e - 1] + 1, k) for s, e, k in found if e > s])


def order_key(name):
    """What a name sorts by: the text as it is printed, without a finding id. A withheld name sorts by its marker (kind and length),
    so the position of a name among its siblings tells nothing about the text that was withheld."""
    return scrub(name, None, True, True)


_TIE_SALT = secrets.token_bytes(16)


def tie_key(name):
    """What breaks a tie between names that print the same: a keyed hash of the raw name under a salt drawn at the start of this run.
    It is not the listing order, the inode or the name's rank (a tree unpacked in name order has its inodes in name order too), and
    it is not the same in the next run, so no order of the answer, and no finding id handed out in that order, repeats between runs
    or tells which of two withheld names is the smaller. The cost: names that print alike come in an order drawn afresh each run."""
    return hashlib.blake2b(name.encode("utf-8", "backslashreplace"), key=_TIE_SALT, digest_size=8).digest()


def sort_key(name):
    return (order_key(name), tie_key(name))


def scrub(text, where=None, allow=False, dry=False):
    """The text with every string of a withheld shape replaced by a marker (a kind, a length, a finding id). With a values file
    open, the original goes there once, named by `where`. The same text always gets the same id and one row. `allow` is for a
    field that holds a name or a path: random-looking text of 16 characters or more is withheld in it, not only of 20."""
    if not isinstance(text, str) or len(text) < 6:
        return text
    if dry:
        spans = find_spans(text, allow)
        if not spans:
            return text
        pieces, last = [], 0
        for s, e, kind in spans:
            pieces.append(text[last:s])
            pieces.append("<%s withheld, %d characters>" % (kind, e - s))
            last = e
        pieces.append(text[last:])
        return "".join(pieces)
    key = (text, allow)
    known = _SEEN.get(key)
    if known is not None:
        return known
    spans = find_spans(text, allow)
    if not spans:
        _remember(key, text)
        return text
    fid = "W%06d" % (WITHHELD["count"] + 1)
    pieces, last = [], 0
    for s, e, kind in spans:
        pieces.append(text[last:s])
        if kind == "text over the scan budget":
            pieces.append("<text over the scan budget withheld, %d characters>" % (e - s))
        else:
            pieces.append("<%s withheld, %d characters, %s>" % (kind, e - s, fid))
        last = e
    pieces.append(text[last:])
    out = "".join(pieces)
    WITHHELD["count"] += 1
    if VALUES[0] is not None:
        VALUES[0].add(fid, {"where": where or "text"}, text)
    _remember(key, out)
    _remember((out, allow), out)                                # a text that is already judged is a fixed point
    return out


def _remember(key, out):
    """The judged texts, bounded by their characters: a run of long lines cannot grow the cache past a few MiB."""
    if len(key[0]) > (2 << 20):
        return
    if _SEEN_CHARS[0] > (8 << 20) or len(_SEEN) > 20000:
        _SEEN.clear()
        _SEEN_CHARS[0] = 0
    _SEEN[key] = out
    _SEEN_CHARS[0] += len(key[0]) + (len(out) if out is not key[0] else 0)


def shown(path, where=None):
    """A name or a path as it may be printed: the whole string goes through scrub with the 16-character floor of a name."""
    return scrub(path, where, True)


class Listed:
    """One entry of a directory, kept as its name and its directory only (a listing of 200,000 entries is a few tens of MiB)."""
    __slots__ = ("name", "path")

    def __init__(self, name, directory):
        self.name = name
        self.path = os.path.join(directory, name)

    def stat(self, follow_symlinks=True):
        return os.stat(self.path, follow_symlinks=follow_symlinks)


class SortedListing:
    def __init__(self, directory, keyed):
        self.directory, self.keyed = directory, keyed

    def __len__(self):
        return len(self.keyed)

    def __iter__(self):
        for _key, _inode, name in self.keyed:
            yield Listed(name, self.directory)


def list_sorted(directory):
    """The entries of a directory in the order of what is printed (order_key) and then of tie_key, so the position of an entry
    tells nothing about a withheld name. Only (key, tie, name) is held per entry."""
    keyed = []
    with os.scandir(directory) as it:
        for entry in it:
            keyed.append((order_key(entry.name), tie_key(entry.name), entry.name))
    keyed.sort(key=lambda item: (item[0], item[1]))
    return SortedListing(directory, keyed)


def inline_text(text, limit=256):
    """A path as an inline list shows it: its first `limit` characters and its length. The whole is in the table the answer names,
    so nothing is lost; a list of long paths cannot push the summary out of the first 64 KiB the model reads."""
    if not isinstance(text, str) or len(text) <= limit:
        return text
    return text[:limit] + "<... %d characters in all; the whole is in the table>" % len(text)


# ---- the serialisation boundary and the independent check ----------------------------------------------------------------
# Everything the tool prints and every row it writes to a table file passes release() / row_out(): the withholding above is
# applied to EVERY key and value of the structure, so a field nobody listed is covered, and the structure is then read once more
# by the check below, which is written apart from it (its own normaliser by Unicode category, its own named-secret scan, token
# prefixes, user-info scan, long digit runs, PEM markers and class-run measure of random text; it calls nothing of the withholding
# above). A string it finds suspect is replaced by <withheld: N bytes> and counted; the answer then says so and is partial.
# The check judges by shape as well and has its own misses (documented in the manifest); it is a second wall, not a proof.
# [Local to this pack. It is meant to be replaced by the pack-wide reference block; keep it in this one marked block, identical in
# every tool.]

BOUNDARY = {"replaced": 0, "by": {}, "where": [], "not_listed": 0}
MAX_REPLACED_LISTED = 25
OWN_SHOWN = set()                  # names of files this run made and shows (random names, nothing in them is evidence)
TYPED_FIELDS = {"modified_epoch_ns": r"[0-9]{1,24}", "sha256": r"[0-9a-f]{64}", "sha256_of_bytes_read": r"[0-9a-f]{64}", "sha1": r"[0-9a-f]{40}", "md5": r"[0-9a-f]{32}"}
_B_MARK = re.compile(r"<[A-Za-z][A-Za-z -]{2,60} withheld, [0-9]+ characters, W[0-9]{6}>|<withheld: [0-9]+ bytes>"
                     r"|<withheld: an integer of [0-9]+ bits>|<text over the scan budget withheld, [0-9]+ characters>")
_B_PLAIN = re.compile(r"[\x20-\x7e]*")
_B_DROP = frozenset(("Cc", "Cf", "Mn", "Me", "Cs", "Co", "Cn", "Zl", "Zp"))
_B_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|%([0-9a-fA-F]{2})")


def _b_fold(text):
    """The text as a reader sees it: no control, format, combining, private or unassigned character (so NUL, zero-width, bidi,
    variation selectors and the NULs of UTF-16 read as 8-bit all vanish), spaces of every kind one space, compatibility forms
    (full-width, ligatures) folded."""
    if _B_PLAIN.fullmatch(text):
        return text
    out = []
    for ch in text:
        if ch == "\n":
            out.append(ch)
            continue
        if ch < " " or ch == "\x7f":
            if ch == "\t" or ch == "\r":
                out.append(" ")
            continue
        category = unicodedata.category(ch)
        if category in _B_DROP:
            continue
        if category == "Zs":
            out.append(" ")
        elif ord(ch) > 127:
            out.append(unicodedata.normalize("NFKC", ch))
        else:
            out.append(ch)
    return "".join(out)


def _b_unescape(text):
    def one(m):
        value = int(m.group(1) or m.group(2) or m.group(3), 16)
        return chr(value) if 0x21 <= value < 0x7f else m.group(0)
    return _B_ESCAPE.sub(one, text)


_B_PEM = re.compile(r"-----\s*(?:BEGIN|END)[A-Z ]*PRIVATE KEY|PRIVATE KEY BLOCK|PuTTY-User-Key-File", re.I)
_B_PREFIX = re.compile(
    r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA|ABIA|ACCA)[A-Z0-9]{14}|gh[pousr]_[A-Za-z0-9]{20}|github_pat_[A-Za-z0-9_]{20}|glpat-[A-Za-z0-9_-]{16}"
    r"|xox[a-z]-[A-Za-z0-9-]{14}|xapp-[A-Za-z0-9-]{14}|dop_v1_[A-Za-z0-9]{14}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{14}|AIza[A-Za-z0-9_-]{20}|ya29\.[A-Za-z0-9_.-]{16}"
    r"|(?<![A-Za-z0-9])(?:npm_|pypi-|shpat_|shpss_|hf_)[A-Za-z0-9_-]{14}|(?<![A-Za-z0-9])SG\.[A-Za-z0-9_.-]{16}"
    r"|(?<![A-Za-z0-9])sk-(?=[A-Za-z0-9_-]{0,40}[0-9])[A-Za-z0-9_-]{20}"
    r"|eyJ[A-Za-z0-9_-]{8}|SK[0-9a-f]{32}|1//0[A-Za-z0-9_-]{20}|hooks\.slack\.com/services/", re.I)
_B_DIGITS = re.compile(r"[0-9]{19}|(?<![0-9])[0-9]{6}(?:[-_. ]?[0-9]{6}){7}(?![0-9])")
_B_PADDED = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{15,}={1,2}(?![A-Za-z0-9+=])")
_B_RUN = re.compile(r"[A-Za-z0-9+/_=-]{20,}")
_B_HEXISH = re.compile(r"[0-9A-Fa-f]+")
_B_ID = re.compile(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|S-1-[0-9]+(?:-[0-9]+)+|/var/folders/[a-z0-9_]{2}/[a-z0-9_]{30}(?=/|$)")
_B_OPTION = re.compile(r"(?<![\w-])--?(?:pass(?:word|wd|phrase)?|pwd|secret|token|api-?key|client-secret|access-?key)(?:=|[ \t]+)[^\s=-]", re.I)
_B_CLIENT = re.compile(r"(?:mysql|mariadb)\w*[^\n]{0,200}?\s-p\S|sshpass[^\n]{0,200}?\s-p\s*\S"
                       r"|(?<![\w-])(?:-[uU]|--user)(?:=|[ \t]+)[^\s:%]{1,64}[:%]\S", re.I)
_B_DELIM = re.compile(r"[=:]")
_B_NAMECH = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_B_STRONG = ("password", "passwd", "passphrase", "pwd", "secret", "token", "credential", "apikey", "api_key", "api-key", "accesskey", "access_key",
             "access-key", "accountkey", "account_key", "privatekey", "private_key", "masterkey", "master_key", "signingkey", "sharedkey", "shared_key",
             "authorization", "cookie")
_B_WEAK = ("pass", "pw", "auth", "sig", "sas")
_B_NOT_WEAK = ("bypass", "compass", "overpass", "underpass", "trespass", "surpass", "impass", "encompass")
_B_FILE_ENDINGS = frozenset("png jpg jpeg gif svg webp ico bmp tif tiff heic plist json txt log db dat xml htm html css js py exe dll lnk".split())


def _b_named_secret(flat):
    """A name that says it is a secret right before an `=` or a `:` that has a value after it. The name is the run of name
    characters that ends at the delimiter (read backwards from it, at most 64 characters), so a prefix glued to it or joined
    with `_` does not matter: DB_PASSWORD=, adminPassword=, X-Api-Key:."""
    size = len(flat)
    for m in _B_DELIM.finditer(flat):
        i = m.start()
        j = i + 1
        while j < size and j - i <= 5 and flat[j] in " \t\"'\\":
            j += 1
        if j >= size or flat[j] in "<>\n" or flat.startswith("//", j):
            continue
        k = i
        while k > 0 and i - k < 5 and flat[k - 1] in " \t\"'\\":
            k -= 1
        n = k
        while n > 0 and k - n < 64 and flat[n - 1] in _B_NAMECH:
            n -= 1
        low = flat[n:k].lower()
        for form in (low, low[:-1] if low.endswith("s") else low):
            if form.endswith(_B_STRONG):
                return True
            if form.endswith(_B_WEAK) and not form.endswith(_B_NOT_WEAK):
                return True
    return False


def _b_user_info(flat):
    """user:password@host, with a password that may hold / ? # or @: for each `@` look back to the last `:` within 256 characters."""
    pos = 0
    while True:
        at = flat.find("@", pos)
        if at < 0:
            return False
        pos = at + 1
        host = flat[at + 1:at + 80]
        run = re.match(r"[A-Za-z0-9][A-Za-z0-9.-]*", host)
        if not run:
            continue
        colon = flat.rfind(":", max(0, at - 256), at)
        if colon <= 0 or colon + 1 >= at:
            continue
        name = re.search(r"[A-Za-z0-9._%+-]{0,64}$", flat[max(0, colon - 64):colon])
        secret = flat[colon + 1:at]
        if "\n" in secret or " " in secret or "\\" in secret:
            continue
        name_start = colon - len(name.group())
        if not name.group() and flat[max(0, colon - 2):colon] != "//":
            continue
        after_scheme = flat[max(0, name_start - 2):name_start] == "//"
        labels = run.group().rstrip(".").split(".")
        dotted_ip = len(labels) == 4 and all(x.isdigit() for x in labels)
        real_host = any(x.isalpha() and len(x) >= 2 and x.lower() not in _B_FILE_ENDINGS for x in labels[1:])
        if after_scheme or dotted_ip or real_host:
            return True


def _b_class(ch):
    return 0 if ch.isdigit() else 1 if ch.isupper() else 2


_B_LOWWORD = re.compile(r"[a-z]{3,}")


def _b_long_lower(body):
    """The share of a text that sits in runs of three or more small letters: high in words, low in random letters and digits."""
    return sum(len(m.group()) for m in _B_LOWWORD.finditer(body)) / len(body)


def _b_random_body(body):
    """Whether letters and digits change class the way random text does: the mean length of the runs of one class is short and
    not many letters sit in words."""
    if len(body) < 20 or _B_HEXISH.fullmatch(body):
        return False
    classes = [_b_class(c) for c in body]
    if len(set(classes)) < 2:
        return False
    runs = 1 + sum(1 for a, b in zip(classes, classes[1:]) if a != b)
    return len(body) / runs <= 2.25 and _b_long_lower(body) <= 0.5


def _b_random_run(run):
    """A run of 20 or more characters of letters, digits and `/ _ + = -`: each piece between the separators alone, and every window
    of whole pieces up to 64 letters and digits in which no piece reads as a word (a key with a `/` in it is two pieces)."""
    pieces = [p for p in re.split(r"[/_+=-]+", run) if p]
    if not pieces or max(map(len, pieces)) < 4:
        return False
    for i in range(len(pieces)):
        if _b_random_body(pieces[i]):
            return True
        total = len(pieces[i])
        for j in range(i + 1, min(len(pieces), i + 12)):
            total += len(pieces[j])
            if total > 64:
                break
            if all(len(x) < 4 or _b_long_lower(x) <= 0.5 for x in pieces[i:j + 1]) and total >= 20 and _b_random_body("".join(pieces[i:j + 1])):
                return True
    return False


def _b_suspect(text):
    """The name of the check a string fails, or None."""
    if not text or len(text) < 6:
        return None
    for shown_name in OWN_SHOWN:
        if shown_name in text:
            text = text.replace(shown_name, " ")
    flat = _B_MARK.sub(" ", _b_fold(text))
    for form in ((flat, _b_unescape(flat)) if ("%" in flat or "\\" in flat) else (flat,)):
        if _B_PEM.search(form):
            return "a private-key marker"
        if _b_named_secret(form) or _B_OPTION.search(form) or _B_CLIENT.search(form):
            return "a named secret"
        if _B_PREFIX.search(form):
            return "a token prefix"
        stripped = _B_ID.sub(" ", form)
        if _B_DIGITS.search(stripped):
            return "a long digit run or a recovery-password shape"
        if _b_user_info(form):
            return "user-info"
        if _B_PADDED.search(stripped):
            return "padded base64"
        for run in _B_RUN.findall(stripped):
            if _b_random_run(run):
                return "a random-looking run"
    return None


_B_CACHE = {}
_B_CACHE_CHARS = [0]


def _b_verdict(text):
    known = _B_CACHE.get(text, False)
    if known is not False:
        return known
    try:
        reason = _b_suspect(text)
    except Exception:                              # a check that cannot judge fails closed (a signal's SystemExit is not swallowed)
        reason = "a string the check could not judge"
    if len(text) <= (2 << 20):
        if _B_CACHE_CHARS[0] > (8 << 20) or len(_B_CACHE) > 20000:
            _B_CACHE.clear()
            _B_CACHE_CHARS[0] = 0
        _B_CACHE[text] = reason
        _B_CACHE_CHARS[0] += len(text)
    return reason


def _b_replace(size, where, reason):
    BOUNDARY["replaced"] += 1
    BOUNDARY["by"][reason] = BOUNDARY["by"].get(reason, 0) + 1
    if len(BOUNDARY["where"]) < MAX_REPLACED_LISTED:
        BOUNDARY["where"].append({"at": where or "/", "check": reason})
    else:
        BOUNDARY["not_listed"] += 1
    return "<withheld: %d bytes>" % size


def _b_size(text):
    return len(text.encode("utf-8", "surrogatepass"))


def backstop(value, where="", key=None):
    """The structure read back and checked: a key or a string value the check finds suspect is replaced by <withheld: N bytes>, a
    huge integer by its size; the place is named by its top-level key and its indexes, never by an evidence-derived key."""
    if isinstance(value, str):
        pattern = TYPED_FIELDS.get(key)
        if pattern and re.fullmatch(pattern, value):
            return value
        reason = _b_verdict(value)
        return _b_replace(_b_size(value), where, reason) if reason else value
    if isinstance(value, int) and not isinstance(value, bool):
        if value.bit_length() > 63 and key not in TYPED_FIELDS:
            _b_replace(0, where, "a very large integer")
            return "<withheld: an integer of %d bits>" % value.bit_length()
        return value
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            child = k if (not where and isinstance(k, str) and re.fullmatch(r"[a-z][a-z_]{0,40}", k)) else "*"
            new_key = backstop(k, "%s/(key)" % where, None) if isinstance(k, str) else k
            while new_key in out:
                new_key = "%s #" % new_key
            out[new_key] = backstop(v, "%s/%s" % (where, child) if where else child, k if isinstance(k, str) else None)
        return out
    if isinstance(value, list):
        return [backstop(v, "%s/%d" % (where, i)) for i, v in enumerate(value)]
    return value


def row_out(row, tool=""):
    """A table row on its way to its page and its file: the withholding on every key and value, then the check."""
    return backstop(scrub_all(json.loads(json.dumps(row, default=str))), tool)


def release(doc):
    """The final answer: normalised to what JSON carries, the withholding on every key and value, the check, and the account of
    what the check had to replace. A complete answer is partial when it replaced anything."""
    SCRUB_DEADLINE[0] = time.monotonic() + 120                  # the final answer is judged whatever the run's clock says
    doc = backstop(scrub_all(json.loads(json.dumps(doc, default=str))), "")
    values = VALUES[0]
    if values is not None:                     # a string first judged here is a finding too: it goes to the values file, then the file is closed
        if isinstance(doc, dict) and isinstance(doc.get("withheld"), dict):
            doc["withheld"] = {"strings_withheld": WITHHELD["count"], "values": values.summary()}
        values.close()
    if BOUNDARY["replaced"] and isinstance(doc, dict):
        note = {"strings_replaced_by_the_check": BOUNDARY["replaced"], "by_check": dict(BOUNDARY["by"]), "replaced_at": list(BOUNDARY["where"]),
                "replaced_not_listed": BOUNDARY["not_listed"],
                "note": "every key and value of this answer and of its table files was withheld by shape, then read back by a second check written "
                        "apart from the first; a string the second check found suspect is <withheld: N bytes> and its place is in replaced_at"}
        out = {}
        for k, v in doc.items():
            out[k] = v
            if k == "status_basis":
                out["boundary"] = note
        if "boundary" not in out:
            out["boundary"] = note
        if out.get("status") == "complete":
            out["status"] = "partial"
            out["status_basis"] = "%s; %d string(s) held a secret-shaped text that the first withholding missed and were replaced at the output boundary (see boundary)" % (
                out.get("status_basis") or "every directory was listed", BOUNDARY["replaced"])
        doc = out
    return doc


def write_answer(doc):
    print(json.dumps(release(doc), indent=2, default=str))


# ---- what a delivery may hold besides copied files ---------------------------------------------------------------------

DISK_SIGNATURES = [
    (0, b"EVF\x09\x0d\x0a\xff\x00", "disk_container", "EnCase evidence file (EWF, E01 family)"),
    (0, b"EVF2\x0d\x0a\x81\x00", "disk_container", "EnCase evidence file version 2 (Ex01)"),
    (0, b"QFI\xfb", "disk_container", "QCOW disk image"),
    (0, b"KDMV", "disk_container", "VMware sparse extent (VMDK)"),
    (0, b"# Disk DescriptorFile", "disk_container", "VMware VMDK descriptor"),
    (0, b"vhdxfile", "disk_container", "VHDX virtual disk"),
    (0, b"conectix", "disk_container", "VHD virtual disk (dynamic or differencing: the footer is repeated at the start)"),
    (0, b"<<< Oracle VM VirtualBox Disk Image >>>", "disk_container", "VirtualBox VDI"),
    (0, b"LVF\x09\x0d\x0a\xff\x00", "archive", "EnCase logical evidence file (L01)"),
    (0, b"ADSEGMENTEDFILE\x00", "archive", "AccessData AD1 logical image"),
    (0, b"ADCRYPT", "archive", "AccessData AD1 logical image, encrypted"),
    (0, b"PK\x03\x04", "archive", "ZIP"),
    (0, b"PK\x05\x06", "archive", "ZIP (empty)"),
    (0, b"7z\xbc\xaf\x27\x1c", "archive", "7-Zip"),
    (0, b"Rar!\x1a\x07", "archive", "RAR"),
    (0, b"\x1f\x8b", "archive", "gzip"),
    (0, b"BZh", "archive", "bzip2"),
    (0, b"\xfd7zXZ\x00", "archive", "xz"),
    (0, b"\x28\xb5\x2f\xfd", "archive", "Zstandard"),
    (257, b"ustar", "archive", "tar"),
    (0, b"EMiL", "memory_capture", "LiME memory capture"),
    (0, b"PAGEDU64", "memory_capture", "Windows crash dump (what it holds depends on the dump type, which is not read here)"),
    (0, b"PAGEDUMP", "memory_capture", "Windows crash dump (what it holds depends on the dump type, which is not read here)"),
]
RAW_SIGNATURES = [
    (512, b"EFI PART", "a GPT header at offset 512"),
    (3, b"NTFS    ", "an NTFS boot sector (OEM id at offset 3)"),
    (3, b"EXFAT   ", "an exFAT boot sector (OEM id at offset 3)"),
    (3, b"-FVE-FS-", "a BitLocker volume header (OEM id at offset 3)"),
    (82, b"FAT32   ", "a FAT32 boot sector (type string at offset 82)"),
    (0, b"LUKS\xba\xbe", "a LUKS header"),
    (0, b"XFSB", "an XFS superblock"),
    (32, b"NXSB", "an APFS container superblock (offset 32)"),
]
DISK_EXT = {".e01", ".ex01", ".dd", ".raw", ".img", ".vhd", ".vhdx", ".vmdk", ".qcow2", ".qcow", ".vdi", ".001"}
RAW_EXT = {".dd", ".raw", ".img", ".bin", ".001", ""}
MEMORY_EXT = {".mem", ".vmem", ".vmss", ".lime"}
ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".bz2", ".xz", ".zst", ".ad1", ".l01", ".aff4"}
SEGMENT_EXT = re.compile(r"^\.(?:e|ex|s|l)\d\d$|^\.\d{3}$|^\.ad\d+$")      # E02, Ex02, S01, L02, .002, .ad2: a later segment of a set
# First bytes of files that are plainly not a disk or a memory capture, whatever their name says.
NOT_A_CONTAINER = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF8", b"SQLite format 3\x00", b"%PDF-", b"II*\x00", b"MM\x00*", b"<?xml", b"{\\rtf")


def is_image_named(ext):
    return ext in DISK_EXT or bool(SEGMENT_EXT.match(ext))


def wants_head(name, size, top_level):
    """Whether a file's first bytes are read to classify it: a top-level object, a file named like an image, a memory
    capture or an archive, and any file of at least MIN_RAW_BYTES (a renamed image is large). The rest are copied files."""
    ext = os.path.splitext(name)[1].lower()
    return top_level or is_image_named(ext) or ext in MEMORY_EXT or ext in ARCHIVE_EXT or size >= MIN_RAW_BYTES


def open_regular(path, **kw):
    """A regular file opened for reading as text without following a link at its name and without blocking on a pipe: a
    log that was swapped for a link or a pipe after the walk is refused, not read."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        return os.fdopen(fd, "r", **kw)
    except BaseException:
        os.close(fd)
        raise


def read_head(path):
    """The first HEAD_BYTES of a regular file, opened without following a link and without blocking on a pipe; None for
    anything that is not a regular file once opened."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, HEAD_BYTES)
    finally:
        os.close(fd)


def classify_head(name, head, size, top_level):
    """What a file is, from its first bytes and its name, or None when it is an ordinary file. The answer says which
    (`basis`: bytes, or extension only), and what in the bytes it rests on. A raw image has no container header: its
    volume or partition signatures are looked for in a file named like an image of at least MIN_RAW_BYTES. A name that says
    image, raw or memory with nothing in the bytes to confirm it is `unknown` at the top of the delivery: a raw memory capture
    carries no signature either. Below the top, a file under MIN_RAW_BYTES named like one, or whose bytes are plainly something
    else (a PNG, a database), is a copied file. An archive signature counts only on a file named like an archive, or on a
    top-level file with no extension (a .docx is a ZIP and is a document)."""
    ext = os.path.splitext(name)[1].lower()
    for offset, magic, kind, fmt in DISK_SIGNATURES:
        if kind == "archive" and ext not in ARCHIVE_EXT and not SEGMENT_EXT.match(ext) and not (top_level and ext == ""):
            continue
        if head[offset:offset + len(magic)] == magic:
            return {"class": kind, "format": fmt, "basis": "bytes", "evidence": "signature at offset %d" % offset}
    if head[:4] == b"\x7fELF" and len(head) > 17 and head[5] in (1, 2):
        etype = int.from_bytes(head[16:18], "little" if head[5] == 1 else "big")
        if etype == 4:
            return {"class": "memory_capture", "format": "ELF core dump (one process, or a kernel core)", "basis": "bytes",
                    "evidence": "ELF header, type core"}
    named_image = is_image_named(ext)
    if (ext in RAW_EXT or named_image) and size >= MIN_RAW_BYTES:
        seen = [what for offset, magic, what in RAW_SIGNATURES if head[offset:offset + len(magic)] == magic]
        if len(head) >= 512 and head[510:512] == b"\x55\xaa":
            seen.append("a boot signature at offset 510 (an MBR, or a FAT or NTFS boot sector)")
        if len(head) > 1082 and head[1080:1082] == b"\x53\xef":
            seen.append("an ext superblock magic at offset 1080")
        if seen:
            return {"class": "disk_container", "format": "raw image (no container header)", "basis": "bytes",
                    "evidence": "; ".join(seen) + ". Whether it is a whole disk or one volume is not decided here"}
    if (named_image or ext in MEMORY_EXT) and (head.startswith(NOT_A_CONTAINER) or (not top_level and size < MIN_RAW_BYTES)):
        return None
    if ext in MEMORY_EXT:
        return {"class": "memory_capture", "format": "named like a memory capture (no signature to confirm it)",
                "basis": "extension only", "evidence": "name ends %s" % ext}
    if named_image:
        looked = ("and no partition table or volume signature in the first sectors" if size >= MIN_RAW_BYTES
                  else "(the file is under %d bytes: volume signatures were not looked for)" % MIN_RAW_BYTES)
        return {"class": "unknown", "format": None, "basis": "extension only",
                "evidence": "name ends %s but the first bytes carry no recognised container signature %s; a raw memory capture and "
                            "a raw disk with an unusual first sector both look like this" % (ext, looked)}
    if ext in ARCHIVE_EXT or SEGMENT_EXT.match(ext):
        return {"class": "archive", "format": "named like an archive (no signature to confirm it)", "basis": "extension only",
                "evidence": "name ends %s" % ext}
    return None
# ---- END SHARED BLOCK ------------------------------------------------------------------------------------------------

import csv
import json
import os
import re
import stat

PARSER = "collection_id/3"
TOOL = "collection_id"
VALUES_NAME = "collection-id-values.jsonl"
KNOWN_PARAMETERS = ("root", "limit", "time_limit_seconds", "write_values")
MAX_LINE = 1 << 20                # a log line longer than this is read in part; the whole line stays in the evidence at its locator
MAX_CONSECUTIVE_CSV_ERRORS = 1000
MAX_DISTINCT = 100000             # distinct names counted from a log; beyond it they are counted, not named

FAMILIES = {
    "$mft": "the NTFS master file table", "$j": "the USN change journal", "$logfile": "the NTFS transaction log",
    "system": "the SYSTEM hive", "software": "the SOFTWARE hive", "sam": "the SAM hive", "security": "the SECURITY hive",
    "ntuser.dat": "a user hive", "usrclass.dat": "a shell-bag hive", "amcache.hve": "Amcache", "srudb.dat": "SRUM",
    "consolehost_history.txt": "PowerShell history",
    "auth.log": "a Linux authentication log", "secure": "a Linux authentication log",
    "wtmp": "Linux login records", "btmp": "Linux failed logins",
    "packages.xml": "the Android package list", "manifest.db": "an iOS backup manifest",
    "hiberfil.sys": "the hibernation file (a file named like one: memory-bearing, not a capture)",
    "pagefile.sys": "the page file (a file named like one: memory-bearing, not a capture)",
    "swapfile.sys": "the swap file (a file named like one: memory-bearing, not a capture)",
}
MEMORY_BEARING = ("hiberfil.sys", "pagefile.sys", "swapfile.sys")
INSIDE_COLLECTED = ("[root]", "uploads")        # a directory below which the files are the source host's own
UAC_EVENT = re.compile(r"^\s*\[?(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s?(?:Z|[+-]\d{2}:?\d{2}))?)\]?\s*"
                       r"(?:[-:|]\s*)?\[?(?P<level>INFO|INF|WARNING|WARN|ERROR|ERR|COMMAND|CMD|DEBUG|DBG)\]?(?:\s|:|$)")
UAC_ERROR_LEVELS = ("ERROR", "ERR")
UAC_COMMAND_LEVELS = ("COMMAND", "CMD")
UAC_FAILURE_WORDS = ("error", "cannot", "permission denied", "failed", "no such file")
CONSOLE_LINE = re.compile(r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) \| (?P<level>[A-Z]{3})\] ")
SKIP_TARGET_COLUMNS = ("sourcefile", "source", "filename", "file", "path")
SKIP_REASON_COLUMNS = ("reason", "message", "error", "status")
UPLOAD_TARGET_KEYS = ("Path", "StoredName", "vfs_path")
UPLOAD_MARKERS = ("StoredName", "UploadId", "StoredSize", "Components")
LOG_LEVEL_WORDS = ("TRACE", "DEBUG", "DEFAULT", "INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL")


class Survey:
    def __init__(self, root, limit, problems):
        self.root = root
        self.prefix = root.rstrip(os.sep) + os.sep
        self.directories = self.files = 0
        self.links, self.special, self.errors = [], [], []
        self.links_total = self.special_total = self.errors_total = 0
        self.stopped = None
        self.families = {}
        self.memory_bearing = []
        self.kape = {}                        # (directory, run id) -> {"copy": rel, "skip": rel, "console": rel}
        self.uac_logs, self.uac_dirs = [], []
        self.velociraptor = {}                # directory -> {"uploads": rel, "context": rel}
        self.collected_data_logs = []
        self.layout_clues = []
        self.counts = {"disk_container": 0, "memory_capture": 0, "archive": 0, "unknown": 0, "unknown_nested": 0}
        self.other_files = self.tree_files = 0
        self.nested_archives = 0
        self.reads_head = 0
        self.head_errors = 0
        self.objects = Table(TOOL + "-objects", limit)
        self.problems = problems

    def rel(self, path):
        return path[len(self.prefix):] if path.startswith(self.prefix) else os.path.relpath(path, self.root)

    def problem(self, kind, path, what, exc=None, inline=None):
        row = {"kind": kind, "path": shown(path, kind), "what": what}
        if exc is not None:
            row["error"] = describe(exc)
        self.problems.add(row)
        if inline is not None and len(inline) < FIRST_PROBLEMS:
            inline.append({k: (inline_text(v) if k == "path" else v) for k, v in row.items() if k != "kind"})


def walk(survey):
    root = survey.root
    stack = [root]
    while stack:
        if out_of_time():
            survey.stopped = {"reason": "the time limit ended the walk", "directories_not_listed": len(stack)}
            return
        directory = stack.pop()
        is_top = directory == root
        try:
            entries = list_sorted(directory)
        except OSError as exc:
            survey.errors_total += 1
            survey.problem("walk_error", survey.rel(directory), "the directory could not be listed", exc, survey.errors)
            continue
        survey.directories += 1
        subdirs = []
        for position, entry in enumerate(entries):
            if out_of_time():
                survey.stopped = {"reason": "the time limit ended the walk", "directories_not_listed": len(stack) + len(subdirs),
                                  "entries_not_examined_in_the_current_directory": len(entries) - position}
                return
            if is_own(entry):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                survey.errors_total += 1
                survey.problem("walk_error", survey.rel(entry.path), "the entry could not be examined", exc, survey.errors)
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                survey.links_total += 1
                survey.problem("symbolic_link", survey.rel(entry.path), "a symbolic link: not followed", None, survey.links)
                if entry.name == "[root]":
                    survey.uac_dirs.append(survey.rel(entry.path))
            elif stat.S_ISDIR(mode):
                subdirs.append(entry.path)
                if entry.name == "[root]":
                    survey.uac_dirs.append(survey.rel(entry.path))
                if is_top and entry.name.lower() in ("c", "c$", "windows"):
                    survey.layout_clues.append({"path": shown(entry.name, "layout clue"), "basis": "a top-level directory name",
                                                "compatible_with": ["a KAPE target tree", "CyLR output", "a hand-made copy"]})
            elif stat.S_ISREG(mode):
                survey.files += 1
                handle_file(survey, entry, st, is_top)
            else:
                survey.special_total += 1
                survey.problem("special_file", survey.rel(entry.path), "not a regular file: not read", None, survey.special)
        stack.extend(reversed(subdirs))


def inside_collected_data(rel):
    return any(part in INSIDE_COLLECTED for part in rel.split(os.sep)[:-1])


def handle_file(survey, entry, st, is_top):
    name = entry.name
    lower = name.lower()
    rel = survey.rel(entry.path)
    if lower in FAMILIES:
        fam = survey.families.setdefault(FAMILIES[lower], {"count": 0, "first_paths": []})
        fam["count"] += 1
        if len(fam["first_paths"]) < 3:
            fam["first_paths"].append(shown(rel, "artefact family path"))
        if lower in MEMORY_BEARING:
            survey.memory_bearing.append(lower)
    marker = None
    for suffix, key in (("_copylog.csv", "copy"), ("_skiplog.csv", "skip"), ("_consolelog.txt", "console")):
        if lower.endswith(suffix):
            marker = ("kape", key, name[:-len(suffix)])
    if name == "uac.log":
        marker = ("uac", None, None)
    if name in ("uploads.json", "collection_context.json"):
        marker = ("velociraptor", "uploads" if name == "uploads.json" else "context", None)
    if marker is not None:
        if inside_collected_data(rel):
            survey.collected_data_logs.append(shown(rel, "log inside collected data"))
            survey.problem("log_inside_collected_data", rel, "a collector record inside collected data: it belongs to the source host, "
                           "not to this delivery, and is not read")
        elif marker[0] == "kape":
            survey.kape.setdefault((os.path.dirname(rel), marker[2]), {})[marker[1]] = rel
        elif marker[0] == "uac":
            survey.uac_logs.append(rel)
        else:
            survey.velociraptor.setdefault(os.path.dirname(rel), {})[marker[1]] = rel
    if wants_head(name, st.st_size, is_top):
        survey.reads_head += 1
        try:
            head = read_head(entry.path)
        except OSError as exc:
            survey.head_errors += 1
            survey.errors_total += 1
            survey.problem("walk_error", rel, "the first bytes could not be read", exc, survey.errors)
            head = None
        found = classify_head(name, head, st.st_size, is_top) if head is not None else None
        if found:
            kind = found["class"]
            if kind == "archive" and not is_top:
                survey.nested_archives += 1
                survey.other_files += 1
                survey.tree_files += 1
                return
            survey.counts["unknown_nested" if kind == "unknown" and not is_top else kind] += 1
            survey.objects.add({"path": shown(rel, "object path"), "top_level": is_top, "bytes": st.st_size, **found,
                                "note": "classified by this tool from the first bytes and the name; the object was not opened"})
            return
    survey.other_files += 1
    if os.sep in rel:
        survey.tree_files += 1


# ---- the collectors' own records ---------------------------------------------------------------------------------------


def open_text(path):
    return open_regular(path, encoding="utf-8-sig", errors="surrogateescape", newline="")


def undecodable(text):
    return any("\udc80" <= c <= "\udcff" for c in text)


def binary_reason(path):
    """Why a log cannot be read as UTF-8 text at all (a UTF-16 byte-order mark, or NUL bytes in its first 4 KiB), or None."""
    try:
        head = read_head(path)
    except OSError:
        return None
    if head is None:
        return None
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "the file is UTF-16 (byte-order mark): it is not read as UTF-8 text"
    if b"\x00" in head:
        return "the file holds NUL bytes in its first 4 KiB: it is binary or UTF-16 without a mark, and is not read as text"
    return None


def new_record(survey, rel, kind, adapter):
    return {"log": shown(rel, "log path"), "kind": kind, "adapter": adapter, "status": "parsed", "rows": 0, "problems": []}


def note_problem(survey, record, row):
    if len(record["problems"]) < FIRST_PROBLEMS:
        record["problems"].append(row)
    survey.problems.add({"kind": "log_problem", "path": record["log"], "what": "a row or line of a collector's log that was not read as recognised", **row})


def read_csv_log(survey, rel, kind, failures, unrecognised):
    """A KAPE copy or skip log, streamed. A skip-log row is kept whole as a failure row with the collector's own words; a copy
    log is counted. Columns that are not the ones expected make the log `partial` (the rows go to the unrecognised-rows table,
    never to the failures), and a log that is binary, UTF-16 or unreadable `unsupported` or `unreadable`."""
    path = os.path.join(survey.root, rel)
    record = new_record(survey, rel, kind, "kape_csv/2")
    record.update(malformed_rows=0, rows_with_undecodable_bytes=0)
    reason = binary_reason(path)
    if reason:
        record.update(status="unsupported", reason=reason)
        return record
    try:
        fh = open_text(path)
    except OSError as exc:
        record.update(status="unreadable", reason=describe(exc))
        return record
    with fh:
        reader = csv.reader(fh, strict=True)
        try:
            header = next(reader)
        except StopIteration:
            record.update(status="unsupported", reason="the file is empty: no header row")
            return record
        except (csv.Error, OSError) as exc:
            record.update(status="unsupported", reason="the header row could not be read (%s)" % describe(exc))
            return record
        names = [h.strip() for h in header]
        lowered = [n.lower() for n in names]
        record["columns"] = [scrub(n, "csv header") for n in names]
        target_col = next((i for i, n in enumerate(lowered) if n in SKIP_TARGET_COLUMNS), None)
        reason_col = next((i for i, n in enumerate(lowered) if n in SKIP_REASON_COLUMNS), None)
        recognised = True
        if kind == "copy_log":
            if "sourcefile" not in lowered:
                recognised = False
                record.update(status="partial", reason="no SourceFile column: rows are counted, nothing else is read")
        elif target_col is None and reason_col is None:
            recognised = False
            record.update(status="partial", reason="neither a target column nor a reason column is recognised: every row is kept whole "
                          "in the unrecognised rows, and none is a failure")
        ordinal, consecutive = 0, 0
        while True:
            if out_of_time():
                record.update(status="partial", reason="the time limit stopped the read after row %d" % ordinal)
                break
            start_line = reader.line_num + 1                 # a record can span lines (a quoted newline): its locator is the line it starts on
            try:
                row = next(reader)
            except StopIteration:
                break
            except csv.Error as exc:
                record["malformed_rows"] += 1
                consecutive += 1
                note_problem(survey, record, {"locator": {"line": start_line}, "error": describe(exc)})
                if consecutive >= MAX_CONSECUTIVE_CSV_ERRORS:
                    record.update(status="partial", reason="the read stopped after %d consecutive unreadable rows" % consecutive)
                    break
                continue
            consecutive = 0
            if not row:
                continue
            ordinal += 1
            record["rows"] = ordinal
            bad = len(row) != len(names)
            if bad:
                record["malformed_rows"] += 1
                note_problem(survey, record, {"locator": {"line": start_line}, "error": "%d fields where the header has %d" % (len(row), len(names))})
            if any(undecodable(v) for v in row):
                record["rows_with_undecodable_bytes"] += 1
            if kind == "skip_log":
                where = "skip log row %d" % ordinal
                values = {scrub(n, where): scrub(v, where) for n, v in zip(names, row)}
                if recognised:
                    failures.add({"collector": "KAPE", "log": record["log"], "locator": {"row": ordinal, "line": start_line},
                                  "outcome": "skipped",
                                  "target": scrub(row[target_col], where) if target_col is not None and target_col < len(row) else None,
                                  "reason": scrub(row[reason_col], where) if reason_col is not None and reason_col < len(row) else None,
                                  "row_values": values, "malformed": bad})
                else:
                    unrecognised.add({"collector": "KAPE", "log": record["log"], "locator": {"row": ordinal, "line": start_line},
                                      "row_values": values, "malformed": bad})
        if record["malformed_rows"] and record["status"] == "parsed":
            record["status"] = "partial"
            record["reason"] = "some rows are malformed (see problems): they are counted, and kept whole where they are a skip row"
    return record


def read_console_log(survey, rel):
    """A KAPE console log, streamed: its levelled lines are counted by level and the warnings and errors it records are rows of
    the problems table with their locator. They are the collector's own words about what it did, not failures of this
    delivery, and the log does not feed the failure count."""
    path = os.path.join(survey.root, rel)
    record = new_record(survey, rel, "console_log", "kape_console/1")
    record.update(levels={}, unmatched_lines=0, lines=0)
    reason = binary_reason(path)
    if reason:
        record.update(status="unsupported", reason=reason)
        return record
    try:
        fh = open_text(path)
    except OSError as exc:
        record.update(status="unreadable", reason=describe(exc))
        return record
    with fh:
        number = 0
        while True:
            if out_of_time():
                record.update(status="partial", reason="the time limit stopped the read after line %d" % number)
                break
            try:
                line = fh.readline(MAX_LINE)
            except OSError as exc:
                record.update(status="partial", reason="the read stopped at line %d (%s)" % (number + 1, describe(exc)))
                break
            if not line:
                break
            number += 1
            record["lines"] = number
            text = line.rstrip("\r\n")
            found = CONSOLE_LINE.match(text)
            if found:
                level = found.group("level")
                record["levels"][level] = record["levels"].get(level, 0) + 1
                if level in ("WRN", "ERR"):
                    survey.problems.add({"kind": "console_line", "path": record["log"], "locator": {"line": number}, "level": level,
                                         "text": scrub(text, "console log line %d" % number)})
            elif text.strip():
                record["unmatched_lines"] += 1
    if record["unmatched_lines"] and record["status"] == "parsed":
        record["status"] = "partial"
        record["reason"] = "%d line(s) match no levelled shape this adapter knows (a wrapped message, a banner, another version's form): counted, never read as levelled" % record["unmatched_lines"]
    return record


def read_uac_log(survey, rel, failures):
    path = os.path.join(survey.root, rel)
    record = new_record(survey, rel, "uac_log", "uac_log_lines/2")
    record.update(lines=0, events=0, levels={}, unmatched_lines=0, unlabelled_lines_with_failure_words=0, unlabelled_examples=[],
                  lines_naming_dates_or_host=[], command_stderr_lines=0, long_lines=0)
    reason = binary_reason(path)
    if reason:
        record.update(status="unsupported", reason=reason)
        return record
    try:
        fh = open_regular(path, encoding="utf-8", errors="surrogateescape", newline="")
    except OSError as exc:
        record.update(status="unreadable", reason=describe(exc))
        return record
    with fh:
        number = 0
        while True:
            if out_of_time():
                record.update(status="partial", reason="the time limit stopped the read after line %d" % number)
                break
            try:
                line = fh.readline(MAX_LINE)
            except OSError as exc:
                record.update(status="partial", reason="the read stopped at line %d (%s)" % (number + 1, describe(exc)))
                break
            if not line:
                break
            number += 1
            long_line = len(line) == MAX_LINE and not line.endswith("\n")
            if long_line:
                record["long_lines"] += 1
                while True:                  # the rest of the line is skipped, not stored: the whole line is in the evidence at this number
                    rest = fh.readline(MAX_LINE)
                    if not rest or rest.endswith("\n"):
                        break
            record["lines"] = number
            text = line.rstrip("\r\n")
            low = text.lower()
            where = "UAC log line %d" % number
            if "start date" in low or "end date" in low or "hostname" in low:
                row = {"line": number, "text": scrub(text, where)}
                survey.problems.add({"kind": "uac_line_naming_date_or_host", "path": record["log"], "locator": {"line": number}, "text": row["text"]})
                if len(record["lines_naming_dates_or_host"]) < FIRST_PROBLEMS:
                    record["lines_naming_dates_or_host"].append(row)
            found = UAC_EVENT.match(text)
            if found:
                record["events"] += 1
                level = found.group("level")
                record["levels"][level] = record["levels"].get(level, 0) + 1
                if level in UAC_ERROR_LEVELS:
                    failures.add({"collector": "UAC", "log": record["log"], "locator": {"line": number}, "outcome": "error",
                                  "target": None, "reason": scrub(text, where), "long_line": long_line})
                elif level in UAC_COMMAND_LEVELS and " 2> " in text:
                    record["command_stderr_lines"] += 1
                    survey.problems.add({"kind": "uac_command_stderr", "path": record["log"], "locator": {"line": number},
                                         "text": scrub(text, where)})
            elif text.strip():
                record["unmatched_lines"] += 1
                if any(w in low for w in UAC_FAILURE_WORDS):
                    record["unlabelled_lines_with_failure_words"] += 1
                    row = {"line": number, "text": scrub(text, where)}
                    survey.problems.add({"kind": "uac_unlabelled_line", "path": record["log"], "locator": {"line": number}, "text": row["text"]})
                    if len(record["unlabelled_examples"]) < FIRST_PROBLEMS:
                        record["unlabelled_examples"].append(row)
    if record["status"] == "parsed" and record["events"] == 0:
        record["status"] = "unsupported"
        record["reason"] = "no line starts with a date, a time and a level word this adapter knows: failures are not counted from this log"
    elif record["status"] == "parsed" and record["unmatched_lines"]:
        record["status"] = "partial"
        record["reason"] = "%d line(s) match no recognised event shape: counted, kept unlabelled, never counted as failures" % record["unmatched_lines"]
    return record


def plain_json(value):
    """The JSON text of a value with its characters as they are: json.dumps writes a non-ASCII character as \\uXXXX and a NUL or other
    control character as \\u00XX, and the fold of the withholding reads real characters, so a token split by one of them would be
    judged as text with a backslash in it. Only the escapes json.dumps itself made are undone (an escaped backslash is kept)."""
    text = json.dumps(value, ensure_ascii=False, default=str)
    return re.sub(r"\\(?:(\\)|u(00[01][0-9a-f]))", lambda m: m.group() if m.group(1) else chr(int(m.group(2), 16)), text)


def jsonl_rows(fh, record, survey, label):
    """(line number, row) for each JSON object of a JSON Lines stream; a line that is not valid JSON, not an object, or too long
    is counted and located and the stream goes on. A JSON array is not JSON Lines: it ends the stream with `unsupported`."""
    number = 0
    first = True
    while True:
        if out_of_time():
            record.update(status="partial", reason="the time limit stopped the read of %s after line %d" % (label, number))
            return
        try:
            line = fh.readline(MAX_LINE)
        except OSError as exc:
            record.update(status="partial", reason="the read of %s stopped at line %d (%s)" % (label, number + 1, describe(exc)))
            return
        if not line:
            return
        number += 1
        if len(line) == MAX_LINE and not line.endswith("\n"):
            record["malformed_rows"] += 1
            note_problem(survey, record, {"file": label, "locator": {"line": number}, "error": "a line longer than %d bytes: read no further" % MAX_LINE})
            while True:
                rest = fh.readline(MAX_LINE)
                if not rest or rest.endswith("\n"):
                    break
            continue
        if not line.strip():
            continue
        if first and line.lstrip().startswith("["):
            record.update(status="unsupported", reason="%s is a JSON array, not JSON Lines: nothing was read from it" % label)
            return
        first = False
        try:
            row = json.loads(line)
        except (ValueError, RecursionError):
            record["malformed_rows"] += 1
            note_problem(survey, record, {"file": label, "locator": {"line": number}, "error": "not valid JSON"})
            continue
        if not isinstance(row, dict):
            record["non_object_rows"] += 1
            note_problem(survey, record, {"file": label, "locator": {"line": number}, "error": "a JSON line that is not an object"})
            continue
        yield number, row


def upload_error(value, depth=0):
    """The first upload record under `value` that carries an Error: a dictionary with a non-empty Error and a key only an upload
    record has (StoredName, UploadId, StoredSize, Components). Velociraptor puts an upload in a result row as a nested record."""
    if depth > 4:
        return None
    if isinstance(value, dict):
        err = value.get("Error")
        if err not in (None, "", [], {}) and any(k in value for k in UPLOAD_MARKERS):
            return value
        for child in value.values():
            found = upload_error(child, depth + 1)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value[:1000]:
            found = upload_error(child, depth + 1)
            if found is not None:
                return found
    return None


def sub_status(sub):
    if sub["status"] != "parsed":
        return sub["status"]
    return "partial" if sub["malformed_rows"] or sub["non_object_rows"] else "parsed"


def read_velociraptor(survey, directory, files, failures):
    """One Velociraptor collection container (a directory holding uploads.json and/or collection_context.json). The version this
    pack pins writes a failed upload to no row of uploads.json: it is a result row's upload record with an Error, and an ERROR
    line of log.json. So the container is read whole only when results/*.json and log.json were read as well."""
    base = os.path.join(survey.root, directory) if directory else survey.root
    anchor = files.get("uploads") or files.get("context")
    record = new_record(survey, anchor, "velociraptor_container", "velociraptor_container/1")
    record.update(malformed_rows=0, non_object_rows=0, container=shown(directory or ".", "log path"), sources={}, objects=0,
                  uploads_rows=0, rows_stored_smaller_than_file=0, artefacts={}, result_rows=0, rows_with_upload_error=0,
                  log_levels={}, error_lines=0, warning_lines=0)
    partial = []

    def source(name, status, **extra):
        record["sources"][name] = {"status": status, **extra}
        if status != "parsed":
            partial.append("%s is %s" % (name, status))

    # uploads.json
    if files.get("uploads"):
        rel = files["uploads"]
        reason = binary_reason(os.path.join(survey.root, rel))
        if reason:
            source("uploads.json", "unsupported", reason=reason)
        else:
            sub = {"log": record["log"], "status": "parsed", "malformed_rows": 0, "non_object_rows": 0, "problems": record["problems"]}
            try:
                fh = open_text(os.path.join(survey.root, rel))
            except OSError as exc:
                source("uploads.json", "unreadable", reason=describe(exc))
            else:
                with fh:
                    for number, row in jsonl_rows(fh, sub, survey, "uploads.json"):
                        record["uploads_rows"] += 1
                        size, stored = row.get("file_size"), row.get("uploaded_size")
                        if isinstance(size, int) and isinstance(stored, int) and stored < size and row.get("Type") != "idx":
                            record["rows_stored_smaller_than_file"] += 1
                            survey.problems.add({"kind": "upload_stored_smaller_than_file", "path": shown(rel, "log path"),
                                                 "locator": {"line": number}, "target": scrub(str(row.get("vfs_path")), "uploads row"),
                                                 "file_size": size, "uploaded_size": stored,
                                                 "note": "a sparse or partial upload, or a failed one: results/*.json and log.json say which"})
                record["malformed_rows"] += sub["malformed_rows"]
                record["non_object_rows"] += sub["non_object_rows"]
                source("uploads.json", sub_status(sub), **({"reason": sub["reason"]} if "reason" in sub else {}))

    # results/*.json: where this version records a failed upload
    results_dir = os.path.join(base, "results")
    names = []
    try:
        names = sorted((n for n in os.listdir(results_dir) if n.endswith(".json")), key=sort_key)
    except OSError:
        pass
    if not names:
        source("results/*.json", "not_found", reason="no results/*.json beside the container's index: a failed upload is recorded there in this version")
    else:
        sub = {"log": record["log"], "status": "parsed", "malformed_rows": 0, "non_object_rows": 0, "problems": record["problems"]}
        for name in names:
            rel = os.path.join(directory, "results", name) if directory else os.path.join("results", name)
            artefact = scrub(name[:-len(".json")], "artefact name")
            if len(record["artefacts"]) < MAX_DISTINCT:
                record["artefacts"].setdefault(artefact, 0)
            try:
                fh = open_text(os.path.join(survey.root, rel))
            except OSError as exc:
                survey.problems.add({"kind": "log_problem", "path": shown(rel, "log path"), "what": "a results file could not be opened", "error": describe(exc)})
                sub["status"] = "partial"
                continue
            with fh:
                for number, row in jsonl_rows(fh, sub, survey, name):
                    record["result_rows"] += 1
                    if artefact in record["artefacts"]:
                        record["artefacts"][artefact] += 1
                    found = upload_error(row)
                    if found is not None:
                        record["rows_with_upload_error"] += 1
                        where = "results row at line %d" % number
                        target = next((found[k] for k in UPLOAD_TARGET_KEYS if isinstance(found.get(k), str) and found.get(k)), None)
                        err = found.get("Error")
                        failures.add({"collector": "Velociraptor", "log": shown(rel, "log path"), "locator": {"line": number},
                                      "outcome": "error", "artefact": artefact,
                                      "target": scrub(target, where) if target else None,
                                      "reason": scrub(err if isinstance(err, str) else plain_json(err), where),
                                      "row_values": scrub_all(found)})
        record["malformed_rows"] += sub["malformed_rows"]
        record["non_object_rows"] += sub["non_object_rows"]
        source("results/*.json", sub_status(sub), files=len(names), **({"reason": sub["reason"]} if "reason" in sub else {}))

    # log.json: the collection's own log; an ERROR line is a recorded error
    log_rel = os.path.join(directory, "log.json") if directory else "log.json"
    if not os.path.isfile(os.path.join(base, "log.json")):
        source("log.json", "not_found", reason="no log.json beside the container's index: the collection's own errors are recorded there")
    else:
        sub = {"log": record["log"], "status": "parsed", "malformed_rows": 0, "non_object_rows": 0, "problems": record["problems"]}
        try:
            fh = open_text(os.path.join(survey.root, log_rel))
        except OSError as exc:
            source("log.json", "unreadable", reason=describe(exc))
        else:
            with fh:
                for number, row in jsonl_rows(fh, sub, survey, "log.json"):
                    level = row.get("level")
                    level = level if isinstance(level, str) else "?"
                    word = level.upper() if level.upper() in LOG_LEVEL_WORDS else "other"       # a level is evidence: only the words of the log's own scale are keys
                    record["log_levels"][word] = record["log_levels"].get(word, 0) + 1
                    message = row.get("message")
                    text = scrub(message if isinstance(message, str) else plain_json(message), "log.json line %d" % number)
                    if level.upper() == "ERROR":
                        record["error_lines"] += 1
                        failures.add({"collector": "Velociraptor", "log": shown(log_rel, "log path"), "locator": {"line": number},
                                      "outcome": "error", "target": None, "reason": text})
                    elif level.upper() in ("WARN", "WARNING"):
                        record["warning_lines"] += 1
                        survey.problems.add({"kind": "velociraptor_log_warning", "path": shown(log_rel, "log path"),
                                             "locator": {"line": number}, "text": text})
            record["malformed_rows"] += sub["malformed_rows"]
            record["non_object_rows"] += sub["non_object_rows"]
            source("log.json", sub_status(sub), **({"reason": sub["reason"]} if "reason" in sub else {}))
    if partial:
        record["status"] = "partial" if any(v["status"] == "parsed" for v in record["sources"].values()) else "unsupported"
        record["reason"] = "; ".join(partial) + ": the failure count is not determined from this container"
    return record


def main():
    install_signal_handlers()
    args = read_args()
    root = want_str(args, "root", "root is required: the collection directory")
    limit = want_int(args, "limit", DEFAULT_LIMIT)
    seconds = want_int(args, "time_limit_seconds", 1500, 1, 3400)
    csv.field_size_limit(MAX_LINE)
    try:
        VALUES[0] = SecretValues(want_bool(args, "write_values"), VALUES_NAME, TOOL)
    except SecretValuesRefused as exc:
        fail(str(exc))
    if not os.path.isdir(root):
        fail("no such directory" if not os.path.isfile(root) else
             "root is a file: give the directory that holds it (a collector's record is read from its directory)", root=root)
    start_clock(seconds)
    problems = Table(TOOL + "-problems", FIRST_PROBLEMS)
    survey = Survey(root, limit, problems)
    walk(survey)

    failures = Table(TOOL + "-failures", limit)
    unrecognised = Table(TOOL + "-unrecognised-rows", limit)
    runs = Table(TOOL + "-runs", limit)
    records = []                     # every log record, for the status and the count
    failure_sources = []             # the records the failure count rests on
    candidates = []
    kape_markers = []
    for (directory, run_id), logs in sorted(survey.kape.items(), key=lambda kv: (order_key(kv[0][0]), order_key(kv[0][1]), tie_key(kv[0][0] + "\0" + kv[0][1]))):
        run = {"collector": "KAPE", "run_id": scrub(run_id, "KAPE run id"), "directory": shown(directory or ".", "log path"), "logs": []}
        if "copy" in logs:
            rec = read_csv_log(survey, logs["copy"], "copy_log", failures, unrecognised)
            run["logs"].append(rec)
            run["files_in_copy_log"] = rec["rows"] if rec["status"] in ("parsed", "partial") else None
        if "skip" in logs:
            rec = read_csv_log(survey, logs["skip"], "skip_log", failures, unrecognised)
            run["logs"].append(rec)
            failure_sources.append(rec)
        if "console" in logs:
            run["logs"].append(read_console_log(survey, logs["console"]))
        run["collector_version"] = "unknown"
        records.extend(run["logs"])
        kape_markers += [lg["log"] for lg in run["logs"]]
        runs.add(run)
    uac_markers = []
    for rel in survey.uac_logs:
        rec = read_uac_log(survey, rel, failures)
        records.append(rec)
        failure_sources.append(rec)
        uac_markers.append(rec["log"])
        runs.add({"collector": "UAC", "log": rec["log"], "collector_version": "unknown", "record": rec})
    velo_markers = []
    for directory, files in sorted(survey.velociraptor.items(), key=lambda kv: sort_key(kv[0])):
        rec = read_velociraptor(survey, directory, files, failures)
        records.append(rec)
        failure_sources.append(rec)
        velo_markers += [shown(v, "log path") for v in files.values() if v]
        runs.add({"collector": "Velociraptor", "container": rec["container"], "collector_version": "unknown", "record": rec})

    if kape_markers:
        candidates.append({"collector": "KAPE", "basis": "log files named like KAPE's copy, skip and console logs",
                           "observed_markers": kape_markers[:FIRST_PROBLEMS], "markers_total": len(kape_markers)})
    if survey.uac_logs or survey.uac_dirs:
        markers = uac_markers + [shown(p, "marker directory") for p in survey.uac_dirs]
        candidates.append({"collector": "UAC",
                           "basis": "a uac.log file" if survey.uac_logs else "a [root] directory name only: no log was found",
                           "observed_markers": markers[:FIRST_PROBLEMS], "markers_total": len(markers)})
    if survey.velociraptor:
        candidates.append({"collector": "Velociraptor", "basis": "uploads.json or collection_context.json",
                           "observed_markers": velo_markers[:FIRST_PROBLEMS], "markers_total": len(velo_markers)})

    tables = {"failed_targets": failures.finish(), "unrecognised_rows": unrecognised.finish(), "runs": runs.finish(),
              "objects": survey.objects.finish(), "problems": problems.finish()}
    values = VALUES[0]                    # closed by release(), after the last string of the answer has been judged

    top_archives = survey.counts["archive"]
    walk_complete = not survey.stopped and survey.errors_total == 0
    all_read = bool(failure_sources) and all(r["status"] == "parsed" for r in failure_sources)
    count_known = all_read and walk_complete and top_archives == 0
    seen = tables["failed_targets"]["matched"]
    if count_known:
        failure_count = seen
        basis = ("every failure-source log was read whole: the rows the logs record as skipped (KAPE skip log), lines with an ERROR level (UAC) "
                 "and the Velociraptor upload errors and ERROR log lines. A skip is the collector's own recorded outcome, not a judgement; "
                 "the count says nothing about what a log omits")
    else:
        failure_count = None
        why = []
        if not failure_sources:
            why.append("no skip log, UAC log or Velociraptor container was read")
        why += ["%s is %s" % (r["log"], r["status"]) for r in failure_sources if r["status"] != "parsed"]
        if survey.stopped:
            why.append("the walk stopped early")
        if survey.errors_total:
            why.append("%d walk or read error(s)" % survey.errors_total)
        if top_archives:
            why.append("%d archive(s) were not opened" % top_archives)
        basis = "not determined (%s). This is not zero failures; failed_targets_seen is how many rows were read" % "; ".join(why[:10])

    total = survey.files
    parts = []
    if survey.tree_files > 0:
        parts.append("logical")
    for key in ("disk_container", "memory_capture", "archive", "unknown"):
        if survey.counts[key]:
            parts.append(key)
    if total == 0:
        kind = "empty"
    elif not parts:
        kind = "logical"
    else:
        kind = parts[0] if len(parts) == 1 else "mixed"
    caveats = []
    undetermined = survey.counts["unknown"] + survey.counts["unknown_nested"]
    if undetermined:
        caveats.append("%d object(s) are named like an image or a capture and have no signature: each may be a disk or a memory capture" % undetermined)
    if top_archives:
        caveats.append("%d top-level archive(s) were not opened" % top_archives)
    if survey.memory_bearing:
        caveats.append("files named like memory-bearing files are present (%s): they are not captures" % ", ".join(sorted(set(survey.memory_bearing))))
    if survey.stopped or survey.errors_total:
        caveats.append("the walk was incomplete")
    not_observed = [] if undetermined else [label for key, label in (("disk_container", "disk containers"), ("memory_capture", "memory captures"))
                                            if survey.counts[key] == 0]

    problem_lines = []
    if survey.stopped:
        problem_lines.append("the walk stopped early: %s" % survey.stopped["reason"])
    if survey.errors_total:
        problem_lines.append("%d walk or read error(s): see walk.first_errors and the problems table" % survey.errors_total)
    for r in records:
        if r["status"] != "parsed":
            problem_lines.append("%s is %s" % (r["log"], r["status"]))
    status = "complete" if not problem_lines else "partial"
    problem_basis = "; ".join(problem_lines[:10]) + ("; and %d more (see the records)" % (len(problem_lines) - 10) if len(problem_lines) > 10 else "")

    out = {
        "tool": TOOL, "parser": PARSER, "root": shown(root, "root"), "status": status,
        "status_basis": ("every directory was listed and every recognised log was read whole" if status == "complete" else problem_basis),
        "ignored_parameters": ignored_parameters(args, KNOWN_PARAMETERS),
        "delivery": {"kind": kind,
                     "object_counts": {**survey.counts, "other_files": survey.other_files, "other_files_below_the_top_level": survey.tree_files},
                     "nested_archives_named_like_archives": survey.nested_archives,
                     "basis": "each classified object on its own (see objects); the files that are not classified are 'other files' (copied files, "
                              "notes, logs, captures), and only those below the top level count as a copied tree; mixed means more than one kind "
                              "is present",
                     "not_observed": not_observed, "not_observed_complete": not caveats, "not_observed_caveats": caveats,
                     "not_observed_basis": "no object of this kind was seen among the files walked, by signature or name; a limit of this "
                                           "delivery, not a finding about the source"},
        "failed_target_count": failure_count,
        "failed_targets_seen": seen,
        "failed_target_count_basis": basis,
        "walk": {"directories": survey.directories, "files": total, "symbolic_links_not_followed": survey.links_total,
                 "special_files_not_read": survey.special_total, "errors": survey.errors_total, "first_errors": survey.errors,
                 "first_links": survey.links, "first_special_files": survey.special, "stopped": survey.stopped,
                 "logs_inside_collected_data": [inline_text(x) for x in survey.collected_data_logs[:FIRST_PROBLEMS]],
                 "logs_inside_collected_data_total": len(survey.collected_data_logs),
                 "reads_first_bytes_of": "%d object(s): top-level files, files named like an image, a memory capture or an archive, and files of %d bytes or more" % (survey.reads_head, MIN_RAW_BYTES),
                 "first_bytes_unreadable": survey.head_errors},
        "collector_candidates": candidates,
        "layout_clues": survey.layout_clues,
        "artefact_families_by_name": dict(sorted(survey.families.items(), key=lambda kv: (-kv[1]["count"], kv[0]))),
        "artefact_families_basis": "a file's own name only: a file of that name may be empty, truncated or not that artefact",
        "tables": tables,
        "withheld": {"strings_withheld": WITHHELD["count"], "values": values.summary()},
        "note": ("A hypothesis from names, first bytes and the collectors' own logs. It does not say the collector finished, what it was "
                 "asked to copy, or whether a digest matches; the logs and manifests themselves are the record. A recorded skip or error "
                 "is the collector's outcome, to be reported with its own words and not explained or judged. Source paths are not "
                 "reconstructed here: collection_index offers hypotheses, and only a collector's own mapping observes one. Every page "
                 "below is the first rows of a table whose whole is in the file `tables` names."),
        "objects": survey.objects.page,
        "runs": runs.page,
        "failed_targets": failures.page,
        "unrecognised_rows": unrecognised.page,
        "problems": problems.page,
    }
    write_answer(out)


if __name__ == "__main__":
    try:
        main()
    except (SystemExit, KeyboardInterrupt):
        raise
    except BaseException as exc:                  # a bug here is a JSON error that names it, not a traceback and a half-written answer
        fail("the tool stopped on an unexpected error (%s)" % type(exc).__name__, detail=str(exc))
