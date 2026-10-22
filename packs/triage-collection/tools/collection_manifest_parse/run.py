#!/usr/bin/env python3
"""Read the records a collector wrote into canonical records, one per row or line, each with the locator of its raw row.

A delivered collection carries the collector's own account of what it did: KAPE's copy, skip and console logs, UAC's log and its
hash lists, a Velociraptor container's uploads.json, result rows and log. This tool reads them with a versioned adapter each
(the answer's `adapters` names the schema every adapter reads) and writes one record per row or line to a table whose whole is
a file the answer names. A record keeps what the collector wrote, as it wrote it: the source path and the delivered path it
claims, the size, the digest with the algorithm the collector used, its times (each a raw string, a clock of the collector's own),
the outcome (copied, skipped, uploaded, upload_error, a recorded warning or error) and the collector's own words for a failure.
Nothing is decided here: whether the file the record names is in the delivery and matches is collection_manifest_verify; where a
delivered file came from is collection_path_map; what the delivery covers is collection_coverage.

What a record is not: a finding, a verified fact or a proof that the collector finished. A record whose columns or lines an
adapter does not know is `partial` or `unsupported` and is counted, kept whole where it is a row, never read as zero failures.
`failures_recorded.count` of a run is `null`, never 0, unless every failure-source record of that run was read whole, the walk was
complete and no archive at the top of the delivery went unopened. CyLR writes no record this pack has a schema for: the answer
says so in `unsupported`, and a CyLR tree is read as copied files. A record found inside collected data (below [root] or uploads)
belongs to the source host and is listed, not read. The collector's version is `unknown` unless a record states it.

SECRET-SAFE OUTPUT (docs/packs.md, "Secrets and sensitive output"). Every key and value of the answer and of the table files is
passed through the shared withholding block; a digest the collector recorded for a file that is a credential store (by its name)
is withheld from the record and goes only to the values file. `write_values: true` (a job only, run with `secret_output: true`)
writes the real strings that were withheld to `$OUT/collection-manifest-parse-values.jsonl`, mode 0600, created before anything is read.
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


# ---- BEGIN RECORDS BLOCK ---------------------------------------------------------------------------------------------
# Identical in collection_manifest_parse, collection_manifest_verify, collection_path_map, collection_coverage and the
# collection_intake recipe (the recipe defines out_of_time, describe, WITHHELD and VALUES before it). A tool is standalone, so what they share is
# copied, and tests/pack-triage-records.test.ts holds the copies equal. Edit it in all of them, never in one. It holds: the
# census of a delivered tree (or of an archive's members), the adapters that read a collector's own records into canonical
# records (KAPE copy, skip and console logs, UAC's log and hash lists, a Velociraptor container), the join of a record to the
# delivered file it names, the hash of a file in one pass, the glob the callers' patterns use, and the name hint for a
# credential store. It prints nothing, and the strings it returns are the caller's to withhold (the tables do); only the digest of a
# credential store is withheld here. It needs `out_of_time()`, `describe(exc)`, `WITHHELD` and `VALUES`.
import collections
import csv
import hashlib
import io
import json
import os
import re
import stat

MAX_CENSUS = 2000000              # entries held for the join; past it the census is partial and no record is called missing
REC_LINE = 1 << 20                # a log line longer than this is read in part; the whole line stays in the evidence at its locator
REC_CHUNK = 1 << 20
REC_FIRST = 25                    # problems of a source kept in its summary; every one goes to the caller's sink
MAX_CONSECUTIVE_BAD_ROWS = 1000
INSIDE_COLLECTED = ("[root]", "uploads")        # a directory below which the files are the source host's own
UAC_EVENT = re.compile(r"^\s*\[?(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s?(?:Z|[+-]\d{2}:?\d{2}))?)\]?\s*"
                       r"(?:[-:|]\s*)?\[?(?P<level>INFO|INF|WARNING|WARN|ERROR|ERR|COMMAND|CMD|DEBUG|DBG)\]?(?:\s|:|$)")
UAC_ERROR_LEVELS = ("ERROR", "ERR")
UAC_COMMAND_LEVELS = ("COMMAND", "CMD")
CONSOLE_LINE = re.compile(r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) \| (?P<level>[A-Z]{3})\] ")
UPLOAD_MARKERS = ("StoredName", "UploadId", "StoredSize", "Components")
UPLOAD_PATH_KEYS = ("Path", "OSPath", "SourceFile", "FullPath", "vfs_path")
LOG_LEVEL_WORDS = ("TRACE", "DEBUG", "DEFAULT", "INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL")
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HASH_LIST_NAMES = {"hash_executables.md5": "md5", "hash_executables.sha1": "sha1", "hash_executables.sha256": "sha256"}
HASH_LINE = re.compile(r"^(?P<hex>[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})[ \t]+\*?(?P<path>.+)$")
HASH_LINE_BSD = re.compile(r"^(?P<tag>MD5|SHA1|SHA256) \((?P<path>.+)\) = (?P<hex>[0-9A-Fa-f]{32,64})$")
KAPE_COPY_KNOWN = ("copiedtimestamp", "sourcefile", "destinationfile", "filesize", "sourcefilesha1", "deferredcopy", "createdonutc",
                   "modifiedonutc", "lastaccessedonutc", "copyduration")
KAPE_COPY_MAPPED = ("copiedtimestamp", "sourcefile", "destinationfile", "filesize", "sourcefilesha1", "createdonutc", "modifiedonutc", "lastaccessedonutc")
KAPE_SKIP_KNOWN = ("sourcefile", "sourcefilesha1", "reason")
SKIP_TARGET_COLUMNS = ("sourcefile", "source", "filename", "file", "path")
SKIP_REASON_COLUMNS = ("reason", "message", "error", "status")
ADAPTERS = {
    "kape_copy_log": {"id": "kape_copy_log/2", "collector": "KAPE", "reads": "*_CopyLog.csv",
                      "schema": "a header with SourceFile and DestinationFile; the other columns KAPE writes are kept by name"},
    "kape_skip_log": {"id": "kape_skip_log/2", "collector": "KAPE", "reads": "*_SkipLog.csv",
                      "schema": "a header with a target column (SourceFile) or a reason column (Reason)"},
    "kape_console_log": {"id": "kape_console_log/1", "collector": "KAPE", "reads": "*_ConsoleLog.txt",
                         "schema": "lines of the form [date time | LVL] text; warnings and errors are rows, none is a failure"},
    "uac_log": {"id": "uac_log/2", "collector": "UAC", "reads": "uac.log",
                "schema": "lines that start with a date, a time and a level word (UAC 3.4.0: DBG INF ERR CMD; 2.9.1: DEBUG INFO WARNING ERROR COMMAND)"},
    "hash_list": {"id": "hash_list/1", "collector": "UAC", "reads": "hash_executables.md5, .sha1, .sha256",
                  "schema": "one 'hex  path' line per file (the md5sum, sha1sum and sha256sum forms) or 'ALGORITHM (path) = hex'"},
    "velociraptor_container": {"id": "velociraptor_container/2", "collector": "Velociraptor", "reads": "uploads.json, results/*.json, log.json, collection_context.json",
                               "schema": "the container 0.77.2 writes: uploads.json rows (vfs_path, file_size, uploaded_size, Type), result rows with an upload record, log.json rows"},
    "cylr": {"id": None, "collector": "CyLR", "reads": None, "supported": False,
             "schema": "none: no record of CyLR is read; a CyLR archive is a tree of copied files, and a top-level C or C$ directory is a layout clue, not a manifest"},
}


# ---- the census: what a delivery holds, by name -------------------------------------------------------------------------


class Census:
    """The relative path, size and kind (f regular file, l link, s special) of every entry of a delivered tree or of an archive's
    members, keyed by the case-folded path so that a record's claim is joined to the file it names whatever the case. Links and
    special files are recorded and never followed. `complete` is false when a directory could not be listed, an entry could not be
    examined, the walk stopped or the cap was reached: a record that names no file is then unverifiable, never missing."""

    def __init__(self, cap=MAX_CENSUS):
        self.cap = cap
        self.by_key = {}
        self.total = self.files = self.dirs = self.links = self.special = 0
        self.capped = False
        self.complete = True
        self.errors = []
        self.errors_total = 0
        self.stopped = None
        self.marked_dirs = []             # directories (and links) named [root]: UAC's directory of collected files

    @staticmethod
    def key(rel):
        return rel.replace(os.sep, "/").casefold()

    def add(self, rel, size, kind):
        if self.total >= self.cap:
            self.capped = True
            self.complete = False
            return
        self.total += 1
        if kind == "f":
            self.files += 1
        elif kind == "l":
            self.links += 1
        else:
            self.special += 1
        self.by_key.setdefault(self.key(rel), []).append((rel, size, kind))

    def error(self, rel, what, exc=None):
        self.complete = False
        self.errors_total += 1
        if len(self.errors) < REC_FIRST:
            self.errors.append({"path": rel, "what": what, **({"error": describe(exc)} if exc is not None else {})})

    def entries(self):
        for group in self.by_key.values():
            for item in group:
                yield item

    def lookup(self, rel):
        return self.by_key.get(self.key(rel), [])


def walk_census(root, census, skip=None):
    """Everything below `root`, one pass, without following a link. `skip(entry)` leaves out the files this run itself writes."""
    prefix = root.rstrip(os.sep) + os.sep
    stack = [root]
    seen = 0
    while stack:
        if out_of_time():
            census.stopped = {"reason": "the time limit ended the walk", "directories_not_listed": len(stack)}
            census.complete = False
            return
        directory = stack.pop()
        rel_dir = directory[len(prefix):] if directory.startswith(prefix) else ""
        try:
            with os.scandir(directory) as it:
                entries = list(it)
        except OSError as exc:
            census.error(rel_dir or ".", "the directory could not be listed", exc)
            continue
        census.dirs += 1
        for entry in entries:
            seen += 1
            if (seen & 1023) == 0 and out_of_time():
                census.stopped = {"reason": "the time limit ended the walk", "directories_not_listed": len(stack)}
                census.complete = False
                return
            if skip is not None and skip(entry):
                continue
            rel = entry.path[len(prefix):] if entry.path.startswith(prefix) else os.path.relpath(entry.path, root)
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                census.error(rel, "the entry could not be examined", exc)
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                census.add(rel, 0, "l")
                if entry.name == "[root]":
                    census.marked_dirs.append(rel)
            elif stat.S_ISDIR(mode):
                stack.append(entry.path)
                if entry.name == "[root]":
                    census.marked_dirs.append(rel)
            elif stat.S_ISREG(mode):
                census.add(rel, st.st_size, "f")
            else:
                census.add(rel, 0, "s")


class DirSource:
    """A delivered directory as a source of bytes: a regular file is opened without following a link at its name and without
    blocking on a pipe; anything else is refused."""
    kind = "directory"

    def __init__(self, root):
        self.root = root

    def path(self, rel):
        return os.path.join(self.root, rel)

    def open_binary(self, rel):
        fd = os.open(self.path(rel), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(22, "not a regular file")
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise

    def head(self, rel, count=4096):
        with self.open_binary(rel) as fh:
            return fh.read(count)


def open_text(src, rel):
    return io.TextIOWrapper(src.open_binary(rel), encoding="utf-8-sig", errors="surrogateescape", newline="")


def undecodable(text):
    return any("\udc80" <= c <= "\udcff" for c in text)


def binary_reason(src, rel):
    """Why a log cannot be read as UTF-8 text at all (a UTF-16 byte-order mark, or NUL bytes in its first 4 KiB), or None."""
    try:
        head = src.head(rel)
    except OSError:
        return None
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "the file is UTF-16 (byte-order mark): it is not read as UTF-8 text"
    if b"\x00" in head:
        return "the file holds NUL bytes in its first 4 KiB: it is binary or UTF-16 without a mark, and is not read as text"
    return None


def inside_collected_data(rel):
    return any(part in INSIDE_COLLECTED for part in rel.split("/")[:-1]) or any(part in INSIDE_COLLECTED for part in rel.split(os.sep)[:-1])


def parent_of(rel):
    cut = max(rel.rfind("/"), rel.rfind(os.sep))
    return rel[:cut] if cut >= 0 else ""


def name_of(rel):
    return rel[max(rel.rfind("/"), rel.rfind(os.sep)) + 1:]


def join_rel(*parts):
    return "/".join(p for p in parts if p)


def discover(census):
    """The collectors' records among the files of a census, by name: KAPE runs (a directory and a run id), UAC logs and hash
    lists, Velociraptor containers (a directory with uploads.json or collection_context.json, its results/*.json and its
    log.json). A record found inside collected data (below [root] or uploads) belongs to the source host and is listed apart,
    never read. Sorted by the name's bytes, so a run reads the same records in the same order every time."""
    found = {"kape": {}, "uac_logs": [], "uac_hashes": [], "uac_dirs": [], "velociraptor": {}, "velo_results": {}, "velo_logs": {}, "inside_collected": []}
    for rel, size, kind in sorted((e for e in census.entries() if e[2] == "f"), key=lambda e: os.fsencode(e[0])):
        name = name_of(rel)
        low = name.lower()
        directory = parent_of(rel)
        marker = None
        for suffix, key in (("_copylog.csv", "copy"), ("_skiplog.csv", "skip"), ("_consolelog.txt", "console")):
            if low.endswith(suffix):
                marker = ("kape", key, name[:-len(suffix)])
        if name == "uac.log":
            marker = ("uac", None, None)
        elif low in HASH_LIST_NAMES:
            marker = ("uac_hash", None, None)
        elif name in ("uploads.json", "collection_context.json"):
            marker = ("velociraptor", "uploads" if name == "uploads.json" else "context", None)
        elif name.endswith(".json") and name_of(directory) == "results":
            marker = ("velo_result", None, None)
        elif name == "log.json":
            marker = ("velo_log", None, None)
        if marker is None:
            continue
        if inside_collected_data(rel):
            if marker[0] in ("kape", "uac", "uac_hash", "velociraptor"):
                found["inside_collected"].append(rel)
            continue
        if marker[0] == "kape":
            found["kape"].setdefault((directory, marker[2]), {})[marker[1]] = rel
        elif marker[0] == "uac":
            found["uac_logs"].append(rel)
        elif marker[0] == "uac_hash":
            found["uac_hashes"].append(rel)
        elif marker[0] == "velociraptor":
            found["velociraptor"].setdefault(directory, {})[marker[1]] = rel
        elif marker[0] == "velo_result":
            found["velo_results"].setdefault(parent_of(directory), []).append(rel)
        else:
            found["velo_logs"][directory] = rel
    found["uac_dirs"] = sorted(census.marked_dirs, key=os.fsencode)
    return found


# ---- the adapters: a collector's own record, one canonical record per row ------------------------------------------------


class Sink:
    """Where an adapter puts what it reads. A tool subclasses it to write tables; the default keeps the lists."""

    def __init__(self):
        self.records = []
        self.problems = []
        self.count = 0

    def record(self, rec):
        self.count += 1
        rec["n"] = self.count
        self.records.append(rec)

    def problem(self, row):
        self.problems.append(row)


def new_source(rel, collector, adapter, kind, **extra):
    return {"log": rel, "collector": collector, "kind": kind, "adapter": ADAPTERS[adapter]["id"], "status": "parsed", "rows": 0, "records": 0,
            "malformed_rows": 0, "problems_total": 0, "problems": [], **extra}


def note(sink, source, locator, error, **extra):
    source["problems_total"] += 1
    row = {"log": source["log"], "locator": locator, "error": error, **extra}
    if len(source["problems"]) < REC_FIRST:
        source["problems"].append({"locator": locator, "error": error})
    sink.problem(row)


def emit(sink, source, run, base, **fields):
    source["records"] += 1
    rec = {"collector": source["collector"], "run": run, "directory": base or ".", "adapter": source["adapter"], "log": source["log"]}
    rec.update(fields)
    sink.record(rec)


def whole_int(text):
    if isinstance(text, bool):
        return None
    if isinstance(text, int):
        return text if text >= 0 else None
    if isinstance(text, str) and re.fullmatch(r"[0-9]{1,20}", text.strip()):
        return int(text.strip())
    return None


def hash_claim(algorithm, value):
    """The lower-case hex of a digest of the length its algorithm has, else None (the raw text stays in the row's fields). A row's
    claims are a dictionary of algorithm to digest: the key says which algorithm the collector used, and no digest is read as another."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or not re.fullmatch(r"[0-9A-Fa-f]+", value):
        return None
    want = {"md5": 32, "sha1": 40, "sha256": 64}.get(algorithm)
    if want is None or len(value) != want:
        return None
    return value.lower()


def read_kape_csv(src, rel, kind, run, base, sink):
    """A KAPE copy or skip log, streamed. A copy-log row becomes a `copy` record (the source path, the destination path, the size,
    the SHA-1 of the source and the times, each as the collector wrote it, and the whole row by column name); a skip-log row a
    `skip` record with the collector's own words. A header without the columns an adapter needs is `partial` (copy log: rows are
    counted, nothing else is read) and a log that is binary, UTF-16 or unreadable `unsupported` or `unreadable`."""
    adapter = "kape_copy_log" if kind == "copy" else "kape_skip_log"
    source = new_source(rel, "KAPE", adapter, kind + "_log", run=run, directory=base or ".", columns=[], unrecognised_columns=[], rows_with_undecodable_bytes=0)
    reason = binary_reason(src, rel)
    if reason:
        source.update(status="unsupported", reason=reason)
        return source
    try:
        fh = open_text(src, rel)
    except OSError as exc:
        source.update(status="unreadable", reason=describe(exc))
        return source
    csv.field_size_limit(REC_LINE)
    with fh:
        reader = csv.reader(fh, strict=True)
        try:
            header = next(reader)
        except StopIteration:
            source.update(status="unsupported", reason="the file is empty: no header row")
            return source
        except (csv.Error, OSError) as exc:
            source.update(status="unsupported", reason="the header row could not be read (%s)" % describe(exc))
            return source
        names = [h.strip() for h in header]
        lowered = [n.lower() for n in names]
        source["columns"] = names
        known = KAPE_COPY_KNOWN if kind == "copy" else KAPE_SKIP_KNOWN
        source["unrecognised_columns"] = [n for n, low in zip(names, lowered) if low not in known]
        column = {low: i for i, low in reversed(list(enumerate(lowered)))}
        recognised = True
        if kind == "copy":
            if "sourcefile" not in column:
                recognised = False
                source.update(status="partial", reason="no SourceFile column: rows are counted, nothing else is read")
        elif not any(c in column for c in SKIP_TARGET_COLUMNS + SKIP_REASON_COLUMNS):
            recognised = False
            source.update(status="partial", reason="neither a target column nor a reason column is recognised: every row is kept whole in "
                          "unrecognised_row records, and none is a failure")
        target_col = next((column[c] for c in SKIP_TARGET_COLUMNS if c in column), None)
        reason_col = next((column[c] for c in SKIP_REASON_COLUMNS if c in column), None)

        def cell(row, name):
            i = column.get(name)
            return row[i] if i is not None and i < len(row) else None

        ordinal, consecutive = 0, 0
        while True:
            if out_of_time():
                source.update(status="partial", reason="the time limit stopped the read after row %d" % ordinal)
                break
            start_line = reader.line_num + 1                  # a record can span lines (a quoted newline): its locator is the line it starts on
            try:
                row = next(reader)
            except StopIteration:
                break
            except csv.Error as exc:
                source["malformed_rows"] += 1
                consecutive += 1
                note(sink, source, {"line": start_line}, describe(exc))
                if consecutive >= MAX_CONSECUTIVE_BAD_ROWS:
                    source.update(status="partial", reason="the read stopped after %d consecutive unreadable rows" % consecutive)
                    break
                continue
            consecutive = 0
            if not row:
                continue
            ordinal += 1
            source["rows"] = ordinal
            bad = len(row) != len(names)
            if bad:
                source["malformed_rows"] += 1
                note(sink, source, {"line": start_line, "row": ordinal}, "%d fields where the header has %d" % (len(row), len(names)))
            if any(undecodable(v) for v in row):
                source["rows_with_undecodable_bytes"] += 1
            fields = {n: v for n, v in zip(names, row)}
            locator = {"log": rel, "row": ordinal, "line": start_line}
            flags = ["malformed_row"] if bad else []
            if not recognised:
                emit(sink, source, run, base, kind="unrecognised_row", outcome="recorded", locator=locator, fields=fields, flags=flags)
            elif kind == "copy":
                size_raw = cell(row, "filesize")
                claim = hash_claim("sha1", cell(row, "sourcefilesha1"))
                emit(sink, source, run, base, kind="copy", outcome="copied", locator=locator,
                     source_path_claim=cell(row, "sourcefile"), delivered_path_claim=cell(row, "destinationfile"),
                     size_claim=whole_int(size_raw), hash_claims={"sha1": claim} if claim else {},
                     times={n: v for n, v in zip(names, row) if n.lower() in ("copiedtimestamp", "createdonutc", "modifiedonutc", "lastaccessedonutc")},
                     fields={n: v for n, v in fields.items() if n.lower() not in KAPE_COPY_MAPPED}, flags=flags + (["size_not_a_whole_number"] if size_raw not in (None, "") and whole_int(size_raw) is None else []) +
                     (["hash_claim_not_a_digest"] if cell(row, "sourcefilesha1") not in (None, "") and not claim else []))
            else:
                target = row[target_col] if target_col is not None and target_col < len(row) else None
                why = row[reason_col] if reason_col is not None and reason_col < len(row) else None
                claim = hash_claim("sha1", cell(row, "sourcefilesha1"))
                emit(sink, source, run, base, kind="skip", outcome="skipped", locator=locator, source_path_claim=target, delivered_path_claim=None,
                     reason=why, hash_claims={"sha1": claim} if claim else {},
                     fields={n: v for n, v in fields.items() if n.lower() not in KAPE_SKIP_KNOWN}, flags=flags)
        if source["malformed_rows"] and source["status"] == "parsed":
            source["status"] = "partial"
            source["reason"] = "some rows are malformed (see problems): each is a record with the flag malformed_row"
    return source


def read_console(src, rel, run, base, sink):
    """A KAPE console log: its levelled lines are counted by level, and a warning or an error is a record (a recorded line of the
    collector's own, never a failure count: it says what the collector wrote, not that a target was lost)."""
    source = new_source(rel, "KAPE", "kape_console_log", "console_log", run=run, directory=base or ".", lines=0, levels={}, unmatched_lines=0)
    reason = binary_reason(src, rel)
    if reason:
        source.update(status="unsupported", reason=reason)
        return source
    try:
        fh = open_text(src, rel)
    except OSError as exc:
        source.update(status="unreadable", reason=describe(exc))
        return source
    with fh:
        number = 0
        while True:
            if out_of_time():
                source.update(status="partial", reason="the time limit stopped the read after line %d" % number)
                break
            try:
                line = fh.readline(REC_LINE)
            except OSError as exc:
                source.update(status="partial", reason="the read stopped at line %d (%s)" % (number + 1, describe(exc)))
                break
            if not line:
                break
            number += 1
            source["lines"] = number
            if len(line) == REC_LINE and not line.endswith("\n"):
                while True:
                    rest = fh.readline(REC_LINE)
                    if not rest or rest.endswith("\n"):
                        break
            text = line.rstrip("\r\n")
            found = CONSOLE_LINE.match(text)
            if found:
                level = found.group("level")
                source["levels"][level] = source["levels"].get(level, 0) + 1
                if level in ("WRN", "ERR"):
                    emit(sink, source, run, base, kind="log_event", outcome="warning" if level == "WRN" else "error", counts_as_failure=False,
                         locator={"log": rel, "line": number}, text=text)
            elif text.strip():
                source["unmatched_lines"] += 1
    if source["unmatched_lines"] and source["status"] == "parsed":
        source["status"] = "partial"
        source["reason"] = ("%d line(s) match no levelled shape this adapter knows (a wrapped message, a banner, another version's form): "
                            "counted, never read as levelled" % source["unmatched_lines"])
    return source


def read_uac_log(src, rel, sink):
    """UAC's log, streamed. A line with an ERR or ERROR level is a record and a failure; a command's stderr line is counted apart;
    a line that matches no event shape is counted and kept unlabelled (never a failure); a summary that says 0 errors is not one."""
    base = parent_of(rel)
    source = new_source(rel, "UAC", "uac_log", "uac_log", run=base or ".", directory=base or ".", lines=0, events=0, levels={}, unmatched_lines=0, command_stderr_lines=0,
                        long_lines=0, unlabelled_lines_with_failure_words=0)
    reason = binary_reason(src, rel)
    if reason:
        source.update(status="unsupported", reason=reason)
        return source
    try:
        fh = io.TextIOWrapper(src.open_binary(rel), encoding="utf-8", errors="surrogateescape", newline="")
    except OSError as exc:
        source.update(status="unreadable", reason=describe(exc))
        return source
    with fh:
        number = 0
        while True:
            if out_of_time():
                source.update(status="partial", reason="the time limit stopped the read after line %d" % number)
                break
            try:
                line = fh.readline(REC_LINE)
            except OSError as exc:
                source.update(status="partial", reason="the read stopped at line %d (%s)" % (number + 1, describe(exc)))
                break
            if not line:
                break
            number += 1
            long_line = len(line) == REC_LINE and not line.endswith("\n")
            if long_line:
                source["long_lines"] += 1
                while True:
                    rest = fh.readline(REC_LINE)
                    if not rest or rest.endswith("\n"):
                        break
            source["lines"] = number
            text = line.rstrip("\r\n")
            low = text.lower()
            found = UAC_EVENT.match(text)
            if found:
                source["events"] += 1
                level = found.group("level")
                source["levels"][level] = source["levels"].get(level, 0) + 1
                if level in UAC_ERROR_LEVELS:
                    emit(sink, source, run=base or ".", base=base, kind="log_event", outcome="error", counts_as_failure=True,
                         locator={"log": rel, "line": number}, text=text, flags=["long_line"] if long_line else [])
                elif level in UAC_COMMAND_LEVELS and " 2> " in text:
                    source["command_stderr_lines"] += 1
            elif text.strip():
                source["unmatched_lines"] += 1
                if any(w in low for w in ("error", "cannot", "permission denied", "failed", "no such file")):
                    source["unlabelled_lines_with_failure_words"] += 1
                    note(sink, source, {"line": number}, "a line with a failure word that matches no event shape: counted, never a failure", text=text)
    if source["status"] == "parsed" and source["events"] == 0:
        source["status"] = "unsupported"
        source["reason"] = "no line starts with a date, a time and a level word this adapter knows: failures are not counted from this log"
    elif source["status"] == "parsed" and source["unmatched_lines"]:
        source["status"] = "partial"
        source["reason"] = "%d line(s) match no recognised event shape: counted, kept unlabelled, never counted as failures" % source["unmatched_lines"]
    return source


def read_hash_list(src, rel, sink):
    """One 'digest  path' line per file (the md5sum, sha1sum and sha256sum forms, or 'ALGORITHM (path) = digest'). Each line is a
    `hash_claim` record: a claim about a file of the source host, named by its path there; whether the delivery holds that file
    is the join's to say. The algorithm is read from the digest's length and checked against the list's name."""
    base = parent_of(rel)
    if name_of(base) == "hash_executables":                  # UAC writes the list in its own directory beside [root]
        base = parent_of(base)
    expected = HASH_LIST_NAMES.get(name_of(rel).lower())
    source = new_source(rel, "UAC", "hash_list", "hash_list", run=base or ".", directory=base or ".", lines=0, algorithm=expected, unmatched_lines=0)
    reason = binary_reason(src, rel)
    if reason:
        source.update(status="unsupported", reason=reason)
        return source
    try:
        fh = io.TextIOWrapper(src.open_binary(rel), encoding="utf-8", errors="surrogateescape", newline="")
    except OSError as exc:
        source.update(status="unreadable", reason=describe(exc))
        return source
    with fh:
        number = 0
        while True:
            if out_of_time():
                source.update(status="partial", reason="the time limit stopped the read after line %d" % number)
                break
            try:
                line = fh.readline(REC_LINE)
            except OSError as exc:
                source.update(status="partial", reason="the read stopped at line %d (%s)" % (number + 1, describe(exc)))
                break
            if not line:
                break
            number += 1
            source["lines"] = number
            if len(line) == REC_LINE and not line.endswith("\n"):
                while True:
                    rest = fh.readline(REC_LINE)
                    if not rest or rest.endswith("\n"):
                        break
            text = line.rstrip("\r\n")
            if not text.strip():
                continue
            found = HASH_LINE.match(text)
            digest = path = None
            if found:
                digest, path = found.group("hex"), found.group("path")
            else:
                bsd = HASH_LINE_BSD.match(text)
                if bsd:
                    digest, path = bsd.group("hex"), bsd.group("path")
            if digest is None:
                source["unmatched_lines"] += 1
                continue
            algorithm = HASH_LENGTHS.get(len(digest))
            flags = []
            if expected and algorithm != expected:
                flags.append("digest_length_disagrees_with_the_list_name")
                note(sink, source, {"line": number}, "a %d-character digest in a list named for %s" % (len(digest), expected))
            claim = hash_claim(algorithm, digest) if algorithm else None
            emit(sink, source, run=base or ".", base=base, kind="hash_claim", outcome="recorded", locator={"log": rel, "line": number},
                 source_path_claim=path, delivered_path_claim=None, hash_claims={algorithm: claim} if claim else {}, flags=flags)
    if source["unmatched_lines"] and source["status"] == "parsed":
        source["status"] = "partial"
        source["reason"] = "%d line(s) are not a digest and a path: counted, read as nothing" % source["unmatched_lines"]
    return source


def jsonl_rows(fh, source, sink, label):
    """(line number, row) for each JSON object of a JSON Lines stream; a line that is not valid JSON, not an object, or too long
    is counted and located and the stream goes on. A JSON array is not JSON Lines: it ends the stream with `unsupported`."""
    number = 0
    first = True
    while True:
        if out_of_time():
            source.update(status="partial", reason="the time limit stopped the read of %s after line %d" % (label, number))
            return
        try:
            line = fh.readline(REC_LINE)
        except OSError as exc:
            source.update(status="partial", reason="the read of %s stopped at line %d (%s)" % (label, number + 1, describe(exc)))
            return
        if not line:
            return
        number += 1
        if len(line) == REC_LINE and not line.endswith("\n"):
            source["malformed_rows"] += 1
            note(sink, source, {"file": label, "line": number}, "a line longer than %d bytes: read no further" % REC_LINE)
            while True:
                rest = fh.readline(REC_LINE)
                if not rest or rest.endswith("\n"):
                    break
            continue
        if not line.strip():
            continue
        if first and line.lstrip().startswith("["):
            source.update(status="unsupported", reason="%s is a JSON array, not JSON Lines: nothing was read from it" % label)
            return
        first = False
        try:
            row = json.loads(line)
        except (ValueError, RecursionError):
            source["malformed_rows"] += 1
            note(sink, source, {"file": label, "line": number}, "not valid JSON")
            continue
        if not isinstance(row, dict):
            source["non_object_rows"] += 1
            note(sink, source, {"file": label, "line": number}, "a JSON line that is not an object")
            continue
        yield number, row


def upload_records(value, depth=0):
    """Every upload record under `value`: a dictionary with a key only an upload record has (StoredName, UploadId, StoredSize,
    Components). Velociraptor puts an upload in a result row as a nested record."""
    if depth > 4:
        return
    if isinstance(value, dict):
        if any(k in value for k in UPLOAD_MARKERS):
            yield value
            return
        for child in value.values():
            yield from upload_records(child, depth + 1)
    elif isinstance(value, list):
        for child in value[:1000]:
            yield from upload_records(child, depth + 1)


def has_error(value):
    err = value.get("Error")
    return err not in (None, "", [], {})


def text_of(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)


def claims_of(upload):
    """The digests a Velociraptor upload record carries, under the key spellings its versions use."""
    out = {}
    for algorithm, keys in (("sha256", ("sha256", "Sha256", "SHA256")), ("md5", ("md5", "Md5", "MD5")), ("sha1", ("sha1", "Sha1", "SHA1"))):
        for key in keys:
            if isinstance(upload.get(key), str) and upload[key].strip():
                claim = hash_claim(algorithm, upload[key])
                if claim:
                    out[algorithm] = claim
                break
    return out


def read_velociraptor(src, directory, files, found, sink):
    """One Velociraptor collection container: a directory holding uploads.json and/or collection_context.json. The version this
    pack pins writes a failed upload to no row of uploads.json: it is a result row's upload record with an Error, and an ERROR line
    of log.json. So the container is read whole only when results/*.json and log.json were read as well, and a source that is not
    there makes the container `partial`: the outcomes it would have recorded are unknown, which is not zero."""
    anchor = files.get("uploads") or files.get("context")
    source = new_source(anchor, "Velociraptor", "velociraptor_container", "velociraptor_container", run=directory or ".", directory=directory or ".", container=directory or ".",
                        sources={}, non_object_rows=0, uploads_rows=0, rows_stored_smaller_than_file=0, result_rows=0, upload_records=0,
                        rows_with_upload_error=0, log_levels={}, error_lines=0, warning_lines=0, artefacts={})
    partial = []

    def part(name, status, **extra):
        source["sources"][name] = {"status": status, **extra}
        if status != "parsed":
            partial.append("%s is %s" % (name, status))

    def sub_status(sub):
        if sub["status"] != "parsed":
            return sub["status"]
        return "partial" if sub["malformed_rows"] or sub["non_object_rows"] else "parsed"

    def sub_of():
        return {"log": source["log"], "status": "parsed", "malformed_rows": 0, "non_object_rows": 0, "problems": source["problems"], "problems_total": 0}

    def fold(sub):
        source["malformed_rows"] += sub["malformed_rows"]
        source["non_object_rows"] += sub["non_object_rows"]
        source["problems_total"] += sub["problems_total"]

    if files.get("uploads"):
        rel = files["uploads"]
        reason = binary_reason(src, rel)
        if reason:
            part("uploads.json", "unsupported", reason=reason)
        else:
            sub = sub_of()
            try:
                fh = open_text(src, rel)
            except OSError as exc:
                part("uploads.json", "unreadable", reason=describe(exc))
            else:
                with fh:
                    for number, row in jsonl_rows(fh, sub, sink, "uploads.json"):
                        source["uploads_rows"] += 1
                        size, stored = row.get("file_size"), row.get("uploaded_size")
                        flags = []
                        if isinstance(size, int) and isinstance(stored, int) and stored < size and row.get("Type") != "idx":
                            source["rows_stored_smaller_than_file"] += 1
                            flags.append("stored_smaller_than_file")
                        if row.get("Type") == "idx":
                            flags.append("sparse_index")
                        vfs = row.get("vfs_path")
                        emit(sink, source, directory or ".", directory, kind="upload", outcome="uploaded", locator={"log": rel, "line": number},
                             source_path_claim=None, delivered_path_claim=vfs if isinstance(vfs, str) else None,
                             size_claim=stored if isinstance(stored, int) and not isinstance(stored, bool) and stored >= 0 else None,
                             logical_size_claim=size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else None,
                             hash_claims={}, times={k: row[k] for k in ("Timestamp", "started") if k in row}, fields=row, flags=flags)
                fold(sub)
                part("uploads.json", sub_status(sub), **({"reason": sub["reason"]} if "reason" in sub else {}))
    else:
        part("uploads.json", "not_found", reason="no uploads.json beside collection_context.json: the container's index of stored files is absent")

    names = sorted(found["velo_results"].get(directory, []), key=os.fsencode)
    if not names:
        part("results/*.json", "not_found", reason="no results/*.json beside the container's index: a failed upload is recorded there in this version")
    else:
        sub = sub_of()
        for rel in names:
            artefact = name_of(rel)[:-len(".json")]
            if len(source["artefacts"]) < 100000:
                source["artefacts"].setdefault(artefact, 0)
            try:
                fh = open_text(src, rel)
            except OSError as exc:
                note(sink, source, {"file": rel}, "a results file could not be opened: %s" % describe(exc))
                sub["status"] = "partial"
                continue
            with fh:
                for number, row in jsonl_rows(fh, sub, sink, name_of(rel)):
                    source["result_rows"] += 1
                    if artefact in source["artefacts"]:
                        source["artefacts"][artefact] += 1
                    for upload in upload_records(row):
                        source["upload_records"] += 1
                        failed = has_error(upload)
                        if failed:
                            source["rows_with_upload_error"] += 1
                        stored_name = upload.get("StoredName")
                        components = upload.get("Components")
                        delivered = stored_name if isinstance(stored_name, str) and stored_name else (
                            "/".join(str(c) for c in components) if isinstance(components, list) and components and all(isinstance(c, (str, int)) for c in components) else None)
                        path = next((upload[k] for k in UPLOAD_PATH_KEYS if isinstance(upload.get(k), str) and upload.get(k)), None)
                        size, stored = upload.get("Size"), upload.get("StoredSize")
                        flags = []
                        if isinstance(size, int) and isinstance(stored, int) and stored < size:
                            flags.append("stored_smaller_than_file")
                        emit(sink, source, directory or ".", directory, kind="upload_result", outcome="upload_error" if failed else "uploaded",
                             counts_as_failure=failed, locator={"log": rel, "line": number}, artefact=artefact, source_path_claim=path,
                             delivered_path_claim=delivered, accessor=upload.get("Accessor") if isinstance(upload.get("Accessor"), str) else None,
                             size_claim=stored if isinstance(stored, int) and not isinstance(stored, bool) and stored >= 0 else None,
                             logical_size_claim=size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else None,
                             hash_claims=claims_of(upload), reason=text_of(upload.get("Error")) if failed else None, fields=upload, flags=flags)
        fold(sub)
        part("results/*.json", sub_status(sub), files=len(names), **({"reason": sub["reason"]} if "reason" in sub else {}))

    log_rel = found["velo_logs"].get(directory)
    if not log_rel:
        part("log.json", "not_found", reason="no log.json beside the container's index: the collection's own errors are recorded there")
    else:
        sub = sub_of()
        try:
            fh = open_text(src, log_rel)
        except OSError as exc:
            part("log.json", "unreadable", reason=describe(exc))
        else:
            with fh:
                for number, row in jsonl_rows(fh, sub, sink, "log.json"):
                    level = row.get("level")
                    level = level if isinstance(level, str) else "?"
                    word = level.upper() if level.upper() in LOG_LEVEL_WORDS else "other"
                    source["log_levels"][word] = source["log_levels"].get(word, 0) + 1
                    if level.upper() in ("ERROR", "WARN", "WARNING"):
                        is_error = level.upper() == "ERROR"
                        source["error_lines" if is_error else "warning_lines"] += 1
                        emit(sink, source, directory or ".", directory, kind="log_event", outcome="error" if is_error else "warning",
                             counts_as_failure=is_error, locator={"log": log_rel, "line": number}, text=text_of(row.get("message")))
            fold(sub)
            part("log.json", sub_status(sub), **({"reason": sub["reason"]} if "reason" in sub else {}))
    if partial:
        source["status"] = "partial" if any(v["status"] == "parsed" for v in source["sources"].values()) else "unsupported"
        source["reason"] = "; ".join(partial) + ": the failure count is not determined from this container"
    return source


def read_collection(src, found, sink):
    """Every recognised record of a census, in a fixed order: KAPE runs, UAC logs and hash lists, Velociraptor containers. Returns
    the source summaries (one per log, one per container), each with its adapter, its status and why."""
    sources = []
    for (directory, run_id), logs in sorted(found["kape"].items(), key=lambda kv: (os.fsencode(kv[0][0]), os.fsencode(kv[0][1]))):
        run = run_id
        if "copy" in logs:
            sources.append(read_kape_csv(src, logs["copy"], "copy", run, directory, sink))
        if "skip" in logs:
            sources.append(read_kape_csv(src, logs["skip"], "skip", run, directory, sink))
        if "console" in logs:
            sources.append(read_console(src, logs["console"], run, directory, sink))
    for rel in found["uac_logs"]:
        sources.append(read_uac_log(src, rel, sink))
    for rel in found["uac_hashes"]:
        sources.append(read_hash_list(src, rel, sink))
    for directory, files in sorted(found["velociraptor"].items(), key=lambda kv: os.fsencode(kv[0])):
        sources.append(read_velociraptor(src, directory, files, found, sink))
    return sources


# ---- the join: a record to the delivered file it names --------------------------------------------------------------------


def path_parts(text):
    """The components of a path as a collector wrote it, whichever separator, without a drive prefix (C: or C$)."""
    parts = [p for p in re.split(r"[\\/]+", text) if p]
    if parts and re.fullmatch(r"[A-Za-z][:$]", parts[0]):
        parts = parts[1:]
    return parts


def percent_quote(part):
    return part.replace("%", "%25").replace(":", "%3A")


def candidate_paths(rec):
    """The delivered paths (relative to the record's own directory) a record may name, with how each was derived. A KAPE copy row
    names a destination whose tail is the path in the delivered tree; a Velociraptor row a stored name under uploads/; a UAC hash
    list a file of the source host that the collector's [root] directory would hold."""
    collector, kind = rec.get("collector"), rec.get("kind")
    claim = rec.get("delivered_path_claim")
    if collector == "KAPE" and kind == "copy" and isinstance(claim, str):
        return "suffix", path_parts(claim)
    if collector == "Velociraptor" and isinstance(claim, str):
        raw = [p for p in claim.split("/") if p]
        forms = []
        for lead in ((), ("uploads",), ("uploads", "auto")):
            where = "/".join(lead) or "the container"
            forms.append((lead + tuple(raw), "stored name under " + where))
            forms.append((lead + tuple(percent_quote(p) for p in raw), "stored name with the colon and the percent sign escaped, under " + where))
        return "exact", forms
    if collector == "UAC" and kind == "hash_claim" and isinstance(rec.get("source_path_claim"), str):
        parts = [p for p in rec["source_path_claim"].split("/") if p]
        return "exact", [(("[root]",) + tuple(parts), "UAC's [root] convention: a hypothesis, not a record of the collector")]
    return None, None


def resolve(census, rec):
    """{status, rel, matched_by, depth, candidates}: `found` (one file), `ambiguous` (several files differing by case, or only the
    file name matches), `missing` (nothing, and the census is complete), `unknown` (nothing, and the census is not complete), or
    `no_claim`. A link or a special file at the name is `not_regular`. The longest tail of a KAPE destination wins; a tail of one
    component is a weak match and is never `found`."""
    how, spec = candidate_paths(rec)
    base = rec.get("directory") or ""
    base = "" if base == "." else base
    if how is None:
        return {"status": "no_claim", "rel": None, "matched_by": None, "depth": 0, "candidates": []}
    hits = []
    if how == "suffix":
        parts = spec
        if not parts:
            return {"status": "no_claim", "rel": None, "matched_by": None, "depth": 0, "candidates": []}
        for i in range(len(parts)):
            depth = len(parts) - i
            hits = census.lookup(join_rel(base, "/".join(parts[i:])))
            if hits:
                weak = depth == 1 and len(parts) > 1
                return finish(hits, "the destination's last %d component(s) under the log's directory%s" % (depth, " (only the file name matches)" if weak else ""),
                              depth, weak)
    else:
        for parts, why in spec:
            hits = census.lookup(join_rel(base, "/".join(parts)))
            if hits:
                return finish(hits, why, len(parts), False)
    return {"status": "missing" if census.complete else "unknown", "rel": None, "matched_by": None, "depth": 0, "candidates": []}


def finish(hits, why, depth, weak):
    rels = sorted({h[0] for h in hits}, key=os.fsencode)
    regular = [h for h in hits if h[2] == "f"]
    if weak:
        return {"status": "ambiguous", "rel": rels[0] if len(rels) == 1 else None, "matched_by": why, "depth": depth, "candidates": rels[:REC_FIRST],
                "reason": "only the file name matches"}
    if len(rels) > 1:
        return {"status": "ambiguous", "rel": None, "matched_by": why, "depth": depth, "candidates": rels[:REC_FIRST],
                "reason": "%d delivered files differ from each other only by case" % len(rels)}
    if len(hits) > len(rels):
        return {"status": "ambiguous", "rel": None, "matched_by": why, "depth": depth, "candidates": rels[:REC_FIRST],
                "reason": "the name appears %d times (an archive can hold one name twice)" % len(hits)}
    if not regular:
        return {"status": "not_regular", "rel": rels[0], "matched_by": why, "depth": depth, "candidates": rels,
                "reason": "the delivered entry is a link or a special file: it is not followed"}
    return {"status": "found", "rel": rels[0], "size": regular[0][1], "matched_by": why, "depth": depth, "candidates": rels}


# ---- hashing a delivered file in one pass ------------------------------------------------------------------------------------


class HashStopped(Exception):
    def __init__(self, read):
        super().__init__("the time limit ended the read")
        self.read = read


def digest_object(name):
    try:
        return hashlib.new(name, usedforsecurity=False)
    except (TypeError, ValueError):
        try:
            return hashlib.new(name)
        except ValueError:
            return None


def hash_file(src, rel, algorithms):
    """{algorithm: hex} for the algorithms asked, always with sha256 (an independent digest beside the collector's own), and the
    bytes read, in one pass over the file. An algorithm this Python does not have is left out. Raises OSError, or HashStopped
    when the time limit ends the read."""
    wanted = ["sha256"] + [a for a in algorithms if a != "sha256"]
    objects = {a: digest_object(a) for a in wanted}
    objects = {a: o for a, o in objects.items() if o is not None}
    total = 0
    with src.open_binary(rel) as fh:
        while True:
            block = fh.read(REC_CHUNK)
            if not block:
                break
            total += len(block)
            for o in objects.values():
                o.update(block)
            if out_of_time():
                raise HashStopped(total)
    return {a: o.hexdigest() for a, o in objects.items()}, total


# ---- patterns the callers' questions use ---------------------------------------------------------------------------------------


def norm_text(text):
    return text.replace("\\", "/").casefold()


def glob_match(pattern, text):
    """`*` (any run, `/` included) and `?` (one character) over case-folded text with `/` for either separator: no regular
    expression, so a pattern cannot be made to take exponential time; the cost is at most the product of the two lengths."""
    p = t = 0
    star = -1
    mark = 0
    while t < len(text):
        if p < len(pattern) and (pattern[p] == "?" or pattern[p] == text[t]):
            p += 1
            t += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            mark = t
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            t = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)




# the path conventions and the name hints of collection_index, copied from it unchanged (tests/pack-triage-records.test.ts holds them equal)
DRIVE_BARE = re.compile(r"^[A-Za-z]$")
DRIVE_MARKED = re.compile(r"^([A-Za-z])(?:\$|:|%3[Aa])$")
# Greedy, so the split is at the LAST underscore: report.txt_Zone.Identifier has to give "report.txt" and
# "Zone.Identifier", not "report" and the rest.
STREAM_HINT = re.compile(r"^(.+)_(\$?[A-Za-z][\w.$-]{1,40})$")
KNOWN_STREAMS = {"zone.identifier", "summaryinformation", "documentsummaryinformation", "favicon", "encryptable",
                 "afp_afpinfo", "afp_resource", "com.dropbox.attributes", "com.apple.quarantine", "ads", "$data"}
PLAIN_SUFFIXES = {"plist", "json", "db", "txt", "log", "xml", "png", "jpg", "jpeg", "gif", "html", "htm", "css", "js", "sqlite", "dat", "bin", "md"}   # a "stream" that ends like a file
RESERVED = {"CON", "PRN", "AUX", "NUL"} | {"COM%d" % i for i in range(1, 10)} | {"LPT%d" % i for i in range(1, 10)}
# First directory names of a Unix-like root: a path that starts with one is read as rooted at /.
UNIX_TOP = {"etc", "var", "home", "usr", "opt", "tmp", "bin", "sbin", "lib", "lib64", "root", "srv", "mnt", "run", "boot", "dev",
            "proc", "sys", "media", "private", "Library", "Users", "Applications", "System", "Volumes"}
# What a name says about a file that holds, or is, a credential store. A name hint and nothing more.
CREDENTIAL_NAMES = {
    "shadow": "a password verifier file", "gshadow": "a password verifier file", "shadow-": "a password verifier file",
    "gshadow-": "a password verifier file", "master.passwd": "a password verifier file", "spwd.db": "a password verifier file",
    "pwd.db": "a password verifier file", ".htpasswd": "a password verifier file", "sam": "a Windows account database hive",
    "security": "a Windows security hive", "ntds.dit": "a directory database with password verifiers", "wallet.dat": "a wallet file",
    "keychain-2.db": "a keychain", "keychain-2.db-wal": "a keychain", "keychain-2.db-shm": "a keychain",
    "krb5.keytab": "a Kerberos key table", ".env": "an environment file that often holds secrets",
    "login data": "a browser saved-credential database", "login data for account": "a browser saved-credential database",
    "logins.json": "a browser saved-credential file", "key3.db": "a browser key database", "key4.db": "a browser key database",
    "cert9.db": "a browser certificate and key database", "signons.sqlite": "a browser saved-credential database",
    "cookies": "a browser cookie store", "cookies.sqlite": "a browser cookie store", "local state": "a browser key-wrapping file",
    "web data": "a browser form and card store", ".pgpass": "a saved-credential file", ".netrc": "a saved-credential file",
    ".git-credentials": "a saved-credential file", ".npmrc": "a saved-credential file", ".pypirc": "a saved-credential file",
    ".dockercfg": "a saved-credential file", "id_rsa.bak": "a private key file",
    "terraform.tfstate": "infrastructure state that holds secrets", "terraform.tfstate.backup": "infrastructure state that holds secrets",
    "credentials.xml": "a saved-credential file", "credentials": "a saved-credential file", "credentials.db": "a saved-credential database",
    "access_tokens.db": "a cloud access-token database", "accesstokens.json": "a cloud access-token file", "msal_token_cache.json": "a token cache",
    "token_cache.json": "a token cache", "wp-config.php": "a web application configuration that holds database credentials",
    "secrets.yaml": "a secrets file", "secrets.yml": "a secrets file", "secrets.json": "a secrets file", "tokens.json": "a token file", "vault.json": "a vault file",
    ".my.cnf": "a database client file that can hold a password", ".s3cfg": "a saved-credential file", ".boto": "a saved-credential file", "htpasswd": "a password verifier file",
    "lsass.dmp": "a process dump of the credential-holding LSASS process", "kubeconfig": "a saved-credential file", ".vault-token": "a token file",
}
CREDENTIAL_SUFFIXES = {".p8": "a private key file", ".jceks": "a Java key store", ".pkcs12": "a key and certificate store", ".asc": "an armoured key or message file",
                       ".ovpn": "a VPN profile that can hold keys", ".rdp": "a remote-desktop file that can hold a saved credential", ".tfvars": "variables that can hold secrets",
                       ".ppk": "a private key file", ".p12": "a key and certificate store", ".pfx": "a key and certificate store",
                       ".pem": "a key or certificate file", ".key": "a key file", ".keytab": "a Kerberos key table", ".kdb": "a password database",
                       ".kdbx": "a password database", ".jks": "a Java key store", ".keystore": "a Java key store", ".gpg": "an encrypted file",
                       ".keychain": "a keychain", ".keychain-db": "a keychain", ".bek": "a BitLocker key file", ".kirbi": "a Kerberos ticket",
                       ".ccache": "a Kerberos credential cache"}
CREDENTIAL_DIRECTORIES = {".gnupg": "a GnuPG directory", ".aws": "an AWS credentials directory", ".azure": "an Azure credentials directory",
                          "gcloud": "a Google Cloud credentials directory", ".kube": "a Kubernetes configuration directory", ".docker": "a Docker configuration directory",
                          ".vnc": "a VNC configuration directory",  "protect": "a DPAPI master-key store",
                          "credentials": "a Windows credential store", "vault": "a Windows vault", "private-keys-v1.d": "a GnuPG private key store"}


def credential_hint(name, parents):
    """What a file's name (and its directories) say it is, or None. `parents` are the directory names above it, lower case."""
    low = name.lower()
    found = CREDENTIAL_NAMES.get(low)
    if found is None and low.startswith(("sam.log", "security.log", "software.log", "system.log")):
        found = "a hive transaction log (it can hold credential material)"
    if found is None and low.startswith("id_") and not low.endswith(".pub"):
        found = "a private key file"
    if found is None and low.startswith("ssh_host_") and low.endswith("_key"):
        found = "a host private key file"
    if found is None and low == "config.json" and ".docker" in parents:
        found = "a saved-credential file"
    if found is None and low == "config" and ".kube" in parents:
        found = "a saved-credential file"
    if found is None and low.startswith("shadow"):
        found = "a password verifier file"
    if found is None and "recovery" in low and ("bitlocker" in low or "key" in low) and low.endswith((".txt", ".bek", ".csv")):
        found = "a BitLocker recovery key file"
    if found is None:
        found = CREDENTIAL_SUFFIXES.get(os.path.splitext(low)[1])
    if found is None and low != "known_hosts" and low != "config" and not low.endswith(".pub") and ".ssh" in parents:
        found = "an SSH directory file"
    if found is None:
        for directory in parents:
            if directory in CREDENTIAL_DIRECTORIES:
                found = CREDENTIAL_DIRECTORIES[directory]
                break
    return found


def source_path_hypothesis(rel):
    """What a convention would make of a path in the collection: a hypothesis with its method, its confidence, what it could
    not explain and the other readings. It is never an observation; only a collector's own mapping observes a source path."""
    parts = [p for p in rel.split(os.sep) if p not in ("", ".")]
    first = parts[0] if parts else ""
    rest = parts[1:]
    alternatives, unresolved = [], []
    marked = DRIVE_MARKED.match(first)
    uac_at = parts.index("[root]") if "[root]" in parts[:-1] else -1
    if len(parts) < 2:
        path = "/".join(parts)
        method, confidence = "none: a file at the top of the collection has no directory to read a convention from", "none"
    elif uac_at >= 0:
        path = "/" + "/".join(parts[uac_at + 1:])
        unresolved = parts[:uac_at]
        method = "UAC's [root] directory holds the collected files below /" + (" (the directories above it are unresolved)" if uac_at else "")
        confidence = "medium" if uac_at == 0 else "low"
    elif marked or DRIVE_BARE.match(first):
        letter = (marked.group(1) if marked else first).upper()
        path = letter + ":\\" + "\\".join(rest)
        if marked:
            method, confidence = "the first directory is spelled like a drive (%s)" % first, "medium"
        else:
            method, confidence = "the first directory is a single letter, read as a drive letter", "low"
        alternatives.append({"path": "/" + "/".join(parts), "if": "the first directory is an ordinary directory that happens to be named %s" % first})
    elif first == "uploads":
        path = "/".join(parts)
        method, confidence = "none: the delivered path, unchanged (uploads/<accessor>/<path> needs the collector's own index to read)", "none"
        unresolved = parts[:3] if len(parts) > 2 else parts[:1]
        if len(parts) > 3 and DRIVE_MARKED.match(parts[2]):
            alternatives.append({"path": DRIVE_MARKED.match(parts[2]).group(1).upper() + ":\\" + "\\".join(parts[3:]),
                                 "if": "uploads/<accessor>/<drive> is Velociraptor's layout (check the collection's own records)"})
    elif first in UNIX_TOP:
        path = "/" + "/".join(parts)
        method, confidence = "the first directory is a top-level directory of a Unix-like file system, read as rooted at /", "low"
        if first == "root":
            unresolved = ["root"]
            alternatives.append({"path": "/" + "/".join(rest), "if": "root is a collector's wrapper directory and not the /root home directory"})
    else:
        path = "/".join(parts)
        method, confidence = "none: the delivered path, unchanged; no convention recognised", "none"
    return {"path": path, "method": method, "confidence": confidence, "unresolved_components": unresolved, "alternatives": alternatives}




def split_stream(path):
    """(base, stream) for a source path with NTFS stream syntax (C:\\dir\\file:name), else (path, None). A drive's own colon is not one."""
    if not isinstance(path, str):
        return path, None
    start = 2 if re.match(r"^[A-Za-z]:[\\/]", path) else 0
    last = max(path.rfind("\\"), path.rfind("/"))
    colon = path.find(":", max(start, last + 1))
    if colon <= 0 or colon == len(path) - 1:
        return path, None
    return path[:colon], path[colon + 1:]


def component_notes(rel):
    """What in a delivered path a reader could misread: components that are not UTF-8 (escaped here as surrogates), and components
    that carry percent-escapes (a collector's way of writing ':' and the like)."""
    not_utf8, escaped = [], []
    for part in rel.replace(os.sep, "/").split("/"):
        if undecodable(part):
            not_utf8.append(part)
        elif re.search(r"%[0-9A-Fa-f]{2}", part):
            escaped.append(part)
    return not_utf8, escaped


def percent_decode(part):
    return re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 0x80 else m.group(0), part)


def source_path_shown(rec):
    """The source path a record claims, normalised only so that two claims of one file compare equal: '/' for either separator, no
    trailing stream, the case kept (the caller folds it when it compares)."""
    claim = rec.get("source_path_claim")
    if not isinstance(claim, str):
        return None
    base, _stream = split_stream(claim)
    return base.replace("\\", "/")


def path_hint(*paths):
    """The first credential-store hint any of the given paths carries (by the name and the directories above it), or None."""
    for path in paths:
        if isinstance(path, str) and path:
            parts = [p for p in re.split(r"[\\/]+", path) if p]
            if parts:
                found = credential_hint(parts[-1], [p.lower() for p in parts[:-1]])
                if found:
                    return found
    return None


def withhold_digest(value, where):
    """A digest of a file that is a credential store never leaves in an answer or a table: it goes to the values file (a job run with
    secret_output and write_values) and what is printed names its length and a finding id. Returns the marker."""
    WITHHELD["count"] += 1
    fid = "W%06d" % WITHHELD["count"]
    if VALUES[0] is not None:
        VALUES[0].add(fid, {"where": where}, value)
    return "<digest of a credential store withheld, %d characters, %s>" % (len(value), fid)


def guard_digests(rec):
    """For a record that names a credential store, the collector's own digests are withheld from the record (the comparison still
    runs on the real ones, in the caller)."""
    hint = path_hint(rec.get("source_path_claim"), rec.get("delivered_path_claim"))
    if hint and rec.get("hash_claims"):
        where = "record %s of %s" % ((rec.get("locator") or {}).get("row") or (rec.get("locator") or {}).get("line"), rec.get("log"))
        rec["hash_claims"] = {algorithm: withhold_digest(value, where) for algorithm, value in rec["hash_claims"].items()}
        rec["flags"] = list(rec.get("flags") or []) + ["digest_withheld_credential_store"]
        rec["credential_store_hint"] = hint
    return rec

# ---- END RECORDS BLOCK -----------------------------------------------------------------------------------------------


PARSER = "collection_manifest_parse/1"
TOOL = "collection_manifest_parse"
VALUES_NAME = "collection-manifest-parse-values.jsonl"
KNOWN_PARAMETERS = ("root", "collectors", "limit", "time_limit_seconds", "write_values")
COLLECTOR_NAMES = {"kape": "KAPE", "uac": "UAC", "velociraptor": "Velociraptor", "cylr": "CyLR"}
FAILURE_SOURCES = ("skip_log", "uac_log", "velociraptor_container")


class ParseSink(Sink):
    """Writes each record to the records table as it is read and keeps the counts the answer states."""

    def __init__(self, records, problems):
        super().__init__()
        self.table, self.problem_table = records, problems
        self.by_kind, self.by_outcome, self.by_algorithm = collections.Counter(), collections.Counter(), collections.Counter()
        self.failures = collections.Counter()           # (collector, run) -> records the collector's own words record as a failure
        self.with_claim = collections.Counter()

    def record(self, rec):
        self.count += 1
        rec["n"] = self.count
        guard_digests(rec)
        self.by_kind[rec["kind"]] += 1
        self.by_outcome[rec["outcome"]] += 1
        for algorithm in rec.get("hash_claims") or {}:
            self.by_algorithm[algorithm] += 1
        if rec.get("hash_claims"):
            self.with_claim["hash"] += 1
        if rec.get("size_claim") is not None:
            self.with_claim["size"] += 1
        if rec["kind"] == "skip" or rec.get("counts_as_failure"):
            self.failures[(rec["collector"], rec["run"])] += 1
        self.table.add(rec)

    def problem(self, row):
        self.problem_table.add({"kind": "record_problem", **row})


def main():
    install_signal_handlers()
    args = read_args()
    root = want_str(args, "root", "root is required: the collection directory")
    limit = want_int(args, "limit", DEFAULT_LIMIT)
    seconds = want_int(args, "time_limit_seconds", 1500, 1, 3400)
    wanted = args.get("collectors")
    if wanted is not None:
        if not isinstance(wanted, list) or not wanted or any(not isinstance(w, str) or w.lower() not in COLLECTOR_NAMES for w in wanted):
            fail("collectors is a list of: %s" % ", ".join(sorted(COLLECTOR_NAMES)))
        wanted = {COLLECTOR_NAMES[w.lower()] for w in wanted}
    try:
        VALUES[0] = SecretValues(want_bool(args, "write_values"), VALUES_NAME, TOOL)
    except SecretValuesRefused as exc:
        fail(str(exc))
    if not os.path.isdir(root):
        fail("no such directory" if not os.path.isfile(root) else
             "root is a file: give the directory that holds it (a collector's record is read from its directory)", root=root)
    start_clock(seconds)
    problems = Table(TOOL + "-problems", FIRST_PROBLEMS)
    records = Table(TOOL + "-records", limit, always=True)
    records.open_now()                      # before the walk: a root that holds the table's own file must not list it
    census = Census()
    walk_census(root, census, skip=is_own)
    found = discover(census)
    if wanted is not None:
        found["kape"] = found["kape"] if "KAPE" in wanted else {}
        found["uac_logs"] = found["uac_logs"] if "UAC" in wanted else []
        found["uac_hashes"] = found["uac_hashes"] if "UAC" in wanted else []
        found["velociraptor"] = found["velociraptor"] if "Velociraptor" in wanted else {}
    sink = ParseSink(records, problems)
    sources = read_collection(DirSource(root), found, sink)

    top_archives = sum(1 for rel, _size, kind in census.entries() if kind == "f" and os.sep not in rel and "/" not in rel
                       and os.path.splitext(rel)[1].lower() in ARCHIVE_EXT)
    runs = {}
    for s in sources:
        runs.setdefault((s["collector"], s["run"], s.get("directory", ".")), []).append(s)
    run_rows, all_known = [], bool(runs)
    for (collector, run, directory), group in runs.items():
        failure_sources = [s for s in group if s["kind"] in FAILURE_SOURCES]
        why = []
        if not failure_sources:
            why.append("no skip log, UAC log or Velociraptor container was read for this run")
        why += ["%s is %s" % (s["log"], s["status"]) for s in failure_sources if s["status"] != "parsed"]
        if not census.complete:
            why.append("the walk was incomplete")
        if top_archives:
            why.append("%d archive(s) at the top of the delivery were not opened" % top_archives)
        known = not why
        all_known = all_known and known
        run_rows.append({"collector": collector, "run": run, "directory": directory, "collector_version": "unknown",
                         "version_basis": "no record this tool reads states it",
                         "sources": [s["log"] for s in group],
                         "failures_recorded": {"count": sink.failures[(collector, run)] if known else None,
                                               "basis": ("every failure-source record of this run was read whole: the rows its skip log records as skipped (KAPE), the ERR "
                                                         "lines (UAC) and the upload errors and ERROR lines (Velociraptor). A skip is the collector's own outcome, not a "
                                                         "judgement, and the count says nothing about what a record omits" if known else
                                                         "not determined (%s). This is not zero failures" % "; ".join(why[:6])),
                                               "seen": sink.failures[(collector, run)]}})
    unsupported = [{"collector": "CyLR", "adapter": ADAPTERS["cylr"]["schema"], "supported": False}] if (wanted is None or "CyLR" in wanted) else []
    tables = {"records": records.finish(), "problems": problems.finish()}
    values = VALUES[0]
    sources_table = Table(TOOL + "-sources", limit)
    for s in sources:
        sources_table.add(s)
    tables["sources"] = sources_table.finish()

    problem_lines = []
    if census.stopped:
        problem_lines.append("the walk stopped early: %s" % census.stopped["reason"])
    if census.errors_total:
        problem_lines.append("%d walk or read error(s)" % census.errors_total)
    if census.capped:
        problem_lines.append("the census reached its cap of %d entries" % census.cap)
    problem_lines += ["%s is %s" % (s["log"], s["status"]) for s in sources if s["status"] != "parsed"]
    status = "complete" if not problem_lines else "partial"
    basis = ("every directory was listed and every recognised record was read whole" if status == "complete" else
             "; ".join(problem_lines[:10]) + ("; and %d more (see sources)" % (len(problem_lines) - 10) if len(problem_lines) > 10 else ""))
    total_failures = sum(r["failures_recorded"]["seen"] for r in run_rows)
    out = {
        "tool": TOOL, "parser": PARSER, "root": shown(root, "root"), "status": status, "status_basis": basis,
        "ignored_parameters": ignored_parameters(args, KNOWN_PARAMETERS),
        "adapters": {k: {kk: vv for kk, vv in v.items() if vv is not None} for k, v in ADAPTERS.items()},
        "adapters_basis": "the schemas this tool reads, by collector and version where one is known; a record in another shape is partial or unsupported "
                          "(counted, kept whole where it is a row), never zero failures",
        "census": {"files": census.files, "directories": census.dirs, "symbolic_links_not_followed": census.links, "special_files_not_read": census.special,
                   "errors": census.errors_total, "first_errors": [{k: shown(v, "census error") if k == "path" else v for k, v in e.items()} for e in census.errors],
                   "stopped": census.stopped, "capped": census.capped, "complete": census.complete},
        "collectors_recognised": sorted({s["collector"] for s in sources}),
        "runs": run_rows,
        "failures_recorded": {"count": total_failures if all_known else None, "seen": total_failures,
                              "basis": ("every run's failure-source records were read whole" if all_known else
                                        "not determined for every run (see runs[].failures_recorded.basis); this is not zero failures; `seen` is how many were read all the same")},
        "records_total": sink.count,
        "records_by_kind": dict(sorted(sink.by_kind.items())),
        "records_by_outcome": dict(sorted(sink.by_outcome.items())),
        "records_with": {"hash_claim": sink.with_claim["hash"], "size_claim": sink.with_claim["size"]},
        "hash_claims_by_algorithm": dict(sorted(sink.by_algorithm.items())),
        "hash_claims_basis": "each digest is the collector's own, with the algorithm it used; none is equated with another algorithm, and none is checked here "
                             "(collection_manifest_verify does that, and measures an independent SHA-256 beside it)",
        "unsupported": unsupported,
        "logs_inside_collected_data": [inline_text(shown(x, "log inside collected data")) for x in found["inside_collected"][:FIRST_PROBLEMS]],
        "logs_inside_collected_data_total": len(found["inside_collected"]),
        "tables": tables,
        "withheld": {"strings_withheld": WITHHELD["count"], "values": values.summary()},
        "note": ("Canonical records, one per row or line a collector wrote, each with the locator of its raw row, the paths and digests as the collector wrote them "
                 "and what it says it did. A record is a claim by the collector, not a finding: whether the delivered file exists and matches is "
                 "collection_manifest_verify, and where a delivered file came from is collection_path_map. The whole of every table is in the file its entry names; "
                 "the pages below are its first rows."),
        "sources": sources_table.page,
        "problems": problems.page,
        "records": records.page,
    }
    write_answer(out)


if __name__ == "__main__":
    try:
        main()
    except (SystemExit, KeyboardInterrupt):
        raise
    except BaseException as exc:                  # a bug here is a JSON error that names it, not a traceback and a half-written answer
        fail("the tool stopped on an unexpected error (%s)" % type(exc).__name__, detail=str(exc))
