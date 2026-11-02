#!/usr/bin/env python3
"""Keep the clocks a collection carries apart, say what each one can and cannot tell, and compare them only where they name the same file.

A delivered collection has several clocks and none is the time of the event. This tool reads them as separate objects, each with
its own precision and its own zone (or the lack of one), and never merges them:

  - the archive's member times (clock 2): a zip header's DOS date and time (two-second steps, no zone: the local time of the machine
    that wrote the archive), a zip's extended-timestamp and NTFS extra fields where they are present (UTC, one second and 100 ns), a
    tar header's mtime (whole seconds, UTC) and a pax mtime (as many fractional digits as the writer wrote). The archive is read in
    one pass by the same bounded readers as the collection-intake recipe (the compressed stream's CRC and length, a second stream
    appended to the first, the end-of-archive marker and the 1 MiB bound on a metadata record), and nothing is extracted;
  - the delivered files' modification times (clock 3): read from the delivered tree itself, one lstat per entry, to the nanosecond
    (`modified_epoch_ns` is the raw value as a decimal string, because a JSON number past 2^53 does not survive a JavaScript or jq 1.6
    reader). The tree is walked here, with collection_index's rules (links recorded and never followed, nothing opened, special files
    counted), and not read from a census file: a census is another job's output with a producer version this tool would have to
    trust, while the lstat call is the same field read first-hand;
  - the collector's own record times (clock 1) and the acquisition interval (clock 4) are not read by this version of the tool.

It gives the interval of each clock (earliest and latest, with the raw value), the precision and the zone of each, a date
distribution reported as `apparent_flattening` when more than 90% of more than 20 files fall on one date (a count and no cause:
a reset mtime, a copy that stamped its own time, a build that set one date and a real burst of activity all look like this), a
per-file comparison of an archive member with the delivered file of the same name (joined by the name with NFC and case folding,
after `member_prefix` is removed), and the conflicts. A comparison says `equal`, `within_precision`, `consistent_with_zone_offset`
(a zip's zoneless time that matches the delivered time under some offset of whole quarter hours: any offset would, so it is not a
determination), `differs`, or that the join was ambiguous or found no file. `local_zone` (an IANA zone name) reads a zip's zoneless
times under that zone and names the times a clock change makes ambiguous or non-existent; without it no zone is assumed and a
zoneless time is never read as UTC.

What it does not say: why a time is what it is, whether the extractor or the collector set a delivered time, which clock is right,
or anything about the event. A histogram is a lead, not proof of lost metadata. A file the archive and the tree both hold under
names that differ (another prefix, another case or a renamed file) is listed as present on one side only.

SECRET-SAFE OUTPUT (docs/packs.md, "Secrets and sensitive output"). Paths are printed through the shared withholding block and
the output boundary; `write_values: true` (a job only) writes the real strings to `$OUT/collection-timestamps-values.jsonl`, mode
0600, created before anything is read.
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
    write_answer({"error": scrub(str(message)), "status": "failed", "status_basis": "the tool stopped with an error: %s" % scrub(str(message)), **extra})
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
                      "status": "failed", "status_basis": "stopped by signal %d before the answer was complete" % signum}))
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
            x, y = fa.read(CHUNK), fb.read(CHUNK)
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
    ("base64-shaped text", re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{15,}={1,2}(?![A-Za-z0-9+=])")),
    ("webhook URL", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("credential after a header", re.compile(r"(?i:(?:proxy-)?authorization[ \t]{0,3}[:=][ \t]{0,3}(?:basic|bearer|token|negotiate|digest)[ \t]{1,8})(?P<secret>[^\s'\",;]{1,2048})")),
    ("credential after a header", re.compile(r"(?i:(?:set-)?cookie[ \t]{0,3}:[ \t]{0,3})(?P<secret>[^\r\n]{1,1024})")),
    ("credential after a key name", re.compile(r"(?i:[?&]sig=)(?P<secret>[A-Za-z0-9%+/=]{16,})")),
    ("credential after a key name", re.compile(r"(?i:\bConvertTo-SecureString[ \t]{1,8}(?:-String[ \t]{1,8})?)(?P<secret>'[^'\r\n]{1,512}'|\"[^\"\r\n]{1,512}\"|[^\s;|]{1,512})")),
]
# A web token (`eyJ`, 8 or more name characters, then two to four `.`-joined parts) is found by `_web_token_spans`, not by an expression: tried at
# every `eyJ` of a run of name characters, an expression runs to the end of the run, fails there and starts again three characters on, so a
# text of `eyJ` repeated cost the square of its length (8,192 characters took 0.5 s, a window; 64 KiB took 6 s). The first `eyJ` of a run
# that has 8 name characters after it decides for the run, and a run is read once.
_WEB_RUN = re.compile(r"[A-Za-z0-9_=-]+")
_WEB_PART = re.compile(r"[A-Za-z0-9_=-]*")


def _web_token_spans(f):
    """(start, end) of each web-token-shaped text of `f`, left to right: what `eyJ[A-Za-z0-9_=-]{8,}(?:\\.[A-Za-z0-9_=-]*){2,4}` finds, in time
    linear in the text."""
    spans, pos = [], 0
    while True:
        at = f.find("eyJ", pos)
        if at < 0:
            return spans
        stop = _WEB_RUN.match(f, at).end()            # the run of name characters the `eyJ` is in, to its end
        parts, end = 0, stop
        if stop - (at + 3) >= 8:
            while parts < 4 and f.startswith(".", end):
                end = _WEB_PART.match(f, end + 1).end()
                parts += 1
        if parts >= 2:
            spans.append((at, end))
            pos = end
        else:
            pos = stop                                # no later `eyJ` of this run has more after it, or a different end


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
        spans += [(s, e, "web-token-shaped text") for s, e in _web_token_spans(f)]
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

import collections
import datetime
import decimal
import struct
import tarfile
import zipfile


# ---- BEGIN ARCHIVE BLOCK ---------------------------------------------------------------------------------------------
# Identical in the collection-intake recipe and collection_timestamps (tests/pack-triage-archive-block.test.ts holds the copies equal): the bounded
# readers of a zip and of a tar (plain, gzip, bzip2, xz) and the checks of how an archive ended. It needs open_regular (binary), describe, struct,
# tarfile and zipfile. Edit it in both, never in one.
def tar_kind(head):
    """How the bytes of a tar are wrapped, from the first bytes: gz, bz2, xz, or tar (not compressed)."""
    if head[:2] == b"\x1f\x8b":
        return "gz"
    if head[:3] == b"BZh":
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    return "tar"


def sniff(path, expired=None):
    """(format, why): zip, or tar (plain, gzip, bzip2 or xz), judged from the bytes; 7z is named and not read. A tar that is cut before its first
    header, or whose first header is a metadata record over the bound, is not 'not a tar': the reason says it could not be told."""
    try:
        with open_regular(path) as fh:
            head = fh.read(512)
    except OSError as exc:
        return None, "the file could not be read (%s)" % describe(exc)
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip", None
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return None, "a 7z archive: this recipe reads zip and tar; list it with archive-members and extract it with archive_extract"
    if head[257:262] == b"ustar" or tar_kind(head) != "tar":
        try:
            with open_regular(path) as raw:
                stream = TarStream(raw, tar_kind(head), expired or (lambda: False))
                with tarfile.open(fileobj=stream, mode="r|", tarinfo=BoundedTarInfo) as tf:
                    tf.next()
        except ClockStopped:
            return None, "the time limit ended the read of the first member header: could not tell"
        except TarMetaTooLarge as exc:
            return None, "the first member header is a metadata record over the bound (%s): could not tell" % exc
        except (tarfile.TarError, OSError, EOFError) as exc:
            if isinstance(exc, EOFError) or str(exc) in ("truncated header", "empty file", "unexpected end of data"):
                return None, "the archive ends inside or before its first member header (%s): could not tell" % describe(exc)
            return None, "not a tar archive (%s)" % describe(exc)
        return "tar", None
    return None, "neither a zip nor a tar by its first bytes"


class Stopped(Exception):
    pass


class ClockStopped(Stopped):
    """The clock a caller gave ran out while the archive was being read."""


class StreamDamaged(tarfile.ReadError):
    """The compressed stream around the tar is damaged (a header, a block, or the gzip CRC-32 or length)."""


class TarMetaTooLarge(tarfile.ReadError):
    """A pax or GNU long-name record is larger than any real one: it is refused before tarfile reads it whole into memory."""


MAX_META = 1 << 20                # the largest tar metadata record (pax header, GNU long name or link) that is read
STEP_IN = 1 << 16
STEP_OUT = 1 << 20                # one decompression call returns at most this much; the clock is looked at between calls
META_TYPES = (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK, tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE)


class BoundedTarInfo(tarfile.TarInfo):
    """A tar header that refuses a metadata record over MAX_META before tarfile reads it."""

    def _proc_member(self, tarfile_):
        if self.type in META_TYPES and self.size > MAX_META:
            raise TarMetaTooLarge("a tar metadata record of %d bytes, over the bound of %d" % (self.size, MAX_META))
        return super()._proc_member(tarfile_)


def gz_header_length(buf):
    """The length of the gzip header at the start of `buf`, None when `buf` is too short to tell; ValueError when it is not a gzip header."""
    if len(buf) < 10:
        return None
    if buf[0] != 0x1F or buf[1] != 0x8B or buf[2] != 8:
        raise ValueError("not a gzip header")
    flags, pos = buf[3], 10
    if flags & 4:
        if len(buf) < pos + 2:
            return None
        pos += 2 + (buf[pos] | buf[pos + 1] << 8)
    for bit in (8, 16):
        if flags & bit:
            end = buf.find(b"\0", pos)
            if end < 0:
                if len(buf) > MAX_META:
                    raise ValueError("the gzip header is longer than %d bytes" % MAX_META)
                return None
            pos = end + 1
    if flags & 2:
        pos += 2
    return pos if len(buf) >= pos else None


class TarStream:
    """The bytes of a tar for tarfile's stream reader. A compressed tar is decompressed here, by our own reader, in steps: each call to
    the decompressor may return at most STEP_OUT bytes (so a few KiB of input cannot become gigabytes in one call) and the clock is
    consulted between calls. For gzip the header is read here and the CRC-32 and length in the trailer are checked against the bytes
    the stream returned (tarfile does not keep them); what the check or the stream's end finds is told by `problem()`, after the
    tar inside has been read, so a damaged trailer around a readable tar is partial, not a refusal."""

    def __init__(self, raw, kind, expired):
        self.raw, self.kind, self.expired = raw, kind, expired
        self.chunk, self.pos = b"", 0
        self.raw_done = False
        self.error = None
        self.d = None
        self.name = {"gz": "gzip", "bz2": "bzip2", "xz": "xz"}.get(kind, kind)
        self.errors = ()
        self.stage = "header" if kind == "gz" else "body"          # gzip only: header, body, trailer (the deflate stream has ended)
        self.hbuf = bytearray()
        self.crc = self.size = 0
        self.trailer_error = None
        self.served = 0                                            # bytes of the tar returned so far, and the last of them (see block_at)
        self.tail = bytearray()
        self.rest = b""                                            # gzip: the bytes after the deflate stream that are not the trailer
        try:
            if kind == "gz":
                import zlib
                self.zlib = zlib
                self.d, self.errors = zlib.decompressobj(-15), (zlib.error,)
            elif kind == "bz2":
                import bz2
                self.d = bz2.BZ2Decompressor()
            elif kind == "xz":
                import lzma
                self.d, self.errors = lzma.LZMADecompressor(format=lzma.FORMAT_XZ), (lzma.LZMAError,)
        except ImportError as exc:
            raise tarfile.CompressionError("this Python has no %s module (%s)" % (self.name, exc))

    def _more(self):
        data = self.raw.read(STEP_IN)
        if not data:
            self.raw_done = True
        return data

    def _damaged(self, exc):
        self.error = StreamDamaged("the %s stream is damaged (%s)" % (self.name, exc))
        raise self.error from None

    def _gz_open(self):
        """Read the gzip header; the bytes after it go to the deflate stream. False when the stream ends inside the header."""
        while True:
            try:
                n = gz_header_length(self.hbuf)
            except ValueError as exc:
                self._damaged(exc)
            if n is not None:
                break
            more = self._more()
            if not more:
                return False
            self.hbuf += more
        self.pending_in = bytes(self.hbuf[n:])
        self.hbuf = bytearray()
        self.stage = "body"
        return True

    def _gz_trailer(self):
        """The deflate stream has ended: its CRC-32 and length are in the next 8 bytes."""
        rest = bytes(self.d.unused_data)
        while len(rest) < 8 and not self.raw_done:
            rest += self._more()
        self.stage = "trailer"
        if len(rest) < 8:
            self.trailer_error = "the gzip trailer is cut (%d of 8 bytes): the stream is not finished" % len(rest)
            return
        crc, size = struct.unpack("<II", rest[:8])
        self.rest = rest[8:]
        if crc != (self.crc & 0xFFFFFFFF):
            self.trailer_error = "the gzip CRC-32 is not that of the bytes the stream returned: the stream is damaged"
        elif size != (self.size & 0xFFFFFFFF):
            self.trailer_error = "the gzip trailer's length is not that of the bytes the stream returned: the stream is damaged"

    def _step(self):
        """Fill `chunk` with the next bytes; False when the stream has no more (finished, or cut)."""
        if self.error is not None:
            raise self.error
        if self.expired():
            raise ClockStopped()
        self.chunk, self.pos = b"", 0
        if self.kind == "tar":
            self.chunk = self.raw.read(STEP_OUT)
            return bool(self.chunk)
        if self.kind == "gz":
            if self.stage == "trailer":
                return False
            if self.stage == "header":
                if not self._gz_open():
                    return False
            feed = self.d.unconsumed_tail
            if not feed:
                feed, self.pending_in = self.pending_in, b""
            if not feed and not self.raw_done:
                feed = self._more()
        else:
            if self.d.eof:
                return False
            feed = b""
            if self.d.needs_input and not self.raw_done:
                feed = self._more()
        try:
            out = self.d.decompress(feed, STEP_OUT)
        except (ValueError, EOFError, OSError) + self.errors as exc:
            self._damaged(exc)
        if self.kind == "gz":
            self.crc = self.zlib.crc32(out, self.crc)
            self.size += len(out)
            if self.d.eof:
                self._gz_trailer()
        if not out and not feed and not self.d.eof:
            return False                          # no input left and nothing pending: the stream is cut
        self.chunk = out
        return True

    def read(self, size):
        if size is None or size < 0:
            raise ValueError("TarStream reads a bounded size")
        parts = []
        while size > 0:
            if self.pos < len(self.chunk):
                piece = self.chunk[self.pos:self.pos + size]
                self.pos += len(piece)
                size -= len(piece)
                parts.append(piece)
                continue
            if not self._step():
                break
        out = b"".join(parts)
        self.served += len(out)
        self.tail += out
        if len(self.tail) > (1 << 17):
            del self.tail[:-(1 << 16)]
        return out

    def block_at(self, offset):
        """The 512 bytes of the tar at `offset`, if they are among the last bytes returned, else None."""
        start = self.served - len(self.tail)
        i = offset - start
        return bytes(self.tail[i:i + 512]) if i >= 0 and i + 512 <= len(self.tail) else None

    def problem(self):
        """Why the compressed stream under the tar did not end as a finished one (it never reached its end, is damaged, its gzip CRC-32 or
        length disagree, or another stream or garbage follows it), or None; None too for a tar that is not compressed. The tar inside may be
        whole while the stream around it is not."""
        if self.d is None:
            return None
        if self.error is not None:
            return str(self.error)
        if not self.d.eof:
            return "the %s stream does not reach its end (cut, or damaged): the tar inside may be whole while the stream around it is not" % self.name
        if self.trailer_error:
            return self.trailer_error
        rest = self.rest if self.kind == "gz" else bytes(self.d.unused_data)
        total, nonzero = len(rest), len(rest) - rest.count(0)
        while True:
            if self.expired():
                return "the time limit ended the check of the bytes after the %s" % ("gzip trailer" if self.kind == "gz" else self.name + " stream")
            block = self.raw.read(1 << 20)
            if not block:
                break
            total += len(block)
            nonzero += len(block) - block.count(0)
        if total == 0 or (self.kind == "xz" and nonzero == 0 and total % 4 == 0):          # xz allows zero padding to a multiple of 4 bytes
            return None
        return ("%d byte(s) follow the %s (another %s, or garbage): a reader stops after the first one, so what follows was not read"
                % (total, "gzip trailer" if self.kind == "gz" else self.name + " stream", "gzip member" if self.kind == "gz" else "stream"))


def tar_end(tf, expired, stream=None):
    """How a tar stream ended, after its last member: `marker` (an all-zero block where a header should be: the writer finished the archive),
    `boundary` (the stream ended exactly where a header should start, with no end marker: cut there, or written without one), `partial` (part
    of a header, `bytes` long), `damaged` (a block that is not zero and not a header where the marker should be), or `unknown`. After a
    marker the rest of the stream is read: bytes that are not zero are members a tar reader does not reach (a second archive appended to
    the first)."""
    try:
        pending = tf.fileobj.pos - tf.offset
    except AttributeError:
        return {"kind": "unknown"}
    if pending == 0:
        return {"kind": "boundary"}
    if pending < 512:
        return {"kind": "partial", "bytes": pending}
    block = stream.block_at(tf.offset) if stream is not None else None
    if block is not None and block.count(0) != 512:
        return {"kind": "damaged", "nonzero": 512 - block.count(0)}
    after, nonzero, first = 0, 0, None
    try:
        while True:
            if expired():
                return {"kind": "marker", "after_marker_bytes": after, "after_marker_checked": False}
            block = tf.fileobj.read(1 << 20)
            if not block:
                break
            if block.count(0) != len(block):
                nonzero += len(block) - block.count(0)
                if first is None:
                    first = after + next(i for i, b in enumerate(block) if b)
            after += len(block)
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        return {"kind": "marker", "after_marker_bytes": after, "after_marker_error": describe(exc)}
    return {"kind": "marker", "after_marker_bytes": after, "after_marker_nonzero": nonzero, "after_marker_first_nonzero": first, "tail_bytes": pending + after}


def tar_end_problem(end):
    """Why a tar's end is not the end of a finished archive, or None."""
    if end.get("compression"):
        return end["compression"]
    kind = end.get("kind")
    if kind == "boundary":
        return "the tar ends where a member header should start and has no end-of-archive marker (two zero blocks is the standard and one is accepted, as GNU tar does): it is cut there, or was written without one, and any member after that point is not known"
    if kind == "partial":
        return "the tar ends %d byte(s) into a member header and has no end-of-archive marker: it is cut there, and the members after that point are not known" % end["bytes"]
    if kind == "damaged":
        return ("the block where the tar's end-of-archive marker should start is not zero and is not a member header (%d byte(s) are not zero): a damaged "
                "header, or something that is not a tar block; the members after that point are not known" % end["nonzero"])
    if kind == "unknown":
        return "this Python does not show where the tar stream ended: whether the archive has its end-of-archive marker is not known"
    if end.get("after_marker_error"):
        return "the bytes after the tar's end-of-archive marker could not be read (%s)" % end["after_marker_error"]
    if end.get("after_marker_checked") is False:
        return "the time limit ended the check of the bytes after the tar's end-of-archive marker"
    if end.get("after_marker_nonzero"):
        return ("%d byte(s) that are not zero follow the tar's end-of-archive marker (the first at offset %d after it): a reader stops at the marker, so whatever "
                "is there, a second archive appended to the first for one, was not read" % (end["after_marker_nonzero"], end["after_marker_first_nonzero"]))
    if not hasattr(tarfile.TarInfo, "_proc_member"):
        return "this Python's tarfile has no hook for the bound on a tar metadata record (%d bytes): the bound was not enforced" % MAX_META
    return None


def zip_problem(path, infos, start_dir, expired):
    """Why a zip is not read whole by its central directory, or None: bytes before the first member (another archive in front, or a
    concatenation, whose members are never read), bytes between one member and the next or before the central directory, members that
    overlap, and bytes after the end record. A reader follows the central directory of the last archive in the file."""
    notes = []
    try:
        with open_regular(path) as fh:
            size = os.fstat(fh.fileno()).st_size
            tail = min(size, (1 << 16) + 22)
            fh.seek(size - tail)
            data = fh.read(tail)
            at = data.rfind(b"PK\x05\x06")
            if at >= 0 and len(data) >= at + 22:
                comment = struct.unpack("<H", data[at + 20:at + 22])[0]
                after = len(data) - (at + 22 + comment)
                if after > 0:
                    notes.append("%d byte(s) follow the zip's end record" % after)
            spans = sorted(infos, key=lambda i: i.header_offset)
            if spans and spans[0].header_offset > 0:
                notes.append("%d byte(s) come before the first member (another archive in front of this one, or a self-extractor): the members of what is in front are not read"
                             % spans[0].header_offset)
            for k, info in enumerate(spans):
                if (k & 1023) == 0 and expired():
                    notes.append("the time limit ended the check of the space between members")
                    break
                fh.seek(info.header_offset)
                head = fh.read(30)
                if len(head) < 30 or head[:4] != b"PK\x03\x04":
                    break                       # reading the member says so
                name_len, extra_len = struct.unpack("<HH", head[26:30])
                flags = struct.unpack("<H", head[6:8])[0]
                end = info.header_offset + 30 + name_len + extra_len + info.compress_size
                following = spans[k + 1].header_offset if k + 1 < len(spans) else start_dir
                if following is None:
                    continue
                gap = following - end
                if gap < 0:
                    notes.append("members overlap (the member at offset %d runs into the next)" % info.header_offset)
                    break
                if gap > (24 if flags & 8 else 0):
                    notes.append("%d byte(s) lie between the member at offset %d and the next part of the file that the central directory names" % (gap, info.header_offset))
                    break
    except (OSError, struct.error) as exc:
        notes.append("the layout of the zip could not be checked (%s)" % describe(exc))
    if not notes:
        return None
    return "; ".join(notes[:3]) + ": a reader follows the central directory, so bytes it does not name were not read"


def end_problem(fmt, end):
    return end.get("zip") if fmt == "zip" else tar_end_problem(end)


# ---- END ARCHIVE BLOCK -----------------------------------------------------------------------------------------------


PARSER = "collection_timestamps/1"
TOOL = "collection_timestamps"
VALUES_NAME = "collection-timestamps-values.jsonl"
KNOWN_PARAMETERS = ("root", "archive", "member_prefix", "local_zone", "limit", "time_limit_seconds", "write_values")

_open_regular_text = open_regular


def open_regular(path, **kw):
    """The shared block's text opener when a text option is given, else the archive block's: a regular file, binary, opened without following
    a link and without blocking on a pipe (a FIFO, a device or a directory is refused before anything is read)."""
    if kw:
        return _open_regular_text(path, **kw)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file (a pipe, a device, a directory or a link): it is not opened")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


NS = 10 ** 9
DAY_NS = 86400 * NS
EPOCH = datetime.datetime(1970, 1, 1)
FILETIME_UNIX_TICKS = 116444736000000000        # 100 ns ticks from 1601-01-01 to 1970-01-01 (the base timestamp_decode's FILETIME epoch)
DECIMALS = decimal.Context(prec=80, traps=[decimal.InvalidOperation, decimal.Overflow, decimal.DivisionByZero])
MAX_DATES = 100000                # distinct dates counted per clock; beyond it a date is counted in `dates_not_counted`
FLATTEN_FILES, FLATTEN_SHARE = 20, 90      # more than 90% of more than 20 files on one date, as collection_index reports it
MAX_HELD = 2000000                # delivered files held for the join; past it the comparison is partial and no file is called absent
MAX_ZIP_MEMBERS = 2000000         # a zip with more members is not opened (zipfile holds every header)
MEMORY_CHECK_EVERY = 1024
MEMORY_ENV = ("COLLECTION_MEMORY_BYTES", "COLLECTION_INTAKE_MEMORY_BYTES")
NESTED_SUFFIXES = (".zip", ".tar", ".tgz", ".tar.gz", ".tbz2", ".tar.bz2", ".txz", ".tar.xz", ".7z", ".rar", ".gz", ".bz2", ".xz", ".zst", ".ad1", ".e01", ".ex01")
OUTCOMES = ("equal", "within_precision", "consistent_with_zone_offset", "differs", "ambiguous_join", "member_time_unreadable",
            "only_in_archive", "only_in_delivery")


def memory_ceiling():
    """The bytes this process may hold, as far as it can be known: COLLECTION_MEMORY_BYTES when it is a positive whole number, else the smallest
    of the cgroup limit and the address-space and data limits. None when nothing limits it that this can see."""
    for name in MEMORY_ENV:
        try:
            if os.environ.get(name) and int(os.environ[name]) > 0:
                return int(os.environ[name])
        except ValueError:
            pass
    found = []
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            with open(path) as fh:
                text = fh.read().strip()
            if text.isdigit() and int(text) < (1 << 60):
                found.append(int(text))
        except OSError:
            pass
    try:
        import resource
        for which in (resource.RLIMIT_AS, resource.RLIMIT_DATA):
            soft = resource.getrlimit(which)[0]
            if soft != resource.RLIM_INFINITY:
                found.append(soft)
    except (ImportError, ValueError, OSError):
        pass
    return min(found) if found else None


MEMORY_CEILING = [None, False]         # (bytes, looked up)


def size_text(n):
    if n >= 1 << 20:
        return "%d MB" % (n >> 20)
    if n >= 1 << 10:
        return "%d KB" % (n >> 10)
    return "%d bytes" % n


def over_memory():
    """A sentence when the process holds more than 60% of what it may hold, else None: the pass stops there, partial, and says so, instead of
    being killed with nothing written."""
    if not MEMORY_CEILING[1]:
        MEMORY_CEILING[0], MEMORY_CEILING[1] = memory_ceiling(), True
    ceiling = MEMORY_CEILING[0]
    if not ceiling:
        return None
    try:
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    except (ImportError, OSError):
        return None
    if peak * 10 > ceiling * 6:
        return "the memory bound (%s held of the %s this process may hold)" % (size_text(peak), size_text(ceiling))
    return None


def join_key(text):
    """The key a member name and a delivered path are joined by: '/' for either separator, no leading './' or '/', then NFC-normalised and
    case-folded (a name written in decomposed form, as macOS writes it, is the same name as its precomposed twin)."""
    parts = [p for p in text.replace("\\", "/").split("/") if p not in ("", ".")]
    return unicodedata.normalize("NFC", "/".join(parts)).casefold()


def iso_from_ns(ns, zone):
    """ISO 8601 with the fraction the value has (to the nanosecond), `Z` for UTC and no mark for a wall-clock reading; None past the years 1 to 9999."""
    seconds, frac = divmod(ns, NS)
    try:
        moment = EPOCH + datetime.timedelta(seconds=seconds)
    except OverflowError:
        return None
    text = moment.isoformat()
    if frac:
        text += "." + ("%09d" % frac).rstrip("0")
    return text + ("Z" if zone == "utc" else "")


def day_text(day):
    try:
        return (EPOCH + datetime.timedelta(days=day)).date().isoformat()
    except OverflowError:
        return "out of range"


class Clock:
    """What one clock holds: how many files, the earliest and the latest with their raw values, the files per date, the precision and the zone.
    The date is the UTC date, or the wall-clock date for a clock that states no zone."""

    def __init__(self, key, label, zone, epoch, precision):
        self.key, self.label, self.zone, self.epoch, self.precision = key, label, zone, epoch, precision
        self.files = 0
        self.lo = self.hi = None            # (ns, raw)
        self.dates = collections.Counter()
        self.dates_not_counted = 0
        self.unreadable = 0
        self.unreadable_first = []
        self.sub_second = self.finer_than_100ns = self.odd_seconds = 0
        self.local_status = collections.Counter()

    def add(self, ns, raw):
        self.files += 1
        if self.lo is None or ns < self.lo[0]:
            self.lo = (ns, raw)
        if self.hi is None or ns > self.hi[0]:
            self.hi = (ns, raw)
        day = ns // DAY_NS
        if day in self.dates or len(self.dates) < MAX_DATES:
            self.dates[day] += 1
        else:
            self.dates_not_counted += 1
        if ns % NS:
            self.sub_second += 1
        if ns % 100:
            self.finer_than_100ns += 1
        if (ns // NS) % 2:
            self.odd_seconds += 1

    def refuse(self, where, why):
        self.unreadable += 1
        if len(self.unreadable_first) < FIRST_PROBLEMS:
            self.unreadable_first.append({"where": shown(where, "member"), "why": why})

    def observed_resolution(self):
        if not self.files:
            return "no file read"
        if not self.sub_second:
            return "whole seconds in every file read" + (" and always even seconds (a two-second clock)" if not self.odd_seconds else "")
        if not self.finer_than_100ns:
            return "a fraction of a second in %d of %d files, never finer than 100 ns" % (self.sub_second, self.files)
        return "nanosecond fractions in %d of %d files" % (self.finer_than_100ns, self.files)

    def flattening(self):
        if not self.dates or self.files <= FLATTEN_FILES:
            return None
        day, count = self.dates.most_common(1)[0]
        if count * 100 > self.files * FLATTEN_SHARE:
            return {"date": day_text(day), "files_on_date": count, "files": self.files,
                    "basis": "more than %d%% of more than %d files are on one date; a count, with no cause (%s)" % (
                        FLATTEN_SHARE, FLATTEN_FILES, "the date is the wall-clock date of a clock with no zone" if self.zone == "none" else "the date is the UTC date")}
        return None

    def end(self, point):
        if point is None:
            return None
        ns, raw = point
        shown_time = iso_from_ns(ns, self.zone)
        out = {"time": shown_time if shown_time is not None else "outside the years 1 to 9999", "modified_epoch_ns": str(ns)}
        if raw != str(ns):
            out["raw"] = raw
        return out

    def summary(self):
        top = self.dates.most_common(1)
        basis = ("the earliest and the latest time of the %d regular files this clock gave" % self.files if self.zone == "utc" else
                 "the earliest and the latest of the %d regular files this clock gave, as wall-clock readings: they are not ordered against a UTC clock" % self.files)
        return {"clock": self.key, "label": self.label, "files": self.files,
                "earliest": self.end(self.lo), "latest": self.end(self.hi), "interval_basis": basis,
                "epoch": self.epoch, "zone": self.zone_text(), "precision": self.precision, "observed_resolution": self.observed_resolution(),
                "distinct_dates": len(self.dates), "dates_not_counted": self.dates_not_counted,
                "most_common_date": ({"date": day_text(top[0][0]), "files": top[0][1]} if top else None),
                "apparent_flattening": self.flattening(),
                "times_not_readable": self.unreadable, "times_not_readable_first": self.unreadable_first,
                **({"local_zone_reading": dict(self.local_status)} if self.local_status else {})}

    def zone_text(self):
        return "none stated: the local time of the machine that wrote it; never assumed to be UTC" if self.zone == "none" else "UTC"


def tar_reading(member):
    """(ns, raw, precision_ns, digits, why) of a tar member's mtime; ns is None with the reason when it cannot be read. A pax mtime is read from its
    text, so a fraction keeps all its digits (tarfile would make a float of it); otherwise the header's whole seconds."""
    pax = (member.pax_headers or {}).get("mtime")
    if pax is not None:
        if not isinstance(pax, str) or len(pax) > 64 or not re.fullmatch(r"-?[0-9]{1,30}(?:\.[0-9]{1,30})?", pax):
            return None, str(pax)[:64], None, 0, "the pax mtime is not a decimal number"
        try:
            ns = int((DECIMALS.create_decimal(pax) * NS).to_integral_value(rounding=decimal.ROUND_FLOOR))
        except decimal.DecimalException:
            return None, pax, None, 0, "the pax mtime is not a number this tool reads"
        digits = len(pax.split(".")[1]) if "." in pax else 0
        return ns, pax, 10 ** (9 - min(9, digits)), digits, None
    try:
        seconds = int(member.mtime)
    except (OverflowError, ValueError, TypeError):
        return None, str(member.mtime), None, 0, "the header's mtime is not a whole number of seconds"
    return seconds * NS, str(seconds), NS, 0, None


def zip_dos_reading(info):
    """(wall-clock ns, raw, why): the zip header's DOS date and time, read through a real date (month 13 or 30 February is refused and said)."""
    y, mo, d, h, mi, s = info.date_time
    raw = "DOS date %04d-%02d-%02d, time %02d:%02d:%02d" % (y, mo, d, h, mi, s)
    try:
        moment = datetime.datetime(y, mo, d, h, mi, s)
    except ValueError as exc:
        return None, raw, "the DOS date and time is not a calendar date and time (%s)" % exc
    delta = moment - EPOCH
    return (delta.days * 86400 + delta.seconds) * NS, raw, None


def zip_extra_reading(info):
    """The UTC mtime a zip's extra fields give, as (ns, raw, precision_ns, kind), or None: the extended timestamp (0x5455: Unix seconds, one
    second) or the NTFS field (0x000a, tag 1: FILETIME, 100 ns)."""
    extra, pos = info.extra or b"", 0
    found = None
    while pos + 4 <= len(extra):
        tag, size = struct.unpack_from("<HH", extra, pos)
        data = extra[pos + 4:pos + 4 + size]
        pos += 4 + size
        if tag == 0x5455 and len(data) >= 5 and data[0] & 1:
            seconds = struct.unpack_from("<i", data, 1)[0]
            found = (seconds * NS, "Unix seconds %d (extended timestamp 0x5455)" % seconds, NS, "extended_timestamp")
        elif tag == 0x000A and len(data) >= 8:
            at = 4
            while at + 4 <= len(data):
                t, s = struct.unpack_from("<HH", data, at)
                if t == 1 and s >= 8 and at + 4 + 8 <= len(data):
                    ticks = struct.unpack_from("<Q", data, at + 4)[0]
                    found = ((ticks - FILETIME_UNIX_TICKS) * 100, "FILETIME 0x%08x_%08x (NTFS field 0x000a)" % (ticks >> 32, ticks & 0xFFFFFFFF), 100, "ntfs_filetime")
                    break
                at += 4 + s
    return found


def local_candidates(zone, wall_ns):
    """([UTC ns], status) for a wall-clock reading under an IANA zone: one reading, two when a clock change repeats the wall time (ambiguous), none
    when the wall time falls in a gap (nonexistent)."""
    wall = EPOCH + datetime.timedelta(seconds=wall_ns // NS)
    utc = datetime.timezone.utc
    out = []
    for fold in (0, 1):
        as_utc = wall.replace(tzinfo=zone, fold=fold).astimezone(utc)
        if as_utc.astimezone(zone).replace(tzinfo=None) != wall:
            continue
        ns = int((as_utc.replace(tzinfo=None) - EPOCH).total_seconds()) * NS
        if ns not in out:
            out.append(ns)
    if not out:
        return [], "nonexistent: the wall time falls in a clock-change gap, so no UTC time has it"
    if len(out) == 2:
        return out, "ambiguous: a clock change repeats this wall time, so two UTC times have it"
    return out, "unambiguous"


def iterate_times(path, fmt, expired, end):
    """(name, kind, info) for each member in archive order, as the recipe's iterate does it (the same bounded readers), keeping the member
    header itself (a ZipInfo, a TarInfo) for its times. `end` is given how the archive ended."""
    if fmt == "zip":
        with open_regular(path) as zipped:
            size = os.fstat(zipped.fileno()).st_size
            zipped.seek(max(0, size - ((1 << 16) + 22)))
            tail = zipped.read()
            at = tail.rfind(b"PK\x05\x06")
            if at >= 0 and len(tail) >= at + 22:
                count = struct.unpack_from("<H", tail, at + 10)[0]
                if count != 0xFFFF and count > MAX_ZIP_MEMBERS:
                    raise ValueError("the zip's central directory names %d members, over the %d this tool opens" % (count, MAX_ZIP_MEMBERS))
            zipped.seek(0)
            with zipfile.ZipFile(zipped) as zf:
                infos = zf.infolist()
                if len(infos) > MAX_ZIP_MEMBERS:
                    raise ValueError("the zip holds %d members, over the %d this tool opens" % (len(infos), MAX_ZIP_MEMBERS))
                for info in infos:
                    mode = (info.external_attr >> 16) & 0o170000
                    kind = "d" if info.is_dir() else "l" if mode == 0o120000 else "s" if mode in (0o020000, 0o060000, 0o010000, 0o140000) else "f"
                    yield info.filename, kind, info
                end["zip"] = zip_problem(path, infos, getattr(zf, "start_dir", None), expired)
    else:
        raw = open_regular(path)
        try:
            stream = TarStream(raw, tar_kind(raw.read(6)), expired)
            raw.seek(0)
            with tarfile.open(fileobj=stream, mode="r|", tarinfo=BoundedTarInfo) as tf:
                for member in tf:
                    kind = "d" if member.isdir() else "f" if member.isreg() else "l" if (member.issym() or member.islnk()) else "s"
                    yield member.name, kind, member
                    tf.members = []
                end.update(tar_end(tf, expired, stream))
                drained = end.get("kind") in ("boundary", "partial") or (end.get("kind") == "marker" and end.get("after_marker_checked", True))
                gone = stream.problem() if drained else None
                if gone:
                    end["compression"] = gone
        finally:
            raw.close()


class Walk:
    """The delivered tree: one lstat per entry, nothing opened, links recorded and never followed."""

    def __init__(self):
        self.files = self.dirs = self.links = self.special = 0
        self.errors = 0
        self.first_errors = []
        self.stopped = None
        self.held = None                 # join key -> [[rel, ns, matched]]
        self.held_count = 0
        self.held_incomplete = None

    def error(self, rel, what, exc):
        self.errors += 1
        if len(self.first_errors) < FIRST_PROBLEMS:
            self.first_errors.append({"path": shown(rel or ".", "walk error"), "what": what, "error": describe(exc)})


def walk_delivered(root, walk, clock, problems):
    stack = [("", root)]
    seen = 0
    while stack:
        rel_dir, path = stack.pop()
        if out_of_time():
            walk.stopped = "the time limit ended the walk (%d directories not listed)" % (len(stack) + 1)
            return
        try:
            listing = list_sorted(path)
        except OSError as exc:
            walk.error(rel_dir, "directory not listed", exc)
            problems.add({"kind": "walk_error", "path": rel_dir or ".", "what": "directory not listed", "error": describe(exc)})
            continue
        subdirs = []
        for entry in listing:
            seen += 1
            if out_of_time():
                walk.stopped = "the time limit ended the walk (%d directories not listed)" % (len(stack) + 1)
                return
            if seen % MEMORY_CHECK_EVERY == 0:
                held = over_memory()
                if held:
                    walk.stopped = "%s ended the walk" % held
                    return
            if is_own(entry):
                continue
            rel = entry.name if not rel_dir else rel_dir + "/" + entry.name
            try:
                st = os.lstat(entry.path)
            except OSError as exc:
                walk.error(rel, "entry not examined", exc)
                problems.add({"kind": "walk_error", "path": rel, "what": "entry not examined", "error": describe(exc)})
                continue
            if stat.S_ISDIR(st.st_mode):
                walk.dirs += 1
                subdirs.append((rel, entry.path))
            elif stat.S_ISREG(st.st_mode):
                walk.files += 1
                ns = st.st_mtime_ns
                clock.add(ns, str(ns))
                if walk.held is not None:
                    if walk.held_count >= MAX_HELD:
                        walk.held_incomplete = "the join holds at most %d delivered files" % MAX_HELD
                    else:
                        walk.held.setdefault(join_key(rel), []).append([rel, ns, False])
                        walk.held_count += 1
            elif stat.S_ISLNK(st.st_mode):
                walk.links += 1
            else:
                walk.special += 1
        stack.extend(reversed(subdirs))


def classify(member_readings, delivered_ns):
    """(outcome, detail) for an archive member against a delivered file. A UTC reading is `equal` when the values are the same, `within_precision`
    when the delivered time is later by less than the member's precision (the archive could not hold the finer part), else `differs`. A zoneless
    reading is `consistent_with_zone_offset` when the difference is a whole number of quarter hours (within 14 hours) plus the two-second step."""
    best = None
    for rd in member_readings:
        if rd["zone"] == "utc":
            delta = delivered_ns - rd["ns"]
            if delta == 0:
                return "equal", {"delta_ns": "0", "used": rd["kind"]}
            if 0 < delta < rd["precision_ns"]:
                return "within_precision", {"delta_ns": str(delta), "used": rd["kind"]}
            if best is None or abs(delta) < best[2]:
                best = ("differs", {"delta_ns": str(delta), "used": rd["kind"]}, abs(delta))
        elif rd.get("candidates") is not None:
            if not rd["candidates"]:
                if best is None:
                    best = ("differs", {"delta_ns": None, "used": rd["kind"], "note": "the wall time does not exist under the zone"}, 1 << 100)
                continue
            for cand in rd["candidates"]:
                delta = delivered_ns - cand
                if 0 <= delta < rd["precision_ns"]:
                    return ("equal" if delta == 0 else "within_precision"), {"delta_ns": str(delta), "used": rd["kind"], "local_status": rd["local_status"]}
            cand = min(rd["candidates"], key=lambda c: abs(delivered_ns - c))
            delta = delivered_ns - cand
            if best is None or abs(delta) < best[2]:
                best = ("differs", {"delta_ns": str(delta), "used": rd["kind"], "local_status": rd["local_status"]}, abs(delta))
        else:
            delta = delivered_ns - rd["ns"]
            quarter = 900 * NS
            k = round(delta / quarter) if abs(delta) < 10 ** 18 else None
            if k is not None and abs(k) <= 56:
                rest = delta - k * quarter
                if 0 <= rest < rd["precision_ns"]:
                    return "consistent_with_zone_offset", {"delta_ns": str(delta), "offset_minutes_candidate": k * 15, "used": rd["kind"],
                                                           "note": "any offset of whole quarter hours fits; this is not a determination of the zone"}
            if best is None or abs(delta) < best[2]:
                best = ("differs", {"delta_ns": str(delta), "used": rd["kind"], "note": "wall-clock minus UTC: they differ by the writer's zone offset as well"}, abs(delta))
    if best is None:
        return "member_time_unreadable", {}
    return best[0], best[1]


def reading_view(rd):
    out = {"clock": rd["kind"], "raw": rd["raw"], "precision": rd["precision"], "zone": "UTC" if rd["zone"] == "utc" else "none stated"}
    shown_time = iso_from_ns(rd["ns"], rd["zone"])
    out["time"] = shown_time if shown_time is not None else "outside the years 1 to 9999"
    if rd.get("candidates") is not None:
        out["local_zone_reading"] = {"status": rd["local_status"], "utc": [iso_from_ns(c, "utc") for c in rd["candidates"]]}
    return out


def member_readings(fmt, info, state, name):
    """The readings of one regular member: a list of dicts (a zip's extra-field UTC time first), and why none was readable."""
    c_main, c_extra = state["clock_main"], state["clock_extra"]
    readings, why = [], None
    if fmt == "zip":
        ns, raw, why = zip_dos_reading(info)
        if ns is not None:
            rd = {"kind": "zip_dos_time", "ns": ns, "raw": raw, "precision": "2 s", "precision_ns": 2 * NS, "zone": "none"}
            if state["zone"] is not None:
                rd["candidates"], rd["local_status"] = local_candidates(state["zone"], ns)
                c_main.local_status[rd["local_status"].split(":")[0]] += 1
            readings.append(rd)
            c_main.add(ns, raw)
        else:
            c_main.refuse(name, why)
        extra = zip_extra_reading(info)
        if extra is not None:
            xns, xraw, xprec, xkind = extra
            readings.insert(0, {"kind": "zip_" + xkind, "ns": xns, "raw": xraw, "precision": "1 s" if xprec == NS else "100 ns", "precision_ns": xprec, "zone": "utc"})
            c_extra.add(xns, xraw)
    else:
        ns, raw, prec, digits, why = tar_reading(info)
        if ns is not None:
            readings.append({"kind": "tar_pax_mtime" if digits else "tar_mtime", "ns": ns, "raw": raw, "precision_ns": prec, "zone": "utc",
                             "precision": "1 s" if prec == NS else "%d fractional digit(s), as the writer wrote them" % digits})
            c_main.add(ns, raw)
        else:
            c_main.refuse(name, why)
    return readings, why


def archive_pass(path, fmt, state):
    """Read the archive once. Each regular member becomes clock-2 readings (and a comparison row when the delivered tree is held)."""
    end = {}
    walk, table, counts, prefix = state["walk"], state["table"], state["counts"], state["prefix_key"]
    seen_names = set()
    try:
        for name, kind, info in iterate_times(path, fmt, out_of_time, end):
            if out_of_time():
                state["stopped"] = "the time limit ended the read of the archive's members"
                return end
            counts["members"] += 1
            if counts["members"] % MEMORY_CHECK_EVERY == 0:
                held = over_memory()
                if held:
                    state["stopped"] = "%s ended the read of the archive's members" % held
                    return end
            if kind == "d":
                counts["directories"] += 1
                continue
            if kind != "f":
                counts["links_or_special"] += 1
                continue
            counts["files"] += 1
            if name.lower().endswith(NESTED_SUFFIXES):
                counts["nested_archives"] += 1
            readings, why = member_readings(fmt, info, state, name)
            if walk.held is None:
                continue
            views = [reading_view(r) for r in readings]
            key = join_key(name)
            if prefix:
                if not key.startswith(prefix):
                    counts["outside_prefix"] += 1
                    state["outcomes"]["only_in_archive"] += 1
                    table.add({"outcome": "only_in_archive", "member": shown(name, "member"), "why": "the name does not start with member_prefix", "member_times": views})
                    continue
                key = key[len(prefix):]
            if key in seen_names:
                counts["duplicate_member_names"] += 1
            elif len(seen_names) < MAX_HELD:
                seen_names.add(key)
            hits = walk.held.get(key)
            if not hits:
                state["outcomes"]["only_in_archive"] += 1
                table.add({"outcome": "only_in_archive", "member": shown(name, "member"), "member_times": views})
                continue
            for h in hits:
                h[2] = True
            if len(hits) > 1:
                state["outcomes"]["ambiguous_join"] += 1
                counts["ambiguous"] += 1
                table.add({"outcome": "ambiguous_join", "member": shown(name, "member"), "candidates": [shown(h[0], "path") for h in hits[:FIRST_PROBLEMS]],
                           "candidates_total": len(hits), "why": "%d delivered files have this name under NFC and case folding" % len(hits), "member_times": views})
                continue
            if not readings:
                state["outcomes"]["member_time_unreadable"] += 1
                table.add({"outcome": "member_time_unreadable", "path": shown(hits[0][0], "path"), "why": why})
                continue
            outcome, detail = classify(readings, hits[0][1])
            state["outcomes"][outcome] += 1
            table.add({"outcome": outcome, "path": shown(hits[0][0], "path"), "member": shown(name, "member") if name != hits[0][0] else None,
                       "member_times": views, "delivered": {"time": iso_from_ns(hits[0][1], "utc"), "modified_epoch_ns": str(hits[0][1])}, "detail": detail})
    except ClockStopped:
        state["stopped"] = "the time limit ended the read of the archive"
    except Exception as exc:                    # a damaged or hostile archive: said, and the answer is partial; never a clean end
        state["archive_error"] = "the archive could not be read to its end (%s: %s)" % (type(exc).__name__, describe(exc))
    return end


def main():
    install_signal_handlers()
    args = read_args()
    root = want_str(args, "root")
    archive = want_str(args, "archive")
    if root is None and archive is None:
        fail("root (the delivered directory) or archive (a zip or tar file) is required")
    prefix_text = want_str(args, "member_prefix")
    zone_name = want_str(args, "local_zone")
    limit = want_int(args, "limit", DEFAULT_LIMIT)
    seconds = want_int(args, "time_limit_seconds", 3000, 1, 3400)
    zone = None
    if zone_name is not None:
        if not re.fullmatch(r"[A-Za-z0-9_+\-]+(?:/[A-Za-z0-9_+\-]+){0,2}", zone_name):
            fail("local_zone must be an IANA zone name such as Europe/Istanbul")
        try:
            import zoneinfo
            zone = zoneinfo.ZoneInfo(zone_name)
        except Exception as exc:
            fail("local_zone cannot be read on this host (%s): no zone is assumed" % type(exc).__name__)
    try:
        VALUES[0] = SecretValues(want_bool(args, "write_values"), VALUES_NAME, TOOL)
    except SecretValuesRefused as exc:
        fail(str(exc))
    if root is not None and not os.path.isdir(root):
        fail("no such directory" if not os.path.isfile(root) else "root is a file: give the delivered directory (an archive goes in `archive`)", root=root)
    start_clock(seconds)
    problems = Table(TOOL + "-problems", FIRST_PROBLEMS)
    table = Table(TOOL + "-comparison", limit, always=True)
    table.open_now()                         # before the walk: a root that holds the table's own file must not list it

    walk = Walk()
    if archive is not None and root is not None:
        walk.held = {}
    delivered = Clock("delivered_mtime", "the delivered files' modification times (collection_index's field)", "utc", "Unix epoch (a file system's own time, UTC)",
                      "the file system's own, to the nanosecond; whoever wrote the tree (an extractor, a copy) may have set any part of it")
    if root is not None:
        walk_delivered(root, walk, delivered, problems)

    state = {"clock_main": Clock("archive_member", "the archive members' header times", "none", "", ""),
             "clock_extra": Clock("archive_member_utc_extra", "a zip's extended-timestamp and NTFS fields", "utc", "Unix epoch (0x5455) or FILETIME (0x000a)", "1 s or 100 ns, as the field says"),
             "walk": walk, "table": table, "zone": zone, "stopped": None, "archive_error": None, "outcomes": collections.Counter(),
             "counts": collections.Counter(), "prefix_key": (join_key(prefix_text) + "/") if prefix_text else ""}
    fmt, end = None, {}
    if archive is not None:
        fmt, why = sniff(archive, out_of_time)
        if fmt is None:
            state["archive_error"] = "the archive was not read: %s" % why
        else:
            m = state["clock_main"]
            if fmt == "zip":
                m.zone, m.epoch, m.precision = "none", "DOS date and time (1980-01-01, local time)", "2 s"
            else:
                m.zone, m.epoch, m.precision = "utc", "Unix epoch", "1 s in a tar header; a pax mtime has as many fractional digits as the writer wrote"
            end = archive_pass(archive, fmt, state)
    if walk.held is not None and fmt is not None and not state["stopped"] and not state["archive_error"] and not walk.held_incomplete:
        for position, items in enumerate(walk.held.values()):      # delivered files the archive does not name, under the clock
            if position % 256 == 0 and out_of_time():
                state["stopped"] = "the time limit ended the list of delivered files the archive does not name"
                break
            for item in items:
                if not item[2]:
                    state["outcomes"]["only_in_delivery"] += 1
                    table.add({"outcome": "only_in_delivery", "path": shown(item[0], "path"), "delivered": {"time": iso_from_ns(item[1], "utc"), "modified_epoch_ns": str(item[1])}})

    tables = {"comparison": table.finish(), "problems": problems.finish()}
    main_clock, extra_clock = state["clock_main"], state["clock_extra"]
    lines = []
    if root is not None and (walk.stopped or walk.errors):
        lines.append("the walk of the delivered tree %s" % (walk.stopped or "had %d error(s)" % walk.errors))
    if walk.held_incomplete:
        lines.append(walk.held_incomplete + ": the comparison does not cover every delivered file")
    if state["archive_error"]:
        lines.append(state["archive_error"])
    if state["stopped"]:
        lines.append(state["stopped"])
    if fmt is not None and not state["archive_error"] and not state["stopped"]:
        problem = end_problem(fmt, end)
        if problem:
            lines.append("the archive did not end as a finished one: %s" % problem)
    if state["counts"]["nested_archives"]:
        lines.append("%d member(s) are archives themselves and were not opened: their members' times are not read" % state["counts"]["nested_archives"])
    if main_clock.unreadable:
        lines.append("%d member time(s) could not be read" % main_clock.unreadable)
    status = "partial" if lines else "complete"
    if root is None and fmt is None:
        status = "failed"
    if status == "complete":
        basis = "every entry of the delivered tree was examined and the archive was read to its end" if root and archive else \
            "every entry of the delivered tree was examined" if root else "the archive was read to its end and the end was examined"
    else:
        basis = "; ".join(lines[:10]) + ("; and %d more" % (len(lines) - 10) if len(lines) > 10 else "")

    clocks = {}
    if fmt is not None:
        clocks["archive_member"] = main_clock.summary()
        if fmt == "zip":
            clocks["archive_member_utc_extra"] = extra_clock.summary()
    if root is not None:
        clocks["delivered_mtime"] = delivered.summary()
    flattening = [{"clock": k, **v["apparent_flattening"]} for k, v in clocks.items() if v.get("apparent_flattening")]
    conflicts = []
    if state["outcomes"]["differs"]:
        conflicts.append({"kind": "member_and_delivered_times_differ", "files": state["outcomes"]["differs"],
                          "note": "the archive's time for these files is not the delivered time; the tool does not say which one an extractor, a copy or the collector set"})
    if state["counts"]["duplicate_member_names"]:
        conflicts.append({"kind": "a_name_is_in_the_archive_more_than_once", "members": state["counts"]["duplicate_member_names"]})
    if state["counts"]["ambiguous"]:
        conflicts.append({"kind": "ambiguous_join", "members": state["counts"]["ambiguous"], "note": "several delivered files share the name under NFC and case folding; each stays a candidate"})
    flat = {c["clock"] for c in flattening}
    if "delivered_mtime" in clocks and "archive_member" in clocks and (("delivered_mtime" in flat) != ("archive_member" in flat)):
        conflicts.append({"kind": "flattened_in_one_clock_only", "flattened": sorted(flat), "note": "one clock puts most files on a single date and the other does not; a count, with no cause"})
    compared = walk.held is not None and fmt is not None
    out = {
        "tool": TOOL, "parser": PARSER, "status": status, "status_basis": basis,
        "root": shown(root, "root") if root is not None else None, "archive": shown(archive, "archive") if archive is not None else None,
        "archive_format": fmt, "ignored_parameters": ignored_parameters(args, KNOWN_PARAMETERS),
        "clocks_not_read": ["the collector's own record times (clock 1)", "the acquisition interval (clock 4)"],
        "clocks": clocks,
        "apparent_flattening": flattening,
        "comparison": {"ran": compared,
                       "joined_by": "the name with '/' separators, NFC and case folding%s" % (", after removing the prefix %s" % shown(prefix_text, "prefix") if prefix_text else ""),
                       "outcomes": {k: state["outcomes"][k] for k in OUTCOMES if state["outcomes"][k]},
                       "basis": "a member and a delivered file are compared only where the join names the same file; files on one side only are rows of the comparison table"
                       if compared else "no comparison: it needs both a root and a readable archive"},
        "conflicts": conflicts,
        "archive_members": dict(state["counts"]) if archive is not None else None,
        "archive_end": dict(end) if end else None,
        "delivered_tree": ({"files": walk.files, "directories": walk.dirs, "symbolic_links_not_followed": walk.links, "special_files_not_read": walk.special,
                            "errors": walk.errors, "first_errors": walk.first_errors, "stopped": walk.stopped} if root is not None else None),
        "tables": tables,
        "withheld": {"strings_withheld": WITHHELD["count"], "values": VALUES[0].summary()},
        "note": ("Separate clocks, each with its precision and zone; none is the time of an event. A date distribution is a lead, not proof of lost metadata. "
                 "The whole comparison is in the file its table names; the page below is its first rows."),
        "comparison_page": table.page,
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
