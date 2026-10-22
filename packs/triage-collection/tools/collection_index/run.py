#!/usr/bin/env python3
"""List every object of a delivered collection with its size, its modified time and its SHA-256, and offer a hypothesis for the
path each file had on the source machine, never a statement of it.

Collectors rewrite paths so they are safe on the examiner's file system, and each does it differently: a drive letter becomes
a directory, a collector's own wrapper directory is added, a named stream's colon becomes something else. This tool does not
undo those rewrites. It reads the path in the collection and says, per file, what a convention would make of it
(`source_path_hypothesis`: the path, the method, the confidence, the components it could not explain, and the other readings),
which is a guess about a layout and not an observation. `source_path_observed` is filled only from a collector's own record: a
KAPE copy log found in the tree, whose DestinationFile ends with the file's path relative to that log's own directory and
whose SourceFile is then the path the collector recorded, with the log and the row. A row belongs to one file: a file below
no copy log's directory, or matched by no row, has no observed path, and a file matched by rows that name different sources, or
sharing its name (letters of case apart) with a sibling, is `ambiguous`. Cite the path in the collection and, beside it, an
observed path with its row or a hypothesis called one; never a hypothesis alone.

What it measures: a census of the objects below the root (regular files with a size, a modified time to the nanosecond the file
system kept, and a digest; symbolic links, which are recorded and never followed; special files; empty directories; every
directory or file it could not list, stat or read, each with its error). A delivery that holds a disk image, a memory capture or
an archive is indexed like any other and each such object says what it looks like (`object_class`, from its first bytes and its
name; the object is not opened). The complete census is written to a file in a job, with `out_file`, with a `contains` filter, and
whenever the inline page cannot hold it, and a rerun never replaces a file that is there. `contains` filters the inline page
only, and it is read on what is printed (a withheld name is searched as its marker, never as the text behind it): the file
holds every object, and with a filter only the matching files are hashed (the others say `not_attempted`).

What it does not measure: the original path of anything the collector did not record; whether a stream was renamed or dropped
(`possible_renamed_streams` is a guess from file-name shape); whether the tree is complete; whether a time is the source's or
the copy's. Times are the delivered file system's, UTC, as Python reads them; `modified_epoch_ns` is the raw value written as a
decimal string, because a JSON number past 2^53 does not survive a JavaScript or jq 1.6 reader. A distribution that puts most
files on one date is reported as a fact about the distribution (`mtime_distribution_anomaly`) with no cause, because a copy that
reset times, a bulk write and real activity all look like it, and the clocks that could tell them apart (the collector's
recorded times, archive member times, the acquisition time) are not read here, except that a matched copy-log row carries its
recorded ModifiedOnUtc beside the delivered time, raw.

SECRET-SAFE OUTPUT (docs/packs.md, "Secrets and sensitive output"). The digest is of the whole file, an integrity record of an
evidence object; it is never a digest of a value inside one. A file whose name marks a credential store (a password verifier
file, a private key, a key chain, a saved-credential database: `may_hold_secrets`, a name hint and nothing more) is not hashed
unless `hash_credential_stores: true` is given with `write_values: true`, in a job; its digest then goes only to the sealed
values file, never to the answer or the index. Run it as a job with `secret_output: true`, and never copy such a digest into a
post, a report or an indicator list. Paths go through the shared withholding block: a string shaped like a recovery password,
an access key, a token, a private-key block, the user-info of a URL, or the value after a credential header, key name or
password option is replaced by its kind, its length and a finding id, in every channel; `write_values: true` (a job only)
writes the real strings to `$OUT/collection-index-values.jsonl`, mode 0600, created before anything is read.
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

import collections
import csv
import datetime
import hashlib

PARSER = "collection_index/4"
TOOL = "collection_index"
VALUES_NAME = "collection-index-values.jsonl"
KNOWN_PARAMETERS = ("root", "contains", "hash", "hash_credential_stores", "limit", "out_file", "time_limit_seconds", "write_values")
MAX_CLAIMS = 2000000              # file/row pairs held while the claimants of a row are counted; past it the mapping is not trusted
MAX_MAP_ROWS = 300000             # copy-log rows held for the path mapping; past it the mapping is partial, and says so
MAX_FIELD = 1 << 20

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


def iso_ns(ns):
    try:
        seconds, fraction = divmod(ns, 10 ** 9)
        when = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
        return when.strftime("%Y-%m-%dT%H:%M:%S") + ".%09dZ" % fraction
    except (OverflowError, OSError, ValueError):
        return None


_BRACE = re.compile(r"\{([0-9]*)(,([0-9]*))?\}")


def refuse_pattern(pattern):
    """Why a `contains` pattern is outside the language this tool accepts, or None. The pattern is the caller's but the names it is
    run on are the evidence's, so a pattern that can backtrack for ever on a long name must not be run at all: a pattern is accepted
    only if it is made of literals, `.`, character classes, `^` `$`, `|`, escapes and groups that are NOT repeated, with at most one
    unbounded repetition (`*`, `+`, `{n,}`), two `{n,m}` (a spread of 64 at most), four `?`, four `|` inside groups (each one can
    double the paths of a name that fits both sides, `(a|a)(a|a)...`; a `|` outside any group only adds a branch) and no
    back-reference or lookaround. What this bounds is the number of paths the engine tries for one start in the name: it grows with
    the length of the name by a small power (the one unbounded repetition) times a constant of the other repetitions and branches,
    and that constant can be large. It is not a promise of speed, which is why search_bounded runs every search under a clock."""
    i, size, depth = 0, len(pattern), 0
    unbounded = wide = optional = inner_pipes = 0
    can_repeat = after_group = False
    while i < size:
        c = pattern[i]
        if c == "\\":
            if i + 1 >= size:
                return "ends with a backslash"
            d = pattern[i + 1]
            if d in "123456789":
                return "uses a back-reference"
            can_repeat, after_group = d not in "AZbB", False
            i += 2
            continue
        if c == "[":
            j = i + 1
            if pattern[j:j + 1] == "^":
                j += 1
            if pattern[j:j + 1] == "]":
                j += 1
            while j < size and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            if j >= size:
                return "has a [ that is not closed"
            i, can_repeat, after_group = j + 1, True, False
            continue
        if c == "(":
            if pattern[i + 1:i + 2] == "?":
                if pattern[i + 1:i + 3] != "?:":
                    return "uses a lookaround, a flag or a named group"
                i += 3
            else:
                i += 1
            depth += 1
            can_repeat = after_group = False
            continue
        if c == ")":
            depth -= 1
            if depth < 0:
                return "has a ) with no ("
            i, can_repeat, after_group = i + 1, False, True
            continue
        quantifier = None
        if c in "*+?":
            quantifier, length = c, 1
        elif c == "{":
            m = _BRACE.match(pattern, i)
            if m:
                quantifier, length = m.group(), len(m.group())
        if quantifier is not None:
            if after_group:
                return "repeats a group"
            if not can_repeat:
                return "repeats nothing"
            if quantifier in ("*", "+"):
                unbounded += 1
            elif quantifier == "?":
                optional += 1
            else:
                low, comma, high = m.group(1), m.group(2), m.group(3)
                if (low and int(low) > 255) or (high and int(high) > 255):
                    return "repeats more than 255 times"
                if comma and not high:
                    unbounded += 1
                elif comma and int(high or 0) - int(low or 0) > 64:
                    return "has a {n,m} that spreads over more than 64"
                elif comma and int(high or 0) > int(low or 0):
                    wide += 1
            i += length
            if pattern[i:i + 1] in ("?", "+") and quantifier != "?":
                i += 1                                          # a lazy or possessive suffix
            can_repeat = False
            continue
        if c == "|" and depth > 0:
            inner_pipes += 1
        can_repeat = c not in "^$|"
        after_group = False
        i += 1
    if inner_pipes > 4:
        return "has more than four | inside groups"
    if unbounded > 1:
        return "has more than one unbounded repetition (* + {n,})"
    if wide > 2 or optional > 4:
        return "has more than two {n,m} or four ?"
    return None


MATCH_SECONDS = 2.0                 # one search of one name by the caller's pattern may take this long; past it the run stops with an error


class PatternTooSlow(Exception):
    pass


def _match_alarm(signum, frame):
    raise PatternTooSlow()


def search_bounded(rx, text, seconds=None):
    """rx.search(text) under a wall-clock bound that holds whatever the pattern: the interval timer's signal is delivered inside the
    regular-expression engine (it looks for signals every few thousand steps), so a search that would take minutes ends with
    PatternTooSlow after `seconds` (MATCH_SECONDS by default). The names are the evidence's and the pattern the caller's."""
    signal.signal(signal.SIGALRM, _match_alarm)
    signal.setitimer(signal.ITIMER_REAL, MATCH_SECONDS if seconds is None else seconds)
    try:
        return rx.search(text)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


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


def tail_key(path):
    return path.replace("/", "\\").strip("\\")


class Mapping:
    """Source paths a collector recorded: the KAPE copy logs found under the root (SourceFile and DestinationFile columns). A
    row belongs to the files below the log's own directory, matched on the path relative to that directory. Other collectors'
    records are not read here, so their files have no observed path."""

    def __init__(self):
        self.logs = []
        self.rows_by_log = []
        self.rows = 0
        self.capped = False
        self.unusable_rows = 0
        self.unreadable = []
        self.unsupported = []
        self._listings = collections.OrderedDict()
        self.prefixes = []                  # per log: the text of DestinationFile before the delivered tree, learned from the files that name a row in full
        self.undecided = set()              # logs whose files name two prefixes equally often: every file of such a log that matches a row is ambiguous
        self.claims = collections.Counter() # (log, row) -> how many files below the log's directory name the row with that prefix
        self.claims_stopped = False

    def load(self, root, rels):
        for rel in rels:
            entry = {"log": shown(rel, "log path"), "directory": shown(os.path.dirname(rel), "log directory"), "_dir": os.path.dirname(rel),
                     "rows": 0, "loaded": 0, "unusable_rows": 0}
            if out_of_time():
                self.unreadable.append({"log": entry["log"], "reason": "the time limit stopped the mapping"})
                continue
            try:
                head = read_head(os.path.join(root, rel))
            except OSError as exc:
                self.unreadable.append({"log": entry["log"], "reason": describe(exc)})
                continue
            if head and (head[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in head):
                self.unsupported.append({"log": entry["log"], "reason": "the log is UTF-16 or binary: it is not read as text"})
                continue
            try:
                fh = open_regular(os.path.join(root, rel), encoding="utf-8-sig", errors="surrogateescape", newline="")
            except OSError as exc:
                self.unreadable.append({"log": entry["log"], "reason": describe(exc)})
                continue
            by_name = {}
            with fh:
                reader = csv.reader(fh, strict=True)
                try:
                    header = [h.strip().lower() for h in next(reader)]
                except (StopIteration, csv.Error, OSError):
                    self.unsupported.append({"log": entry["log"], "reason": "no readable header row"})
                    continue
                if "sourcefile" not in header or "destinationfile" not in header:
                    self.unsupported.append({"log": entry["log"], "reason": "no SourceFile and DestinationFile columns"})
                    continue
                s, d = header.index("sourcefile"), header.index("destinationfile")
                m = header.index("modifiedonutc") if "modifiedonutc" in header else None
                z = header.index("filesize") if "filesize" in header else None
                ordinal = 0
                while True:
                    if (ordinal & 1023) == 0 and out_of_time():
                        self.unreadable.append({"log": entry["log"], "reason": "the time limit stopped the mapping after row %d of this log" % ordinal})
                        break
                    start_line = reader.line_num + 1                  # a record can span lines: its line is the one it starts on
                    try:
                        row = next(reader)
                    except StopIteration:
                        break
                    except csv.Error:
                        entry["unusable_rows"] += 1
                        continue
                    if not row:
                        continue
                    ordinal += 1
                    entry["rows"] = ordinal
                    if len(row) <= max(s, d):
                        entry["unusable_rows"] += 1
                        continue
                    if self.rows >= MAX_MAP_ROWS:
                        self.capped = True
                        continue
                    dest = tail_key(row[d])
                    by_name.setdefault(dest.rsplit("\\", 1)[-1].lower(), []).append((dest, row[s], ordinal, row[m] if m is not None and m < len(row) else None,
                                                                                    row[z] if z is not None and z < len(row) else None, start_line))
                    self.rows += 1
                    entry["loaded"] += 1
            self.unusable_rows += entry["unusable_rows"]
            self.logs.append(entry)
            self.rows_by_log.append(by_name)

    def settle(self, root):
        """Learn each log's destination prefix and count the claimants of every row, from one pass over the names below the root.
        A row belongs to the files whose path relative to the log's directory is the tail of its DestinationFile AND whose
        DestinationFile begins with the log's prefix (the text before the delivered tree, the one the files that name a row in full
        agree on): a shorter path with the same tail (a stray $MFT beside the real C/$MFT) is no claimant. A row claimed by more than
        one file, or a log whose files name two prefixes equally often, makes its files ambiguous, never observed."""
        if not self.logs:
            return
        by_dir = {}
        for i, log in enumerate(self.logs):
            by_dir.setdefault(log["_dir"], []).append(i)
        votes = [collections.Counter() for _ in self.logs]
        pairs = []
        prefix = root.rstrip(os.sep) + os.sep
        stack = [root]
        while stack and not self.claims_stopped:
            if out_of_time():
                self.claims_stopped = True
                break
            directory = stack.pop()
            try:
                with os.scandir(directory) as it:
                    for entry in it:
                        try:
                            if entry.is_symlink() or is_own(entry):
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                        except OSError:
                            continue
                        rel = entry.path[len(prefix):] if entry.path.startswith(prefix) else os.path.relpath(entry.path, root)
                        parts = rel.split(os.sep)
                        for depth in range(len(parts)):
                            logs_here = by_dir.get(os.sep.join(parts[:depth]))
                            if not logs_here:
                                continue
                            key = tail_key(os.sep.join(parts[depth:]))
                            klow = key.lower()
                            for i in logs_here:
                                for dest, source, ordinal, modified, size, line in self.rows_by_log[i].get(klow.rsplit("\\", 1)[-1], ()):
                                    dl = dest.lower()
                                    if dl == klow or dl.endswith("\\" + klow):
                                        found = dl[:len(dl) - len(klow)]
                                        votes[i][found] += 1
                                        pairs.append((i, ordinal, found))
                                        if len(pairs) > MAX_CLAIMS:
                                            self.claims_stopped = True
            except OSError:
                continue
        for i in range(len(self.logs)):
            top = votes[i].most_common(2)
            if not top:
                self.prefixes.append(None)
            elif len(top) == 2 and top[0][1] == top[1][1]:
                self.prefixes.append(None)
                self.undecided.add(i)
            else:
                self.prefixes.append(top[0][0])
        for i, ordinal, found in pairs:
            if i in self.undecided or found == self.prefixes[i]:
                self.claims[(i, ordinal)] += 1

    def _siblings(self, root, rel):
        """How many entries of the file's directory share its name, letters of case apart (two on a case-sensitive file system)."""
        directory = os.path.dirname(os.path.join(root, rel))
        listing = self._listings.get(directory)
        if listing is None:
            try:
                listing = collections.Counter(n.lower() for n in os.listdir(directory))
            except OSError:
                listing = collections.Counter()
            self._listings[directory] = listing
            if len(self._listings) > 64:
                self._listings.popitem(last=False)
        return listing[os.path.basename(rel).lower()]

    def lookup(self, root, rel):
        """(record or None, status): `observed` when the rows that match the file name one source, `ambiguous` when they name
        several or the file shares its name with a sibling, `no_row_matched` otherwise."""
        if self.claims_stopped:
            return None, "mapping_capped"
        hits, reasons = [], []
        for index, log in enumerate(self.logs):
            directory = log["_dir"]
            if directory and not rel.startswith(directory + os.sep):
                continue
            key = tail_key(rel[len(directory) + 1:] if directory else rel)
            klow = key.lower()
            for dest, source, ordinal, modified, size, line in self.rows_by_log[index].get(klow.rsplit("\\", 1)[-1], ()):
                dl = dest.lower()
                if dl == klow or dl.endswith("\\" + klow):
                    if index in self.undecided:
                        reasons.append("the files below this copy log's directory name two destination prefixes equally often, so no row is known to belong to a file")
                    elif dl[:len(dl) - len(klow)] != self.prefixes[index]:
                        continue                                          # a shorter path with the same tail than the files that name a row in full
                    elif self.claims[(index, ordinal)] > 1:
                        reasons.append("a row of the copy log is named by %d files below its directory" % self.claims[(index, ordinal)])
                    hits.append((index, ordinal, source, modified, size, line))
        if not hits:
            return None, ("mapping_capped" if self.capped else "no_row_matched")
        sources = {tail_key(h[2]).lower() for h in hits}
        siblings = self._siblings(root, rel) > 1
        if len(sources) > 1 or reasons or siblings:
            why = ("the rows name different sources" if len(sources) > 1 else
                   "the file shares its name, letters of case apart, with a sibling" if siblings else reasons[0])
            return {"candidates": [{"path": scrub(h[2], "copy log row"), "log": self.logs[h[0]]["log"], "row": h[1], "line": h[5]} for h in hits],
                    "candidate_count": len(hits), "why": why}, "ambiguous"
        first = hits[0]
        source = scrub(first[2], "copy log row")
        record = {"path": source, "reported_by": "KAPE copy log", "log": self.logs[first[0]]["log"], "row": first[1], "line": first[5],
                  "matched_by": "the row's DestinationFile ends with this file's path relative to the log's own directory",
                  "recorded_modified_utc_raw": scrub(first[3], "copy log row") if first[3] is not None else None,
                  "recorded_modified_clock": "the collector's record of the source file's ModifiedOnUtc: a different clock from the delivered file's modified",
                  "recorded_file_size_raw": scrub(first[4], "copy log row") if first[4] is not None else None}
        if len(hits) > 1:
            record["also_rows"] = [{"log": self.logs[h[0]]["log"], "row": h[1], "line": h[5]} for h in hits[1:]]
        if re.search(r"^[A-Za-z]:\\.*:", first[2]) or ":" in first[2][2:]:
            record["stream_syntax_in_path"] = True
        return record, "observed"


class HashStopped(Exception):
    def __init__(self, read):
        super().__init__("the time limit ended the read")
        self.read = read


def hash_file(path, want_hash, want_head):
    """(digest or None, first bytes or None, bytes read). Opened without following a link; a file that changed type after the
    walk is refused. When only the first bytes are wanted only HEAD_BYTES are read."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        if not want_hash:
            head = os.read(fd, HEAD_BYTES)
            return None, head, len(head)
        head = None
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(fd, CHUNK)
            if head is None:
                head = block[:HEAD_BYTES]
            if not block:
                break
            total += len(block)
            digest.update(block)
            if out_of_time():
                raise HashStopped(total)
        return digest.hexdigest(), (head if want_head else None), total
    finally:
        os.close(fd)


def find_copy_logs(root):
    """Names only, one pass: where the KAPE copy logs are, so the mapping is loaded before the census is written."""
    found, stack = [], [root]
    prefix = root.rstrip(os.sep) + os.sep
    while stack and not out_of_time():
        directory = stack.pop()
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.name.lower().endswith("_copylog.csv") and entry.is_file(follow_symlinks=False):
                            found.append(entry.path[len(prefix):] if entry.path.startswith(prefix) else os.path.relpath(entry.path, root))
                    except OSError:
                        continue
        except OSError:
            continue
    return sorted(found, key=sort_key)


def main():
    install_signal_handlers()
    args = read_args()
    root = want_str(args, "root", "root is required: the collection directory")
    limit = want_int(args, "limit", DEFAULT_LIMIT)
    want_hash = want_bool(args, "hash", True)
    credentials_too = want_bool(args, "hash_credential_stores")
    want_values = want_bool(args, "write_values")
    seconds = want_int(args, "time_limit_seconds", 3000, 1, 3400)
    out_file = want_str(args, "out_file")
    csv.field_size_limit(MAX_FIELD)
    pattern = None
    contains = want_str(args, "contains")
    if contains is not None:
        if len(contains) > 2000:
            fail("contains is longer than 2000 characters")
        why = refuse_pattern(contains)
        if why:
            fail("contains is outside the pattern language this tool runs on names (%s): a pattern like it can take minutes on one long "
                 "name. Use literals, ., [classes], ^ $, | and groups that are not repeated, with at most one unbounded repetition "
                 "(* + {n,}), two {n,m}, four ? and four | inside groups; no back-reference or lookaround." % why)
        if not hasattr(signal, "setitimer"):
            fail("contains needs a platform with interval timers, which bound every search of a name; this one has none")
        try:
            pattern = re.compile(contains, re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))
    if credentials_too and not (in_job() and want_values and secret_job()):
        fail("hash_credential_stores needs a secret-output job and write_values: true: the digest of a credential store goes only to the sealed values file, "
             "never to the answer or the index. Run this as job_run tool=collection_index with secret_output: true and write_values: true.")
    try:
        VALUES[0] = SecretValues(want_values, VALUES_NAME, TOOL)
    except SecretValuesRefused as exc:
        fail(str(exc))
    if not os.path.isdir(root):
        fail("no such directory" if not os.path.isfile(root) else "root is a file: give the directory that holds it", root=root)
    dest = None
    if out_file is not None:
        dest = resolve_output(out_file, "out_file")
        if is_inside(dest, root):
            fail("out_file is inside the collection being indexed: the index would list itself and could replace an object of the "
                 "collection. Name a place outside the root.", out_file=out_file)
    start_clock(seconds)
    prefix = root.rstrip(os.sep) + os.sep
    table = Table(TOOL, limit, dest=dest, always=bool(dest) or in_job() or pattern is not None)
    streams = Table(TOOL + "-streams", limit)
    dates_table = Table(TOOL + "-dates", 50)

    mapping = Mapping()
    mapping.load(root, find_copy_logs(root))
    mapping.settle(root)

    census = {"directories_listed": 0, "regular_files": 0, "bytes": 0, "symbolic_links": 0, "special_files": 0, "empty_directories": 0, "errors": 0}
    errors = []
    stopped = None
    dates = collections.Counter()
    unrepresentable = 0
    hashing = {"hashed": 0, "failed": 0, "not_attempted_outside_filter": 0, "not_attempted_hash_false": 0,
               "not_attempted_credential_store_name": 0, "size_changed_during_read": 0, "stopped_by_time_limit": 0,
               "credential_store_digests_in_the_values_file": 0}
    mapped = {"observed": 0, "ambiguous": 0, "no_row_matched": 0, "mapping_capped": 0}
    matching = 0
    row_no = 0
    matches_page, matches_bytes = [], 0

    def problem(rel, what, exc):
        census["errors"] += 1
        if len(errors) < FIRST_PROBLEMS:
            errors.append({"path": inline_text(shown(rel, "census error")), "what": what, "error": describe(exc)})

    def matches(shown_rel, shown_hypothesis=None):
        if pattern is None:
            return True
        try:
            return bool(search_bounded(pattern, shown_rel) or (shown_hypothesis is not None and search_bounded(pattern, shown_hypothesis)))
        except PatternTooSlow:
            fail("contains took more than %g seconds on one name and the run was stopped: the pattern backtracks too long on the evidence's "
                 "names. Use a pattern with fewer repetitions and no alternation of overlapping words." % MATCH_SECONDS)

    def emit(row, hit):
        nonlocal matching, row_no, matches_bytes
        row_no += 1
        row["row"] = row_no
        row["matches_filter"] = hit
        if hit:
            matching += 1
            if pattern is not None:
                text = json.dumps(row, default=str)
                if len(matches_page) < limit and matches_bytes + len(text) <= INLINE_BUDGET:
                    matches_page.append(row)
                    matches_bytes += len(text)
        table.add(row)

    stack = [root]
    while stack and not stopped:
        if out_of_time():
            stopped = {"reason": "the time limit ended the census", "directories_not_listed": len(stack)}
            break
        directory = stack.pop()
        is_top = directory == root
        rel_dir = directory[len(prefix):] if directory.startswith(prefix) else "."
        try:
            entries = list_sorted(directory)
        except OSError as exc:
            problem(rel_dir, "the directory could not be listed", exc)
            shown_dir = shown(rel_dir, "path")
            emit({"kind": "unexamined", "in_collection": shown_dir, "error": describe(exc)}, matches(shown_dir))
            continue
        census["directories_listed"] += 1
        if not entries and not is_top:
            census["empty_directories"] += 1
            shown_dir = shown(rel_dir, "path")
            emit({"kind": "directory", "in_collection": shown_dir, "entries": 0, "empty": True}, matches(shown_dir))
        subdirs = []
        parents = [p.lower() for p in rel_dir.split(os.sep) if p and p != "."]
        for position, entry in enumerate(entries):
            if out_of_time():
                stopped = {"reason": "the time limit ended the census", "directories_not_listed": len(stack) + len(subdirs),
                           "entries_not_examined_in_the_current_directory": len(entries) - position}
                break
            if is_own(entry):
                continue
            rel = entry.path[len(prefix):] if entry.path.startswith(prefix) else os.path.relpath(entry.path, root)
            shown_rel = shown(rel, "path")
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                problem(rel, "the entry could not be examined", exc)
                emit({"kind": "unexamined", "in_collection": shown_rel, "error": describe(exc)}, matches(shown_rel))
                continue
            mode = st.st_mode
            if stat.S_ISDIR(mode):
                subdirs.append(entry.path)
                continue
            if stat.S_ISLNK(mode):
                census["symbolic_links"] += 1
                target, link_error = None, None
                try:
                    target = os.readlink(entry.path)
                except OSError as exc:
                    problem(rel, "the link could not be read", exc)
                    link_error = describe(exc)
                row = {"kind": "symlink", "in_collection": shown_rel, "link_target": scrub(target, "link target") if target is not None else None,
                       "followed": False}
                if link_error:
                    row["error"] = link_error
                emit(row, matches(shown_rel))
                continue
            if not stat.S_ISREG(mode):
                census["special_files"] += 1
                what = next((n for t, n in ((stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
                                            (stat.S_ISCHR, "a character device")) if t(mode)), "a special file")
                emit({"kind": "special", "in_collection": shown_rel, "what": what, "read": False}, matches(shown_rel))
                continue
            census["regular_files"] += 1
            census["bytes"] += st.st_size
            name = entry.name
            ns = st.st_mtime_ns
            iso = iso_ns(ns)
            if iso is None:
                unrepresentable += 1
            else:
                dates[iso[:10]] += 1
            hypothesis = scrub_all(source_path_hypothesis(rel))
            observed, status = (mapping.lookup(root, rel) if mapping.logs else (None, "no_collector_mapping"))
            if status in mapped:
                mapped[status] += 1
            notes = []
            base, extension = os.path.splitext(name)
            if base.upper() in RESERVED:
                notes.append("the base name is a Windows reserved device name; whether a collector renamed it is not established")
            # the guess is made on the name as it is printed: a token that holds `_` (a JWT, base64url, hf_, sk-proj-) is withheld before
            # the name is split at its last `_`, never after, so no piece of it is judged alone
            found = STREAM_HINT.match(shown(name, "stream name")) if "_" in name and "." in name else None
            if found and "." in found.group(1):
                suffix = found.group(2)
                if suffix.lower() in KNOWN_STREAMS or (("." in suffix and suffix.rsplit(".", 1)[1].lower() not in PLAIN_SUFFIXES) or suffix.startswith("$")):
                    streams.add({"file": shown_rel, "possible_original": scrub("%s:%s" % (found.group(1), suffix), "stream name"),
                                 "known_stream": suffix.lower() in KNOWN_STREAMS,
                                 "basis": "heuristic: the file name's shape only; a stream that was dropped, not renamed, leaves nothing to find"})
            hint = credential_hint(name, parents)
            hit_filter = matches(shown_rel, hypothesis["path"])
            do_hash = want_hash and hit_filter and (credentials_too or hint is None)
            if not want_hash:
                hashing["not_attempted_hash_false"] += 1
            elif not hit_filter:
                hashing["not_attempted_outside_filter"] += 1
            elif hint is not None and not credentials_too:
                hashing["not_attempted_credential_store_name"] += 1
            row = {"kind": "file", "in_collection": shown_rel, "bytes": st.st_size, "modified": iso, "modified_epoch_ns": str(ns),
                   "source_path_hypothesis": hypothesis,
                   "source_path_observed": observed if status == "observed" else None, "source_path_mapping": status}
            if status == "ambiguous":
                row["source_path_candidates"] = observed
            if notes:
                row["notes"] = notes
            if hint is not None:
                row["may_hold_secrets"] = {"kind": hint, "basis": "a name hint only; the absence of this mark says nothing"}
            digest = head = None
            read_head_for_class = wants_head(name, st.st_size, is_top)
            if do_hash or read_head_for_class:
                try:
                    digest, head, nread = hash_file(entry.path, do_hash, read_head_for_class)
                    if do_hash:
                        if hint is not None:
                            # a credential store's digest goes to the values file only, never to the answer or the index
                            VALUES[0].add("D%06d" % (hashing["credential_store_digests_in_the_values_file"] + 1),
                                          {"where": "sha256 of a credential-store file", "file": rel}, digest)
                            hashing["credential_store_digests_in_the_values_file"] += 1
                            row["sha256"] = None
                            row["hash_status"] = "hashed; the digest is in the values file only"
                        elif nread != st.st_size:
                            row["sha256"] = None
                            row["sha256_of_bytes_read"] = digest
                            row["hash_status"] = "size_changed_during_read"
                            row["hash_note"] = "%d bytes were read where the census saw %d: the file changed during the read, and the digest is not of the object the census listed" % (nread, st.st_size)
                            hashing["size_changed_during_read"] += 1
                            census["errors"] += 1
                            if len(errors) < FIRST_PROBLEMS:
                                errors.append({"path": shown_rel, "what": "the file changed size during the read", "error": row["hash_note"]})
                        else:
                            row["sha256"] = digest
                            row["hash_status"] = "hashed"
                            hashing["hashed"] += 1
                except HashStopped as stop:
                    row["sha256"] = None
                    row["hash_status"] = "stopped: the time limit ended the read after %d bytes" % stop.read
                    hashing["stopped_by_time_limit"] += 1
                    stopped = stopped or {"reason": "the time limit ended a hash", "directories_not_listed": len(stack) + len(subdirs),
                                          "entries_not_examined_in_the_current_directory": len(entries) - position - 1}
                except OSError as exc:
                    if do_hash:
                        row["sha256"] = None
                        row["hash_status"] = "failed"
                        row["hash_error"] = describe(exc)
                        hashing["failed"] += 1
                    else:
                        row["class_error"] = describe(exc)
                    problem(rel, "the file could not be read", exc)
            if "sha256" not in row:
                row["sha256"] = None
                row["hash_status"] = ("not_attempted: hash was false" if not want_hash else
                                      "not_attempted: outside the contains filter" if not hit_filter else
                                      "not_attempted: the name marks a credential store (hash_credential_stores with write_values, in a job, hashes it into the values file)")
            if head is not None:
                klass = classify_head(name, head, st.st_size, is_top)
                if klass:
                    row["object_class"] = {**klass, "note": "from the first bytes and the name; the object was not opened"}
            elif read_head_for_class and (is_image_named(extension.lower()) or extension.lower() in MEMORY_EXT | ARCHIVE_EXT):
                klass = classify_head(name, b"", st.st_size, is_top)
                if klass:
                    row["object_class"] = {**klass, "note": "from the name only: the first bytes could not be read"}
            emit(row, hit_filter)
            if stopped:
                break
        if stopped:
            break
        stack.extend(reversed(subdirs))

    stream_info = streams.finish()
    for date, count in sorted(dates.items(), key=lambda kv: (-kv[1], kv[0])):
        dates_table.add({"date_utc": date, "files": count})
    dates_info = dates_table.finish()
    page = table.finish()
    values = VALUES[0]                    # closed by release(), after the last string of the answer has been judged
    shown_page = matches_page if pattern is not None else table.page

    dominant = dates.most_common(1)
    anomaly = None
    total = census["regular_files"]
    if dominant and total > 20 and dominant[0][1] / total > 0.9:
        anomaly = {"dominant_date_utc": dominant[0][0], "files_on_that_date": dominant[0][1], "regular_files": total,
                   "fraction": round(dominant[0][1] / total, 4), "threshold": 0.9, "minimum_files": 20,
                   "what_it_is": "a fact about the delivered modification times, as UTC calendar dates",
                   "not_established": "the cause: a copy that reset the times, one bulk write and a real burst of activity all look like this. "
                                      "The clocks that could tell them apart are the collector's recorded times, the archive's member times, "
                                      "the acquisition time and the times stored inside the files; they are separate clocks and are not read here"}
    problems = []
    if stopped:
        problems.append(stopped["reason"])
    if census["errors"]:
        problems.append("%d object(s) could not be listed, examined or read, or changed during the read: see census.first_errors and the rows with kind unexamined" % census["errors"])
    if mapping.unreadable or mapping.unsupported:
        problems.append("a copy log could not be used for the path mapping")
    if mapping.unusable_rows:
        problems.append("%d copy-log row(s) could not be used for the path mapping" % mapping.unusable_rows)
    if mapping.capped:
        problems.append("the path mapping stopped at %d copy-log rows" % MAX_MAP_ROWS)
    if mapping.claims_stopped:
        problems.append("the pass that counts which files name each copy-log row did not finish (time limit or %d pairs): no path is observed" % MAX_CLAIMS)
    inline_limited = matching > len(shown_page)
    out = {
        "tool": TOOL, "parser": PARSER, "root": shown(root, "root"),
        "status": "complete" if not problems else "partial",
        "status_basis": "every directory was listed and every object was recorded" if not problems else "; ".join(problems),
        "ignored_parameters": ignored_parameters(args, KNOWN_PARAMETERS),
        "census": {**census, "first_errors": errors, "stopped": stopped},
        "entry_count": matching,
        "entries_inline": len(shown_page),
        "inline_limited": inline_limited,
        "complete_index": page.get("all_results"),
        "index": {**{k: v for k, v in page.items() if k not in ("matched", "returned", "truncated")}, "rows": page["matched"],
                  "scope": "every object walked, with matches_filter on each row", "filter": {"contains": contains, "rows_matching": matching}},
        "hashing": {"requested": want_hash, "algorithm": "sha256", "whole_file": True, **hashing},
        "source_paths": {"hypothesis": "every file row carries source_path_hypothesis: a convention's reading, with method, confidence, unresolved components and alternatives",
                         "observed": mapping_summary(mapping, mapped)},
        "time_basis": "modified is the delivered file's st_mtime, UTC, to the nanosecond; modified_epoch_ns is the raw value as a decimal string (a JSON "
                      "number past 2^53 does not survive every reader); both are the clock of the copy you were handed",
        "mtime_distribution_anomaly": anomaly,
        "modification_dates_distinct": len(dates),
        "modification_dates_table": dates_info,
        "modification_dates": dict(sorted(dates.items(), key=lambda kv: (-kv[1], kv[0]))[:50]),
        "modification_times_not_representable": unrepresentable,
        "possible_renamed_streams_table": stream_info,
        "withheld": {"strings_withheld": WITHHELD["count"], "values": values.summary()},
        "note": ("A census of the delivered objects with a hypothesis for each source path. Cite the path in the collection with its sha256, and an observed "
                 "source path only with its copy-log row; a hypothesis is a guess about a layout. The complete index file holds every row; "
                 "the entries here are a page."),
        "entries": shown_page,
        "possible_renamed_streams": streams.page,
    }
    write_answer(out)


def mapping_summary(mapping, mapped):
    if not mapping.logs and not mapping.unreadable and not mapping.unsupported:
        return {"status": "no collector mapping available", "basis": "no KAPE copy log was found under the root; the other collectors' records are not read by this tool"}
    partial = bool(mapping.capped or mapping.claims_stopped or mapping.unreadable or mapping.unsupported or mapping.unusable_rows)
    lists = {}
    for name, items in (("logs", [{k: v for k, v in entry.items() if k != "_dir"} for entry in mapping.logs]), ("logs_unreadable", mapping.unreadable),
                        ("logs_unsupported", mapping.unsupported)):
        table = Table(TOOL + "-" + name.replace("_", "-"), FIRST_PROBLEMS)
        for row in items:
            table.add(row)
        lists[name + "_table"] = table.finish()
        lists[name] = table.page
    return {"status": "partial" if partial else "read",
            "reported_by": "KAPE copy log (SourceFile and DestinationFile)", "rows_loaded": mapping.rows, "rows_unusable": mapping.unusable_rows, "files": mapped,
            "basis": "a file has an observed path only when the rows whose DestinationFile ends with its path relative to a copy log's own directory, "
                     "and begins with the destination prefix the files that name a row in full agree on, name one source and no other file names the same row; "
                     "digests in the log are not compared here. Each list below is the first rows of a table whose whole is in the file its *_table entry names",
            **lists}


if __name__ == "__main__":
    try:
        main()
    except (SystemExit, KeyboardInterrupt):
        raise
    except BaseException as exc:                  # a bug here is a JSON error that names it, not a traceback and a half-written answer
        fail("the tool stopped on an unexpected error (%s)" % type(exc).__name__, detail=str(exc))
