#!/usr/bin/env python3
"""Compare what a collector's profile could request with what the delivery's own records say was requested, excluded and collected.

It is a parser and a comparator, never a live collector: nothing in a delivery or in a definition is executed, and a profile or an
artefact definition found inside the delivery is data to describe, never trusted as the definition of what was requested. The
definitions come from three corpora the pack pins (UAC's release, Velociraptor's source tree for its artifact definitions, the
KapeFiles repository for its `.tkape` target files). Each corpus archive is hashed and compared with the list of sha256 this script
carries before one member of it is read; one that is not on the list is refused, and with `allow_unpinned: true` it is read all the same
and everything taken from it is reported with version `unknown` and `pinned: false`. A definition file is reported with its corpus, its
version and its sha256; where no corpus is available the answer says `definitions_not_available` and is partial.

  - UAC: a profile's artefact list (include globs and `!` exclude globs, in order) is resolved against the artefact files of the pinned
    corpus. The profile is named by the caller or by the delivery's UAC log; a profile file found in the delivery is compared with the
    pinned profile of the same name and reported as differing, never used. A selection with a variable in it is
    `unresolved_dynamic_selection`.
  - Velociraptor: the collection's own record of its request (`collection_context.json`, an ArtifactCollectorContext whose `request` holds
    `artifacts` and `specs` with `parameters.env` key and value pairs) is read as data, each artefact is looked up by name in the pinned
    definitions, and a parameter that selects targets at run time (a glob, a path, a regex, a list) whose value is not in the record is
    `unresolved_dynamic_selection`. The VQL is never run. A definition delivered in the collection that differs from the pinned one is
    reported.
  - KAPE: the targets a run names (from the `--target` of the console log's command line, or `kape_targets`) are resolved through the
    pinned `.tkape` files, compound targets included (a `Path` that names another `.tkape`, to a depth bound; a cycle is refused by name),
    into the paths and file masks they could request, and compared with the copy and skip logs. A path with a KAPE variable (`%user%`) is a
    dynamic selection and is never expanded.

What it does not say: that a collector finished, that a profile was the one actually run, that a target not collected was wanted, or
why. A match of a delivered file to a pattern is a match of names. `proposed_additional_evidence` is a list of what the definitions say
could have been taken and was not found, never a command to collect it. YAML is read by a bounded reader of the subset the definitions
use: anchors, aliases, tags, merge keys, complex keys, more than one document and tabs in indentation are refused by name, and so are a
file, a line count, a depth, a node count or a scalar over its bound.

SECRET-SAFE OUTPUT (docs/packs.md, "Secrets and sensitive output"). Paths and log text are printed through the shared withholding block
and the output boundary; `write_values: true` (a job only) writes the real strings to `$OUT/collection-profile-compare-values.jsonl`, mode
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
        if i > 0 and flat[i - 1] in "=:":                 # a delimiter right after a delimiter has no name before it: a run of 2 MiB of them is skipped, not judged one by one
            continue
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
import hashlib
import struct
import tarfile
import zipfile


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
import sys
import unicodedata

MEMORY_ENV = ("COLLECTION_MEMORY_BYTES", "COLLECTION_INTAKE_MEMORY_BYTES")      # the bytes this process may hold, set by hand (the second name is the recipe's own, still read)


def memory_ceiling():
    """The bytes this process may hold, as far as it can be known: COLLECTION_MEMORY_BYTES (or the recipe's COLLECTION_INTAKE_MEMORY_BYTES) when
    it is a positive whole number, else the smallest of the cgroup limit and the address-space and data limits. None when nothing limits it that
    this can see."""
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


def over_memory():
    """A sentence when the process holds more than 60% of what it may hold (the census and the per-member state of a delivery of millions of
    entries are what grow with the input), else None: the census and the pass stop there, partial, and say so, instead of being killed with
    nothing written."""
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


def size_text(n):
    """A byte count in the largest unit that does not make it 0 (a tiny override is not '0 MB')."""
    if n >= 1 << 20:
        return "%d MB" % (n >> 20)
    if n >= 1 << 10:
        return "%d KB" % (n >> 10)
    return "%d bytes" % n


CLOCK_EVERY = 256                  # a loop over the census asks the clock and the memory bound this many entries apart


def census_clock(census, position, what):
    """True when the time limit or the memory bound says a loop over the census must end here (asked every CLOCK_EVERY entries): the census is then
    marked stopped and not complete, so that the answer is partial and no record is called missing."""
    if position % CLOCK_EVERY:
        return False
    reason = "the time limit" if out_of_time() else over_memory()
    if not reason:
        return False
    if census.stopped is None:
        census.stopped = {"reason": "%s ended %s" % (reason, what), "directories_not_listed": 0}
    census.complete = False
    return True


def fold_name(text):
    """The key a name is joined by: NFC-normalised, then case-folded, so a name written in decomposed form (as macOS writes it) is the same name
    as its precomposed record."""
    return unicodedata.normalize("NFC", text).casefold()


MEMORY_CHECK_EVERY = 1024          # the census asks for the memory this many entries apart (one getrusage call each)
MAX_CENSUS = 2000000              # entries held for the join; past it the census is partial and no record is called missing
REC_LINE = 1 << 20                # a log line longer than this is read in part; the whole line stays in the evidence at its locator
REC_CHUNK = 1 << 20
MAX_PATH_PARTS = 1024              # components of a claimed path the join looks at: the tail of a longer one (no real path has more); a longer exact claim names no file
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
ENCRYPTED_PAYLOAD = "data.zip"
ENCRYPTED_METADATA = "metadata.json"
ENCRYPTION_KEYS = ("Scheme", "EncryptedPass", "PublicKey")
ENCRYPTION_METADATA_BYTES = 65536
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
    "velociraptor_encrypted": {"id": "velociraptor_encrypted/1", "collector": "Velociraptor", "reads": "metadata.json, data.zip", "supported": False,
                               "schema": ("the encrypted collection 0.77.2 writes when a password is set (reporting/container.go, NewContainerFromWriter, tag v0.77.2; the metadata keys are set by "
                                          "artifacts/definitions/Server/Utils/CreateCollector.yaml at the same tag): an outer zip of metadata.json (plain; written only when the collector was "
                                          "given metadata, with the keys Scheme, EncryptedPass and PublicKey) and data.zip, a stored member that is itself encrypted with the zip password "
                                          "(github.com/alexmullins/zip, WinZip AES) and holds the collected members. It is recognised by those two member names with nothing else beside them, "
                                          "and by the encrypted flag of data.zip in the outer zip or the Scheme key of metadata.json, never by entropy. Nothing is decrypted and no record is read"),
                               "unsupported_reason": "an encrypted Velociraptor collection: its records are inside the encrypted payload (data.zip), which is not decrypted and was not read"},
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
        return fold_name(rel.replace(os.sep, "/"))

    def add(self, rel, size, kind):
        if self.total >= self.cap:
            self.capped = True
            self.complete = False
            return
        if self.stopped is not None and self.stopped.get("memory"):
            self.complete = False
            return
        self.total += 1
        if self.total % MEMORY_CHECK_EVERY == 0:
            held = over_memory()
            if held:
                self.stopped = {"reason": held, "memory": True, "entries_held": self.total}
                self.complete = False
                return
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
        if census.stopped is not None and census.stopped.get("memory"):
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
            if census.stopped is not None and census.stopped.get("memory"):
                return
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
    found = {"kape": {}, "uac_logs": [], "uac_hashes": [], "uac_dirs": [], "velociraptor": {}, "velo_results": {}, "velo_logs": {}, "velo_encrypted": {}, "inside_collected": []}
    payloads = {}
    for position, (rel, size, kind) in enumerate(sorted((e for e in census.entries() if e[2] == "f"), key=lambda e: os.fsencode(e[0]))):
        if census_clock(census, position, "the search for the collectors' records"):
            break
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
        if name == ENCRYPTED_PAYLOAD and not inside_collected_data(rel):
            payloads[directory] = {"payload": rel, "metadata": None, "other": False}
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
    if payloads:
        # an encrypted Velociraptor collection is an outer container of data.zip and, when the collector was given metadata, metadata.json: the
        # directory that holds those and nothing else (a file or a link beside them makes it an ordinary directory with a file named data.zip)
        for position, (rel, size, kind) in enumerate(census.entries()):
            if census_clock(census, position, "the search for encrypted collections"):
                break
            entry = payloads.get(parent_of(rel))
            if entry is None:
                continue
            name = name_of(rel)
            if name == ENCRYPTED_PAYLOAD and kind == "f":
                continue
            if name == ENCRYPTED_METADATA and kind == "f":
                entry["metadata"] = rel
            else:
                entry["other"] = True
        found["velo_encrypted"] = {d: {"payload": e["payload"], "metadata": e["metadata"]} for d, e in payloads.items() if not e["other"]}
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


def read_encryption_metadata(src, rel):
    """What metadata.json beside data.zip says: which of the documented keys it holds and how long each value is. A value is withheld whole
    (it may be an encrypted password or a key); nothing of it is printed. The file is read to 64 KiB at most."""
    info = {"present": True, "bytes": None, "keys": [], "other_keys": 0, "values": {}}
    try:
        with src.open_binary(rel) as fh:
            data = fh.read(ENCRYPTION_METADATA_BYTES + 1)
    except (OSError, ValueError) as exc:
        info["problem"] = "metadata.json could not be read (%s)" % describe(exc)
        return info
    if len(data) > ENCRYPTION_METADATA_BYTES:
        info["problem"] = "metadata.json is over %d bytes: not parsed" % ENCRYPTION_METADATA_BYTES
        return info
    info["bytes"] = len(data)
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (ValueError, RecursionError):
        info["problem"] = "metadata.json is not JSON text: not read"
        return info
    if not isinstance(doc, dict):
        info["problem"] = "metadata.json is not a JSON object: not read"
        return info
    for key in ENCRYPTION_KEYS:
        if key in doc:
            value = doc[key]
            try:
                text = value if isinstance(value, str) else json.dumps(value)
            except (ValueError, TypeError, RecursionError):
                text = ""
            info["keys"].append(key)
            info["values"][key] = withhold_value(text, "metadata.json, %s" % key)
    info["other_keys"] = len(doc) - len(info["keys"])
    return info


def read_velociraptor_encrypted(src, directory, files, sink):
    """One encrypted Velociraptor collection (see the velociraptor_encrypted adapter), or None when the directory only looks like one. It is
    recognised by data.zip being an encrypted member of the zip the source reads (`src.encrypted`) or by metadata.json holding the Scheme
    key. The records are inside the encrypted payload: nothing is decrypted, no record is read, the source is `unsupported`, and no failure
    count is determined for the run."""
    payload, meta = files["payload"], files.get("metadata")
    info = read_encryption_metadata(src, meta) if meta else None
    flagged = payload in getattr(src, "encrypted", ())
    named = info is not None and "Scheme" in info["keys"]
    if not (flagged or named):
        return None
    basis = (["data.zip is an encrypted member of the zip (general-purpose flag bit 0)"] if flagged else []) + (["metadata.json holds the Scheme key"] if named else [])
    source = new_source(payload, "Velociraptor", "velociraptor_encrypted", "velociraptor_encrypted", run=directory or ".", directory=directory or ".", container=directory or ".",
                        payload=payload, recognised_by=basis, decrypted=False, metadata=info if info is not None else {"present": False})
    source.update(status="unsupported", reason=ADAPTERS["velociraptor_encrypted"]["unsupported_reason"])
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
    for directory, files in sorted(found["velo_encrypted"].items(), key=lambda kv: os.fsencode(kv[0])):
        source = read_velociraptor_encrypted(src, directory, files, sink)
        if source is not None:
            sources.append(source)
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
        return "suffix", path_parts(claim)[-MAX_PATH_PARTS:]
    if collector == "Velociraptor" and isinstance(claim, str):
        raw = [p for p in claim.split("/") if p]
        if len(raw) > MAX_PATH_PARTS:
            return "exact", []
        forms = []
        for lead in ((), ("uploads",), ("uploads", "auto")):
            where = "/".join(lead) or "the container"
            forms.append((lead + tuple(raw), "stored name under " + where))
            forms.append((lead + tuple(percent_quote(p) for p in raw), "stored name with the colon and the percent sign escaped, under " + where))
        return "exact", forms
    if collector == "UAC" and kind == "hash_claim" and isinstance(rec.get("source_path_claim"), str):
        parts = [p for p in rec["source_path_claim"].split("/") if p]
        if len(parts) > MAX_PATH_PARTS:
            return "exact", []
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
                "all_candidates": rels, "reason": "only the file name matches"}
    if len(rels) > 1:
        return {"status": "ambiguous", "rel": None, "matched_by": why, "depth": depth, "candidates": rels[:REC_FIRST],
                "all_candidates": rels, "reason": "%d delivered files differ from each other only by case" % len(rels)}
    if len(hits) > len(rels):
        return {"status": "ambiguous", "rel": None, "matched_by": why, "depth": depth, "candidates": rels[:REC_FIRST],
                "all_candidates": rels, "reason": "the name appears %d times (an archive can hold one name twice)" % len(hits)}
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
    return fold_name(text.replace("\\", "/"))


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


def withhold_value(value, where):
    """A value that may hold a secret (an encrypted password, a key) never leaves in an answer or a table: it goes to the values file (a job
    run with secret_output and write_values) and what is printed names its length and a finding id. Returns the marker."""
    WITHHELD["count"] += 1
    fid = "W%06d" % WITHHELD["count"]
    if VALUES[0] is not None:
        VALUES[0].add(fid, {"where": where}, value)
    return "<value withheld, %d characters, %s>" % (len(value), fid)


DIGEST_KEY = re.compile(r"md5|sha|hash|digest|checksum", re.I)
DIGEST_HEX = re.compile(r"(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{56}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{96}|[0-9A-Fa-f]{128})")


def withhold_field_digests(value, where, digest_key=False, any_key=False):
    """(copy of `value` with every digest-shaped string under a digest-named key withheld, how many). The row's own `fields` keep the
    collector's keys and structure: a key named md5, Sha256, hash or digest (at any depth, a list under it too) whose string is the hex of a
    digest of a known length is the digest of the file the row is about. With `any_key`, a digest-shaped string is withheld whatever its key
    (a record that names a credential store, whose columns may be shifted). The walk is iterative: it has no depth at which it stops."""
    holder = [None]
    count = 0
    stack = [(value, (None, where), digest_key, holder, 0)]
    while stack:
        item, path, dk, parent, slot = stack.pop()
        if isinstance(item, dict):
            new = {}
            parent[slot] = new
            for key in item:
                new[key] = None
            for key, sub in reversed(list(item.items())):
                stack.append((sub, (path, key), dk or bool(DIGEST_KEY.search(str(key))), new, key))
        elif isinstance(item, list):
            new = [None] * len(item)
            parent[slot] = new
            for i in range(len(item) - 1, -1, -1):
                stack.append((item[i], path, dk, new, i))
        elif (dk or any_key) and isinstance(item, str) and DIGEST_HEX.fullmatch(item.strip()):
            names = []
            node = path
            while node[0] is not None:
                names.append(str(node[1]))
                node = node[0]
            parent[slot] = withhold_digest(item.strip(), "%s%s" % (node[1], "".join(", field %s" % n for n in reversed(names))))
            count += 1
        else:
            parent[slot] = item
    return holder[0], count


def guard_digests(rec):
    """For a record that names a credential store, every digest the record carries is withheld from the record: the claims, the digests
    in the collector's own `fields` (a Velociraptor upload record keeps its sha256, md5 and sha1 there) under whatever key or column
    they stand in, and a path claim that is itself a digest (a row with a column missing shifts the others). The comparison still runs
    on the real ones, in the caller, from the claims it took before this."""
    hint = path_hint(rec.get("source_path_claim"), rec.get("delivered_path_claim"))
    if not hint:
        return rec
    where = "record %s of %s" % ((rec.get("locator") or {}).get("row") or (rec.get("locator") or {}).get("line"), rec.get("log"))
    withheld = 0
    if rec.get("hash_claims"):
        rec["hash_claims"] = {algorithm: withhold_digest(value, where) for algorithm, value in rec["hash_claims"].items()}
        withheld += len(rec["hash_claims"])
    if isinstance(rec.get("fields"), dict):
        rec["fields"], count = withhold_field_digests(rec["fields"], where, any_key=True)
        withheld += count
    for claim in ("source_path_claim", "delivered_path_claim"):
        if isinstance(rec.get(claim), str) and DIGEST_HEX.fullmatch(rec[claim].strip()):
            rec[claim] = withhold_digest(rec[claim].strip(), "%s, %s" % (where, claim))
            withheld += 1
    if withheld:
        rec["flags"] = list(rec.get("flags") or []) + ["digest_withheld_credential_store"]
        rec["credential_store_hint"] = hint
    return rec

# ---- END RECORDS BLOCK -----------------------------------------------------------------------------------------------


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



# ---- a bounded reader of the YAML subset the pinned definitions use ---------------------------------------------------------------------
# Block mappings and sequences, plain, single-quoted and double-quoted scalars (a quoted scalar may span lines), literal and folded block
# scalars, flow sequences and mappings, comments and one document. Every scalar is read as text. Anchors, aliases, tags, merge keys, complex
# keys, directives, more than one document, tabs in indentation and duplicate keys are refused by name, and so is a file, a line count, a
# depth, a node count or a scalar over its bound; the clock is looked at every YAML_CLOCK_EVERY lines. Nothing is evaluated.

YAML_MAX_BYTES = 2 << 20
YAML_MAX_LINES = 100000
YAML_MAX_DEPTH = 24
YAML_MAX_NODES = 200000
YAML_MAX_SCALAR = 1 << 20
YAML_FLOW_DEPTH = 8
YAML_CLOCK_EVERY = 256
YAML_MAX_KEY = 1024


def split_key(text):
    """(key_text, rest) when `text` starts a block-mapping entry, else None: a quoted key or a plain key (no '#'), then ':' followed by a space or the end of
    the line. A linear scan with a bound on the key (a regular expression with a lazy run before the colon backtracks quadratically on a long run of spaces)."""
    if not text:
        return None
    c = text[0]
    if c in "\"'":
        k = 1
        while k < len(text) and k <= YAML_MAX_KEY + 1:
            ch = text[k]
            if c == '"' and ch == "\\":
                k += 2
                continue
            if ch == c:
                if c == "'" and text[k + 1:k + 2] == "'":
                    k += 2
                    continue
                break
            k += 1
        if k >= len(text) or text[k] != c:
            return None
        after = text[k + 1:].lstrip(" \t")
        if not after.startswith(":") or (len(after) > 1 and after[1] not in " \t"):
            return None
        return text[:k + 1], after[1:].strip()
    if c in "[]{},#&*!|>%@`" or c.isspace():
        return None
    if c in "?-" and (len(text) < 2 or text[1].isspace() or text[1] == "#"):
        return None
    i = text.find(":")
    while 0 <= i <= YAML_MAX_KEY:
        if i + 1 == len(text) or text[i + 1] in " \t":
            break
        i = text.find(":", i + 1)
    else:
        return None
    key = text[:i].rstrip()
    if key == "" or "#" in key:
        return None
    return key, text[i + 1:].strip()


class YamlRefused(Exception):
    """A document this reader refuses; `code` names why, `line` where."""

    def __init__(self, code, line=None):
        super().__init__(code)
        self.code, self.line = code, line


class YamlReader:
    def __init__(self, text):
        if len(text.encode("utf-8", "surrogatepass")) > YAML_MAX_BYTES:
            raise YamlRefused("file_over_bound")
        raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        if len(raw) > YAML_MAX_LINES:
            raise YamlRefused("too_many_lines")
        self.raw = raw
        self.n = len(raw)
        self.nodes = 0
        self.pos = 0
        self.docs = 0

    def tick(self, i):
        if i % YAML_CLOCK_EVERY == 0 and out_of_time():
            raise YamlRefused("time_limit", i + 1)

    def count(self, i):
        self.nodes += 1
        if self.nodes > YAML_MAX_NODES:
            raise YamlRefused("too_many_nodes", i + 1)

    @staticmethod
    def indent_of(line, i):
        stripped = line.lstrip(" ")
        n = len(line) - len(stripped)
        if stripped.startswith("\t") or "\t" in line[:n]:
            raise YamlRefused("tab_indentation", i + 1)
        return n, stripped

    @staticmethod
    def strip_comment(s):
        """The text without a trailing comment (a # preceded by space or at the start, outside quotes)."""
        quote = None
        for k, ch in enumerate(s):
            if quote:
                if ch == quote:
                    quote = None if not (quote == "'" and s[k + 1:k + 2] == "'") else quote
                elif ch == "\\" and quote == '"':
                    pass
                continue
            if ch in "\"'" and (k == 0 or s[k - 1] in " \t[{,:"):
                quote = ch
            elif ch == "#" and (k == 0 or s[k - 1] in " \t"):
                return s[:k].rstrip()
        return s.rstrip()

    def next_line(self, i):
        """(index, indent, content) of the first line at or after i that holds content, or None. A document marker is handled here."""
        while i < self.n:
            self.tick(i)
            line = self.raw[i]
            ind, body = self.indent_of(line, i)
            text = self.strip_comment(body)
            if text == "":
                i += 1
                continue
            if ind == 0 and (text == "---" or text.startswith("--- ")):
                self.docs += 1
                if self.docs > 1 or any(self.raw[j].strip() and not self.raw[j].lstrip().startswith("#") for j in range(i)):
                    raise YamlRefused("more_than_one_document", i + 1)
                if text != "---":
                    self.raw[i] = " " * 0 + text[4:]
                    continue
                i += 1
                continue
            if ind == 0 and text == "...":
                i += 1
                continue
            if ind == 0 and text.startswith("%"):
                raise YamlRefused("directive", i + 1)
            return i, ind, text
        return None

    def refuse_marker(self, text, i):
        c = text[:1]
        if c == "&":
            raise YamlRefused("anchor", i + 1)
        if c == "*":
            raise YamlRefused("alias", i + 1)
        if c == "!":
            raise YamlRefused("tag", i + 1)

    def parse_document(self):
        found = self.next_line(0)
        if found is None:
            return None
        i, ind, text = found
        value, i = self.node(i, ind, 0)
        rest = self.next_line(i)
        if rest is not None:
            if self.docs and rest[2] == "---":
                raise YamlRefused("more_than_one_document", rest[0] + 1)
            raise YamlRefused("unexpected_content", rest[0] + 1)
        return value

    def node(self, i, ind, depth):
        if depth > YAML_MAX_DEPTH:
            raise YamlRefused("too_deep", i + 1)
        found = self.next_line(i)
        if found is None:
            return None, self.n
        i, line_ind, text = found
        if line_ind < ind:
            return None, i
        ind = line_ind
        if text == "-" or text.startswith("- "):
            return self.sequence(i, ind, depth)
        if text.startswith("? "):
            raise YamlRefused("complex_key", i + 1)
        if self.is_key_line(text):
            return self.mapping(i, ind, depth)
        value, i2 = self.scalar_or_flow(i, text, ind - 1, depth)
        return value, i2

    def is_key_line(self, text):
        return split_key(text) is not None

    def sequence(self, i, ind, depth):
        out = []
        self.count(i)
        while True:
            found = self.next_line(i)
            if found is None or found[1] != ind or not (found[2] == "-" or found[2].startswith("- ")):
                if found is not None and found[1] > ind:
                    raise YamlRefused("bad_indentation", found[0] + 1)
                return out, (found[0] if found else self.n)
            i, _, text = found
            rest = text[1:].lstrip(" ")
            offset = len(text) - len(rest)
            if rest == "":
                value, i = self.node(i + 1, ind + 1, depth + 1)
            else:
                self.refuse_marker(rest, i)
                self.raw[i] = " " * (ind + offset) + self.strip_comment(self.raw[i].lstrip(" "))[offset:]
                value, i = self.node(i, ind + offset, depth + 1)
            out.append(value)
            if len(out) > YAML_MAX_NODES:
                raise YamlRefused("too_many_nodes", i + 1)

    def mapping(self, i, ind, depth):
        out = {}
        self.count(i)
        while True:
            found = self.next_line(i)
            if found is None or found[1] != ind:
                if found is not None and found[1] > ind:
                    raise YamlRefused("bad_indentation", found[0] + 1)
                return out, (found[0] if found else self.n)
            i, _, text = found
            if text == "-" or text.startswith("- "):
                return out, i
            m = split_key(text)
            if m is None:
                raise YamlRefused("not_a_mapping_entry", i + 1)
            key_text, rest = m
            self.refuse_marker(key_text, i)
            if key_text == "<<":
                raise YamlRefused("merge_key", i + 1)
            key = self.quoted_key(key_text, i)
            if key in out:
                raise YamlRefused("duplicate_key", i + 1)
            rest = rest.strip()
            self.count(i)
            if rest == "" or rest.startswith("#"):
                nxt = self.next_line(i + 1)
                if nxt is not None and nxt[1] > ind:
                    value, i = self.node(i + 1, ind + 1, depth + 1)
                elif nxt is not None and nxt[1] == ind and (nxt[2] == "-" or nxt[2].startswith("- ")):
                    value, i = self.sequence(nxt[0], ind, depth + 1)
                else:
                    value, i = None, i + 1
            else:
                self.refuse_marker(rest, i)
                if rest[0] in "|>":
                    value, i = self.block_scalar(i, rest, ind)
                else:
                    value, i = self.scalar_or_flow(i, rest, ind, depth + 1, start_text=True)
            out[key] = value
            if len(out) > YAML_MAX_NODES:
                raise YamlRefused("too_many_nodes", i + 1)

    def quoted_key(self, text, i):
        if text[:1] == '"':
            return self.double_quoted(text[1:-1], i)
        if text[:1] == "'":
            return text[1:-1].replace("''", "'")
        return text

    def block_scalar(self, i, header, ind):
        """A literal (|) or folded (>) block scalar: the lines more indented than the key, with the chomping indicator."""
        chomp = "clip"
        fixed = None
        for ch in header[1:]:
            if ch == "-":
                chomp = "strip"
            elif ch == "+":
                chomp = "keep"
            elif ch.isdigit() and ch != "0":
                fixed = int(ch)
            elif ch in " \t":
                break
            elif ch == "#":
                break
            else:
                raise YamlRefused("bad_block_scalar_header", i + 1)
        lines = []
        total = 0
        j = i + 1
        base = None
        while j < self.n:
            self.tick(j)
            line = self.raw[j]
            if line.strip() == "":
                lines.append("")
                j += 1
                continue
            lead = len(line) - len(line.lstrip(" "))
            if "\t" in line[:lead + 1] and line[lead:lead + 1] == "\t" and base is None:
                raise YamlRefused("tab_indentation", j + 1)
            if base is None:
                base = (ind + fixed) if fixed else lead
                if base <= ind:
                    break
            if lead < base:
                break
            lines.append(line[base:])
            total += len(line)
            if total > YAML_MAX_SCALAR:
                raise YamlRefused("scalar_over_bound", j + 1)
            j += 1
        trailing = 0
        while lines and lines[-1] == "":
            lines.pop()
            trailing += 1
        if header[0] == "|":
            text = "\n".join(lines)
        else:
            parts, prev_blank = [], False
            for ln in lines:
                if ln == "":
                    parts.append("\n")
                    prev_blank = True
                elif parts and not prev_blank and not ln.startswith(" "):
                    parts.append(" " + ln)
                else:
                    parts.append(ln)
                    prev_blank = False
            text = "".join(parts)
        if lines:
            text += {"strip": "", "clip": "\n", "keep": "\n" * (1 + trailing)}[chomp]
        self.count(i)
        return text, j

    def double_quoted(self, body, i):
        out = []
        k = 0
        while k < len(body):
            ch = body[k]
            if ch != "\\":
                out.append(ch)
                k += 1
                continue
            k += 1
            if k >= len(body):
                raise YamlRefused("bad_escape", i + 1)
            e = body[k]
            simple = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/", "0": "\0", " ": " ", "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "v": "\v"}
            if e in simple:
                out.append(simple[e])
                k += 1
            elif e in "xuU":
                width = {"x": 2, "u": 4, "U": 8}[e]
                digits = body[k + 1:k + 1 + width]
                try:
                    if len(digits) != width:
                        raise ValueError
                    out.append(chr(int(digits, 16)))
                except (ValueError, OverflowError):
                    raise YamlRefused("bad_escape", i + 1)
                k += 1 + width
            else:
                raise YamlRefused("bad_escape", i + 1)
        return "".join(out)

    def scalar_or_flow(self, i, text, ind, depth, start_text=False):
        """A scalar or a flow collection that starts with `text` on line i; continuation lines are the lines more indented than `ind`."""
        self.refuse_marker(text, i)
        j = i + 1
        first = text
        if first[:1] in "[{":
            buf = first
            depth, quote = self.flow_scan(first, 0, None)
            while (depth > 0 or quote is not None) and j < self.n:
                self.tick(j)
                seg = " " + self.strip_comment(self.raw[j].strip())
                buf += seg
                depth, quote = self.flow_scan(seg, depth, quote)
                if len(buf) > YAML_MAX_SCALAR:
                    raise YamlRefused("scalar_over_bound", j + 1)
                j += 1
            value, end = self.flow(buf, 0, 0, i)
            if buf[end:].strip():
                raise YamlRefused("unexpected_content", i + 1)
            return value, j
        if first[:1] in "\"'":
            q = first[0]
            buf = first
            close, pos = self.quote_scan(buf, q, 1)
            while close < 0 and j < self.n:
                self.tick(j)
                buf += "\n" + self.raw[j].strip()
                if len(buf) > YAML_MAX_SCALAR:
                    raise YamlRefused("scalar_over_bound", j + 1)
                close, pos = self.quote_scan(buf, q, pos)
                j += 1
            if close < 0:
                raise YamlRefused("unterminated_quote", i + 1)
            if self.strip_comment(buf[close + 1:]).strip():
                raise YamlRefused("unexpected_content", i + 1)
            body = buf[1:close]
            value = body.replace("''", "'") if q == "'" else self.double_quoted(body, i)
            if "\n" in value and q == "'":
                value = " ".join(p.strip() for p in value.split("\n"))
            self.count(i)
            return value, j
        parts = [first]
        total = len(first)
        while j < self.n:
            self.tick(j)
            line = self.raw[j]
            if line.strip() == "":
                nxt = self.next_line(j)
                if nxt is not None and nxt[1] > ind and not start_text:
                    j += 1
                    continue
                break
            lead = len(line) - len(line.lstrip(" "))
            if lead <= ind:
                break
            cont = self.strip_comment(line.strip())
            if cont == "":
                j += 1
                continue
            parts.append(cont)
            total += len(cont)
            if total > YAML_MAX_SCALAR:
                raise YamlRefused("scalar_over_bound", j + 1)
            j += 1
        self.count(i)
        return " ".join(parts), j

    @staticmethod
    def quote_end(buf, q):
        k = 1
        while k < len(buf):
            if buf[k] == "\\" and q == '"':
                k += 2
                continue
            if buf[k] == q:
                if q == "'" and buf[k + 1:k + 2] == "'":
                    k += 2
                    continue
                return k
            k += 1
        return -1

    @staticmethod
    def quote_scan(buf, q, pos):
        """(index of the closing quote or -1, position to continue from): scanning resumes where the last call stopped, so a quoted scalar over many
        lines is read once and not once per line."""
        k = pos
        while k < len(buf):
            if buf[k] == "\\" and q == '"':
                if k + 1 >= len(buf):
                    return -1, k
                k += 2
                continue
            if buf[k] == q:
                if q == "'":
                    if buf[k + 1:k + 2] == "'":
                        k += 2
                        continue
                return k, k
            k += 1
        return -1, k

    @staticmethod
    def flow_scan(seg, depth, quote):
        """(depth, quote) after `seg`, continuing from the state the lines before it left: brackets outside quotes, so a flow collection that spans
        lines is judged once per line and never again over the text already seen."""
        k = 0
        while k < len(seg):
            ch = seg[k]
            if quote:
                if ch == "\\" and quote == '"':
                    k += 1
                elif ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            k += 1
        return depth, quote

    def flow(self, s, k, depth, i):
        if depth > YAML_FLOW_DEPTH:
            raise YamlRefused("too_deep", i + 1)
        while k < len(s) and s[k] == " ":
            k += 1
        if k >= len(s):
            raise YamlRefused("unterminated_flow", i + 1)
        self.count(i)
        if s[k] == "[":
            out = []
            k += 1
            while True:
                while k < len(s) and s[k] == " ":
                    k += 1
                if k >= len(s):
                    raise YamlRefused("unterminated_flow", i + 1)
                if s[k] == "]":
                    return out, k + 1
                value, k = self.flow(s, k, depth + 1, i)
                out.append(value)
                if len(out) > YAML_MAX_NODES:
                    raise YamlRefused("too_many_nodes", i + 1)
                while k < len(s) and s[k] == " ":
                    k += 1
                if k < len(s) and s[k] == ",":
                    k += 1
                elif k < len(s) and s[k] == "]":
                    continue
                else:
                    raise YamlRefused("unterminated_flow", i + 1)
        if s[k] == "{":
            out = {}
            k += 1
            while True:
                while k < len(s) and s[k] == " ":
                    k += 1
                if k >= len(s):
                    raise YamlRefused("unterminated_flow", i + 1)
                if s[k] == "}":
                    return out, k + 1
                key, k = self.flow_scalar(s, k, i, stop=":,}")
                while k < len(s) and s[k] == " ":
                    k += 1
                value = None
                if k < len(s) and s[k] == ":":
                    k += 1
                    value, k = self.flow(s, k, depth + 1, i)
                if key in out:
                    raise YamlRefused("duplicate_key", i + 1)
                if key == "<<":
                    raise YamlRefused("merge_key", i + 1)
                out[key] = value
                if len(out) > YAML_MAX_NODES:
                    raise YamlRefused("too_many_nodes", i + 1)
                while k < len(s) and s[k] == " ":
                    k += 1
                if k < len(s) and s[k] == ",":
                    k += 1
                elif k < len(s) and s[k] == "}":
                    continue
                else:
                    raise YamlRefused("unterminated_flow", i + 1)
        return self.flow_scalar(s, k, i, stop=",]}")

    def flow_scalar(self, s, k, i, stop):
        if s[k] in "&*!":
            raise YamlRefused({"&": "anchor", "*": "alias", "!": "tag"}[s[k]], i + 1)
        if s[k] in "\"'":
            q = s[k]
            close, _ = self.quote_scan(s, q, k + 1)
            if close < 0:
                raise YamlRefused("unterminated_quote", i + 1)
            body = s[k + 1:close]
            return (body.replace("''", "'") if q == "'" else self.double_quoted(body, i)), close + 1
        start = k
        while k < len(s) and s[k] not in stop:
            if s[k] == ":" and ":" in stop and not (k + 1 >= len(s) or s[k + 1] in " ,]}"):
                k += 1
                continue
            k += 1
        self.count(i)
        return s[start:k].strip(), k


def read_yaml(text):
    """The document as plain dicts, lists and strings, or YamlRefused. RecursionError and MemoryError are refusals too."""
    try:
        return YamlReader(text).parse_document()
    except RecursionError:
        raise YamlRefused("too_deep")
    except MemoryError:
        raise YamlRefused("memory")

PARSER = "collection_profile_compare/1"
TOOL = "collection_profile_compare"
VALUES_NAME = "collection-profile-compare-values.jsonl"
KNOWN_PARAMETERS = ("root", "definitions", "allow_unpinned", "collectors", "profile", "delivered_profile", "kape_targets", "needs", "limit", "time_limit_seconds", "write_values")

_open_regular_text = open_regular


def open_regular(path, **kw):
    """The shared block's text opener when a text option is given, else the archive block's: a regular file, binary, opened without following
    a link and without blocking on a pipe."""
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


# The corpora this tool reads, by the sha256 of the archive. A corpus whose hash is not here is refused (or read as `unknown` with allow_unpinned).
# Each is the archive requires/host.json pins as data (the images install them under DEFAULT_DEFINITIONS, one directory per corpus).
PINNED = {
    "uac": [{"version": "3.4.0", "sha256": "d333b72990c25d48b93200648a58084f8b79ff917d1e609dd92ac6ba9fb387db", "name": "uac-3.4.0.tar.gz"}],
    "velociraptor": [{"version": "0.77.2", "sha256": "6070f075f4e97b81c3bec07808a6db04b2e0f62941519116cfb2be76d0ce8fcc", "name": "velociraptor-0.77.2-source.tar.gz"}],
    "kape": [{"version": "b235d571d361db87fdf0d6528a5aa44bd800f15a", "sha256": "bad6689edb8024c6b736ae4c862caab23a137f417adbc4e5384ccdb0df199509",
              "name": "KapeFiles-b235d571d361db87fdf0d6528a5aa44bd800f15a.zip"}],
}
# Where the images put the three corpora, one directory per corpus (<name>-<version>/), used when `definitions` is not given and the directory exists.
DEFAULT_DEFINITIONS = os.environ.get("DFIRSWARM_TRIAGE_DEFINITIONS", "/opt/dfir/data/triage-definitions")
CORPUS_PREFIX = {"uac": "uac", "velociraptor": "velociraptor", "kape": "kapefiles"}
CORPUS_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz", ".zip")
MAX_CORPUS_BYTES = 1 << 29
MAX_CORPUS_FILES = 100000
MAX_CORPUS_TEXT = 128 << 20
MAX_MEMBER_NAME = 1024
COMPOUND_DEPTH = 8
MAX_NAME_MATCH = 4096               # characters of a file name a mask is matched against
MAX_MASK = 256                    # characters of a mask or a pattern a glob is run with
KAPE_ENTRY_BUDGET = 200000        # entries visited in resolving one target, compound targets included
MAX_ROWS_BYTES_PER_PATH = 4096
MAX_CONTEXT_BYTES = 8 << 20
MAX_LOG_LINE = 8192
CLOCK_EVERY = 256
MAX_COUNTED_DIRS = 2000000
VARIABLE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]{0,40}%|\$\{[^}]{0,80}\}|\$[A-Za-z_][A-Za-z0-9_]{0,40}")
TARGETING = re.compile(r"glob|path|target|regex|list|file|pattern|rule|dir", re.I)
SECTIONS = ("could_request", "requested", "excluded", "collected", "not_collected", "unresolved", "proposed_additional_evidence", "differs", "unknown")


def sha256_of(path):
    """(hex, bytes) of a regular file, in 1 MiB steps under the clock; None when it cannot be read whole."""
    h = hashlib.sha256()
    total = 0
    with open_regular(path) as fh:
        while True:
            if out_of_time():
                return None, total
            block = fh.read(CHUNK)
            if not block:
                break
            total += len(block)
            if total > MAX_CORPUS_BYTES:
                return None, total
            h.update(block)
    return h.hexdigest(), total


def wanted_member(kind, name):
    low = name.lower()
    if kind == "uac":
        return low.endswith((".yaml", ".yml")) and ("/profiles/" in "/" + low or "/artifacts/" in "/" + low)
    if kind == "velociraptor":
        return low.endswith((".yaml", ".yml")) and "artifacts/definitions/" in low
    return low.endswith(".tkape")


def member_key(kind, name):
    """The member's path inside the corpus: the first component (the archive's top directory) removed for a tar."""
    parts = [p for p in name.split("/") if p not in ("", ".")]
    return "/".join(parts)


def read_corpus_members(path, kind):
    """{member: text} for the definition files of one verified archive, or (None, why). Bounded: a member over YAML_MAX_BYTES, a name over
    MAX_MEMBER_NAME, more than MAX_CORPUS_FILES files or MAX_CORPUS_TEXT bytes are counted as refused, not read."""
    fmt, why = sniff(path, out_of_time)
    if fmt is None:
        return None, why, []
    members, refused, total = {}, [], 0
    end = {}

    def take(name, data):
        nonlocal total
        key = member_key(kind, name)
        if len(name) > MAX_MEMBER_NAME or len(members) >= MAX_CORPUS_FILES or total + len(data) > MAX_CORPUS_TEXT:
            refused.append({"member": shown(name[:200], "member"), "code": "over_corpus_bound"})
            return
        try:
            members[key] = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            refused.append({"member": shown(name[:200], "member"), "code": "not_utf8"})
            return
        total += len(data)

    try:
        if fmt == "zip":
            with open_regular(path) as zipped, zipfile.ZipFile(zipped) as zf:
                infos = zf.infolist()
                if len(infos) > MAX_CORPUS_FILES * 20:
                    return None, "the zip holds %d members, over the bound" % len(infos), []
                for position, info in enumerate(infos):
                    if position % CLOCK_EVERY == 0 and out_of_time():
                        return None, "the time limit ended the read of the corpus", refused
                    if info.is_dir() or not wanted_member(kind, info.filename):
                        continue
                    if info.file_size > YAML_MAX_BYTES:
                        refused.append({"member": shown(info.filename[:200], "member"), "code": "file_over_bound"})
                        continue
                    with zf.open(info) as fh:
                        data = fh.read(YAML_MAX_BYTES + 1)
                    if len(data) > YAML_MAX_BYTES:
                        refused.append({"member": shown(info.filename[:200], "member"), "code": "file_over_bound"})
                        continue
                    take(info.filename, data)
                zp = zip_problem(path, infos, getattr(zf, "start_dir", None), out_of_time)
                if zp:
                    return None, "the corpus zip is not read whole by its central directory: %s" % zp, refused
        else:
            raw = open_regular(path)
            try:
                stream = TarStream(raw, tar_kind(raw.read(6)), out_of_time)
                raw.seek(0)
                with tarfile.open(fileobj=stream, mode="r|", tarinfo=BoundedTarInfo) as tf:
                    for member in tf:
                        if not member.isreg() or not wanted_member(kind, member.name):
                            continue
                        if member.size > YAML_MAX_BYTES:
                            refused.append({"member": shown(member.name[:200], "member"), "code": "file_over_bound"})
                            continue
                        fh = tf.extractfile(member)
                        take(member.name, fh.read(YAML_MAX_BYTES + 1) if fh else b"")
                        tf.members = []
                    end.update(tar_end(tf, out_of_time, stream))
                    drained = end.get("kind") in ("boundary", "partial") or (end.get("kind") == "marker" and end.get("after_marker_checked", True))
                    gone = stream.problem() if drained else None
                    if gone:
                        end["compression"] = gone
            finally:
                raw.close()
            problem = end_problem(fmt, end)
            if problem:
                return None, "the corpus archive did not end as a finished one: %s" % problem, refused
    except ClockStopped:
        return None, "the time limit ended the read of the corpus", refused
    except Exception as exc:
        return None, "the corpus archive could not be read (%s: %s)" % (type(exc).__name__, describe(exc)), refused
    return members, None, refused


class Corpora:
    """The verified corpora of a definitions directory: per kind, the archive's name, version, sha256 and size, whether it is pinned, and the texts of its
    definition files by member path. Each file is hashed and compared with PINNED before one member of it is read."""

    def __init__(self):
        self.by_kind = {}
        self.report = []
        self.unavailable = {k: "no definitions directory was given" for k in PINNED}

    def load(self, directory, allow_unpinned):
        try:
            names = sorted(os.listdir(directory), key=os.fsencode)
        except OSError as exc:
            self.unavailable = {k: "the definitions directory could not be listed (%s)" % describe(exc) for k in PINNED}
            return
        self.unavailable = {k: "no archive of this corpus is in the definitions directory" for k in PINNED}
        # A corpus directory (<name>-<version>/, as the images install them) is read one level down; a link or a file is never entered.
        expanded = []
        for name in names[:200]:
            path = os.path.join(directory, name)
            if name.lower().startswith(tuple(CORPUS_PREFIX.values())) and not name.lower().endswith(CORPUS_SUFFIXES):
                try:
                    inside = sorted(os.listdir(path), key=os.fsencode) if stat.S_ISDIR(os.lstat(path).st_mode) else None
                except OSError:
                    inside = None
                if inside is not None:
                    expanded += [(os.path.join(path, s), s) for s in inside[:50]]
                    continue
            expanded.append((path, name))
        for path, name in expanded[:200]:
            low = name.lower()
            kind = next((k for k, p in CORPUS_PREFIX.items() if low.startswith(p)), None)
            if kind is None or not low.endswith(CORPUS_SUFFIXES):
                continue
            if out_of_time():
                self.unavailable = {k: "the time limit ended the check of the definitions" for k in PINNED}
                return
            entry = {"corpus": kind, "name": shown(name, "definitions file")}
            self.report.append(entry)
            try:
                st = os.lstat(path)
            except OSError as exc:
                entry.update(status="refused", why="could not be examined (%s)" % describe(exc))
                continue
            if not stat.S_ISREG(st.st_mode):
                entry.update(status="refused", why="not a regular file")
                continue
            try:
                digest, size = sha256_of(path)
            except OSError as exc:
                entry.update(status="refused", why="could not be read (%s)" % describe(exc))
                continue
            if digest is None:
                entry.update(status="refused", why="over %d bytes or the time limit ended the hash" % MAX_CORPUS_BYTES)
                continue
            entry.update(sha256=digest, bytes=size)
            pin = next((p for p in PINNED[kind] if p["sha256"] == digest), None)
            if pin is None and not allow_unpinned:
                entry.update(status="refused", pinned=False, why="its sha256 is not on the list this tool carries for %s" % kind)
                self.unavailable[kind] = "the archive's sha256 is not on the list of pinned corpora"
                continue
            if kind in self.by_kind:
                entry.update(status="refused", why="another archive of this corpus was already read")
                continue
            members, why, refused = read_corpus_members(path, kind)
            if members is None:
                entry.update(status="refused", pinned=pin is not None, why=why)
                self.unavailable[kind] = why
                continue
            entry.update(status="read", pinned=pin is not None, version=pin["version"] if pin else "unknown", members_read=len(members),
                         members_refused=len(refused), members_refused_first=refused[:FIRST_PROBLEMS])
            self.by_kind[kind] = {"version": entry["version"], "pinned": pin is not None, "sha256": digest, "members": members}
            self.unavailable.pop(kind, None)


def parse_member(text, where, run):
    """The YAML of one definition file, or None with the refusal counted (the code names why)."""
    try:
        return read_yaml(text)
    except YamlRefused as exc:
        run.yaml_refused[exc.code] += 1
        if len(run.yaml_refused_first) < FIRST_PROBLEMS:
            run.yaml_refused_first.append({"where": shown(where[:300], "definition file"), "code": exc.code, "line": exc.line})
        return None


class Run:
    """The answer being built: counted sections with their first rows inline, every row in one table file."""

    def __init__(self, table, problems):
        self.table, self.problems = table, problems
        self.counts = collections.Counter()
        self.first = {s: [] for s in SECTIONS}
        self.yaml_refused = collections.Counter()
        self.yaml_refused_first = []
        self.notes = []
        self.partial = []
        self.used = {}                    # definition files used, one entry per (corpus, member): {corpus, version, sha256 of the archive, member, sha256 of the member}
        self.member_digests = {}

    def row(self, section, **fields):
        self.counts[section] += 1
        row = {"section": section, **fields}
        if len(self.first[section]) < FIRST_PROBLEMS:
            self.first[section].append({k: (inline_text(v) if isinstance(v, str) else v) for k, v in fields.items()})
        self.table.add(row)

    def use(self, corpus, kind, member):
        entry = corpus.by_kind[kind]
        if (kind, member) in self.used:
            return
        if (kind, member) not in self.member_digests:
            self.member_digests[(kind, member)] = hashlib.sha256(entry["members"][member].encode("utf-8", "surrogatepass")).hexdigest()
        self.used[(kind, member)] = {"corpus": kind, "version": entry["version"], "pinned": entry["pinned"], "archive_sha256": entry["sha256"],
                                     "member": shown(member[:300], "definition file"), "member_sha256": self.member_digests[(kind, member)]}


def as_list(value):
    return value if isinstance(value, list) else [] if value is None else [value]


def is_text(value):
    return isinstance(value, str) and value != ""


def dir_prefixes(census):
    """The set of folded directory paths that hold at least one entry of the census (every ancestor of every entry), built under the clock and the memory bound."""
    dirs = set()
    for position, (rel, _size, _kind) in enumerate(census.entries()):
        if position % CLOCK_EVERY == 0 and (out_of_time() or (position % MEMORY_CHECK_EVERY == 0 and over_memory())):
            return dirs, False
        key = Census.key(rel)
        while "/" in key:
            key = key.rsplit("/", 1)[0]
            if key in dirs:
                break
            dirs.add(key)
            if len(dirs) > MAX_COUNTED_DIRS:
                return dirs, False
    return dirs, True


# ---- UAC ----------------------------------------------------------------------------------------------------------------------------


def uac_index(corpus, run):
    """(profiles, artefacts): {name: doc} from the pinned UAC corpus. A profile is keyed by its file name without the extension; an artefact by its
    path below `artifacts/`."""
    profiles, artefacts = {}, {}
    members = corpus.by_kind["uac"]["members"]
    for position, member in enumerate(sorted(members, key=os.fsencode)):
        if position % CLOCK_EVERY == 0 and out_of_time():
            run.partial.append("the time limit ended the read of the UAC definitions")
            break
        parts = member.split("/")
        low = [p.lower() for p in parts]
        if "profiles" in low:
            name = os.path.splitext(parts[-1])[0]
            doc = parse_member(members[member], member, run)
            if isinstance(doc, dict):
                profiles[name.lower()] = (member, doc)
        elif "artifacts" in low:
            rel = "/".join(parts[low.index("artifacts") + 1:])
            doc = parse_member(members[member], member, run)
            if isinstance(doc, dict):
                artefacts[rel] = (member, doc)
    return profiles, artefacts


def uac_resolve(profile_doc, artefacts, run, profile_name):
    """(included {artefact: [patterns]}, excluded [(pattern, [artefact])]) from a profile's `artifacts` list, in order: an entry is an include glob over the
    artefact files, one that starts with `!` removes the files it matches from those included so far. An entry with a variable is an unresolved
    dynamic selection; an include that matches no pinned artefact file is `unknown`."""
    included = {}
    excluded = []
    keys = {a: norm_text(a) for a in artefacts}
    for position, entry in enumerate(as_list(profile_doc.get("artifacts"))):
        if out_of_time():
            run.partial.append("the time limit ended the resolution of profile %s" % shown(profile_name, "profile"))
            break
        if is_text(entry) and len(entry) > MAX_MASK:
            run.row("unknown", collector="UAC", profile=shown(profile_name, "profile"), entry=entry[:MAX_MASK], why="the entry is over %d characters (%d): it is not run as a glob, and its first %d characters are shown" % (MAX_MASK, len(entry), MAX_MASK))
            continue
        if not is_text(entry):
            run.row("unknown", collector="UAC", profile=shown(profile_name, "profile"), entry=str(entry)[:200], why="a profile entry that is not text")
            continue
        negative = entry.startswith("!")
        pattern = entry[1:] if negative else entry
        if VARIABLE.search(pattern):
            run.row("unresolved", collector="UAC", kind="unresolved_dynamic_selection", profile=shown(profile_name, "profile"), entry=entry,
                    why="the entry holds a variable: it is a selection made when the collector runs, and it is not expanded here")
            continue
        wanted = norm_text(pattern)
        matched = [a for a, k in keys.items() if glob_match(wanted, k)]
        if negative:
            removed = [a for a in matched if a in included]
            for a in removed:
                del included[a]
            excluded.append((entry, sorted(removed)))
        else:
            if not matched:
                run.row("unknown", collector="UAC", profile=shown(profile_name, "profile"), entry=entry, why="no artefact file of the pinned UAC definitions matches this entry")
            for a in matched:
                included.setdefault(a, []).append(entry)
    return included, excluded


def uac_items(artefacts, name):
    """The collector items of one artefact file: {collector, path, command, output_file, output_directory, description, condition}."""
    member, doc = artefacts[name]
    out = []
    base = doc.get("output_directory") if is_text(doc.get("output_directory")) else None
    for item in as_list(doc.get("artifacts")):
        if not isinstance(item, dict):
            continue
        out.append({"collector": item.get("collector") if is_text(item.get("collector")) else "unknown",
                    "path": item.get("path") if is_text(item.get("path")) else None,
                    "command": item.get("command") if is_text(item.get("command")) else None,
                    "output_file": item.get("output_file") if is_text(item.get("output_file")) else None,
                    "output_directory": item.get("output_directory") if is_text(item.get("output_directory")) else base,
                    "description": item.get("description") if is_text(item.get("description")) else None,
                    "condition": item.get("condition") if is_text(item.get("condition")) else (doc.get("condition") if is_text(doc.get("condition")) else None)})
    return out


def profile_from_log(src, rel):
    """The profile name a UAC log line gives, or None: the first line with the word `profile` followed by a name, read under the clock. The form of the
    line is not pinned to a version, so this is a reading of the log's words, said as such."""
    try:
        fh = open_text(src, rel)
    except OSError:
        return None
    with fh:
        for number in range(1, 20001):
            if number % CLOCK_EVERY == 0 and out_of_time():
                return None
            line = fh.readline(MAX_LOG_LINE)
            if not line:
                return None
            m = re.search(r"(?i)\bprofile\b[ :=]{1,3}([A-Za-z0-9_.\-]{1,64})", line[:2048])
            if m and m.group(1).lower() not in ("not", "found", "is", "was", "name", "file", "path", "list"):
                return m.group(1), number
    return None


def uac_section(args, run, census, found, src, corpus, needs, dirs):
    """Everything for the UAC runs in the delivery (or the profile the caller names)."""
    logs = found["uac_logs"]
    wanted_profile = args.get("profile")
    if not logs and wanted_profile is None and args.get("delivered_profile") is None:
        return
    if "uac" not in corpus.by_kind:
        run.partial.append("definitions_not_available for UAC: %s" % corpus.unavailable.get("uac", "no corpus"))
        run.notes.append({"collector": "UAC", "definitions_not_available": corpus.unavailable.get("uac")})
        return
    profiles, artefacts = uac_index(corpus, run)
    version = corpus.by_kind["uac"]["version"]
    pinned = corpus.by_kind["uac"]["pinned"]
    base = parent_of(logs[0]) if logs else ""
    name, basis = wanted_profile, "named by the caller"
    if name is None and logs:
        got = profile_from_log(src, logs[0])
        if got:
            name, basis = got[0], "the word after `profile` on line %d of %s" % (got[1], logs[0])
    delivered = None
    if args.get("delivered_profile") is not None:
        rel = args["delivered_profile"]
        delivered = read_delivered_yaml(src, census, rel, run)
        if delivered is not None and name is None and is_text(delivered.get("name")):
            name, basis = delivered["name"], "the name field of the delivered profile file"
    if name is None:
        run.row("unknown", collector="UAC", why="no profile name: the delivery's UAC log has no line this tool reads one from and none was given", log=logs[0] if logs else None)
        run.partial.append("the UAC profile is not known")
        return
    pin = profiles.get(name.lower())
    if pin is None:
        run.row("unknown", collector="UAC", profile=shown(name, "profile"), why="the profile is not among the %s UAC definitions (version %s)" % ("pinned" if pinned else "unpinned", version))
        run.partial.append("UAC profile %s is not in the definitions" % shown(name, "profile"))
        return
    run.use(corpus, "uac", pin[0])
    included, excluded = uac_resolve(pin[1], artefacts, run, name)
    run.row("requested", collector="UAC", profile=shown(name, "profile"), profile_basis=basis, definitions_version=version, pinned=pinned, artefact_files=len(included),
            note="the artefact files the pinned profile of this name lists; whether the run used this profile is the delivery's record, not proof")
    for pattern, removed in excluded:
        run.row("excluded", collector="UAC", profile=shown(name, "profile"), entry=pattern, removed_artefacts=removed[:FIRST_PROBLEMS], removed_total=len(removed))
    if delivered is not None:
        pinned_list = [e for e in as_list(pin[1].get("artifacts")) if is_text(e)]
        got = [e for e in as_list(delivered.get("artifacts")) if is_text(e)]
        if pinned_list != got:
            run.row("differs", collector="UAC", profile=shown(name, "profile"), why="the profile file in the delivery lists different artefacts from the pinned profile of the same name; the pinned one is used",
                    only_in_delivered=[e for e in got if e not in pinned_list][:FIRST_PROBLEMS], only_in_pinned=[e for e in pinned_list if e not in got][:FIRST_PROBLEMS],
                    counts={"delivered": len(got), "pinned": len(pinned_list)})
    log_errors = collect_uac_errors(src, logs, run) if logs else []
    for position, art in enumerate(sorted(included, key=os.fsencode)):
        if position % CLOCK_EVERY == 0 and out_of_time():
            run.partial.append("the time limit ended the comparison of the UAC artefacts with the delivery")
            break
        for idx, item in enumerate(uac_items(artefacts, art)):
            run.use(corpus, "uac", artefacts[art][0]) if idx == 0 else None
            dynamic = [v for v in (item["path"], item["output_directory"], item["output_file"]) if v and VARIABLE.search(v)]
            run.row("could_request", collector="UAC", artefact=art, collector_kind=item["collector"], path=item["path"], command=item["command"], output_directory=item["output_directory"],
                    output_file=item["output_file"], condition=item["condition"], description=item["description"])
            if dynamic:
                run.row("unresolved", collector="UAC", kind="unresolved_dynamic_selection", artefact=art, entry=dynamic[0], why="the item holds a variable that is set when the collector runs")
                continue
            where, present = None, None
            if item["output_file"] and item["output_directory"] and logs:
                where = join_rel(base, item["output_directory"].strip("/"), item["output_file"])
                present = bool(census.lookup(where))
            elif item["path"] and logs and item["collector"] in ("find", "file", "stat"):
                where = join_rel(base, "[root]", item["path"].strip("/"))
                present = bool(census.lookup(where)) or Census.key(where.rstrip("/")) in dirs
            if present is None:
                continue
            if present:
                run.row("collected", collector="UAC", artefact=art, delivered_path=where, basis="a delivered file or directory has the name the definition gives; its content is not read")
            else:
                words = [t for t in log_errors if (item["output_file"] and item["output_file"] in t) or art.rsplit("/", 1)[-1] in t][:3]
                run.row("not_collected", collector="UAC", artefact=art, expected_path=where, collector_words=words,
                        basis="no delivered entry has the name the definition gives%s" % ("" if census.complete else " (the census is not complete: this is not absence)"))
                if census.complete and (not needs or any(n in art.lower() or (item["description"] and n in item["description"][:4096].lower()) for n in needs)):
                    run.row("proposed_additional_evidence", collector="UAC", artefact=art, gives=item["description"],
                            why="the pinned definition lists it for the profile and no delivered entry has its output name; an item for the operator to consider, not a command")


def collect_uac_errors(src, logs, run):
    """The ERR lines of the UAC log, whole, bounded to 2000 kept, for the collector's own words."""
    out = []
    try:
        fh = open_text(src, logs[0])
    except OSError:
        return out
    with fh:
        for number in range(1, 2000001):
            if number % CLOCK_EVERY == 0 and out_of_time():
                run.partial.append("the time limit ended the read of the UAC log")
                break
            line = fh.readline(MAX_LOG_LINE)
            if not line:
                break
            found = UAC_EVENT.match(line)
            if found and found.group("level") in UAC_ERROR_LEVELS and len(out) < 2000:
                out.append(line.rstrip("\r\n")[:512])
    return out


def read_delivered_yaml(src, census, rel, run):
    """A YAML file of the delivery named by the caller (relative to root), read as data under the bounds; None when it cannot be."""
    if not isinstance(rel, str) or not rel or "\0" in rel:
        run.row("unknown", why="delivered_profile is not a path")
        return None
    hits = census.lookup(rel)
    if len(hits) != 1 or hits[0][2] != "f":
        run.row("unknown", why="delivered_profile %s names %d regular files in the delivery" % (shown(rel, "delivered file"), len([h for h in hits if h[2] == "f"])))
        run.partial.append("the delivered profile file was not found")
        return None
    try:
        with src.open_binary(hits[0][0]) as fh:
            data = fh.read(YAML_MAX_BYTES + 1)
    except OSError as exc:
        run.partial.append("the delivered profile file could not be read (%s)" % describe(exc))
        return None
    if len(data) > YAML_MAX_BYTES:
        run.yaml_refused["file_over_bound"] += 1
        run.yaml_refused_first.append({"where": shown(rel[:300], "delivered file"), "code": "file_over_bound", "line": None})
        run.partial.append("the delivered profile file is over the bound and was refused")
        return None
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        run.yaml_refused["not_utf8"] += 1
        run.partial.append("the delivered profile file is not UTF-8 and was not read")
        return None
    doc = parse_member(text, rel, run)
    if not isinstance(doc, dict):
        run.partial.append("the delivered profile file was refused or is not a mapping")
        return None
    return doc


# ---- Velociraptor ------------------------------------------------------------------------------------------------------------------


def velociraptor_section(args, run, census, found, src, corpus, needs):
    containers = found["velociraptor"]
    if not containers:
        return
    if "velociraptor" not in corpus.by_kind:
        run.partial.append("definitions_not_available for Velociraptor: %s" % corpus.unavailable.get("velociraptor", "no corpus"))
        run.notes.append({"collector": "Velociraptor", "definitions_not_available": corpus.unavailable.get("velociraptor")})
        return
    entry = corpus.by_kind["velociraptor"]
    index = {}
    for position, member in enumerate(sorted(entry["members"], key=os.fsencode)):
        if position % CLOCK_EVERY == 0 and out_of_time():
            run.partial.append("the time limit ended the read of the Velociraptor definitions")
            break
        doc = parse_member(entry["members"][member], member, run)
        if isinstance(doc, dict) and is_text(doc.get("name")):
            index.setdefault(doc["name"].lower(), (member, doc))
    yaml_files = [rel for position, (rel, _size, kind) in enumerate(census.entries()) if kind == "f" and rel.lower().endswith((".yaml", ".yml")) and not inside_collected_data(rel)]
    for directory, files in sorted(containers.items(), key=lambda kv: os.fsencode(kv[0])):
        context = files.get("context")
        if not context:
            run.row("unknown", collector="Velociraptor", container=directory or ".", why="no collection_context.json beside the container's index: the collection's own record of its request is absent")
            run.partial.append("%s has no record of its request" % (directory or "the container"))
            continue
        request = read_request(src, context, run)
        if request is None:
            continue
        specs = request["specs"]
        run.row("requested", collector="Velociraptor", container=directory or ".", record=context, artefacts=[s["artifact"] for s in specs][:FIRST_PROBLEMS], artefacts_total=len(specs),
                definitions_version=entry["version"], pinned=entry["pinned"])
        delivered_defs = delivered_definitions(src, census, directory, run, yaml_files)
        seen_specs = set()
        for spec in specs:
            if out_of_time():
                run.partial.append("the time limit ended the comparison of the Velociraptor request with the definitions")
                return
            name = spec["artifact"]
            spec_key = (name, tuple(sorted(spec["env"].items()))) if len(spec["env"]) <= 64 else None
            if spec_key is not None:
                if spec_key in seen_specs:
                    continue
                if len(seen_specs) < 100000:
                    seen_specs.add(spec_key)
            pin = index.get(name.lower())
            if pin is None:
                run.row("unknown", collector="Velociraptor", container=directory or ".", artefact=name, why="the artefact is not among the %s Velociraptor definitions (version %s)" % ("pinned" if entry["pinned"] else "unpinned", entry["version"]))
                continue
            run.use(corpus, "velociraptor", pin[0])
            doc = pin[1]
            params = {p["name"]: p for p in as_list(doc.get("parameters")) if isinstance(p, dict) and is_text(p.get("name"))}
            recorded = spec["env"]
            run.row("could_request", collector="Velociraptor", container=directory or ".", artefact=name, type=doc.get("type") if is_text(doc.get("type")) else None,
                    parameters=[{"name": k, "default": v.get("default") if isinstance(v.get("default"), str) else None, "value_in_record": recorded.get(k)} for k, v in list(params.items())[:FIRST_PROBLEMS]],
                    parameters_total=len(params), definition=shown(pin[0], "definition file"))
            if name.lower().startswith("windows.kapefiles.targets"):
                run.row("unresolved", collector="Velociraptor", kind="unresolved_dynamic_selection", container=directory or ".", artefact=name,
                        why="the artefact embeds KAPE target definitions: which targets it takes is resolved with the KAPE route, not here")
            for pname, p in params.items():
                if pname in recorded:
                    continue
                if TARGETING.search(pname) and (p.get("type") in (None, "", "string", "csv", "regex", "json", "upload", "yaml") or not isinstance(p.get("type"), str)):
                    run.row("unresolved", collector="Velociraptor", kind="unresolved_dynamic_selection", container=directory or ".", artefact=name, parameter=pname,
                            default=p.get("default") if isinstance(p.get("default"), str) else None,
                            why="a parameter that can select what is collected has no value in the collection's record: it was given when the collector ran, or it ran with the default")
            for pname in sorted(set(recorded) - set(params)):
                run.row("unknown", collector="Velociraptor", container=directory or ".", artefact=name, parameter=pname, why="the record gives a parameter the pinned definition does not have")
            dd = delivered_defs.get(name.lower())
            if dd is not None and dd != doc:
                run.row("differs", collector="Velociraptor", container=directory or ".", artefact=name,
                        why="a definition delivered in the collection differs from the pinned one; the pinned one is used and the delivered one is only described")
    return


def read_request(src, rel, run):
    """The request in collection_context.json (an ArtifactCollectorContext): {specs: [{artifact, env: {key: value}}]}. `request.artifacts` names with no
    spec become specs with no parameters. None, with a note, when the file is not what this tool reads."""
    try:
        with src.open_binary(rel) as fh:
            data = fh.read(MAX_CONTEXT_BYTES + 1)
    except OSError as exc:
        run.partial.append("%s could not be read (%s)" % (shown(rel, "record"), describe(exc)))
        return None
    if len(data) > MAX_CONTEXT_BYTES:
        run.partial.append("%s is over %d bytes and was not read" % (shown(rel, "record"), MAX_CONTEXT_BYTES))
        return None
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (ValueError, RecursionError):
        run.partial.append("%s is not JSON text and was not read" % shown(rel, "record"))
        return None
    request = doc.get("request") if isinstance(doc, dict) else None
    if not isinstance(request, dict):
        run.row("unknown", collector="Velociraptor", record=rel, why="the record has no `request` object: it is not an ArtifactCollectorContext this tool reads")
        run.partial.append("%s holds no request" % shown(rel, "record"))
        return None
    specs, seen = [], set()
    for spec in as_list(request.get("specs")):
        if not isinstance(spec, dict) or not is_text(spec.get("artifact")):
            continue
        env = {}
        params = spec.get("parameters")
        for e in as_list(params.get("env") if isinstance(params, dict) else None):
            if isinstance(e, dict) and is_text(e.get("key")) and len(env) < 10000:
                env[e["key"]] = e.get("value") if isinstance(e.get("value"), str) else ""
        specs.append({"artifact": spec["artifact"], "env": env})
        seen.add(spec["artifact"])
    for name in as_list(request.get("artifacts")):
        if is_text(name) and name not in seen:
            specs.append({"artifact": name, "env": {}})
    if len(specs) > 20000:
        run.partial.append("the request names over 20000 artefacts: the rest is not read")
        specs = specs[:20000]
    return {"specs": specs}


MAX_DELIVERED_YAML = 5000
MAX_DELIVERED_YAML_BYTES = 256 << 20


def delivered_definitions(src, census, directory, run, yaml_files):
    """{artefact name lowercased: doc} for definition YAML files the container itself carries (outside uploads and results), read as data under the bounds:
    at most MAX_DELIVERED_YAML files and MAX_DELIVERED_YAML_BYTES bytes of them in all, the clock asked before every file."""
    out = {}
    prefix = Census.key(directory) + "/" if directory else ""
    read_files = read_bytes = 0
    for rel in yaml_files:
        if out_of_time():
            run.partial.append("the time limit ended the read of the definition files in the collection")
            break
        key = Census.key(rel)
        if not key.startswith(prefix) or "/results/" in "/" + key:
            continue
        if read_files >= MAX_DELIVERED_YAML or read_bytes >= MAX_DELIVERED_YAML_BYTES:
            run.partial.append("the collection holds more definition files than the %d files or %d bytes this tool reads: the rest were not read" % (MAX_DELIVERED_YAML, MAX_DELIVERED_YAML_BYTES))
            break
        read_files += 1
        try:
            with src.open_binary(rel) as fh:
                data = fh.read(YAML_MAX_BYTES + 1)
        except OSError:
            continue
        read_bytes += len(data)
        if len(data) > YAML_MAX_BYTES:
            run.yaml_refused["file_over_bound"] += 1
            run.partial.append("a definition file in the collection is over the bound and was refused")
            continue
        try:
            doc = parse_member(data.decode("utf-8-sig"), rel, run)
        except UnicodeDecodeError:
            run.yaml_refused["not_utf8"] += 1
            continue
        if isinstance(doc, dict) and is_text(doc.get("name")):
            out[doc["name"].lower()] = doc
    return out


# ---- KAPE ----------------------------------------------------------------------------------------------------------------------------


def kape_index(corpus, run):
    """{lowercased file name without .tkape: (member, doc)} from the pinned KapeFiles corpus."""
    out = {}
    members = corpus.by_kind["kape"]["members"]
    for position, member in enumerate(sorted(members, key=os.fsencode)):
        if position % CLOCK_EVERY == 0 and out_of_time():
            run.partial.append("the time limit ended the read of the KAPE targets")
            break
        doc = parse_member(members[member], member, run)
        if isinstance(doc, dict):
            out.setdefault(os.path.basename(member)[:-len(".tkape")].lower(), (member, doc))
    return out


def kape_leaves(name, index, run, stack=(), depth=0, budget=None):
    """([leaf entries], [problems]) of a target by name. A `Path` that names another .tkape is a compound entry: it is followed to COMPOUND_DEPTH, a cycle is
    refused by name, a target not in the pinned set is `unknown`, and a fan-out past KAPE_ENTRY_BUDGET entries (or the time limit) ends the expansion."""
    budget = budget if budget is not None else [KAPE_ENTRY_BUDGET]
    key = name.lower()
    if key.endswith(".tkape"):
        key = key[:-len(".tkape")]
    if key in stack:
        return [], [{"kind": "cycle", "target": name, "chain": [*stack, key]}]
    if depth > COMPOUND_DEPTH:
        return [], [{"kind": "too_deep", "target": name}]
    pin = index.get(key)
    if pin is None:
        return [], [{"kind": "unknown", "target": name}]
    leaves, problems = [], []
    for entry in as_list(pin[1].get("Targets")):
        budget[0] -= 1
        if budget[0] < 0 or (budget[0] % CLOCK_EVERY == 0 and out_of_time()):
            problems.append({"kind": "too_many", "target": name})
            break
        if not isinstance(entry, dict):
            continue
        path = entry.get("Path")
        if is_text(path) and path.lower().endswith(".tkape"):
            sub_leaves, sub_problems = kape_leaves(os.path.basename(path.replace("\\", "/")), index, run, (*stack, key), depth + 1, budget)
            leaves += sub_leaves
            problems += sub_problems
            continue
        leaves.append({"target": key, "member": pin[0], "name": entry.get("Name") if is_text(entry.get("Name")) else None,
                       "category": entry.get("Category") if is_text(entry.get("Category")) else None, "path": path if is_text(path) else None,
                       "mask": entry.get("FileMask") if is_text(entry.get("FileMask")) else "*",
                       "recursive": str(entry.get("Recursive")).lower() == "true", "is_directory": str(entry.get("IsDirectory")).lower() == "true"})
    return leaves, problems


def kape_norm(path):
    """A KAPE path as the join key: slashes, no drive, folded, no trailing slash."""
    parts = path_parts(path)
    return fold_name("/".join(parts))


class KapeSink(Sink):
    """Counts each copy-log and skip-log row against the targets' directories: a row belongs to a target when its source file's directory is the target's
    directory (or below it for a recursive target) and its name matches the mask. Nothing is held per row beyond the counters."""

    def __init__(self, by_dir, run):
        super().__init__()
        self.by_dir, self.run = by_dir, run
        self.copied = collections.Counter()
        self.skipped = collections.Counter()
        self.skip_words = collections.defaultdict(list)
        self.rows = 0
        self.oversize = 0
        self.by_dir_leaf = []
        self.masks = []
        self.depths = sorted({k.count("/") + 1 for k in by_dir})

    def problem(self, row):
        self.run.problems.add({"kind": "record_problem", **row})

    def record(self, rec):
        self.count += 1
        if rec.get("collector") != "KAPE" or rec.get("kind") not in ("copy", "skip"):
            return
        claim = rec.get("source_path_claim")
        if not isinstance(claim, str):
            return
        self.rows += 1
        parts = path_parts(claim)
        if len(parts) < 2:
            return
        if len(parts) > MAX_PATH_PARTS or len(parts[-1]) > MAX_NAME_MATCH:
            self.oversize += 1                  # a path no file system holds: counted, not matched
            return
        name = fold_name(parts[-1])
        directory = [fold_name(p) for p in parts[:-1]]
        for depth in self.depths:               # only the depths a target's directory has: one join each, never one per component
            if depth > len(directory):
                break
            key = "/".join(directory[:depth])
            for idx in self.by_dir.get(key, ()):
                leaf = self.by_dir_leaf[idx]
                if depth != len(directory) and not leaf["recursive"]:
                    continue
                if glob_match(self.masks[idx], name):
                    (self.copied if rec["kind"] == "copy" else self.skipped)[idx] += 1
                    if rec["kind"] == "skip" and len(self.skip_words[idx]) < 3:
                        self.skip_words[idx].append(str(rec.get("reason") or "")[:256])


def kape_section(args, run, census, found, src, corpus, needs):
    runs = found["kape"]
    given = args.get("kape_targets")
    if not runs and given is None:
        return
    if "kape" not in corpus.by_kind:
        run.partial.append("definitions_not_available for KAPE: %s" % corpus.unavailable.get("kape", "no corpus"))
        run.notes.append({"collector": "KAPE", "definitions_not_available": corpus.unavailable.get("kape")})
        return
    index = kape_index(corpus, run)
    entry = corpus.by_kind["kape"]
    names, basis = [], "named by the caller"
    if given is not None:
        names = list(given)
    else:
        basis = "the --target of a command line in a console log of the delivery (a reading of the log's words)"
        for (directory, run_id), logs in sorted(runs.items(), key=lambda kv: (os.fsencode(kv[0][0]), os.fsencode(kv[0][1]))):
            console = logs.get("console")
            if not console:
                continue
            try:
                fh = open_text(src, console)
            except OSError:
                continue
            with fh:
                for number in range(1, 200001):
                    if number % CLOCK_EVERY == 0 and out_of_time():
                        run.partial.append("the time limit ended the read of the KAPE console log")
                        break
                    line = fh.readline(MAX_LOG_LINE)
                    if not line:
                        break
                    m = re.search(r"--target[ =]{1,3}([^\s\"']{1,512})", line[:4096])
                    if m:
                        names += [n for n in m.group(1).split(",") if n]
    if not names:
        run.row("unknown", collector="KAPE", why="no target is named: the delivery's console log gives no --target and none was given")
        run.partial.append("the KAPE targets are not known")
        return
    names = list(dict.fromkeys(names))[:1000]
    run.row("requested", collector="KAPE", targets=[shown(n, "target") for n in names[:FIRST_PROBLEMS]], targets_total=len(names), targets_basis=basis,
            definitions_version=entry["version"], pinned=entry["pinned"])
    leaves = []
    budget = [KAPE_ENTRY_BUDGET]
    for name in names:
        got, problems = kape_leaves(name, index, run, budget=budget)
        if got:
            run.use(corpus, "kape", got[0]["member"])
        for p in problems:
            extra = {} if p["kind"] == "unknown" else {"kind": p["kind"]}
            run.row("unknown" if p["kind"] == "unknown" else "unresolved", collector="KAPE", target=shown(p["target"], "target"), chain=p.get("chain"), **extra,
                    why={"unknown": "the target is not among the %s KapeFiles definitions" % ("pinned" if entry["pinned"] else "unpinned"),
                         "cycle": "compound targets name each other in a cycle: refused", "too_deep": "compound targets nest deeper than %d: refused" % COMPOUND_DEPTH,
                         "too_many": "the target expands to more than %d entries (or the time limit ended): the rest is not followed" % KAPE_ENTRY_BUDGET}[p["kind"]])
        leaves += got
    by_dir, resolvable = {}, []
    for leaf in leaves:
        if len(resolvable) + 1 > 200000:
            run.partial.append("over 200000 target entries: the rest are not compared")
            break
        leaf_row = {k: leaf[k] for k in ("target", "name", "category", "path", "mask", "recursive", "is_directory")}
        run.row("could_request", collector="KAPE", **leaf_row)
        if leaf["path"] is None or VARIABLE.search(leaf["path"]):
            run.row("unresolved", collector="KAPE", kind="unresolved_dynamic_selection", target=leaf["target"], entry_name=leaf["name"], path=leaf["path"],
                    why="the path holds a KAPE variable (%user% and the like): it is not expanded by a guess")
            continue
        if len(leaf["mask"]) > MAX_MASK:
            run.row("unresolved", collector="KAPE", kind="mask_over_bound", target=leaf["target"], entry_name=leaf["name"], path=leaf["path"], why="the file mask is over %d characters: it is not run as a glob" % MAX_MASK)
            continue
        idx = len(resolvable)
        resolvable.append(leaf)
        by_dir.setdefault(kape_norm(leaf["path"]), []).append(idx)
    sink = KapeSink(by_dir, run)
    sink.by_dir_leaf = resolvable
    sink.masks = [fold_name(leaf["mask"]) for leaf in resolvable]
    sources = read_collection(src, {**found, "uac_logs": [], "uac_hashes": [], "velociraptor": {}, "velo_encrypted": {}}, sink)
    for s in sources:
        if s["status"] != "parsed":
            run.partial.append("%s is %s%s" % (s["log"], s["status"], " (%s)" % s["reason"] if s.get("reason") else ""))
    if sink.oversize:
        run.partial.append("%d copy-log or skip-log row(s) name a path of over %d components or a file name of over %d characters and were counted, not matched" % (sink.oversize, MAX_PATH_PARTS, MAX_NAME_MATCH))
    if not any(s["kind"] == "copy_log" for s in sources):
        run.partial.append("no KAPE copy log was read to compare the targets with")
    for idx, leaf in enumerate(resolvable):
        if out_of_time():
            run.partial.append("the time limit ended the list of KAPE entries taken and not taken")
            break
        took, skipped = sink.copied[idx], sink.skipped[idx]
        if took:
            run.row("collected", collector="KAPE", target=leaf["target"], entry_name=leaf["name"], path=leaf["path"], mask=leaf["mask"], copy_log_rows=took, skip_log_rows=skipped)
        else:
            run.row("not_collected", collector="KAPE", target=leaf["target"], entry_name=leaf["name"], path=leaf["path"], mask=leaf["mask"], copy_log_rows=0, skip_log_rows=skipped,
                    collector_words=sink.skip_words.get(idx, []),
                    basis="no copy-log row has a source directory and a name the entry could take%s" % ("" if census.complete else " (the census is not complete)"))
            if not needs or any(n in (leaf["target"][:512] + " " + (leaf["name"] or "")[:512] + " " + (leaf["category"] or "")[:512]).lower() for n in needs):
                run.row("proposed_additional_evidence", collector="KAPE", target=leaf["target"], entry_name=leaf["name"], path=leaf["path"],
                        why="the pinned target could take it and no copy-log row shows it taken; an item for the operator to consider, not a command")


def main():
    install_signal_handlers()
    args = read_args()
    root = want_str(args, "root", "root is required: the delivered collection directory")
    definitions = want_str(args, "definitions")
    allow_unpinned = want_bool(args, "allow_unpinned")
    limit = want_int(args, "limit", DEFAULT_LIMIT)
    seconds = want_int(args, "time_limit_seconds", 3000, 1, 3400)
    for key in ("profile", "delivered_profile"):
        want_str(args, key)
    if args.get("needs") is not None and (not isinstance(args["needs"], list) or len(args["needs"]) > 100 or any(not isinstance(v, str) or len(v) > 128 for v in args["needs"])):
        fail("needs must be a list of at most 100 strings of at most 128 characters")
    for key in ("kape_targets", "needs", "collectors"):
        value = args.get(key)
        if value is not None and (not isinstance(value, list) or not value or len(value) > 1000 or any(not isinstance(v, str) or not v or "\0" in v or len(v) > 512 for v in value)):
            fail("%s must be a list of 1 to 1000 non-empty strings" % key)
    wanted = args.get("collectors")
    if wanted is not None and any(w.lower() not in ("uac", "velociraptor", "kape") for w in wanted):
        fail("collectors is a list of: uac, velociraptor, kape")
    wanted = {w.lower() for w in wanted} if wanted else {"uac", "velociraptor", "kape"}
    try:
        VALUES[0] = SecretValues(want_bool(args, "write_values"), VALUES_NAME, TOOL)
    except SecretValuesRefused as exc:
        fail(str(exc))
    if not os.path.isdir(root):
        fail("no such directory" if not os.path.isfile(root) else "root is a file: give the delivered directory", root=root)
    start_clock(seconds)
    problems = Table(TOOL + "-problems", FIRST_PROBLEMS)
    table = Table(TOOL + "-findings", limit, always=True)
    table.open_now()
    run = Run(table, problems)
    census = Census()
    walk_census(root, census, skip=is_own)
    found = discover(census)
    src = DirSource(root)
    corpus = Corpora()
    if definitions is None and os.path.isdir(DEFAULT_DEFINITIONS):
        definitions = DEFAULT_DEFINITIONS
    if definitions is not None:
        corpus.load(definitions, allow_unpinned)
    needs = [n.lower() for n in (args.get("needs") or [])]
    dirs, dirs_complete = (dir_prefixes(census) if "uac" in wanted and found["uac_logs"] else (set(), True))
    if not dirs_complete:
        run.partial.append("the directory index of the census is incomplete")
    if "uac" in wanted:
        uac_section(args, run, census, found, src, corpus, needs, dirs)
    if "velociraptor" in wanted:
        velociraptor_section(args, run, census, found, src, corpus, needs)
    if "kape" in wanted:
        kape_section(args, run, census, found, src, corpus, needs)

    tables = {"findings": table.finish(), "problems": problems.finish()}
    lines = list(dict.fromkeys(run.partial))
    if census.stopped:
        lines.append("the census of the delivered tree stopped: %s" % census.stopped["reason"])
    if census.errors_total:
        lines.append("%d error(s) in the census" % census.errors_total)
    if census.capped:
        lines.append("the census reached its cap of %d entries" % census.cap)
    if run.yaml_refused:
        lines.append("%d definition file(s) were refused by the YAML reader (%s)" % (sum(run.yaml_refused.values()), ", ".join("%s %d" % kv for kv in sorted(run.yaml_refused.items()))))
    if run.counts["unresolved"]:
        lines.append("%d unresolved selection(s): what they select is not known from the definitions and the records" % run.counts["unresolved"])
    if run.counts["unknown"]:
        lines.append("%d name(s) or value(s) the definitions do not know, or that could not be read (see unknown)" % run.counts["unknown"])
    for e in corpus.report:
        if e.get("status") == "read" and not e.get("pinned"):
            lines.append("the %s corpus %s was read under allow_unpinned: its sha256 is not on the list this tool carries, so everything taken from it is version unknown" % (e["corpus"], e["name"]))
    if definitions is None:
        lines.append("definitions_not_available: no definitions directory was given, so no profile, artefact or target was resolved")
    if not any(found[k] for k in ("uac_logs", "velociraptor", "kape")) and not any(args.get(k) for k in ("profile", "delivered_profile", "kape_targets")):
        lines.append("no UAC, Velociraptor or KAPE record was found in the delivery and none was named")
    for kind in ("uac", "velociraptor", "kape"):
        for e in corpus.report:
            if e["corpus"] == kind and e.get("status") == "refused":
                lines.append("the %s corpus file %s was refused: %s" % (kind, e["name"], e["why"]))
    status = "partial" if lines else "complete"
    basis = "every recognised record and every definition used was read whole" if status == "complete" else "; ".join(lines[:10]) + ("; and %d more" % (len(lines) - 10) if len(lines) > 10 else "")
    sections = {s: {"count": run.counts[s], "first": run.first[s]} for s in SECTIONS}
    unique_used = list(run.used.values())
    out = {
        "tool": TOOL, "parser": PARSER, "status": status, "status_basis": basis, "root": shown(root, "root"), "ignored_parameters": ignored_parameters(args, KNOWN_PARAMETERS),
        "definitions": corpus.report,
        "definitions_not_available": {k: v for k, v in corpus.unavailable.items() if k not in corpus.by_kind} if definitions is None or corpus.unavailable else {},
        "definition_files_used": unique_used[:FIRST_PROBLEMS], "definition_files_used_total": len(unique_used),
        "could_request": sections["could_request"], "requested": sections["requested"], "excluded": sections["excluded"], "collected": sections["collected"],
        "not_collected": sections["not_collected"], "unresolved": sections["unresolved"], "differs": sections["differs"], "unknown": sections["unknown"],
        "proposed_additional_evidence": sections["proposed_additional_evidence"],
        "proposed_additional_evidence_basis": "what the definitions say could have been taken and no delivered entry shows taken: a list for the operator, never a command",
        "yaml": {"refused": dict(run.yaml_refused), "refused_first": run.yaml_refused_first,
                 "bounds": {"file_bytes": YAML_MAX_BYTES, "lines": YAML_MAX_LINES, "depth": YAML_MAX_DEPTH, "nodes": YAML_MAX_NODES, "scalar_bytes": YAML_MAX_SCALAR}},
        "notes": run.notes,
        "census": {"files": census.files, "directories": census.dirs, "symbolic_links_not_followed": census.links, "special_files_not_read": census.special,
                   "errors": census.errors_total, "stopped": census.stopped, "capped": census.capped, "complete": census.complete},
        "tables": tables,
        "withheld": {"strings_withheld": WITHHELD["count"], "values": VALUES[0].summary()},
        "note": "A comparison of what a profile or a target list could request with what the delivery's own records and files show. A profile found in the delivery is described and never used as the definition. "
                "The whole of every section is in the findings file the answer names; the sections above hold their first rows.",
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
