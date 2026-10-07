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
# Identical in collection_id and collection_index. A tool is standalone, so what the two share is copied, as LosslessPage
# is in every pack tool, and tests/pack-triage-shared.test.ts holds the two copies equal. Edit it in both, never in
# one. It holds: the error form, typed arguments, where an output may be written and published without replacing another,
# the lossless table, the secret-safe values file (the SecretValues of recovery_key_scan), the withholding of strings
# shaped like a credential, the head-of-file classifier for what a delivery may hold besides copied files, and a deadline.
import atexit
import errno
import json
import os
import re
import secrets
import signal
import stat
import sys
import tempfile
import time
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


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def fail(message, **extra):
    """An error answer: JSON, exit 1, never a traceback. A name in it that is shaped like a credential is withheld."""
    print(json.dumps({"error": scrub(str(message)), "status": "failed", **{k: scrub_all(v) for k, v in extra.items()}}, default=str))
    raise SystemExit(1)


def scrub_all(value):
    """Every string of a structure through scrub, keys included (a key can be the credential)."""
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, dict):
        return {scrub(k) if isinstance(k, str) else k: scrub_all(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub_all(v) for v in value]
    return value


def _stopped_by_signal(signum, frame):
    """A kill leaves no half-written file (atexit runs on SystemExit) and no empty answer."""
    print(json.dumps({"error": "the tool was stopped by signal %d before it finished; nothing it was writing was published" % signum,
                      "status": "failed"}))
    raise SystemExit(128 + signum)


def install_signal_handlers():
    for name in ("SIGTERM", "SIGHUP"):
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
            result["all_results_format"] = "JSON Lines, one complete result per line"
            if str(final) != str(self.path):
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
        self.path = Path(self.out) / name
        register_own(self.path)
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), name)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.shown)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.shown, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace")

    def add(self, finding_id, locator, value):
        if not self.enabled:
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
# A path or a line of a collector's log can carry a string that is a secret. Only shapes that name their own kind are
# withheld (a name that merely looks random is a GUID, a hash or a cache name, and is evidence): so a secret of no
# recognisable shape is not caught, and the skill says to run the tool as a job with secret_output: true. What is caught is
# withheld in every channel (a path, a log line, an error, a dictionary key), the same strings in both tools of the pack; the
# real string goes to the values file when write_values is asked, in a job. A shape with a `secret` group withholds that part
# only (the header or the option name stays); the others withhold the whole match. Each withheld text carries a finding id,
# the finding_id of its row in the values file.

_NO_EXT = r"(?!(?:png|jpe?g|gif|svg|webp|ico|bmp|tiff?|heic|plist|json|txt|log|db|dat|xml|html?|css|js|py|exe|dll|lnk)\b)"
SHAPES = [
    ("recovery-password-shaped text", re.compile(r"(?<![0-9])[0-9]{6}(?P<s>[-_. ]?)(?:[0-9]{6}(?P=s)){6}[0-9]{6}(?![0-9])")),
    ("access-key-shaped text", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}(?![A-Za-z0-9])")),
    ("token-shaped text", re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}"
                                    r"|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,})")),
    ("web-token-shaped text", re.compile(r"(?<![A-Za-z0-9])eyJ[A-Za-z0-9_=-]{8,}(?:\.[A-Za-z0-9_=-]*){2,4}")),
    ("webhook URL", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("private-key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)")),
    ("private-key block", re.compile(r"PuTTY-User-Key-File-\d+:[\s\S]*?(?:Private-MAC:\s*[0-9A-Fa-f]+|\Z)")),
    # user-info: up to the LAST '@' before the host, so a password that holds an '@' is withheld whole; a password that holds a
    # '/', '?' or '#' is withheld when the user name is followed by a colon that is not a port; the bare form needs a host name
    # that is not a file extension (icon@2x.png is a file name)
    ("user-info of a URL", re.compile(r"(?<=//)(?:[^\s/?#'\"<>]+(?=@)|[^\s@:/?#'\"<>]+:(?!\d+(?:[/?#]|$))\S*(?=@[^\s@/?#]))")),
    ("user-info of a URL", re.compile(r"(?<![\w@.:\\-])[A-Za-z0-9._%+-]+:[^\s/\\:'\"<>]+(?=@(?:\d{1,3}(?:\.\d{1,3}){3}"
                                     r"|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:(?!(?:png|jpe?g|gif|svg|webp|ico|bmp|tiff?|heic|plist|json|txt|log"
                                     r"|db|dat|xml|html?|css|js|py|exe|dll|lnk)\b)[A-Za-z]{2,}))(?![\w@-]))")),
    ("credential after a header", re.compile(r"(?i:\b(?:proxy-)?authorization\s*[:=]\s*(?:basic|bearer|token|negotiate|digest)\s+)(?P<secret>[^\s'\",;]+)")),
    ("credential after a key name", re.compile(r"(?i:\b(?:aws_)?(?:secret_access_key|session_token|secret_key)\s*[=:]\s*[\"']?)(?P<secret>[^\s\"',;]+)")),
    ("credential after a key name", re.compile(r"(?i:\b(?:password|passwd|pwd|passphrase|client_secret|api[_-]?key|apikey|access_token|auth_token|secret|token)\s*=\s*[\"']?)"
                                               r"(?P<secret>[^\s\"'&,;]+)")),
    ("credential after a key name", re.compile(r"(?i:[?&]sig=)(?P<secret>[A-Za-z0-9%+/=]{16,})")),
    ("password option", re.compile(r"(?i:\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n|;&]*?\s-p)(?P<secret>\S+)")),
    ("password option", re.compile(r"(?i:\bsshpass\b[^\n|;&]*?\s-p\s*)(?P<secret>\S+)")),
]
_ANY = re.compile("|".join("(?:%s)" % rx.pattern.replace("(?P<secret>", "(?:") for _kind, rx in SHAPES))
WITHHELD = {"count": 0}
VALUES = [None]
_SEEN = {}


def scrub(text, where=None):
    """The text with every string of a withheld shape replaced by a marker (a kind, a length, a finding id). With a values file
    open, the original goes there once, named by `where`. The same text always gets the same id and one row."""
    if not isinstance(text, str) or not _ANY.search(text):
        return text
    known = _SEEN.get(text)
    if known is not None:
        return known
    fid = "W%06d" % (WITHHELD["count"] + 1)
    out = text
    for kind, rx in SHAPES:
        has_secret = "secret" in rx.groupindex

        def mark(m, kind=kind, has_secret=has_secret):
            if has_secret:
                start = m.start()
                s, e = m.span("secret")
                return m.group(0)[:s - start] + "<%s withheld, %d characters, %s>" % (kind, e - s, fid) + m.group(0)[e - start:]
            return "<%s withheld, %d characters, %s>" % (kind, len(m.group()), fid)

        out = rx.sub(mark, out)
    if out != text:
        WITHHELD["count"] += 1
        if len(_SEEN) < 100000:
            _SEEN[text] = out
        if VALUES[0] is not None:
            VALUES[0].add(fid, {"where": where or "text"}, text)
    return out


def shown(path, where=None):
    """A path as it may be printed: the whole string goes through scrub (a component shaped like a recovery password, a
    key id or a token is withheld wherever it stands in the path)."""
    return scrub(path, where)


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
            inline.append({k: v for k, v in row.items() if k != "kind"})


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
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
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
            survey.collected_data_logs.append(rel)
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
        names = sorted(n for n in os.listdir(results_dir) if n.endswith(".json"))
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
                                      "reason": scrub(err if isinstance(err, str) else json.dumps(err, default=str), where),
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
                    record["log_levels"][level] = record["log_levels"].get(level, 0) + 1
                    message = row.get("message")
                    text = scrub(message if isinstance(message, str) else json.dumps(message, default=str), "log.json line %d" % number)
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
    for (directory, run_id), logs in sorted(survey.kape.items()):
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
    for directory, files in sorted(survey.velociraptor.items()):
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
    values = VALUES[0]
    values.close()

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
                 "logs_inside_collected_data": survey.collected_data_logs[:FIRST_PROBLEMS],
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
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    try:
        main()
    except (SystemExit, KeyboardInterrupt):
        raise
    except BaseException as exc:                  # a bug here is a JSON error that names it, not a traceback and a half-written answer
        fail("the tool stopped on an unexpected error (%s)" % type(exc).__name__, detail=str(exc))
