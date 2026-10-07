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

import collections
import csv
import datetime
import hashlib

PARSER = "collection_index/4"
TOOL = "collection_index"
VALUES_NAME = "collection-index-values.jsonl"
KNOWN_PARAMETERS = ("root", "contains", "hash", "hash_credential_stores", "limit", "out_file", "time_limit_seconds", "write_values")
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
}
CREDENTIAL_SUFFIXES = {".ppk": "a private key file", ".p12": "a key and certificate store", ".pfx": "a key and certificate store",
                       ".pem": "a key or certificate file", ".key": "a key file", ".keytab": "a Kerberos key table", ".kdb": "a password database",
                       ".kdbx": "a password database", ".jks": "a Java key store", ".keystore": "a Java key store", ".gpg": "an encrypted file",
                       ".keychain": "a keychain", ".keychain-db": "a keychain", ".bek": "a BitLocker key file", ".kirbi": "a Kerberos ticket",
                       ".ccache": "a Kerberos credential cache"}
CREDENTIAL_DIRECTORIES = {".gnupg": "a GnuPG directory", ".aws": "an AWS credentials directory", "protect": "a DPAPI master-key store",
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
    if found is None and low == "credentials" and ".aws" in parents:
        found = "a saved-credential file"
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


def risky_pattern(pattern):
    """Whether a `contains` pattern repeats a group that itself repeats or alternates, or uses a back-reference: the shapes
    that can backtrack for ever on a long name, which the time limit does not interrupt."""
    if re.search(r"\\[1-9]|\(\?P=", pattern):
        return True
    stack, i, in_class = [], 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "(":
            stack.append(False)
        elif c in "*+{" and stack:
            stack[-1] = True
        elif c == "|" and stack:
            stack[-1] = True
        elif c == ")" and stack:
            inner = stack.pop()
            nxt = pattern[i + 1:i + 2]
            if inner and nxt in ("*", "+", "{"):
                return True
            if stack and (inner or nxt in ("*", "+", "{")):
                stack[-1] = True
        i += 1
    return False


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

    def load(self, root, rels):
        for rel in rels:
            entry = {"log": shown(rel, "log path"), "directory": os.path.dirname(rel), "rows": 0, "loaded": 0, "unusable_rows": 0}
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
                                                                                    row[z] if z is not None and z < len(row) else None))
                    self.rows += 1
                    entry["loaded"] += 1
            self.unusable_rows += entry["unusable_rows"]
            self.logs.append(entry)
            self.rows_by_log.append(by_name)

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
        hits = []
        for index, log in enumerate(self.logs):
            directory = log["directory"]
            if directory and not rel.startswith(directory + os.sep):
                continue
            key = tail_key(rel[len(directory) + 1:] if directory else rel)
            for dest, source, ordinal, modified, size in self.rows_by_log[index].get(key.rsplit("\\", 1)[-1].lower(), ()):
                if dest.lower() == key.lower() or dest.lower().endswith("\\" + key.lower()):
                    hits.append((index, ordinal, source, modified, size))
        if not hits:
            return None, ("mapping_capped" if self.capped else "no_row_matched")
        sources = {tail_key(h[2]).lower() for h in hits}
        if len(sources) > 1 or self._siblings(root, rel) > 1:
            return {"candidates": [{"path": scrub(h[2], "copy log row"), "log": self.logs[h[0]]["log"], "row": h[1]} for h in hits],
                    "candidate_count": len(hits),
                    "why": "the rows name different sources" if len(sources) > 1 else "the file shares its name, letters of case apart, with a sibling"}, "ambiguous"
        first = hits[0]
        source = scrub(first[2], "copy log row")
        record = {"path": source, "reported_by": "KAPE copy log", "log": self.logs[first[0]]["log"], "row": first[1],
                  "matched_by": "the row's DestinationFile ends with this file's path relative to the log's own directory",
                  "recorded_modified_utc_raw": scrub(first[3], "copy log row") if first[3] is not None else None,
                  "recorded_modified_clock": "the collector's record of the source file's ModifiedOnUtc: a different clock from the delivered file's modified",
                  "recorded_file_size_raw": scrub(first[4], "copy log row") if first[4] is not None else None}
        if len(hits) > 1:
            record["also_rows"] = [{"log": self.logs[h[0]]["log"], "row": h[1]} for h in hits[1:]]
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
    return sorted(found)


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
        if risky_pattern(contains):
            fail("contains repeats a group that itself repeats or alternates, or uses a back-reference: it can backtrack for ever on a long "
                 "name and the time limit does not interrupt it. Write the pattern without nested repetition.")
        try:
            pattern = re.compile(contains, re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))
    if credentials_too and not (in_job() and want_values):
        fail("hash_credential_stores needs a job and write_values: true: the digest of a credential store goes only to the sealed values file, "
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
            errors.append({"path": shown(rel, "census error"), "what": what, "error": describe(exc)})

    def matches(shown_rel, shown_hypothesis=None):
        return pattern is None or bool(pattern.search(shown_rel) or (shown_hypothesis is not None and pattern.search(shown_hypothesis)))

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
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
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
            found = STREAM_HINT.match(name)
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
    values = VALUES[0]
    values.close()
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
    print(json.dumps(out, indent=2, default=str))


def mapping_summary(mapping, mapped):
    if not mapping.logs and not mapping.unreadable and not mapping.unsupported:
        return {"status": "no collector mapping available", "basis": "no KAPE copy log was found under the root; the other collectors' records are not read by this tool"}
    partial = bool(mapping.capped or mapping.unreadable or mapping.unsupported or mapping.unusable_rows)
    return {"status": "partial" if partial else "read",
            "reported_by": "KAPE copy log (SourceFile and DestinationFile)", "logs": mapping.logs, "rows_loaded": mapping.rows,
            "rows_unusable": mapping.unusable_rows, "logs_unreadable": mapping.unreadable, "logs_unsupported": mapping.unsupported, "files": mapped,
            "basis": "a file has an observed path only when the rows whose DestinationFile ends with its path relative to a copy log's own directory "
                     "name one source; digests in the log are not compared here"}


if __name__ == "__main__":
    try:
        main()
    except (SystemExit, KeyboardInterrupt):
        raise
    except BaseException as exc:                  # a bug here is a JSON error that names it, not a traceback and a half-written answer
        fail("the tool stopped on an unexpected error (%s)" % type(exc).__name__, detail=str(exc))
