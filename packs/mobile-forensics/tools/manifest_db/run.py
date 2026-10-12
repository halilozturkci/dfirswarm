#!/usr/bin/env python3
"""Read an iOS backup's map: which file, in which domain, under which path, and what state it is in.

A backup is not a file tree. It is a set of files named by a 40-digit hexadecimal id, usually in
directories named by the first two digits, and `Manifest.db` is the map: for each id, the domain
it belonged to and its path within that domain, with the metadata (size, mode, times, protection
class) in an NSKeyedArchiver property list in the `file` column. This lists that map. It does not
rebuild a file system, it opens no payload and it decrypts nothing.

What it reports, and does not infer:

  The backup's own plain files. Manifest.plist, Info.plist and Status.plist are read for the
  encryption flag, the device, the backup's version and date and its completion state, and the key
  material they hold (the keybag, the manifest key) is reported as present, with its length, and
  never printed, hashed or previewed.

  The encryption state is three-valued: encrypted, not encrypted, unknown. A Manifest.plist that is
  missing, unreadable or without an IsEncrypted key is `unknown`; it is never read as unencrypted.
  An encrypted backup is never reported as empty: when Manifest.db opens as SQLite its rows are
  listed with payload_encrypted set (what is encrypted is the content of the files the ids name,
  and this tool opens none); when it does not open as SQLite the listing is `not available` and the
  answer says what Manifest.db was instead. No decryption is provided by this tool or this pack.

  Times. A Manifest.db time is a number of seconds from an epoch the tool is TOLD, not one it
  guesses: `epoch` is "unix" (the default) or "apple" (2001-01-01), applied to every value. The
  raw number is returned beside the ISO 8601 UTC time, with the epoch and the field named. The
  answer carries the earliest and latest value read, so a wrong epoch shows as a range of decades
  rather than as a quietly plausible date. Which epoch a given backup uses is not established by
  this tool: check it against a file whose time the case documents, and run it again with the other
  epoch if they disagree.

  Metadata is read from the keyed archive's root object (the object `$top.root` points at, followed
  through its UID references, with a depth bound and cycle check), not from the first dictionary
  that has a Size. A file column that is missing, not a keyed archive or not well formed says so, per
  entry, and the entry is still listed.

  Each file id is validated (40 hexadecimal digits) before it is joined to a path, and the path is
  checked to stay inside the backup directory; the blob is looked for in the sharded layout
  (`<xx>/<id>`) and in the flat layout (`<id>`) and its state is one of present, missing, a
  directory, a symbolic link (never followed), not applicable (the manifest says the entry is a
  directory or a link), or refused (invalid id).

  If Manifest.db has a -wal or a -journal beside it, the database and its companions are copied to
  a working directory under $OUT (or work/<agent>/tool-output outside a job) and opened there, so a
  committed change that only the WAL holds is in the listing; the original is never opened for
  writing.

THE SECRET-SAFE OUTPUT PATTERN. A path in a backup can be named after a secret, and Manifest.plist
holds the key bag and the wrapped manifest key. Nothing of either is printed: key material is
presence and length, and a path component shaped like a recovery password is withheld. This tool
has no values file: it reads no secret and writes none. A future decryption step would take its
secret from a sealed file by reference, never from an argument.
"""
import datetime
import errno
import hashlib
import json
import math
import os
import plistlib
import re
import shutil
import signal
import sqlite3
import stat
import struct
import sys
import tempfile
import time
from pathlib import Path

PARSER = "manifest_db/2"
TOOL = "manifest_db"
VALUES_NAME = "manifest-db-values.jsonl"   # no values are written: the shared block names a file it never opens
VALUES_FORMAT = "not used"


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
#      (JOB_ID and OUT are set), and only to a file under $OUT: JSON Lines, mode 0600, created
#      exclusively before anything is read. The skill that sends the agent here says the job runs
#      with `secret_output: true`. Outside a job the request is refused and nothing is written.
#   3. A secret is never on a command line: these tools take a path and flags only.
#   4. A printed path component shaped like a recovery password is withheld on every output
#      channel (the answer, the files it names, an error message); the values file keeps the
#      real path.

WITHHELD = "<recovery-password-shaped name withheld>"
PATHS_WITHHELD = [0]
# A BitLocker recovery password is eight groups of six digits. A file or a directory named after
# one (people save a key under its own name) would print it in every row that names the file.
RECOVERY = re.compile(rb"(?<![0-9])(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})-(\d{6})(?![0-9])")
RECOVERY_UTF16LE = re.compile(
    rb"(?<![0-9]\x00)" + (rb"-\x00".join([rb"((?:[0-9]\x00){6})"] * 8)) + rb"(?![0-9]\x00)"
)
RECOVERY_TEXT = re.compile(RECOVERY.pattern.decode("ascii"))


def shown(path, count=True):
    """A path as it may be printed: any component shaped like a recovery password is withheld."""
    if not isinstance(path, str):
        return path
    parts = path.split("/")
    for i, part in enumerate(parts):
        if RECOVERY.search(part.encode("utf-8", "replace")) or RECOVERY_UTF16LE.search(part.encode("utf-16-le", "replace")):
            parts[i] = WITHHELD
            if count:
                PATHS_WITHHELD[0] += 1
    return "/".join(parts)


def scrub(text):
    """Text that may quote a path, with anything shaped like a recovery password withheld."""
    return RECOVERY_TEXT.sub(WITHHELD, text)


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


def fail(message, **extra):
    kept = []
    for page in OPEN_PAGES:
        if page._out is not None:
            try:
                kept.append(page.finish().get("all_results"))
            except Exception:
                pass
    answer = {"error": scrub(str(message)), **{k: (scrub(v) if isinstance(v, str) else v) for k, v in extra.items()}}
    if kept:
        answer["rows_read_before_the_failure_kept_in"] = kept
    for values in OPEN_VALUES:
        values.close()
        if values.written:
            answer["values_written_before_the_failure"] = {"file": values.shown, "rows": values.written}
    print(dumps(answer))
    raise SystemExit(1)


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
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % TOOL
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
        self._fh.write(dumps({"finding_id": finding_id, **locator, "value": value}))
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
    print(dumps(result, indent=2))


def run_main(main):
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure, and never a traceback
        fail("unexpected failure: " + (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
# --- shared with the pack's other tools: end -----------------------------------------------

SQLITE_MAGIC = b"SQLite format 3\x00"
APPLE_EPOCH_UNIX = 978307200          # 2001-01-01T00:00:00Z as Unix seconds
FILE_ID = re.compile(r"[0-9a-fA-F]{40}")
DEFAULT_LIMIT = 200
INLINE_BYTES = 1 << 20
DEFAULT_MAX_SECONDS = 240
MAX_SECONDS_CAP = 270       # manifest.json timeout_seconds (300) less the time to write the answer
BACKUP_FILES = ("Manifest.plist", "Info.plist", "Status.plist")
UNIX_2007 = 1167609600      # 2007-01-01T00:00:00Z: before the first iPhone
MAX_PLIST_BYTES = 32 << 20
MAX_REF_DEPTH = 12
KINDS = {1: "file", 2: "directory", 4: "symlink"}
EPOCH_BASE = {"unix": 0, "apple": APPLE_EPOCH_UNIX}
UNIX_ZERO = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)

# Keys of the plain files that are read, and printed as they are: what identifies the device and
# the backup. Everything else is not read, apart from the NAMES of the top-level keys of Info.plist.
MANIFEST_KEYS = ("Version", "Date", "WasPasscodeSet", "SystemDomainsVersion")
LOCKDOWN_KEYS = ("BuildVersion", "DeviceName", "ProductType", "ProductVersion", "SerialNumber", "UniqueDeviceID")
INFO_KEYS = ("Build Version", "Device Name", "Display Name", "GUID", "ICCID", "IMEI", "Last Backup Date", "MEID",
             "Phone Number", "Product Name", "Product Type", "Product Version", "Serial Number", "Target Identifier",
             "Target Type", "Unique Identifier", "iTunes Version")
STATUS_KEYS = ("BackupState", "Date", "IsFullBackup", "SnapshotState", "UUID", "Version")
KEY_MATERIAL = ("BackupKeyBag", "ManifestKey")
# What an MBFile root object holds that is read (name in the archive, name in the answer).
META_NUMBERS = (("Size", "size"), ("Mode", "mode"), ("UserID", "uid"), ("GroupID", "gid"),
                ("ProtectionClass", "protection_class"), ("Flags", "flags_in_metadata"), ("InodeNumber", "inode"))
META_TIMES = (("Birth", "created"), ("LastModified", "modified"), ("LastStatusChange", "changed"))


def plain(value):
    """A value of a plain plist as JSON: dates as UTC text, bytes as a length, nothing else changed."""
    if isinstance(value, datetime.datetime):
        stamp = value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
        return stamp.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, (bytes, bytearray)):
        return {"_binary_bytes": len(value)}
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return "<%s>" % type(value).__name__


def read_plist(path):
    """(status, tree, reason): a backup's plain plist, read without following a link."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "missing", None, None
    except OSError as exc:
        return "unreadable", None, describe(exc)
    if stat.S_ISLNK(info.st_mode):
        return "link", None, "a symbolic link: not followed"
    if not stat.S_ISREG(info.st_mode):
        return "unreadable", None, "not a regular file"
    if info.st_size > MAX_PLIST_BYTES:
        return "too_large", None, "%d bytes, over %d" % (info.st_size, MAX_PLIST_BYTES)
    try:
        with open(path, "rb") as fh:
            return "ok", plistlib.loads(fh.read()), None
    except Exception as exc:  # a parser fault on hostile input is that file's status, not a crash
        return "unreadable", None, describe(exc)


def pick(tree, keys):
    return {k: plain(tree[k]) for k in keys if isinstance(tree, dict) and k in tree}


def entropy(data):
    """Bits per byte of a sample of at least 256 bytes; None for a shorter one (its statistics are its content)."""
    if len(data) < 256:
        return None
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return -sum(c / len(data) * math.log2(c / len(data)) for c in counts if c)


def key_material(tree):
    out = {}
    for name in KEY_MATERIAL:
        if isinstance(tree, dict) and name in tree:
            value = tree[name]
            out[name] = {"present": True, "bytes": len(value) if isinstance(value, (bytes, bytearray)) else None,
                         "printed": False}
    return out


class Archive:
    """An NSKeyedArchiver graph: the root object, and values followed through UID references with a
    depth bound and a cycle check."""

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


def numeric(value):
    """A number of the archive as JSON: a float that is not finite (JSON has no NaN) is its text."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return plain(value)
    if isinstance(value, float) and not math.isfinite(value):
        return {"_float": repr(value)}
    return value


def when(raw, base):
    """(ISO 8601 UTC, reason) for a number of seconds from the epoch `base` seconds before Unix zero."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None, "not a number"
    try:
        return (UNIX_ZERO + datetime.timedelta(seconds=raw + base)).isoformat().replace("+00:00", "Z"), None
    except (OverflowError, ValueError):
        return None, "out of range for this epoch"


def metadata(blob, base, extra):
    """The entry's metadata fields and a status: ok, absent, not_keyed_archive, malformed."""
    if blob is None:
        return {"metadata_status": "absent", "metadata_reason": "the file column is NULL"}
    if not isinstance(blob, (bytes, bytearray)):
        return {"metadata_status": "malformed", "metadata_reason": "the file column is a %s, not a blob" % type(blob).__name__}
    try:
        tree = plistlib.loads(bytes(blob))
    except Exception as exc:
        return {"metadata_status": "not_keyed_archive", "metadata_reason": "the file column is not a property list: %s" % type(exc).__name__}
    archive = Archive(tree)
    if archive.root is None:
        return {"metadata_status": archive.status, "metadata_reason": archive.reason}
    out = {"metadata_status": "ok"}
    try:
        for source, name in META_NUMBERS:
            value, found = archive.get(source)
            if found:
                out[name] = numeric(value)
        for source, name in META_TIMES:
            value, found = archive.get(source)
            if found:
                out[name + "_raw"] = numeric(value)
                stamp, why = when(value, base)
                out[name] = stamp
                if why:
                    out[name + "_status"] = why
                elif stamp:
                    point = value + base
                    checks = extra["checks"]
                    if extra["backup_ts"] is not None and point > extra["backup_ts"]:
                        checks["after_backup_date"][name] = checks["after_backup_date"].get(name, 0) + 1
                    if point < UNIX_2007 and point != base:
                        checks["before_2007"][name] = checks["before_2007"].get(name, 0) + 1
                    span = extra["times"].setdefault(name, {"values": 0, "zero": 0, "low": None, "high": None})
                    if value == 0:
                        span["zero"] += 1       # a zero is an unset time: converted and returned, left out of the range
                    else:
                        span["values"] += 1
                        point = value + base
                        if span["low"] is None or point < span["low"][0]:
                            span["low"] = (point, stamp)
                        if span["high"] is None or point > span["high"][0]:
                            span["high"] = (point, stamp)
        key, found = archive.get("EncryptionKey")
        out["has_wrapped_file_key"] = bool(found and key is not None and key != "$null")
        cls, found = archive.get("$class")
        if found and isinstance(cls, dict) and isinstance(cls.get("$classname"), str):
            out["archive_class"] = scrub(cls["$classname"])
    except ValueError as exc:
        return {"metadata_status": "malformed", "metadata_reason": str(exc)}
    return out


def stage(db, companions):
    """Copy the database and its companions to a new directory of their own, and return the copy's path."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        parent = Path(out) / "tool-output"
    else:
        parent = Path("work") / safe_name(os.environ.get("AGENT_ID") or "tool") / "tool-output"
    parent.mkdir(parents=True, exist_ok=True)
    directory = tempfile.mkdtemp(prefix="manifest_db-working-copy-", dir=str(parent))
    target = os.path.join(directory, "Manifest.db")
    shutil.copyfile(db, target)
    for suffix in companions:
        shutil.copyfile(db + suffix, target + suffix)
    return target, directory


def blob_state(root, root_real, file_id, kind, valid):
    """(state, layout, bytes) for the blob a manifest entry names, looked for in both layouts, never through a link."""
    if kind in ("directory", "symlink"):
        return "not_applicable", None, None
    if not valid:
        return "refused", None, None
    for layout, path in (("sharded", os.path.join(root, file_id[:2], file_id)), ("flat", os.path.join(root, file_id))):
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError:
            return "unreadable", layout, None
        parent = os.path.realpath(os.path.dirname(path))
        if os.path.commonpath([parent, root_real]) != root_real:
            return "refused", layout, None      # a directory that is a link out of the backup
        if stat.S_ISLNK(info.st_mode):
            return "symlink", layout, None
        if stat.S_ISDIR(info.st_mode):
            return "directory", layout, None
        if stat.S_ISREG(info.st_mode):
            return "present", layout, info.st_size
        return "special", layout, None
    return "missing", None, None


def main():
    started = time.monotonic()
    args = read_args()
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a backup directory or its Manifest.db")
    if not os.path.exists(path):
        fail("no such file or directory", path=shown(path, False))
    contains = args.get("contains")
    pattern = None
    if contains:
        if not isinstance(contains, str) or len(contains) > 1000:
            fail("contains must be a regular expression of at most 1000 characters")
        try:
            pattern = re.compile(contains, re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))
    domain_filter = args.get("domain")
    if domain_filter is not None and not isinstance(domain_filter, str):
        fail("domain must be a string")
    epoch = args.get("epoch", "unix")
    if epoch not in EPOCH_BASE:
        fail('epoch must be "unix" or "apple"', epoch=epoch)
    base = EPOCH_BASE[epoch]
    limit = positive(args, "limit", DEFAULT_LIMIT)
    max_seconds = seconds(args, "max_seconds", DEFAULT_MAX_SECONDS, MAX_SECONDS_CAP)
    deadline = started + max_seconds

    # The backup directory, its Manifest.db, or one of its three plain files (their directory is the backup).
    if os.path.isdir(path):
        root, db = path, os.path.join(path, "Manifest.db")
    elif os.path.basename(path) in BACKUP_FILES:
        root = os.path.dirname(os.path.abspath(path))
        db = os.path.join(root, "Manifest.db")
    else:
        root, db = os.path.dirname(os.path.abspath(path)), path
    if os.path.islink(db):
        fail("Manifest.db is a symbolic link: it is not followed", looked_at=shown(db, False),
             note="Read the file it points to by its own path if the case calls for it.")
    if not os.path.isfile(db):
        fail("no Manifest.db there", looked_at=shown(db, False),
             note="A backup made by iOS 9 or earlier keeps Manifest.mbdb instead, which this tool does not read; "
                  "otherwise this is not a backup directory.")
    root_real = os.path.realpath(root)

    # --- the backup's own plain files --------------------------------------------------
    status_m, manifest, why_m = read_plist(os.path.join(root, "Manifest.plist"))
    status_i, info, why_i = read_plist(os.path.join(root, "Info.plist"))
    status_s, snapshot, why_s = read_plist(os.path.join(root, "Status.plist"))
    manifest_out = {"status": status_m, **({"reason": why_m} if why_m else {})}
    flag = None
    if status_m == "ok" and isinstance(manifest, dict):
        manifest_out.update(pick(manifest, MANIFEST_KEYS))
        manifest_out["top_level_keys"] = sorted(str(k) for k in manifest)
        flag = manifest.get("IsEncrypted", "absent")
        if isinstance(flag, bool):
            state = "encrypted" if flag else "not_encrypted"
            basis = "Manifest.plist IsEncrypted is %s" % ("true" if flag else "false")
        elif flag == "absent":
            state, basis = "unknown", "Manifest.plist has no IsEncrypted key"
        else:
            state, basis = "unknown", "Manifest.plist IsEncrypted is a %s, not a boolean" % type(flag).__name__
        lockdown = manifest.get("Lockdown")
        device = pick(lockdown, LOCKDOWN_KEYS) if isinstance(lockdown, dict) else {}
        material = key_material(manifest)
    else:
        state, basis = "unknown", "Manifest.plist is %s%s" % (status_m, ": " + why_m if why_m else "")
        device, material = {}, {}
    info_out = {"status": status_i, **({"reason": why_i} if why_i else {})}
    if status_i == "ok" and isinstance(info, dict):
        info_out.update(pick(info, INFO_KEYS))
        info_out["top_level_keys"] = sorted(str(k) for k in info)
    status_out = {"status": status_s, **({"reason": why_s} if why_s else {})}
    if status_s == "ok" and isinstance(snapshot, dict):
        status_out.update(pick(snapshot, STATUS_KEYS))
    # Whether the backup finished: SnapshotState of Status.plist, judged here so that nobody has to know which value means it.
    if status_s == "ok" and isinstance(snapshot, dict) and isinstance(snapshot.get("SnapshotState"), str):
        snap = snapshot["SnapshotState"]
        completion = {"state": "finished" if snap == "finished" else "not_finished",
                      "basis": "Status.plist SnapshotState is %s" % json.dumps(scrub(snap))}
    elif status_s == "ok":
        completion = {"state": "unknown", "basis": "Status.plist has no SnapshotState string"}
    else:
        completion = {"state": "unknown", "basis": "Status.plist is %s%s" % (status_s, ": " + why_s if why_s else "")}
    backup_date = None
    for tree, key in ((manifest, "Date"), (info, "Last Backup Date"), (snapshot, "Date")):
        value = tree.get(key) if isinstance(tree, dict) else None
        if isinstance(value, datetime.datetime):
            backup_date = value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
            break

    # --- Manifest.db: what it is, before anything is read from it ------------------------
    db_bytes = os.path.getsize(db)
    with open(db, "rb") as fh:
        sample = fh.read(4096)
    head = sample[:16]
    observations = []
    if completion["state"] != "finished":
        observations.append("the backup's completion state is %s (%s): do not read the listing as a finished backup" % (completion["state"].replace("_", " "), completion["basis"]))
    # A file cut short: SQLite reads the missing part of the last page as zeros, and a row there comes back as nothing.
    cut = False
    if len(sample) >= 100 and head == SQLITE_MAGIC:
        page_size = struct.unpack_from(">H", sample, 16)[0] or 65536
        if page_size == 1:
            page_size = 65536
        declared = struct.unpack_from(">I", sample, 28)[0]
        valid = declared != 0 and struct.unpack_from(">I", sample, 24)[0] == struct.unpack_from(">I", sample, 92)[0]
        if page_size >= 512 and not page_size & (page_size - 1):
            if db_bytes % page_size:
                cut = True
                observations.append("Manifest.db ends %d bytes into a page of %d: the last page is cut short, and a row on it may read as nothing" % (db_bytes % page_size, page_size))
            if valid and db_bytes < declared * page_size:
                cut = True
                observations.append("Manifest.db holds %d pages and its header declares %d: it is cut short" % (db_bytes // page_size, declared))
    skipped_companions = 0
    # A companion that is a link is not followed: it is said, and not copied.
    companions = []
    for suffix in ("-wal", "-journal"):
        try:
            info = os.lstat(db + suffix)
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            observations.append("%s%s is a symbolic link: not followed, not copied, and not applied" % (os.path.basename(db), suffix))
            skipped_companions += 1
        elif stat.S_ISREG(info.st_mode) and info.st_size > 0:
            companions.append(suffix)
    db_file = {"bytes": db_bytes, "format": "SQLite" if head == SQLITE_MAGIC else "not a plaintext SQLite database",
               **({} if head == SQLITE_MAGIC else {"entropy_bits_per_byte_of_first_4096": None if entropy(sample) is None else round(entropy(sample), 2),
                                                    "entropy_note": "what the file starts with is not printed; high entropy is one explanation among others (encryption, compression), not an identification"}),
               "companions": {s: os.lstat(db + s).st_size for s in ("-wal", "-shm", "-journal") if os.path.lexists(db + s)}}
    listing = {"available": False, "reason": None}
    counts = {"files_in_manifest": None, "rows_read": 0, "rows_matching": 0, "invalid_file_ids": 0,
              "metadata": {}, "blobs": {}, "layouts": {}, "wrapped_file_keys": 0}
    entries = LosslessPage(TOOL, [shown(os.path.realpath(db), False), "entries", contains or "", domain_filter or "", epoch], limit, INLINE_BYTES)
    domains = {}
    extra = {"times": {}, "checks": {"after_backup_date": {}, "before_2007": {}},
             "backup_ts": backup_date.timestamp() if backup_date else None}
    contains_timeouts = 0
    stopped_at_row = None
    read_error = None
    work_dir = None

    if head != SQLITE_MAGIC:
        listing["reason"] = ("Manifest.db is not a plaintext SQLite database (its first 16 bytes are not the SQLite header "
                             "string): its rows cannot be read here, and nothing is listed. The file is %d bytes." % db_bytes)
        if state == "not_encrypted":
            observations.append("Manifest.plist says the backup is not encrypted, and Manifest.db is not readable SQLite: the two disagree")
        elif state == "encrypted":
            observations.append("Manifest.db is not readable SQLite, which is consistent with an encrypted backup whose manifest is encrypted; "
                                "this tool does not decrypt it")
    else:
        opened = db
        snapshot_kind = "the main file only (no -wal or -journal beside it)"
        try:
            if companions:
                opened, work_dir = stage(db, companions)
                snapshot_kind = "the main file and %s, copied to a working directory and opened there" % " and ".join(companions)
            # The copy of a database with a -wal or a -journal is opened read-write: a hot journal is rolled back
            # and a WAL read in the copy, never in the original. Without companions the original itself is
            # opened read-only and immutable.
            uri = "file:%s?%s" % (opened.replace("%", "%25").replace("?", "%3f").replace("#", "%23"),
                                  "mode=rw" if companions else "mode=ro&immutable=1")
            connection = sqlite3.connect(uri, uri=True)
            # A TEXT cell that is not UTF-8 is read with its bytes as lone surrogates (JSON escapes them) and
            # does not stop the listing.
            connection.text_factory = lambda raw: raw.decode("utf-8", "surrogateescape")
            tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        except (sqlite3.Error, OSError) as exc:
            fail("Manifest.db would not open as SQLite", db=shown(db), reason=describe(exc) if isinstance(exc, OSError) else scrub(str(exc)),
                 encryption=state, note="Nothing is listed. This is not an empty backup.")
        db_file["snapshot"] = snapshot_kind
        if work_dir:
            db_file["working_copy"] = shown(work_dir)
        if "Files" not in tables:
            fail("Manifest.db has no Files table", tables=tables[:50], encryption=state)
        # The table b-tree in row order, never through the fileID index: a damaged index page must not cost the listing.
        try:
            counts["files_in_manifest"] = connection.execute("SELECT count(*) FROM Files NOT INDEXED").fetchone()[0]
        except sqlite3.Error as exc:
            observations.append("the rows of the Files table could not be counted (%s): the listing goes as far as the table can be read" % type(exc).__name__)
        try:
            cursor = connection.execute("SELECT rowid, fileID, domain, relativePath, flags, file FROM Files NOT INDEXED")
            with_rowid = True
        except sqlite3.OperationalError:
            cursor = connection.execute("SELECT fileID, domain, relativePath, flags, file FROM Files NOT INDEXED")
            with_rowid = False
        listing = {"available": True, "reason": None}
        rows = iter(cursor)
        while True:
            try:
                row = next(rows)
            except StopIteration:
                break
            except sqlite3.Error as exc:
                # A damaged page: what was read is kept, and the rest is not listed.
                read_error = "%s%s after %d rows" % (type(exc).__name__, " (" + exc.sqlite_errorname + ")" if getattr(exc, "sqlite_errorname", None) else "", counts["rows_read"])
                break
            if time.monotonic() > deadline:
                stopped_at_row = counts["rows_read"]
                break
            counts["rows_read"] += 1
            rowid = row[0] if with_rowid else None
            file_id, domain, relative, flags, blob = (row[1:] if with_rowid else row)
            file_id = file_id if isinstance(file_id, str) else ("" if file_id is None else str(file_id))
            domain = domain if isinstance(domain, str) else ("" if domain is None else str(domain))
            relative = relative if isinstance(relative, str) else ("" if relative is None else str(relative))
            domains[domain] = domains.get(domain, 0) + 1
            if domain_filter and domain != domain_filter:
                continue
            if pattern is not None:
                try:
                    if not timed_search(pattern, relative, max(0.01, min(2.0, deadline - time.monotonic()))):
                        continue
                except Timeout:
                    contains_timeouts += 1      # that row is counted and not matched
                    continue
            counts["rows_matching"] += 1
            valid = bool(FILE_ID.fullmatch(file_id))
            if not valid:
                counts["invalid_file_ids"] += 1
            kind = KINDS.get(flags, flags)
            state_b, layout, size_b = blob_state(root, root_real, file_id, kind, valid)
            counts["blobs"][state_b] = counts["blobs"].get(state_b, 0) + 1
            if layout and state_b == "present":
                counts["layouts"][layout] = counts["layouts"].get(layout, 0) + 1
            meta = metadata(blob, base, extra)
            counts["metadata"][meta["metadata_status"]] = counts["metadata"].get(meta["metadata_status"], 0) + 1
            if meta.get("has_wrapped_file_key"):
                counts["wrapped_file_keys"] += 1
            record = {"file_id": scrub(file_id), "file_id_valid": valid, "domain": shown(domain), "relative_path": shown(relative),
                      "flags": numeric(flags), "kind": numeric(kind), "blob": state_b,
                      **({"blob_layout": layout, "blob_bytes": size_b,
                          "on_disk": (file_id[:2] + "/" + file_id) if layout == "sharded" else file_id} if state_b == "present" else {}),
                      **meta, "payload_encrypted": True if state == "encrypted" else (False if state == "not_encrypted" else None),
                      "source": "Manifest.db", **({"manifest_rowid": rowid} if rowid is not None else {}),
                      "parser": PARSER}
            entries.add(record)
        connection.close()

    # --- the answer ------------------------------------------------------------------------
    domain_page = LosslessPage(TOOL, [shown(os.path.realpath(db), False), "domains", domain_filter or ""], limit, INLINE_BYTES)
    for name, number in sorted(domains.items(), key=lambda kv: (-kv[1], kv[0])):
        domain_page.add({"domain": shown(name), "entries": number})
    paging = {"entries": entries.finish(), "domains": domain_page.finish()}
    time_range = {}
    for name, span in sorted(extra["times"].items()):
        time_range[name] = {"earliest": span["low"][1] if span["low"] else None, "latest": span["high"][1] if span["high"] else None,
                            "values": span["values"], "zero_values_left_out": span["zero"]}
    if contains_timeouts:
        observations.append("contains ran past its time on %d path(s): those rows are counted and were not matched" % contains_timeouts)
    complete = (listing["available"] and stopped_at_row is None and read_error is None and not skipped_companions
                and not cut and not contains_timeouts and completion["state"] != "not_finished")
    if listing["available"] and (extra["checks"]["after_backup_date"] or extra["checks"]["before_2007"]):
        observations.append("under epoch %s some times fall after the backup's own date or before 2007: see epoch.consistency. "
                            "That can be a wrong epoch (a 31-year shift between the two), a phone clock, or the case; it is for the examiner to settle." % epoch)
    if not listing["available"]:
        counts.update(rows_read=None, rows_matching=None, metadata=None, blobs=None, layouts=None, invalid_file_ids=None, wrapped_file_keys=None)
    if state == "encrypted" and not listing["available"]:
        complete = False
    status = "complete" if complete else "partial"
    result = {
        "path": shown(path),
        "backup_root": shown(root),
        "manifest_db": shown(db),
        "parser": PARSER,
        "status": status,
        "encrypted": True if state == "encrypted" else (False if state == "not_encrypted" else None),
        "encryption": {
            "state": state, "basis": scrub(basis),
            "payload_encrypted": True if state == "encrypted" else (False if state == "not_encrypted" else None),
            "key_material_in_manifest_plist": material,
            "decryption": "not provided: this tool and this pack carry no decryption backend, and no password is read or accepted",
        },
        "manifest_plist": manifest_out,
        "info_plist": info_out,
        "status_plist": status_out,
        "device": device,
        "manifest_db_file": db_file,
        "listing": listing,
        "observations": observations,
        "completion": completion,
        "epoch": {"applied": epoch, "base": "1970-01-01T00:00:00Z" if epoch == "unix" else "2001-01-01T00:00:00Z",
                  "chosen_by": "the epoch parameter (default unix); never inferred from a value",
                  "range_of_values_read": time_range,
                  "consistency": {"backup_date": None if backup_date is None else backup_date.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
                                  "after_backup_date": extra["checks"]["after_backup_date"],
                                  "before_2007_01_01": extra["checks"]["before_2007"],
                                  "note": "Counts of times, per field, that fall after the backup's own date or before 2007 under the epoch applied. "
                                          "The wrong epoch is a 31-year shift (Apple against Unix), not a range of decades; compare the range with a "
                                          "file whose time the case documents. Nothing here chooses an epoch."}},
        "counts": counts,
        "stopped_at_row": stopped_at_row,
        "read_error": read_error,
        "entries": entries.page,
        "entry_count": counts["rows_matching"],
        "files_in_manifest": counts["files_in_manifest"],
        "domains": domain_page.page,
        "domain_count": len(domains) if listing["available"] else None,
        "filter": {"contains": scrub(contains) if contains else None, "domain": scrub(domain_filter) if domain_filter else None},
        "pages": paging,
        "truncated": any(p["truncated"] for p in paging.values()),
        "paths_withheld": PATHS_WITHHELD[0],
        **({"paths_note": "A path component shaped like a recovery password is withheld from every path in this answer and in "
                          "the files it names."} if PATHS_WITHHELD[0] else {}),
        "note": "This lists a backup's map; it is not the phone's file system. Cite the relative path (what the phone called "
                "the file), the domain and the file id (what was opened), and the Manifest.db row. `encryption.state` "
                "is unknown when Manifest.plist is missing, unreadable or without IsEncrypted: do not read it as "
                "unencrypted. An encrypted backup is not an empty one: its Manifest.db is listed when it opens as "
                "SQLite and otherwise the answer says the listing is not available; which parts of an encrypted backup are "
                "readable depends on the build that made it, and listing.available says what this one allowed. "
                "Key material (the key bag, the manifest key) is reported as present with its length and never printed. "
                "Times are the raw seconds beside a conversion from the epoch you chose (check it against a file whose "
                "time the case documents); a time in the manifest is the file's time on the device as the backup "
                "recorded it, not when it was backed up. blob says whether the file named by an id is in the backup "
                "(present), absent (missing), a directory, a link (never followed), not applicable (the manifest entry "
                "is a directory or a link) or refused (an id that is not 40 hexadecimal digits). status is partial "
                "when the listing is not available, a damaged page ended it (read_error), the file is cut short, the time limit stopped it, "
                "contains ran out of time on a row, a companion that is a link was not applied, or Status.plist says the backup did not finish "
                "(completion). completion is unknown, not a failure, when there is no Status.plist or it has no SnapshotState.",
    }
    send(result)


if __name__ == "__main__":
    run_main(main)
