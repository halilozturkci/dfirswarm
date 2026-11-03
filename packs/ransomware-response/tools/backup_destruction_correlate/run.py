#!/usr/bin/env python3
"""Keep five separate observations of what was done to the recovery paths of a host, and never turn one into another.

For each host and object (the shadow copies, the backup catalogue, the boot-recovery settings, a service's configuration) the tool
keeps, apart:

  1. command_seen: a command line or script text that names a destructive action, in an event of a log;
  2. action_attempted: a process-creation record of the program that carries the action (the record that the process started);
  3. reported_outcome: the exit status that a process-exit record reports for that process (a report, not an effect);
  4. inventory_change_observed: a difference between two inventories of the same host (shadow-copy stores, a service's start type);
  5. recovery_loss_verified: a verification the caller supplies, made apart from the logs (a restore attempt, a listing of the media).

Each carries the host, the actor as recorded, the source record, the time as recorded with its uncertainty, and the alternative
explanations. A command that ran is not a copy that is gone: the tool says "a delete command ran" and "the backups are gone" in
different classes, and reports where one is present without the other.

Inputs are the answers of other tools, by reference (paths; nothing is imported from them and none is run), each versioned by its
`parser`; an unknown version is refused by name. No event text is copied: a command is recognised from a field of the record, only a
recogniser id and the record's own reference are printed, and the text stays in the log the record came from.
"""
import bisect
import builtins
import collections
import datetime
import errno
import functools
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import unicodedata
from pathlib import Path

PARSER = "backup_destruction_correlate/1"
WORK = "correlation"
TOOL = "backup_destruction_correlate"
ACCEPTED = {"events": ("evtx_query/4",), "vss_inventories": ("vss_stores/5",), "service_keys": ("regkv/4",),
            "backup_audits": ("backup_audit_normalise/2", "backup_audit_normalise/3"), "chain_checks": ("snapshot_chain_check/2",),
            "shell_histories": ("shell_history/14",), "cloud_trails": ("cloudtrail_parse/6",)}
KINDS = ("events", "vss_inventories", "service_keys", "backup_audits", "chain_checks", "shell_histories", "cloud_trails")
CLASSES = ("command_seen", "action_attempted", "reported_outcome", "inventory_change_observed", "recovery_loss_verified")
DEFAULT_SECONDS, MAX_SECONDS = 780, 840    # the manifest allows 900
MAX_INPUTS = 20000
MAX_HOSTS = 100000
MAX_LINE = 1 << 20
MAX_DOC = 16 << 20           # an answer document read whole
MAX_TEXT = 65536             # characters of a command field looked at
TRACK_CAP = 100000           # process records held to be matched with their exit records
MAX_VERIFICATIONS = 20000
CLOCK_MAX = 1 << 40          # seconds
DEFAULT_LIMIT = 200
TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$")

# The pattern ransom_note_scan uses to take a file for a note by its name, so that the tools agree on which names are note names.
NAME_HINTS = re.compile(
    r"(readme|read_me|decrypt|restore|recover|unlock|how[\W_]*to|ransom|help[\W_]*|"
    r"your[\W_]*files|instruction|_note|!!!)", re.I)

# What a command line or a script text is recognised as. Each recogniser has an id, the object it concerns and the program that carries it
# (None when no one program does). A match is a statement about the text of a record, never about what the command did.
RECOGNISERS = [
    ("vssadmin_delete_shadows", "shadow_copies", "vssadmin.exe", re.compile(r"vssadmin(?:\.exe)?\W+delete\W+shadows", re.I)),
    ("vssadmin_resize_shadowstorage", "shadow_copies", "vssadmin.exe", re.compile(r"vssadmin(?:\.exe)?\W+resize\W+shadowstorage", re.I)),
    ("wmic_shadowcopy_delete", "shadow_copies", "wmic.exe", re.compile(r"wmic(?:\.exe)?.{0,60}shadowcopy.{0,80}delete", re.I)),
    ("diskshadow_delete_shadows", "shadow_copies", "diskshadow.exe", re.compile(r"diskshadow(?:\.exe)?.{0,300}delete\W+shadows", re.I)),
    ("shadowcopy_class_delete", "shadow_copies", None, re.compile(r"win32_shadowcopy.{0,200}(?:delete|remove-ciminstance|remove-wmiobject)|(?:remove-wmiobject|remove-ciminstance).{0,200}win32_shadowcopy", re.I)),
    ("wbadmin_delete", "backup_catalog", "wbadmin.exe", re.compile(r"wbadmin(?:\.exe)?\W+delete\W+(?:catalog|backup|systemstatebackup)", re.I)),
    ("bcdedit_recovery_off", "boot_recovery", "bcdedit.exe", re.compile(r"bcdedit(?:\.exe)?.{0,80}(?:recoveryenabled\W+(?:no|off|false)|bootstatuspolicy\W+ignoreallfailures)", re.I)),
]
# Process-creation and process-exit records, by log and event id, with the names of the fields that hold what the tool reads.
CREATE = {("security", 4688): ("NewProcessName", "CommandLine", "SubjectUserName", "NewProcessId"),
          ("microsoft-windows-sysmon/operational", 1): ("Image", "CommandLine", "User", "ProcessId")}
EXIT = {("security", 4689): ("ProcessName", "SubjectUserName", "ProcessId", "Status")}
SCRIPT = {("microsoft-windows-powershell/operational", 4104): ("ScriptBlockText", "UserId")}
SERVICE_OBJECT = "service_configuration"
OBJECTS = ("shadow_copies", "backup_catalog", "boot_recovery", "service_configuration", "snapshots", "backups", "virtual_disks", "virtual_machines")
# Linux commands in a shell history (a record of a command typed, not of a process started).
# No recogniser has two open-ended repetitions of overlapping classes side by side (that is quadratic on a 64 KiB command): the rm pattern's are
# bounded, the others have one run of separators between literals and bounded gaps, and a test times every recogniser on hostile texts of several shapes.
LINUX_RECOGNISERS = [
    ("zfs_destroy_snapshot", "snapshots", re.compile(r"\bzfs\s+destroy\b[^;|&\n]{0,200}@")),
    ("lvremove", "snapshots", re.compile(r"\blvremove\b")),
    ("btrfs_subvolume_delete", "snapshots", re.compile(r"\bbtrfs\s+subvolume\s+delete\b")),
    ("restic_forget_or_prune", "backups", re.compile(r"\brestic\b.{0,80}\b(?:forget|prune)\b")),
    ("borg_delete_or_prune", "backups", re.compile(r"\bborg\b.{0,80}\b(?:delete|prune)\b")),
    ("rm_recursive_on_a_backup_path", "backups", re.compile(r"\brm\s{1,8}-[a-zA-Z]{0,12}[rR][a-zA-Z]{0,12}\s{1,8}[^;|&\n]{0,100}(?:backups?|snapshots)\b")),
]
# CloudTrail events that delete a snapshot or a backup: event name -> (event source, object).
CLOUD_EVENTS = {"DeleteSnapshot": ("ec2.amazonaws.com", "snapshots"), "DeleteDBSnapshot": ("rds.amazonaws.com", "snapshots"),
                "DeleteDBClusterSnapshot": ("rds.amazonaws.com", "snapshots"), "DeleteBackupVault": ("backup.amazonaws.com", "backups"),
                "DeleteRecoveryPoint": ("backup.amazonaws.com", "backups"), "DeleteBackupPlan": ("backup.amazonaws.com", "backups")}
# backup_audit_normalise categories: the ones that delete (an action) and the ones that report how a backup went (an outcome only).
AUDIT_ACTIONS = {"snapshot_delete": "snapshots", "retention_prune": "backups", "retention_gc": "backups", "retention_remove": "backups",
                 "disk_delete": "virtual_disks", "vm_delete": "virtual_machines"}
AUDIT_OUTCOMES = {"backup_job": "backups", "backup_end": "backups", "backup_error": "backups", "archive_created": "backups"}
AUDIT_RESULTS = ("ok", "warning", "error", "unknown")
# snapshot_chain_check chain statuses: those that show a base or a dependent file missing are a loss; "complete" is intact; the rest cannot be followed.
CHAIN_LOSS = ("broken", "extent_missing", "data_file_missing")
LINUX_ALTERNATIVES = ["the command was typed in a shell that did not run it", "an administrator's retention work"]
ALTERNATIVES = {
    "command_seen": ["the text was typed or logged and not run", "a script or documentation that contains the text", "an administrator's maintenance"],
    "action_attempted": ["a scheduled maintenance task", "an administrator's action", "a backup product's own clean-up"],
    "reported_outcome": ["an exit status is what the process reported; the effect may differ", "another process with the same id"],
    "inventory_change_observed": ["retention or storage pressure removed the item", "an administrator or a backup product removed it", "the second inventory was of another volume or offset"],
    "recovery_loss_verified": ["the verification covered only part of the media", "the caller's record is not checked by this tool"],
}

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib

# The rows a table shows inline are cut by size as well as by count: the answer is judged, serialised and read back within the run's
# clock, and a `limit` of 1,000,000 over rows of a few hundred bytes would take longer than max_seconds (and leave the answer without
# its keys). The cut is lossless: every row is in the paging file, named by all_results. The same text is in encrypted_survey, and a test
# holds the two classes equal; the model is snapshot_chain_check's LosslessPage.
INLINE_BYTES = 1 << 19


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.page_bytes = 0
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, describe(exc)),
            "status": "failed",
            "status_basis": "the tool stopped with an error (see error); the whole result could not be kept, so there is no answer",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        # ASCII only: U+2028, U+0085, a bidi override and a lone surrogate (a file name that is not UTF-8) are escaped, lose nothing, and a
        # line of the file is always a row.
        text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object, evidence: str | None = None) -> object:
        """Keep a row: read back by the backstop first (`evidence` is the name of a file printed as it is on purpose), then paged. Returns
        the row as kept."""
        row = seal_row(row, evidence)
        self.total += 1
        if len(self.page) < self.limit and self.page_bytes < INLINE_BYTES:
            self.page.append(row)
            self.page_bytes += len(repr(row))
            return row
        if self._out is None:
            # A stop must not come between the temporary file and its registration (self._tmp): the stop handler removes only the
            # registered files. The three stop signals are held for these steps and delivered right after; where the call is missing it is a no-op.
            hold = getattr(signal, "pthread_sigmask", None)
            was = hold(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}) if hold else None
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            finally:
                if hold:
                    hold(signal.SIG_SETMASK, was)
            for kept in self.page:
                self._write(kept)
        self._write(row)
        return row

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self.total > len(self.page) and len(self.page) < self.limit:
            result["inline_cut_by_size"] = (
                "the rows shown inline stop at about %d bytes whatever limit says; the whole list is in all_results" % INLINE_BYTES
            )
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


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


# BEGIN SHARED PAGE
# The same text is in every windows-forensics tool that pages through LosslessPage (held equal by a windows-forensics test): LosslessPage replaces a file of the
# same name; this one places its finished file with place_without_replacing, and registers itself so that a stop can remove its temporary file.
PAGES = []


class NoReplacePage(LosslessPage):
    """LosslessPage whose finished file is placed without replacing an earlier file of the same name (a rerun with other limits, or one
    the time limit stopped, must not leave a smaller file where a larger one was)."""

    def __init__(self, tool, key, limit):
        super().__init__(tool, key, limit)
        PAGES.append(self)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                placed = place_without_replacing(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            self._tmp = None
            self.path = placed
            self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result
# END SHARED PAGE


def finish_page(page) -> dict:
    """page.finish(), with the size cut named: NoReplacePage (the shared block above) replaces LosslessPage.finish, so the cut that
    LosslessPage makes by INLINE_BYTES is said here, outside the block, for every table. The same text is in ransom_note_scan."""
    result = page.finish()
    if page.total > len(page.page) and len(page.page) < page.limit:
        result["inline_cut_by_size"] = (
            "the rows shown inline stop at about %d bytes whatever limit says; the whole list is in all_results" % INLINE_BYTES
        )
    return result


# BEGIN SHARED STOP
# The same text is in every tool that carries this block (tests/pack-shared-stop.test.ts holds the copies equal). SIGTERM, SIGINT and SIGHUP end the tool with JSON
# (status failed with interrupted true: a stop is not a status, the statuses are complete, partial and failed; exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
# The handlers are in as soon as the module has run as far as this block, with a minimal last word until main() installs the tool's own (only
# the start of the interpreter and the compiling of the file come before it). The first signal counts: a second one does nothing while the
# first is answered. print_answer holds the stop signals back while the answer is printed, so exactly one complete document is written
# (the ransomware tools print through it; the windows tools hold the signals in the emit of their boundary block, and carry this text unused).
import signal
import time

STOP = {"last_word": None, "deadline": None}


def set_deadline(seconds):
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    for page in list(globals().get("PAGES", ())):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    last_word = STOP["last_word"]
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def install_signal_handlers(last_word=None):
    STOP["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "failed", "interrupted": True,
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back: a signal that came in the middle of the write would end the process there, with the
    answer cut. The tool ends by itself right after, so a signal that is held is not lost for good."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    STOP["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


install_signal_handlers(lambda signum: interrupted_answer(signum))
# END SHARED STOP


# The phases after the reading (matching exit records, comparing inventories, the summary) are linear and short, and what the reading found is
# worth finishing; they run to at most this many seconds past max_seconds (840 + 20 stays below the manifest's 900). This is outside the shared
# STOP block, whose out_of_time is the reading's clock.
POST_GRACE = 20


def late():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"] + POST_GRACE

# BEGIN SHARED WITHHOLDING
# The same text is in every tool that withholds identifier-shaped strings and credentials (the network, base, encrypted-containers,
# memory, virtualization, ransomware and reverse-engineering packs, and the three tools of the cloud pack), so that they withhold the
# same strings; the tests that hold the copies equal are tests/shared-blocks-census.test.ts (how many carry it),
# tests/pack-re-delta10.test.ts (every copy equal, found by the marker), tests/pack-network-withholding.test.ts,
# tests/pack-base-shared.test.ts, tests/pack-virtualization-shared.test.ts, tests/pack-re-process.test.ts and
# tests/pack-cloud-shared.test.ts. An identifier-shaped string is withheld wherever the tool would print one: a name, a path
# component, a URL, a message that quotes either; and a credential (a value given to a password, a token, a cookie, a pair, a
# switch) by the name it is given under. A carrier may set two names above this block: WITHHOLD_LIMIT, the length past which a text is
# withheld whole (65536 when it sets none), and WITHHOLD_TICK, a hook that long scans call and that may raise to end them at the
# carrier's deadline (none when it sets none). Nothing else in the block is a carrier's to change.
COUNTS = {"names": 0, "urls": 0, "text": 0}
# A run of name characters long enough to be a token. `=` is only a padding at the end (so a key= prefix stays);
# `/` joins pieces of a base64 token and is handled apart, below.
_RUN = re.compile(r"[A-Za-z0-9_+%-]{20,}={0,2}|[A-Za-z0-9_+%-]{14,}={2}")
_SLASHED = re.compile(r"[A-Za-z0-9_+/%-]{30,}={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]{32,}")
# The prefixed secrets that one expression finds. A JWT is not among them: `eyJ` + 8 name characters + `.` + 8 + `.` + the rest, tried at
# every `eyJ`, runs to the end of the run of name characters and fails again at each next `eyJ` of a text made of them, which costs the
# square of the length. `_prefixed_spans` reads a JWT in one pass instead, and puts it in order with these.
_PREFIX_RULES = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                           r"|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}"
                           r"|(?i:basic|bearer)\s+[A-Za-z0-9+/=._~-]{8,}")
_JWT_RUN = re.compile(r"[A-Za-z0-9_-]+")
# User-info: after `//` (a URL, or a scheme-relative one), or bare as name:password@host. A mailto: address is not one.
_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_BARE_USERINFO = re.compile(r"(?<![\w.%+:/-])(?!mailto:)[\w.%+-]{1,64}:[^\s/@:]{1,128}(?=@[\w\[])")


def _withheld(what, length, kind):
    COUNTS[kind] = COUNTS.get(kind, 0) + 1
    return ("<%s withheld %d characters>" % (what, length)) if what else ("<withheld %d characters>" % length)


def _token_run(run):
    """Is this run of name characters shaped like a token, and not like words, dates or versions?"""
    if _HEX.search(run):
        return True
    chunks = [(m.group()[0].isdigit(), m.start(), m.end()) for m in re.finditer(r"[A-Za-z]+|[0-9]+", run)]
    # digits packed between letters ("a9b2c7"), which words, dates and versions do not do
    packed = 0
    for i, (is_digit, start, end) in enumerate(chunks):
        if not is_digit or end - start > 3:
            continue
        before = i > 0 and not chunks[i - 1][0] and chunks[i - 1][2] == start
        after = i + 1 < len(chunks) and not chunks[i + 1][0] and chunks[i + 1][1] == end
        packed += 1 if before or after else 0
    if packed >= 3:
        return True
    letters = [c for c in run if c.isalpha()]
    case_flips = sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower())
    if len(letters) >= 20 and case_flips >= max(8, 0.4 * len(letters)):
        return True
    if run.endswith("==") and len(run) >= 16:
        return True
    if run.endswith("=") and len(run) >= 24:
        return True
    return len(run) >= 40 and run.isalnum() and any(c.isdigit() for c in run) and any(c.isalpha() for c in run)


def _randomish(piece):
    """A piece of a path that is not a plain word: digits among letters, or capitals inside a word."""
    if len(piece) < 4 or "." in piece or re.fullmatch(r"[A-Z][a-z]+", piece):
        return False
    letters = [c for c in piece if c.isalpha()]
    mixed = any(c.islower() for c in letters) and any(c.isupper() for c in letters)
    return (any(c.isdigit() for c in piece) and bool(letters)) or mixed


_SPAN_PIECE = re.compile(r"[A-Za-z0-9_+%-]+")
# A text longer than this is withheld whole, by its length, and not examined: no name, path or URL is tens of thousands of characters
# long, and the answer says how long the text was. Every rule below reads a text of this length in well under a second whatever its
# characters are, so that no call of `scrub` or `token_spans` can run for long on a text a file chose; the limit is the backstop for
# a shape of text that no rule was tried on, and the rules themselves are linear.
TEXT_LIMIT = globals().get("WITHHOLD_LIMIT", 65536)


def _prefixed_spans(text, tail=None):
    """The spans of the prefixed secrets in the text (a vendor prefix, a JWT, `Basic`/`Bearer` and its value), left to right and apart,
    as one expression holding all of them would find them (the first match at each offset, the next search where the last ended), in
    time linear in the text. With `tail`, an expression matched where each span ends, the span takes what it matches.

    A JWT is read from the runs of name characters (`[A-Za-z0-9_-]+`), cut once: its head is the first `eyJ` of a run that is followed
    by 8 or more characters of that run, and it ends where the third part of the JWT does; every later `eyJ` of the run reads the same
    rest, so the first one is the one that matches and a run that does not hold a JWT is not read again for each `eyJ` in it."""
    from bisect import bisect_right
    size = len(text)
    starts, ends, rest = [], [], {}
    if "eyJ" in text:
        for m in _JWT_RUN.finditer(text):
            starts.append(m.start())
            ends.append(m.end())

    def jwt_end(r):      # where a JWT whose head is in run r ends, or -1: `.`, a run of 8 or more, `.`, then the rest of the next run
        if r not in rest:
            end, last = -1, ends[r] + 1
            if (last < size and text[last - 1] == "." and r + 1 < len(starts) and starts[r + 1] == last
                    and ends[r + 1] - last >= 8 and ends[r + 1] < size and text[ends[r + 1]] == "."):
                end = ends[r + 1] + 1
                if r + 2 < len(starts) and starts[r + 2] == end:
                    end = ends[r + 2]
            rest[r] = end
        return rest[r]

    def next_jwt(at):    # (start, end) of the first JWT that starts at or after `at`, or None
        while True:
            p = text.find("eyJ", at)
            if p < 0:
                return None
            r = bisect_right(starts, p) - 1
            if p + 11 <= ends[r] and jwt_end(r) >= 0:
                return p, jwt_end(r)
            at = ends[r]  # no `eyJ` further in this run can be a head either

    spans, at = [], 0
    other = _PREFIX_RULES.search(text)
    jwt = next_jwt(0) if starts else None
    while other is not None or jwt is not None:
        if other is not None and other.start() < at:      # it began inside the span just taken: look again from its end
            other = _PREFIX_RULES.search(text, at)
        elif jwt is not None and jwt[0] < at:
            jwt = next_jwt(at)
        else:
            start, end = other.span() if jwt is None or (other is not None and other.start() < jwt[0]) else jwt
            if tail is not None:
                end = tail.match(text, end).end()
            spans.append((start, end))
            at = end
    return spans


def _grow_spans(text, spans):
    """Each flagged span takes the random-looking pieces next to it across a `/`: the head of a token is not printed.

    One pass cuts the text into pieces (runs of name characters) and keeps where each starts and ends. A span then walks
    that array by index; a piece is judged once, and a walk that reaches a piece an earlier walk has settled stops there, so
    the work is linear in the text and no range is sliced or searched again. (Looking back with a search over everything
    before a piece costs the cube of the length for a name of many `/`-joined pieces.)"""
    from bisect import bisect_left
    starts, ends = [], []
    for m in _SPAN_PIECE.finditer(text):
        starts.append(m.start())
        ends.append(m.end())
    count, size = len(starts), len(text)
    judged_left, judged_right, settled_left, settled_right = {}, {}, {}, {}

    def padded(k):       # where piece k ends with the up to two `=` of padding after it
        e = ends[k]
        if e < size and text[e] == "=":
            e += 2 if e + 1 < size and text[e + 1] == "=" else 1
        return e

    def left_ok(j):
        if j not in judged_left:
            judged_left[j] = _randomish(text[starts[j]:ends[j]])
        return judged_left[j]

    def right_ok(k):
        if k not in judged_right:
            judged_right[k] = _randomish(text[starts[k]:padded(k)])
        return judged_right[k]

    def before(at):      # the piece that growing left from offset `at` takes, or -1. `$` also ends a match before a final line break.
        if at < 2 or text[at - 1] != "/":
            return -1
        for stop in ((at - 1, at - 2) if text[at - 2] == "\n" else (at - 1,)):
            j = bisect_left(ends, stop)
            if j < count and ends[j] == stop:
                return j if left_ok(j) else -1
        return -1

    def after(k):        # the piece that growing right from the end of piece k takes, or -1
        e = padded(k)
        if k + 1 >= count or e >= size - 1 or text[e] != "/" or starts[k + 1] != e + 1:
            return -1
        return k + 1 if right_ok(k + 1) else -1

    def settle(i, step, memo):
        trail = []
        while i not in memo:
            trail.append(i)
            j = step(i)
            if j < 0:
                memo[i] = i
                break
            i = j
        final = memo[i]
        for t in trail:
            memo[t] = final
        return final

    grown = []
    for start, end in spans:
        j = before(start)
        if j >= 0:
            start = starts[settle(j, lambda i: before(starts[i]), settled_left)]
        if end < size - 1 and text[end] == "/":
            k = bisect_left(starts, end + 1)
            if k < count and starts[k] == end + 1 and right_ok(k):
                end = padded(settle(k, after, settled_right))
        grown.append((start, end))
    return grown


def token_spans(text):
    if len(text) > TEXT_LIMIT:
        return [(0, len(text))]
    spans = _prefixed_spans(text)
    for m in _RUN.finditer(text):
        if _token_run(m.group()):
            spans.append(m.span())
    # A base64 token holds `/`: pieces too short to be one alone (an AWS-style secret has two) are caught as a whole.
    for m in _SLASHED.finditer(text):
        run = m.group()
        if "/" in run and sum(1 for p in run.split("/") if _randomish(p)) >= 3 and re.search(r"[0-9+]", run):
            spans.append(m.span())
    grown = _grow_spans(text, spans) if spans else []
    grown.sort()
    merged = []
    for start, end in grown:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def token_shaped(text):
    return bool(token_spans(text))


# ---- credentials: a value is withheld by the name it is given under and by the text around it ----------------------------------
# The rules above find strings that are shaped like an identifier. These find a secret that has no shape, because of what it is
# assigned to (`password=`, a `Name`/`Value` pair, a `-Password` switch, `curl -u user:pass`, `mysql -pSECRET`), and the common
# token families, private key blocks and hashes of an account database. A name decides whether a value is a secret, a value
# decides nothing. Every rule runs in time linear in the text (a bounded stretch after each anchor, no nested repeat), and a
# carrier whose texts are long (a cloud log: a megabyte) sets WITHHOLD_TICK to a hook that ends the work at its deadline.
_CRED_CHECKSUM_NAME = re.compile(r"(?i)checksum|digest|sha[0-9]|md5|etag|crc[0-9]")
_CRED_REDACTED = re.compile(r"^\W*(?:hidden_due_to_security_reasons|redacted|masked|removed|\*+|x{3,}|\[\])\W*$", re.I)
_CRED_NOT_A_VALUE = frozenset(("true", "false", "null", "none", "nil", "undefined", "required", "optional", "enabled", "disabled"))
_CRED_EXACT = {
    "password", "newpassword", "oldpassword", "currentpassword", "passwd", "pwd", "passphrase", "passcode", "pin", "otp",
    "pass", "dbpass", "userpass", "adminpass", "rootpass", "plaintext",
    "secret", "clientsecret", "secretkey", "secretaccesskey", "awssecretaccesskey", "awssecretkey", "secretstring",
    "secretbinary", "secrettext", "secretvalue", "accesskeysecret",
    "sessiontoken", "securitytoken", "accesstoken", "refreshtoken", "idtoken", "bearertoken", "authtoken", "token",
    "tokencode", "mfacode", "verificationcode", "authorizationcode",
    "authorization", "proxyauthorization", "cookie", "setcookie", "apikey", "privatekey", "privatekeypem",
    "sharedaccesskey", "sharedaccesssignature", "accountkey", "primarykey", "secondarykey", "keyvalue", "masterkey",
    "storagekey", "subscriptionkey", "ocpapimsubscriptionkey",
    "connectionstring", "credential", "credentials", "assertion", "samlresponse", "mfasecret",
    "sastoken", "sassignature", "signature", "sig",
    "passwordhash", "nthash", "ntlmhash", "lmhash",
}
_CRED_SUFFIX = ("password", "passwd", "passphrase", "secret", "apikey", "privatekey", "sessiontoken", "securitytoken",
                "accesstoken", "refreshtoken", "clientsecret", "token", "secrettext", "secretkey", "secretaccesskey",
                "primarykey", "secondarykey", "accountkey", "sharedaccesskey", "subscriptionkey", "passwordhash",
                "ntlmhash", "nthash", "passcode", "signature", "cookie")
# a position or an idempotency key under a name that ends in `token`
_CRED_NOT_SECRET = ("nexttoken", "pagetoken", "continuationtoken", "paginationtoken", "nextpagetoken", "pagingtoken",
                    "startingtoken", "nextmarkertoken", "clienttoken", "clientrequesttoken", "idempotencytoken",
                    "nextforwardtoken", "nextbackwardtoken", "requesttoken")
_CRED_CONTAINERS = ("credential", "credentials")
_CRED_NAME_CACHE = {}
_CRED_NAME_KEYS = ("Name", "name", "Key", "key")
_CRED_VALUE_KEYS = ("Value", "NewValue", "OldValue", "value", "newValue", "oldValue")


def is_container_name(name):
    """`credentials` names a group of fields (an access key id, an expiry, a token): each is judged by its own name."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower()) in _CRED_CONTAINERS


def name_is_sensitive(name):
    """Does a field or a parameter of this name hold a secret? (`Password`, `client_secret`, `x-api-key`; not `nextToken`.)"""
    hit = _CRED_NAME_CACHE.get(name)
    if hit is None:
        flat = re.sub(r"[^a-z0-9]", "", str(name).lower())
        hit = flat in _CRED_EXACT or (len(flat) > 6 and flat.endswith(_CRED_SUFFIX) and not flat.endswith(_CRED_NOT_SECRET))
        if len(_CRED_NAME_CACHE) < 20000:
            _CRED_NAME_CACHE[name] = hit
    return hit


_CRED_B64 = "A-Za-z0-9+/_-"
_CRED_B64_RUN = re.compile(r"(?<![%s])[%s]{128,}={0,2}(?![%s])" % (_CRED_B64, _CRED_B64, _CRED_B64))
_CRED_B64_EDGE = "(?<![A-Za-z0-9+/=_-])"
_CRED_B64_END = "(?![A-Za-z0-9+/=_-])"
# The names an assignment is recognised by. A long compound name may carry any prefix (dbPassword=, apiToken=, adminSecret:);
# a short one needs the edge of a word (sig= is not design=).
_CRED_STRONG = (r"password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|"
                r"security[_-]?token|auth[_-]?token|bearer[_-]?token|account[_-]?key|shared[_-]?access[_-]?key|primary[_-]?key|"
                r"secondary[_-]?key|private[_-]?key|subscription[_-]?key|sas[_-]?token|password[_-]?hash|nt[_-]?hash|ntlm[_-]?hash|"
                r"lm[_-]?hash|client[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?key|secret[_-]?text|secret[_-]?value|token|signature|plaintext")
_CRED_SHORT = r"(?<![A-Za-z0-9])(?:pwd|pass|sig|pin|otp|sas)"
_CRED_SEP = r"""(?:\\*["']|["'])?\s*(?:[:=]|%3[dD]|%3[aA])\s*"""
# a short name is a name only as `pwd=value` or `pass:value`: "pass: 3 attempts" is prose
_CRED_SEPS = r"""(?:\\*["']|["'])?(?:\s*(?:=|%3[dD])\s*|:(?=\S))"""
_CRED_NAME = r"(?:(?:%s)%s|%s%s)" % (_CRED_STRONG, _CRED_SEP, _CRED_SHORT, _CRED_SEPS)
_CRED_ARN_TAIL = re.compile(r"arn:[A-Za-z0-9-]+:[A-Za-z0-9-]+:[A-Za-z0-9-]*:[0-9]*:$")
_CRED_PAIR_WHY = "a value paired with a credential name"
_CRED_RULES = [
    # anchored at the start of a run and possessive, so that a megabyte of `eyJ` is read once, not once per `eyJ`
    ("a JSON Web Token", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}+\.[A-Za-z0-9_-]{2,}+(?:\.[A-Za-z0-9_-]*+)?"), 0),
    ("a JSON Web Encryption token", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}+(?:\.[A-Za-z0-9_-]*+){4}"), 0),
    ("a password in a URL", re.compile(r"(?i)(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]{1,20}://[^\s:/@\"'<>\\]{0,256}:([^\s/\"'<>\\]{1,1024})@(?=[^\s/@\"'<>]{1,255})"), 1),
    ("an Azure Functions key", re.compile(r"""(?i)(?:x-functions-key["']?\s*[:=]\s*(?:\\*["'])?|[?&;]code=)([A-Za-z0-9_/+=-]{16,512})"""), 1),
    ("a private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[\s\S]*)"), 0),
    ("a base64 block of key lines", re.compile(r"(?:[A-Za-z0-9+/]{60,80}={0,2}\r?\n){2,}[A-Za-z0-9+/]{2,80}={0,2}"), 0),
    ("an authorization header value", re.compile(
        r"""(?i)authorization["']?\s*[:=]\s*(?:\\*["'])?(?:(?:bearer|basic|digest|negotiate|ntlm|token)\s+)?([^\s"'&,;\\]{1,4096})"""), 1),
    ("a cookie header value", re.compile(r"""(?i)cookie["']?\s*[:=]\s*(?:\\*["'])?([^\r\n"'\\]{1,4096})"""), 1),
    ("a scheme and its credential", re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{3,4096})|\b(?:negotiate|ntlm|digest)\s+([A-Za-z0-9._~+/=-]{24,4096})"), -2),
    ("a value assigned to a credential name (quoted)", re.compile(
        r"""(?i)%s\\*(["'])(.{1,4096}?)(?=\\*\1)""" % _CRED_NAME), 2),
    ("a value assigned to a credential name", re.compile(
        r"""(?i)%s((?:(?!%%26)[^\s"'&<>\\]){1,4096})""" % _CRED_NAME), 1),
    ("a value given to a credential switch", re.compile(
        r"""(?i)(?<![A-Za-z0-9_])-(?:password|pass|pwd|passphrase|secret|clientsecret|apikey|accesstoken|token)\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    ("a secret given to ConvertTo-SecureString", re.compile(
        r"""(?i)ConvertTo-SecureString\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    # `mysql -u<user> -p<password>`: with `-p` glued to its value, and only as an option of a MySQL or MariaDB client (`ssh -p 22`,
    # `nc -p 80` and `mysql -p` alone, which asks for the password, name a port or nothing)
    ("a password given to a MySQL client", re.compile(
        r"""(?i:(?<![\w.-])(?:mysql|mysqldump|mysqladmin|mysqlcheck|mysqlimport|mysqlshow|mariadb|mariadb-dump|mariadb-admin)(?:\.exe)?(?=\s))[^\n]{0,512}?(?<=\s)-p(?=\S)(?:"([^"\n]{1,256})"|'([^'\n]{1,256})'|([^\s"']{1,256}))"""), -3),
    # `curl -u user:password`: the part after the colon, and only when there is one (`curl -u user` asks for it)
    ("a password given to curl", re.compile(
        r"""(?i:(?<![\w.-])curl(?:\.exe)?(?=\s))[^\n]{0,512}?(?<=\s)(?:-u|-U|--user|--proxy-user)(?:\s+|=)(?:"[^":\n]*:([^"\n]{1,256})"|'[^':\n]*:([^'\n]{1,256})'|[^\s:"']*:([^\s"']{1,256}))"""), -3),
    ("a hash pair of an account database", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}:([0-9a-fA-F]{32})(?![0-9a-fA-F])"), 1),
    ("a bcrypt hash", re.compile(r"(?<![A-Za-z0-9$])\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}(?![./A-Za-z0-9])"), 0),
    ("a token of a known family", re.compile(
        r"(?:GOCSPX-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])|"
        r"ya29\.[0-9A-Za-z_-]{20,}|1//0[0-9A-Za-z_-]{30,}|(?:IQoJb3JpZ2lu|FQoGZXIvYXdz|FwoGZXIvYXdz)[A-Za-z0-9+/=]{40,}|"
        r"[A-Za-z0-9_.~-]{3}[0-9]Q~[A-Za-z0-9_.~-]{30,}|[01]\.A[A-Za-z0-9_-]{50,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,})"), 0),
]
_CRED_GROUPS = {-1: (1, 2, 3), -2: (1, 2), -3: (1, 2, 3)}
# A random-looking run of an exact length that keys have: 32, 40 (an AWS secret access key), 43 + "=" and 86 + "==" (a base64 key).
_CRED_SHAPES = [
    ("a key-length base64 string", re.compile(_CRED_B64_EDGE + r"(?:[A-Za-z0-9+/]{32}|[A-Za-z0-9+/]{40}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)" + _CRED_B64_END), True),
]
# A Name/Value pair written as JSON text inside a string (an AuditData in a column of another name, a parameter list in a cell): the
# structure rule (clean_value) cannot see it, so the text rule reads the head of the pair, and the name decides as it does there. The
# value is read by hand, not by an expression: a string up to its first quote (the backslashes before the quote are not part of it), a
# number, a flat array of up to 4,096 characters, or a literal; and the next value of the same pair (`OldValue`, then `NewValue`).
_CRED_PAIR_HEAD = re.compile(r"""(?i)\b(?:name|key)\\*"\s*:\s*\\*"([^"\\]{1,64})\\*"\s*,\s*\\*"(?:new|old)?value\\*"\s*:\s*""")
_CRED_NEXT_VALUE = re.compile(r"""(?i)\s*,\s*\\*"(?:new|old)?value\\*"\s*:\s*""")
_CRED_QUOTE = re.compile(r'\\*"')
_CRED_BARE = re.compile(r"-?[0-9][0-9.eE+-]{0,39}|\[[^\[\]]{0,4096}\]|(?:null|true|false)\b")
# What a text must hold for any rule to match it: a literal one of them looks for, or a run long enough for a shape. A text with none of
# these is judged clean without running the rules (most names, addresses and ids).
_CRED_QUICK = re.compile(r"eyJ|-----BEGIN|\n|authorization|cookie|bearer|basic|digest|negotiate|ntlm|pass|pwd|secret|token|key|signature|sig|"
                         r"plaintext|hash|pin|otp|sas|securestring|gh[pousr]_|github_pat_|xox|AIza|ya29\.|1//0|IQoJb|FQoG|FwoG|Q~|[01]\.A|[sr]k_|"
                         r"://|gocspx|functions|code=|credential|assertion|mfacode|saml|mysql|mariadb|curl|\$2|"
                         r"[A-Za-z0-9+/]{32}|[A-Za-z0-9+/_-]{128}", re.I)
_CRED_CLEAN = set()               # short texts already judged to hold nothing (names, addresses and ids repeat)
_CRED_GATE = 4096                 # a text longer than this is scanned with the carrier's hook in view, rule by rule
# The carrier's hook for long scans: called with the work done so far (1 per stretch found, 4096 between rules over a long text); it may
# raise to end the scan at the carrier's deadline. Most carriers set none and the calls do nothing.
_tick = globals().get("WITHHOLD_TICK") or (lambda units=1: None)


def _cred_json_value(text, at):
    """(start, end, after) of the JSON value whose text starts at `at`: `end` is where what is withheld ends, `after` where the next
    token of the pair begins. None when no value starts there."""
    q = _CRED_QUOTE.match(text, at)
    if q:
        start = q.end()
        close = text.find('"', start)
        if close < 0:
            return start, len(text), len(text)      # a value that is cut off: the rest of the text is the value
        return start, start + len(text[start:close].rstrip("\\")), close + 1
    m = _CRED_BARE.match(text, at)
    if m is None:
        return None
    if m.group()[0] in "nft":
        return at, at, m.end()                     # null, true and false are not secrets
    return m.start(), m.end(), m.end()


def _cred_pair_spans(text, spans):
    for head in _CRED_PAIR_HEAD.finditer(text):
        if not name_is_sensitive(head.group(1)):
            continue
        at = head.end()
        for _ in range(3):
            got = _cred_json_value(text, at)
            if got is None:
                break
            start, end, after = got
            if end > start:
                value = text[start:end]
                if not (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{"))):
                    spans.append((start, end, _CRED_PAIR_WHY))
            more = _CRED_NEXT_VALUE.match(text, after)
            if more is None:
                break
            at = more.end()


def _cred_random_like(run):
    """A run that looks like random base64 and not like a path, a name or a hash: mixed case and digits in the proportions
    random text has (a long path is mostly lower case with few capitals; a hex digest has no case to mix)."""
    n = len(run)
    upper = sum(1 for ch in run if "A" <= ch <= "Z")
    lower = sum(1 for ch in run if "a" <= ch <= "z")
    digit = sum(1 for ch in run if "0" <= ch <= "9")
    return upper * 100 >= 15 * n and lower * 100 >= 15 * n and digit * 100 >= 5 * n


def _cred_name_before(text, at):
    """The letters and digits of the name an assigned value follows (`nextToken=` gives `nexttoken`)."""
    return re.sub(r"[^a-z0-9]", "", text[max(0, at - 64):at].lower())


def _cred_spans(text, shapes):
    spans = []
    big = len(text) > _CRED_GATE
    if "value" in text.lower():
        _cred_pair_spans(text, spans)
    for why, rx, group in _CRED_RULES:
        if big:
            _tick(4096)
        for m in rx.finditer(text):
            if big:
                _tick(1)
            if "assigned to a credential name" in why:
                if _CRED_ARN_TAIL.search(text[max(0, m.start() - 120):m.start()]):
                    continue                              # arn:aws:secretsmanager:...:secret:NAME is a name, not a value
                if _cred_name_before(text, m.start(m.lastindex or 0)).endswith(_CRED_NOT_SECRET):
                    continue                              # nextToken=, pageToken=, clientToken=: a position or an idempotency key
            for g in _CRED_GROUPS.get(group, (group,)):
                if g and m.group(g) is None:
                    continue
                start, end = m.span(g)
                value = text[start:end]
                if g and (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{"))):
                    continue
                if why == "a scheme and its credential" and g == 1 and not (re.search(r"[0-9+/=_.~-]", value) or len(value) >= 16):
                    continue                              # "basic authentication" is prose, "Basic dXNlcjpwYXNz" is not
                if g == 1 and group == -1 and len(m.groups()) >= 2 and m.group(1) in ("'", '"'):
                    continue                              # group 1 of the switch rules is the quote
                spans.append((start, end, why))
    if big:
        _tick(4096)
    for m in _CRED_B64_RUN.finditer(text):
        if _cred_random_like(m.group(0)):
            spans.append((m.start(), m.end(), "a long unbroken base64-like run"))
    if shapes:
        for why, rx, check in _CRED_SHAPES:
            for m in rx.finditer(text):
                if not check or _cred_random_like(m.group(0)):
                    spans.append((m.start(), m.end(), why))
    spans.sort()
    merged = []
    for s in spans:
        if merged and s[0] < merged[-1][1]:
            if s[1] > merged[-1][1]:
                merged[-1] = (merged[-1][0], s[1], merged[-1][2])
            continue
        merged.append(s)
    return merged


def credential_spans(text, shapes=True):
    """(start, end, why) of each stretch of `text` that is a credential by the name it is given under or by its text, in order and
    not overlapping. `shapes` False leaves out the rules that recognise a key by its length alone (a value that is named a checksum or
    a digest is not scanned for them). This is not `token_spans`: an identifier (a GUID, a hex digest, an access key id, an ARN) is
    not a credential here, and a tool that prints identifiers on purpose asks only for these."""
    if len(text) > TEXT_LIMIT:
        return [(0, len(text), "text longer than %d characters" % TEXT_LIMIT)]
    if shapes and text in _CRED_CLEAN:
        return []
    spans = _cred_spans(text, shapes) if _CRED_QUICK.search(text) else []
    if shapes and not spans and len(text) <= 256 and len(_CRED_CLEAN) < 100000:
        _CRED_CLEAN.add(text)
    return spans


def clean_value(value, leaf, note, key=None, pointer="", depth=0, shapes=True, max_depth=200):
    """The structure rule: `value` (what a JSON document decoded to) with every credential in it replaced. A string goes to
    `leaf(text, pointer, shapes)`, which returns what is printed for it. A field whose name says it holds a secret (or a `Value` whose
    `Name` does), at any depth, is not read at all: `note(pointer, why, original)` returns what is printed for it (a number under such
    a name is withheld too: 0 and 1 are not nothing). A key goes through `key(text)` when one is given. A value nested deeper than
    `max_depth` is replaced the same way."""
    if isinstance(value, str):
        return leaf(value, pointer, shapes)
    _tick(1)
    if depth > max_depth and isinstance(value, (dict, list)):
        return note(pointer, "nested deeper than %d levels" % max_depth, value)
    if isinstance(value, dict):
        named = None
        for k in _CRED_NAME_KEYS:
            if isinstance(value.get(k), str):
                named = value[k]
                break
        pair_secret = named is not None and name_is_sensitive(named)
        out = {}
        for k, v in value.items():
            ks = str(k)
            point = "%s/%s" % (pointer, ks.replace("~", "~0").replace("/", "~1"))
            safe_key = key(ks) if key is not None else ks
            if safe_key in out:
                safe_key = "%s#%d" % (safe_key, len(out))
            sensitive = name_is_sensitive(ks) or (pair_secret and ks in _CRED_VALUE_KEYS)
            if sensitive and is_container_name(ks) and isinstance(v, (dict, list)):
                sensitive = False
            if sensitive and not (v is None or isinstance(v, bool) or v == "") and not (isinstance(v, str) and (_CRED_REDACTED.match(v) or v.lower() in _CRED_NOT_A_VALUE)):
                out[safe_key] = note(point, "credential-named field", v)
            else:
                out[safe_key] = clean_value(v, leaf, note, key, point, depth + 1, shapes and not _CRED_CHECKSUM_NAME.search(ks), max_depth)
        return out
    if isinstance(value, list):
        return [clean_value(v, leaf, note, key, "%s/%d" % (pointer, i), depth + 1, shapes, max_depth) for i, v in enumerate(value)]
    return value


def _credentials_withheld(text, kind):
    """`text` with each credential in it withheld. It runs after the rules above, on text that may hold their markers: a stretch that
    begins at a marker is theirs already."""
    if not _CRED_QUICK.search(text):
        return text
    out, last = [], 0
    for start, end, why in credential_spans(text):
        if text.startswith("<", start):
            continue
        out.append(text[last:start])
        out.append(_withheld(why, end - start, kind))
        last = end
    if not out:
        return text
    out.append(text[last:])
    return "".join(out)


def scrub(text, kind="text"):
    """The text with every token-shaped run, every user-info and every credential withheld."""
    if len(text) > TEXT_LIMIT:
        return _withheld("over-long text", len(text), kind)
    text = _USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    text = _BARE_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    out, last = [], 0
    for start, end in token_spans(text):
        out.append(text[last:start])
        out.append(_withheld("token-shaped text", end - start, kind))
        last = end
    out.append(text[last:])
    return _credentials_withheld("".join(out), kind)


def redact_url(url):
    """A URL or request target without its user-info, its token-shaped path text, its query values or its fragment."""
    rest, fragment = (url.split("#", 1) + [None])[:2]
    rest, query = (rest.split("?", 1) + [None])[:2]
    scheme = authority = ""
    m = re.match(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)([^/]*)(.*)$", rest, re.S)
    if m:
        scheme, authority, rest = m.group(1), m.group(2), m.group(3)
        if "@" in authority:
            userinfo, authority = authority.rsplit("@", 1)
            authority = _withheld("userinfo", len(userinfo), "urls") + "@" + authority
    out = scheme + authority + scrub(rest, "urls")
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            name, eq, value = pair.partition("=")
            pairs.append(scrub(name, "urls") + (eq + _withheld("", len(value), "urls") if eq else ""))
        out += "?" + "&".join(pairs)
    if fragment is not None:
        out += "#" + _withheld("", len(fragment), "urls")
    return out


def cell(value):
    """Text for one tab-separated cell or one printed path: no tab or line break, and a byte that was not UTF-8
    (a lone surrogate) written as \\xNN, so that no writer raises on it."""
    text = value if isinstance(value, str) else str(value)
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)
# END SHARED WITHHOLDING


# BEGIN SHARED NAMES
# The same text is in encrypted_survey and ransom_note_scan, so that the two tools judge a name alike (a ransomware-response test holds
# the copies equal). A path is printed only through shown(): every component is judged, and no directory above a file is exempt.
# Everything derived from a name that is withheld (an extension, a stem, a length, the place of the name among its siblings) is withheld
# with it: a name that is withheld is replaced by one constant marker, and the order of a listing never follows the text that was withheld.
WITHHELD = "<identifier-shaped name withheld>"
WITHHELD_PATHS = [0]              # printed paths that had a component withheld (one per call of shown)
_IDRUN = re.compile(r"[A-Za-z0-9]{8,}")
_WORDY = re.compile(r"[A-Z]?[a-z]+(?:[A-Z][a-z]+)*|[A-Z]+")
_PAIR_SEPARATORS = re.compile(r"[^0-9A-Za-z]")
_DIGIT_GROUPS = re.compile(r"(?<![0-9])[0-9]{3,}(?:[ ,][0-9]{3,})+(?![0-9])")
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
SINGLE_CASE_RUN = 16              # a run of letters of one case is a word below this many letters, a random run from here on
HEX_PAIRS = 8                     # this many pairs of hex digits joined by one separator are a byte string
# Directory names every Windows, Linux and ESXi host has, whose letters and digits would otherwise be taken for an identifier, and the names
# of the exceptions Python raises (the tools print the type of an error: IsADirectoryError reads as letters that are not words). A component
# is printed as it is when it is one of these, whole and in any case.
WELL_KNOWN = frozenset((
    "system32", "syswow64", "inetcache", "inetcookies", "inethistory", "msocache", "psreadline", "framework", "framework64",
    "sqlserver", "gpucache", "dawnwebgpucache", "dawngraphitecache", "grshadercache", "indexeddb", "overlay2", "datastore1")
) | frozenset(name.lower() for name, value in vars(builtins).items() if isinstance(value, type) and issubclass(value, BaseException))


# The characters whose NFKC form holds a slash (a full-width solidus, the "a/c", "a/s", "c/o" and "c/u" signs) each read as one backslash, a
# separator that is not a slash: a path is split at the real slashes only, and a folded one would cut a run of pairs into pieces of one.
_SLASH_LIKE = dict.fromkeys((0x2100, 0x2101, 0x2105, 0x2106, 0xFF0F), "\\")
# Characters that show nothing and are not format characters: a combining grapheme joiner, variation selectors, Mongolian free variation
# selectors, hangul and khmer fillers, a braille blank, tag and musical controls, the other default-ignorable code points.
_INVISIBLE = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u2800\u3164"
                        "\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]")


def _unseen(ch):
    """Whether a non-ASCII character shows nothing of its own: a format character, a combining mark, a default-ignorable code point."""
    return unicodedata.category(ch) in ("Cf", "Mn", "Mc", "Me") or _INVISIBLE.match(ch) is not None


def fold(name):
    """The name as the rule reads it: NFKC (a full-width letter or digit is the ASCII one; a full-width solidus is a separator, not a
    slash), every decimal digit of any script as its ASCII digit, and nothing that shows nothing: no format character, no combining mark
    (taken off the letter it sits on before the two are composed), no default-ignorable code point (a zero-width space, a variation
    selector, a filler cannot split a token)."""
    if name.isascii():
        return name
    out = []
    for ch in unicodedata.normalize("NFKC", "".join(c for c in name.translate(_SLASH_LIKE) if c.isascii() or not _unseen(c))):
        if ord(ch) < 128:
            out.append(ch)
        elif unicodedata.category(ch) == "Nd":
            out.append(str(unicodedata.decimal(ch)))
        elif not _unseen(ch):
            out.append(ch)
    return "".join(out)


def _hex_pairs(text):
    """Whether HEX_PAIRS or more pairs of hex digits follow each other, one separator between two. A separator is any character that is not
    an ASCII letter or a digit (the pairs of `id[aa-bb-...-hh]`, `key=aa:bb:...` and `(aa.bb...)` are found: a neighbour of the run that is
    not a letter or a digit does not hide a pair at its end), and only a letter or a digit glued to a pair makes it no pair. A run does not
    cross a slash: a path is read one component at a time (a full-width solidus is not a slash: fold turns it into a separator)."""
    for part in text.split("/"):
        run = 0
        for piece in _PAIR_SEPARATORS.split(part):
            if len(piece) == 2 and piece[0] in HEX_DIGITS and piece[1] in HEX_DIGITS:
                run += 1
                if run >= HEX_PAIRS:
                    return True
            else:
                run = 0
    return False


def _digit_groups(text):
    """Whether groups of three or more digits, joined by a space or a comma, hold ten or more digits together."""
    return any(sum(c.isdigit() for c in m.group(0)) >= 10 for m in _DIGIT_GROUPS.finditer(text))


def shaped(name):
    """Whether a name holds a token shaped like an identifier. The name is folded first (fold). A token is a run of 8 or more ASCII
    letters and digits. It is identifier-shaped when it holds both letters and digits, or is 10 or more digits, or is letters only and is
    not one word, one capitalised word, several capitalised words or all capitals, or is 16 or more letters of one case. So are 8 or more
    pairs of hex digits joined by one separator (any character that is not a letter, a digit or a slash: a colon, a dash, a dot, an underscore,
    a space, a bracket, an equals sign; a letter or a digit glued to a pair at an end of the run makes that pair no pair), and groups of
    digits joined by a space or a comma that hold 10 digits or more. The rule is a shape: a longer or different separator, a different
    grouping and other scripts are not covered (see the manifests)."""
    text = fold(name)
    for m in _IDRUN.finditer(text):
        token = m.group(0)
        if token.isdigit():
            if len(token) >= 10:
                return True
        elif any(c.isdigit() for c in token):
            return True
        elif not _WORDY.fullmatch(token):
            return True
        elif len(token) >= SINGLE_CASE_RUN and (token.islower() or token.isupper()):
            return True
    return len(text) >= 23 and _hex_pairs(text) or len(text) >= 11 and _digit_groups(text)


@functools.lru_cache(maxsize=65536)
def _judge(part):
    """What to print in place of one path component, or None to print it as it is. A component that is judged is withheld whole, by
    one marker that says nothing of its length or its shape."""
    if part.lower() in WELL_KNOWN:
        return None
    if shaped(part):
        return WITHHELD
    return WITHHELD if scrub(part, "names") != part else None


def shown(path, values=(), keep_last=False, count=True):
    """A path as it may be printed: every component that could carry an identifier is withheld.

    A component is withheld when it holds a token shaped like an identifier (shaped), when the shared withholding rules above find a
    token, a key or user-info in it, or when it contains a value the note held (case-insensitive, 8 characters or more). The same rule
    applies to every path a tool prints, so a name is never hidden on one line and printed on the next; a harmless name can be withheld
    with it, and the directory can be listed. keep_last leaves the final component as it is (a name that is itself the evidence).
    """
    if not isinstance(path, str):
        return path
    parts = path.split("/")
    last = len(parts) - 1
    lows = [v.lower() for v in values if len(v) >= 8]
    changed = False
    for i, part in enumerate(parts):
        if not part or (keep_last and i == last):
            continue
        replaced = _judge(part)
        if replaced is None and lows:
            low = part.lower()
            if any(v in low for v in lows):
                replaced = WITHHELD
        if replaced is not None:
            parts[i] = replaced
            changed = True
    if changed and count:
        WITHHELD_PATHS[0] += 1
    return "/".join(parts)


_ORDER_SALT = os.urandom(16)


def print_order(entries, judged, hidden=None):
    """The directory entries in the order an answer prints them: by the text printed for each (the marker for a name that is judged
    and withheld, the name itself otherwise; `judged(entry)` says whether the answer prints the entry's name through the judge;
    `hidden(entry)`, when given, says that a name the first rule lets through is withheld all the same, because the note beneath it holds
    its value: it sorts as the marker does), and the entries that print alike in an order drawn afresh every run (a keyed hash of the whole
    path, the directory above included, under a salt of this run: the same name in two directories has two unrelated ranks). The rank of a
    withheld name among its siblings, the order a directory lists them in and the inode never show in what an answer lists, in the
    order of its rows, in the numbers it hands out or in which entries a limit keeps."""
    texts = []
    for entry in entries:
        name = entry.name
        try:
            if hidden is not None and hidden(entry):
                texts.append(WITHHELD)
            else:
                texts.append((_judge(name) or name) if judged(entry) else name)
        except OSError:
            texts.append(_judge(name) or name)
    order = sorted(range(len(entries)), key=texts.__getitem__)
    out, i = [], 0
    while i < len(order):
        j = i + 1
        while j < len(order) and texts[order[j]] == texts[order[i]]:
            j += 1
        group = order[i:j]
        if len(group) > 1:
            group.sort(key=lambda n: (hashlib.blake2b(entries[n].path.encode("utf-8", "surrogatepass"), key=_ORDER_SALT, digest_size=8).digest(), n))
        out.extend(group)
        i = j
    return [entries[n] for n in out]
# END SHARED NAMES


# BEGIN SHARED BACKSTOP
# The same text is in encrypted_survey and ransom_note_scan (a ransomware-response test holds the copies equal). Every row a page or the census
# keeps and the answer itself pass through here on their way out, whatever the code that made them did: a second check, written apart from
# shown() (it reads a string whole, not component by component, and calls neither the judge, scrub nor any call site's decision), that
# replaces a string holding an identifier-shaped text by a marker, counts it, and makes a complete answer partial. The one exception is on
# purpose: the name of a file that is not named like a note is evidence and is printed as it is (the caller says so with `evidence`, and the
# check refuses that claim for a name that is note-named). Content that is hex by nature (a digest, a tail) is passed by its key.
BOUNDARY = {"replaced": 0, "by": {}, "where": [], "not_listed": 0}
OWN_NAMES = set()                 # the names of the files this run wrote (their digest is the name of the root and of the table)
FREE_KEYS = frozenset(("sha256", "tail_hex", "suffix_hex"))
PROSE_KEYS = frozenset(("reason", "status_basis", "partial_reasons"))    # the tool's own sentences: "(4294967296 bytes)" there is a size, not a name
SERIAL_KEYS = frozenset(("note_id", "finding_id", "first_note_id", "duplicate_of"))      # a sequence number this tool counted: N000001, F1000000
_SERIAL = re.compile(r"[NF][0-9]{6,12}")
MAX_REPLACED_LISTED = 20
MAX_JUDGED = 1 << 16
_SUSPECT = re.compile(r"[A-Za-z0-9]{8}|(?:[0-9A-Fa-f]{2}[^0-9A-Za-z/]){4}|[0-9]{3}[ ,][0-9]{3}")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")
_PAIRS = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{2}(?:[^0-9A-Za-z/][0-9A-Fa-f]{2}){7}(?![0-9A-Za-z])")
_GROUPS = re.compile(r"(?<![0-9])[0-9]{3,}(?:[ ,][0-9]{3,})+(?![0-9])")


class Sealed(dict):
    """A row that has been through the backstop: it is not read again (its evidence name would not pass without the claim made for it)."""


_FOLDS_TO_SLASH = dict.fromkeys((0x2100, 0x2101, 0x2105, 0x2106, 0xFF0F), "\\")      # NFKC turns these into a slash: not a path separator here
_UNSEEN = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u2800\u3164"
                     "\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]")


def _read_as(text):
    """The string as the check reads it: NFKC (a full-width solidus is a separator, not a slash), decimal digits of any script as ASCII
    digits, nothing that shows nothing (no format character, no combining mark, no default-ignorable code point; a mark is taken off the
    character it sits on before the two are composed into one)."""
    if text.isascii():
        return text
    seen = lambda ch: unicodedata.category(ch) in ("Cf", "Mn", "Mc", "Me") or _UNSEEN.match(ch) is not None     # noqa: E731
    kept = []
    for ch in unicodedata.normalize("NFKC", "".join(c for c in text.translate(_FOLDS_TO_SLASH) if c.isascii() or not seen(c))):
        if ch.isascii():
            kept.append(ch)
        elif unicodedata.category(ch) == "Nd":
            kept.append(str(unicodedata.decimal(ch)))
        elif not seen(ch):
            kept.append(ch)
    return "".join(kept)


@functools.lru_cache(maxsize=65536)
def _why(text, prose=False):
    """The reason a string may not be printed (a fixed sentence, never a part of the string), or None. `prose` is a sentence of the tool's
    own (a reason, a status basis): a number of 10 or more digits followed by " bytes" is a size there and is not read as a name."""
    flat = _read_as(text)
    for found in _ALNUM_RUN.finditer(flat):
        run = found.group()
        size = len(run)
        if size < 8 or run.lower() in WELL_KNOWN:
            continue
        digits = sum(1 for c in run if c.isdigit())
        if digits == size:
            if size >= 10 and not (prose and flat.startswith(" bytes", found.end())):
                return "a long run of digits"
        elif digits:
            return "letters and digits in one run"
        elif run.isupper() or run.islower():
            if size >= 16:
                return "a long run of letters of one case"
        elif any(c.isupper() and not (i + 1 < size and run[i + 1].islower()) for i, c in enumerate(run)):
            return "letters that do not read as words"
    if _PAIRS.search(flat):
        return "pairs of hex digits"
    for m in _GROUPS.finditer(flat):
        if sum(c.isdigit() for c in m.group(0)) >= 10:
            return "groups of digits"
    return None


_CLEAN = set()                    # short strings already found clean (keys, repeated words): not read again


def _refuse(text, evidence, prose=False):
    """Why this string may not be printed, or None. `prose` is set for the tool's own sentences (see _why)."""
    size = len(text)
    if size < 8 or text in _CLEAN or text in OWN_NAMES:
        return None
    if size > MAX_JUDGED:
        return "a string too long to check"
    if evidence and not NAME_HINTS.search(evidence):
        if text.lower() in evidence.lower():              # the name itself, or a piece of it (its extension)
            return None
        if text.endswith("/" + evidence):                 # a path whose last component is the evidence
            text = text[:-len(evidence) - 1]
            size = len(text)
            if size < 8:
                return None
    why = None if text.isascii() and not _SUSPECT.search(text) else _why(text, prose)
    if why is None and not prose and size <= 64 and len(_CLEAN) < 20000:
        _CLEAN.add(text)
    return why


def _place(where):
    """The place of a string as text: the keys that are plain words and the indexes above it, never a key that came from a name (a key is a
    word only when it is also one to the second check: a key of letters and digits is not printed, whatever it looks like)."""
    parts = []
    while where is not None:
        where, label = where
        word = not isinstance(label, int) and re.fullmatch(r"[a-z][a-z_0-9]{0,40}", str(label)) and _why(str(label)) is None
        parts.append(label if isinstance(label, int) or word else "*")
    return "/" + "/".join(str(p) for p in reversed(parts))


def _replaced(why, where):
    BOUNDARY["replaced"] += 1
    BOUNDARY["by"][why] = BOUNDARY["by"].get(why, 0) + 1
    if len(BOUNDARY["where"]) < MAX_REPLACED_LISTED:
        BOUNDARY["where"].append({"at": _place(where), "check": why})
    else:
        BOUNDARY["not_listed"] += 1
    return "<withheld at the output: %s>" % why


def _read_back(value, where, key, evidence):
    """`value` with every string checked; the same object when nothing was replaced."""
    if isinstance(value, Sealed):
        return value
    if isinstance(value, str):
        if len(value) < 8 or key in FREE_KEYS or (key in SERIAL_KEYS and _SERIAL.fullmatch(value)):
            return value
        why = _refuse(value, evidence, key in PROSE_KEYS)
        return _replaced(why, where) if why else value
    if isinstance(value, dict):
        pairs, changed = [], False
        for k, v in value.items():
            nk = _read_back(k, (where, "(key)"), None, None) if isinstance(k, str) and len(k) >= 8 else k
            if isinstance(v, (str, dict, list, tuple)):
                nv = _read_back(v, (where, k if nk is k else "(key)"), k if isinstance(k, str) else None, evidence)
            else:
                nv = v
            changed = changed or nk is not k or nv is not v
            pairs.append((nk, nv))
        if not changed:
            return value
        out = {}
        for nk, nv in pairs:
            while nk in out:
                nk = "%s #" % nk
            out[nk] = nv
        return out
    if isinstance(value, (list, tuple)):
        items = [_read_back(v, (where, i), key, evidence) for i, v in enumerate(value)]
        return value if all(a is b for a, b in zip(items, value)) else items
    return value


def seal_row(row, evidence=None):
    """A row on its way to a page or the census: every string read back. `evidence` is the name of the file the row is about when it is
    printed as it is on purpose (a file that is not named like a note)."""
    if isinstance(row, Sealed):
        return row
    out = _read_back(row, None, None, evidence)
    return Sealed(out) if isinstance(out, dict) else out


def release(doc):
    """The answer: every string that was not read back already is read back now. A complete answer that had a string replaced is partial."""
    out = _read_back(doc, None, None, None)
    if BOUNDARY["replaced"] and isinstance(out, dict):
        note = {"strings_replaced_at_the_output": BOUNDARY["replaced"], "by_check": dict(BOUNDARY["by"]), "replaced_at": list(BOUNDARY["where"]),
                "replaced_not_listed": BOUNDARY["not_listed"],
                "note": "every string of this answer and of the files it names was read back by a second check, written apart from the rule "
                        "that withholds names; a string it found identifier-shaped is replaced by a marker and its place is in replaced_at"}
        merged = {}
        for k, v in out.items():
            merged[k] = v
            if k == "status_basis":
                merged["boundary"] = note
        merged.setdefault("boundary", note)
        if merged.get("status") == "complete":
            merged["status"] = "partial"
            if "complete" in merged:
                merged["complete"] = "partial"
            merged["status_basis"] = "%s; %d strings held an identifier-shaped text that the first rule missed and were replaced at the output (see boundary)" % (
                merged.get("status_basis") or "every entry was visited", BOUNDARY["replaced"])
        out = merged
    return out
# END SHARED BACKSTOP


def output_place(tool, key):
    """Where a whole result is written and how the answer names it: (real path, path as cited)."""
    digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    name = f"{tool}-{digest}.jsonl"
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        # In a job only $OUT is written, and it is sealed as the job's output.
        return Path(out) / "tool-output" / name, "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    path = Path("work") / agent / "tool-output" / name
    return path, str(path)


class Profile:
    """One JSON line per record (the tool says which), then a receipt; written whole or not at all.

    The file is made under a temporary name and placed when the receipt is written, so an interrupted run leaves no file with
    the profile's name: a profile that exists ends in its receipt. It is placed without replacing a profile already there (a
    rerun with other limits writes a different profile, and the earlier one, which may be the larger, stays); the answer names
    the file that holds this one. The name is made from the parameters, never from a name of any file.
    """

    def __init__(self, key):
        self.path, self.shown = output_place(TOOL + "-profile", key)
        self.rows = 0
        # A stop must not come between the temporary file and its registration in PAGES, which is how the stop handler finds it. The three
        # stop signals are held for these steps and delivered right after; where the call is missing it is a no-op.
        hold = getattr(signal, "pthread_sigmask", None)
        was = hold(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}) if hold else None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}-")
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            PAGES.append(self)
        finally:
            if hold:
                hold(signal.SIG_SETMASK, was)

    def add(self, row, evidence=None):
        row = seal_row(row, evidence)
        self._out.write(json.dumps(row, ensure_ascii=True, default=str))
        self._out.write("\n")
        self.rows += 1
        return row

    def finish(self, receipt):
        receipt = release({"record": "receipt", "rows": self.rows, **receipt})
        self._out.write(json.dumps(receipt, ensure_ascii=True, default=str))
        self._out.write("\n")
        self._out.flush()
        os.fsync(self._out.fileno())
        self._out.close()
        placed = place_without_replacing(self._tmp, self.path)
        self._tmp = None
        self.path = placed
        self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name


class NoProfile:
    """Stands in for the profile when no file can be made for it: the windows are measured and counted, none is kept."""

    shown = None

    def __init__(self):
        self.rows = 0

    def add(self, row, evidence=None):
        self.rows += 1
        return row

    def finish(self, receipt):
        pass


def fail(message, **extra):
    print_answer(release({"error": message, "status": "failed",
                          "status_basis": "the tool stopped with an error (see error); it produced no %s" % WORK, **extra}))
    raise SystemExit(1)


def describe(exc):
    """An error without the path it names: type, errno name and the system's own words (never the text of an exception that has none:
    it can name the place of the output)."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    words = getattr(exc, "strerror", None) or ("no free name for a result file" if str(exc).startswith("no free name") else "no system message")
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", words)


def where_it_failed(exc):
    """The line of this tool an unexpected exception was raised on: enough to find it, and no text of the exception (which can name a path)."""
    tb = exc.__traceback__
    line = None
    while tb is not None:
        if tb.tb_frame.f_code.co_filename == __file__:
            line = tb.tb_lineno
        tb = tb.tb_next
    return "line %s of the tool" % line if line else "an unknown line"


PROGRESS = {}


def last_word(signum):
    """What the tool says when a stop signal ends it: one JSON answer, never a clean-looking partial one."""
    print(json.dumps({"error": "stopped by signal %d before the %s was complete" % (signum, WORK), "status": "failed",
                      "status_basis": "the tool was stopped by signal %d; the profile and the tables it was still writing were removed, "
                                      "so nothing it had read is an answer" % signum,
                      "interrupted": True, "signal": signum, "coverage_so_far": PROGRESS.get("coverage")}), flush=True)


def drop_temporary_files():
    """Remove the files a page or the profile was still writing (a failure, not a stop signal, ended the tool)."""
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def pread_full(fd, length, offset):
    chunks, got = [], 0
    while got < length:
        data = os.pread(fd, length - got, offset + got)
        if not data:
            break
        chunks.append(data)
        got += len(data)
    return b"".join(chunks)


def evidence_of(name):
    """The name of a file when it is printed as it is on purpose (a file that is not named like a note), else None."""
    return None if NAME_HINTS.search(name) else name


def display(path):
    """The path as it may be printed. Every directory above the file is judged by shown(); the file's own name is withheld when it
    is named like a note and holds an identifier-shaped token, and is otherwise printed as it is: a file that is not named like a
    note is an encrypted file or an ordinary one, and its name is evidence."""
    return shown(path, keep_last=not NAME_HINTS.search(os.path.basename(path)))


def kind_of(mode):
    for test, text in ((stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
                       (stat.S_ISCHR, "a character device"), (stat.S_ISDIR, "a directory")):
        if test(mode):
            return text
    return "a special file"


def open_regular(path):
    """A descriptor for a regular file, opened without following a link and without blocking (a named pipe opens at once and is
    refused by its fstat); its fstat comes with it."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file (%s)" % kind_of(st.st_mode))
    except OSError:
        os.close(fd)
        raise
    return fd, st


def why_not_opened(exc):
    """(reason code, description) for a file that could not be opened: no text of the exception, which can name a path."""
    if isinstance(exc, ValueError):
        return "path_invalid", "ValueError: the path cannot be used as a file name (a NUL byte or a character the system cannot encode)"
    if getattr(exc, "errno", None) == errno.ELOOP:
        return "link_not_followed", describe(exc)
    if getattr(exc, "errno", None) == errno.EINVAL and "not a regular file" in str(getattr(exc, "strerror", "")):
        return "not_a_regular_file", describe(exc)
    return "read_failed", describe(exc)


class Budget:
    def __init__(self, total):
        self.total = total
        self.read = 0

    def allows(self, n):
        return self.read + n <= self.total

    def spend(self, n):
        self.read += n



import calendar
import time as _time


class HostEntry:
    def __init__(self, name):
        self.name = name
        self.path = name


def judged_host(entry):
    return True


def normal_time(value):
    """An ISO 8601 UTC time ending in Z, kept to microseconds, or None."""
    if not isinstance(value, str):
        return None
    m = TIME.match(value)
    if not m:
        return None
    text = m.group(1) + "." + ((m.group(2) or "") + "000000")[:6] + "Z"
    return text if seconds_of(text) is not None else None      # 2026-02-30 is not a time


def seconds_of(iso):
    """Seconds since 1970 of a normal_time string, or None when the year is outside what the clock holds."""
    try:
        return calendar.timegm(_time.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S")) + int(iso[20:26]) / 1e6
    except (ValueError, OverflowError):
        return None


def new_summary():
    return {"counts": collections.Counter(), "times": {}, "comparisons": 0, "intact": 0, "interval": None, "span": None}


class Ctx:
    def __init__(self, only, clocks):
        self.hosts = {}
        self.names = {}
        self.only = only
        self.clocks = clocks
        self.serial = 0
        self.summary = {}
        self.pending = []          # (hid, pid, seconds, object, recogniser, observation reference)
        self.exits = {}            # (host, pid) -> [records with a time, sorted; records with none; the first recorded]
        self.exit_n = 0
        self.exit_seq = 0
        self.dropped = collections.Counter()
        self.filtered = 0
        self.page = None

    def host(self, name):
        found = self.hosts.get(name)
        if found is None:
            if len(self.hosts) >= MAX_HOSTS:
                fail("more than %d hosts: split the report" % MAX_HOSTS)
            found = len(self.hosts) + 1
            self.hosts[name] = found
            self.names[found] = name
        return found

    def add_exit(self, hid, pid, secs, status, source):
        """Keep a process-exit record where the first one at or after a start is found by bisection: a (host, pid) with many records is not walked."""
        self.exit_seq += 1
        held = self.exits.get((hid, pid))
        if held is None:
            held = self.exits[(hid, pid)] = [[], [], None]
        if secs is None:
            held[1].append((self.exit_seq, status, source))
        else:
            bisect.insort(held[0], (secs, self.exit_seq, status, source))
        if held[2] is None:
            held[2] = (secs, status, source)

    def first_exit(self, hid, pid, secs):
        """(time, status, source) of the earliest exit record of the process at or after `secs` by its recorded time; one with no recorded time
        only when none has a time at or after; with no start time, the first record read."""
        held = self.exits.get((hid, pid))
        if held is None:
            return None
        timed, untimed, first = held
        if secs is None:
            return first
        i = bisect.bisect_left(timed, (secs,))
        if i < len(timed):
            return (timed[i][0], timed[i][2], timed[i][3])
        if untimed:
            return (None, untimed[0][1], untimed[0][2])
        return None

    def uncertainty(self, hid):
        clock = self.clocks.get(self.names.get(hid))
        if clock is None:
            return {"clock_offset_seconds": None, "uncertainty_seconds": None,
                    "basis": "the host's clock was not compared with a reference: the time is as recorded in the source"}
        return {"clock_offset_seconds": clock[0], "uncertainty_seconds": clock[1],
                "basis": "offset and uncertainty as the caller gave them for this host (host_clocks); the recorded time is not corrected in the row"}

    def observe(self, hid, cls, obj, time_iso, actor, source, detail=None, interval=None):
        if self.only is not None and obj not in self.only:
            self.filtered += 1
            return None
        self.serial += 1
        row = {"observation_id": "O%d" % self.serial, "class": cls, "host_id": "H%d" % hid, "host": shown(self.names[hid], count=False), "object": obj,
               "time_utc": time_iso, "time_uncertainty": self.uncertainty(hid),
               "actor_as_recorded": shown(actor, count=False) if isinstance(actor, str) and actor else None,
               "source": source, "alternative_explanations": ALTERNATIVES[cls], **(detail or {})}
        if interval:
            row["interval_utc"] = {"from": interval[0], "to": interval[1]}
        key = (hid, obj)
        s = self.summary.get(key)
        if s is None:
            s = self.summary[key] = new_summary()
        s["counts"][cls] += 1
        secs = seconds_of(time_iso) if time_iso else None
        if secs is not None:
            lo, hi = s["times"].get(cls, (secs, secs))
            s["times"][cls] = (min(lo, secs), max(hi, secs))
        if interval:
            a, b = seconds_of(interval[0]), seconds_of(interval[1])
            if a is not None and b is not None:
                s["interval"] = (a, b) if s["interval"] is None else (min(s["interval"][0], a), max(s["interval"][1], b))
        self.page.add(row)
        return row


def read_doc(path):
    fd, st = open_regular(path)
    try:
        data = pread_full(fd, min(st.st_size, MAX_DOC) + 1, 0)
    finally:
        os.close(fd)
    if len(data) > MAX_DOC:
        return None, "larger than %d bytes" % MAX_DOC
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError):
        return None, "not JSON"
    if not isinstance(doc, dict):
        return None, "not a JSON object"
    return doc, None


def check_parser(doc, kind):
    parser = doc.get("parser")
    if parser not in ACCEPTED[kind]:
        fail("an input was written by a parser this tool does not read: %r (for %s it reads %s); an unknown version is refused, not guessed at"
             % (parser[:80] if isinstance(parser, str) else parser, kind, ", ".join(ACCEPTED[kind])))
    return parser


def text_of(data, name):
    value = data.get(name) if isinstance(data, dict) else None
    if isinstance(value, list) and value:
        value = value[0]
    return value if isinstance(value, str) else None


def basename_lower(path):
    return re.split(r"[\\/]", path)[-1].lower() if isinstance(path, str) else ""


def pid_of(text):
    if not isinstance(text, str):
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


TOOL_IMAGES = {r[2] for r in RECOGNISERS if r[2]}
CHANNELS = {"security": "Security", "microsoft-windows-sysmon/operational": "Microsoft-Windows-Sysmon/Operational",
            "microsoft-windows-powershell/operational": "Microsoft-Windows-PowerShell/Operational"}


def handle_event(ctx, hid, row):
    """One event row of an evtx_query answer. Returns False when the row is not one this tool can read."""
    if not isinstance(row, dict):
        return False
    try:
        eid = int(row.get("event_id"))
    except (TypeError, ValueError):
        return False
    channel = row.get("channel")
    key = (channel.lower() if isinstance(channel, str) else "", eid)
    data = row.get("data") if isinstance(row.get("data"), dict) else {}
    when = normal_time(row.get("record_time_utc")) or normal_time(row.get("timestamp"))
    record = row.get("record_id")
    source = {"kind": "event", "channel": CHANNELS.get(key[0], "other"), "event_id": eid, "record_id": record if isinstance(record, int) and not isinstance(record, bool) else None}
    if key in CREATE:
        image_f, cmd_f, user_f, pid_f = CREATE[key]
        image, cmd, user, pid = text_of(data, image_f), text_of(data, cmd_f), text_of(data, user_f), pid_of(text_of(data, pid_f))
        if cmd is not None:
            if len(cmd) > MAX_TEXT:
                ctx.dropped["command_text_cut"] += 1
                cmd = cmd[:MAX_TEXT]
            for rid, obj, program, pattern in RECOGNISERS:
                if pattern.search(cmd):
                    ctx.observe(hid, "command_seen", obj, when, user, {**source, "field": cmd_f}, {"recogniser": rid})
                    if program is not None and basename_lower(image) == program:
                        o = ctx.observe(hid, "action_attempted", obj, when, user, {**source, "field": image_f}, {"recogniser": rid, "program": program})
                        if o is not None and pid is not None:
                            if len(ctx.pending) < TRACK_CAP:
                                ctx.pending.append((hid, pid, seconds_of(when) if when else None, obj, rid, o["observation_id"], user, when, program))
                            else:
                                ctx.dropped["pending_attempts"] += 1
    elif key in SCRIPT:
        text_f, user_f = SCRIPT[key]
        text = text_of(data, text_f)
        if text is not None:
            if len(text) > MAX_TEXT:
                ctx.dropped["command_text_cut"] += 1
                text = text[:MAX_TEXT]
            for rid, obj, program, pattern in RECOGNISERS:
                if pattern.search(text):
                    ctx.observe(hid, "command_seen", obj, when, text_of(data, user_f), {**source, "field": text_f}, {"recogniser": rid})
    elif key in EXIT:
        name_f, user_f, pid_f, status_f = EXIT[key]
        pid, status = pid_of(text_of(data, pid_f)), text_of(data, status_f)
        if pid is not None and status is not None and basename_lower(text_of(data, name_f)) in TOOL_IMAGES:
            if ctx.exit_n < TRACK_CAP:
                ctx.exit_n += 1
                ctx.add_exit(hid, pid, seconds_of(when) if when else None, status[:20], source)
            else:
                ctx.dropped["exit_records"] += 1
    return True


def read_rows(handler, doc, key, rows_file, facts, cut_note):
    """The rows of one answer: those of a rows file when one is given (streamed, under the clock), else the rows inline under `key`."""
    inline = doc.get(key)
    if rows_file is None:
        if not isinstance(inline, list):
            facts["problems"].append("the answer holds no inline %s and no rows file was given" % key)
            return
        for row in inline:
            if out_of_time():
                facts["stopped_by_clock"] = True
                return
            facts["rows"] += 1
            if not handler(row):
                facts["skipped"] += 1
        if cut_note(doc, inline):
            facts["problems"].append("the answer shows only part of its %s inline; give the file that holds the whole table to read all" % key)
        return
    stream_file(handler, rows_file, facts)


def stream_file(handler, path, facts):
    fd, st = open_regular(path)
    try:
        with os.fdopen(os.dup(fd), "rb") as handle:
            readline = handle.readline
            while True:
                if out_of_time():
                    facts["stopped_by_clock"] = True
                    return
                line = readline(MAX_LINE + 1)
                if not line:
                    return
                facts["rows"] += 1
                if len(line) > MAX_LINE:
                    facts["skipped"] += 1
                    while line and not line.endswith(b"\n"):
                        if out_of_time():
                            facts["stopped_by_clock"] = True
                            return
                        line = readline(MAX_LINE + 1)
                    continue
                try:
                    row = json.loads(line)
                except (ValueError, RecursionError):
                    facts["skipped"] += 1
                    continue
                if not handler(row):
                    facts["skipped"] += 1
    finally:
        os.close(fd)


def own_table_cut(doc, key, inline):
    """Whether the answer shows only part of its table `key`: the table's own page record says so (the answer's top-level `truncated` is true
    when any of its tables is cut, and a complete table beside a cut one is complete)."""
    pages = doc.get("pages")
    page = pages.get(key) if isinstance(pages, dict) else None
    if isinstance(page, dict) and isinstance(page.get("truncated"), bool):
        return page["truncated"]
    return bool(doc.get("truncated"))


def read_events(ctx, hid, doc, result_file, facts):
    read_rows(lambda row: handle_event(ctx, hid, row), doc, "events", result_file, facts,
              lambda d, inline: bool(d.get("truncated")) or (isinstance(d.get("count"), int) and d["count"] > len(inline)))


def row_time(row, *names):
    for n in names:
        t = normal_time(row.get(n))
        if t:
            return t
    return None


def handle_audit(ctx, hid, row):
    if not isinstance(row, dict):
        return False
    cat, result = row.get("category"), row.get("result")
    result = result if result in AUDIT_RESULTS else "unknown"
    when = row_time(row, "time_utc")
    source = {"kind": "backup_audit_normalise", "seq": row.get("seq") if isinstance(row.get("seq"), int) else None, "source_id": row.get("source_id") if isinstance(row.get("source_id"), str) and len(row["source_id"]) < 40 else None}
    actor = row.get("actor") if isinstance(row.get("actor"), str) else None
    if cat in AUDIT_ACTIONS:
        obj = AUDIT_ACTIONS[cat]
        ctx.observe(hid, "action_attempted", obj, when, actor, {**source, "field": "category"}, {"category": cat})
        ctx.observe(hid, "reported_outcome", obj, when, actor, {**source, "field": "result"}, {"category": cat, "result": result})
    elif cat in AUDIT_OUTCOMES:
        ctx.observe(hid, "reported_outcome", AUDIT_OUTCOMES[cat], when, actor, {**source, "field": "result"}, {"category": cat, "result": result})
    return True


def handle_chain(ctx, hid, row):
    if not isinstance(row, dict) or not isinstance(row.get("status"), str):
        return False
    status = row["status"]
    s = ctx.summary.setdefault((hid, "backups"), new_summary())
    if status == "complete":
        s["intact"] += 1
    elif status in CHAIN_LOSS:
        ctx.observe(hid, "recovery_loss_verified", "backups", None, None, {"kind": "snapshot_chain_check", "field": "status"},
                    {"chain_status": status, "chain_length": row.get("chain_length") if isinstance(row.get("chain_length"), int) else None,
                     "recorded": "what the chain check found in the files it was given: a base or a dependent file named and not in the set"})
    else:
        ctx.dropped["chains_not_followable"] += 1
    return True


def handle_history(ctx, hid, row, facts):
    if not isinstance(row, dict):
        return False
    parser = row.get("parser")
    if parser not in ACCEPTED["shell_histories"]:
        fail("an input was written by a parser this tool does not read: %r (for shell_histories it reads %s); an unknown version is refused, not guessed at"
             % (parser[:80] if isinstance(parser, str) else parser, ", ".join(ACCEPTED["shell_histories"])))
    command = row.get("command")
    if not isinstance(command, str):
        facts["no_command"] += 1
        return True
    command = command[:MAX_TEXT]
    when = row_time(row, "time")
    for rid, obj, pattern in LINUX_RECOGNISERS:
        if pattern.search(command):
            ctx.observe(hid, "command_seen", obj, when, row.get("user") if isinstance(row.get("user"), str) else None,
                        {"kind": "shell_history", "id": row.get("id") if isinstance(row.get("id"), str) and len(row["id"]) < 20 else None, "field": "command"},
                        {"recogniser": rid, "alternatives_added": LINUX_ALTERNATIVES})
    return True


def handle_cloud(ctx, hid, row):
    if not isinstance(row, dict):
        return False
    name = row.get("event")
    if name not in CLOUD_EVENTS or row.get("source") != CLOUD_EVENTS[name][0]:
        return True
    obj = CLOUD_EVENTS[name][1]
    when = row_time(row, "time_utc")
    actor = row.get("user_name") if isinstance(row.get("user_name"), str) else (row.get("arn") if isinstance(row.get("arn"), str) else None)
    source = {"kind": "cloudtrail_parse", "event": name, "event_source": row.get("source"), "field": "event"}
    ctx.observe(hid, "action_attempted", obj, when, actor, source, {"api_call": name})
    ctx.observe(hid, "reported_outcome", obj, when, actor, {**source, "field": "outcome"},
                {"api_call": name, "outcome_recorded": "no_error" if row.get("outcome") == "no_error_recorded" else "error_or_failure"})
    return True


def read_specs(args, kind):
    value = args.get(kind)
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_INPUTS:
        fail("%s must be a list of at most %d objects" % (kind, MAX_INPUTS))
    allowed = {"events": {"host", "file", "result_file"}, "vss_inventories": {"host", "file", "collected_utc", "volume"}, "service_keys": {"host", "file", "collected_utc"},
               "backup_audits": {"host", "file", "rows_file"}, "chain_checks": {"host", "file", "rows_file"}, "shell_histories": {"host", "file", "answer"},
               "cloud_trails": {"host", "file", "rows_file"}}[kind]
    out = []
    for item in value:
        if not isinstance(item, dict) or set(item) - allowed:
            fail("each entry of %s is an object with the keys %s" % (kind, ", ".join(sorted(allowed))))
        host, path = item.get("host"), item.get("file")
        if not isinstance(host, str) or not host or len(host) > 255 or not isinstance(path, str) or not path:
            fail("each entry of %s needs a host (a name) and a file (a path)" % kind)
        extra = {}
        if kind in ("shell_histories",):
            ans = item.get("answer")
            if ans is not None and (not isinstance(ans, str) or not ans):
                fail("answer is a path")
            extra["answer"] = ans
        elif kind in ("backup_audits", "chain_checks", "cloud_trails"):
            rf = item.get("rows_file")
            if rf is not None and (not isinstance(rf, str) or not rf):
                fail("rows_file is a path")
            extra["rows_file"] = rf
        elif kind != "events":
            collected = normal_time(item.get("collected_utc"))
            if collected is None or seconds_of(collected) is None:
                fail("each entry of %s needs collected_utc, an ISO 8601 UTC time ending in Z: the order of two inventories is the evidence of a change" % kind)
            extra["collected"] = collected
            vol = item.get("volume", "")
            if not isinstance(vol, str) or len(vol) > 100:
                fail("volume is a string of at most 100 characters")
            extra["volume"] = vol
        else:
            rf = item.get("result_file")
            if rf is not None and (not isinstance(rf, str) or not rf):
                fail("result_file is a path")
            extra["result_file"] = rf
        out.append((host, path, extra))
    return out


KNOWN_PARAMS = set(KINDS) | {"verifications", "host_clocks", "only_objects", "limit", "max_seconds"}


def int_param(args, key, default, low, high=None, why=""):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        fail("%s must be an integer" % key)
    if value < low:
        fail("%s must be at least %d" % (key, low))
    if high is not None and value > high:
        fail("%s must be at most %d%s" % (key, high, why))
    return value


FLAG_TEXT = {
    "command_seen_without_inventory_change": "a destructive command was seen, and two complete inventories of this object show no change: the command is not shown to have taken effect",
    "command_seen_nothing_to_compare": "a destructive command was seen, and there are not two complete inventories of this object to compare: its effect is not observed",
    "inventory_change_without_command": "an inventory change was observed with no command or attempt in the logs read: the change has another explanation or the log was not read",
    "command_seen_after_the_last_inventory": "a destructive command was seen with a recorded time (corrected by the host's clock offset, if given) later than the last of the complete inventories of this object: they agree, and say nothing about the command",
    "command_seen_before_the_first_inventory": "a destructive command was seen with a recorded time (corrected by the host's clock offset, if given) earlier than the first of the complete inventories of this object: they agree, and say nothing about the command",
    "reported_exit_without_verified_loss": "a source reported an outcome (a process's exit status, a product's or provider's result, the end of a backup job), and no loss was verified: a reported outcome is not a loss",
    "verified_loss_without_command": "a loss was verified with no command or attempt in the logs read: how it came about is not shown",
    "command_after_the_change_interval": "the recorded time of the command (corrected by the host's clock offset, if given) is later than the interval in which the change was observed, beyond the clock uncertainty: the clocks disagree with the order the evidence needs",
    "command_within_the_change_interval": "the recorded time of the command falls inside the interval in which the change was observed, or within the clock uncertainty of it: the clocks do not settle the order",
}


def match_exits(ctx):
    """Give each attempted process its exit record (bisection, a clock before every attempt). Returns (attempts with no exit record, attempts
    left unmatched because the time ran out)."""
    no_exit = 0
    pending = ctx.pending
    for n, (hid, pid, secs, obj, rid, ref, user, when, program) in enumerate(pending):
        if late():
            return no_exit, len(pending) - n
        match = ctx.first_exit(hid, pid, secs)
        if match is None:
            no_exit += 1
            continue
        status_zero = match[1].lower() in ("0x0", "0")
        ctx.observe(hid, "reported_outcome", obj, when, user, match[2], {"recogniser": rid, "program": program, "attempt_observation": ref,
                                                                          "exit_status_class": "zero" if status_zero else "nonzero",
                                                                          "matched_by": "host and process id, the earliest exit record at or after the start by its recorded time (one with no time only when none has one)"})
    return no_exit, 0


def main():
    install_signal_handlers(last_word)
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError):
        fail("arguments are not valid JSON")
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    limit = int_param(args, "limit", DEFAULT_LIMIT, 1, 1000000000)
    max_seconds = int_param(args, "max_seconds", DEFAULT_SECONDS, 1, MAX_SECONDS, " (the tool's own clock; the manifest's timeout is 900)")
    specs = {kind: read_specs(args, kind) for kind in KINDS}
    only = args.get("only_objects")
    if only is not None:
        if not isinstance(only, list) or len(only) > 100 or not all(isinstance(o, str) and 0 < len(o) <= 64 for o in only):
            fail("only_objects is a list of at most 100 object names")
        only = set(only)
    clocks = {}
    hc = args.get("host_clocks", {})
    if not isinstance(hc, dict) or len(hc) > MAX_HOSTS:
        fail("host_clocks is an object: host name to {offset_seconds, uncertainty_seconds}")
    for name, spec in hc.items():
        ok = isinstance(spec, dict) and set(spec) <= {"offset_seconds", "uncertainty_seconds"}
        if ok:
            off, unc = spec.get("offset_seconds", 0), spec.get("uncertainty_seconds", 0)
            ok = all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and abs(v) <= CLOCK_MAX for v in (off, unc)) and unc >= 0
        if not ok:
            fail("each host clock is {offset_seconds, uncertainty_seconds}: finite numbers of at most %d seconds, the uncertainty not negative" % CLOCK_MAX)
        clocks[name] = (off, unc)
    verifications = args.get("verifications", [])
    if not isinstance(verifications, list) or len(verifications) > MAX_VERIFICATIONS:
        fail("verifications is a list of at most %d records" % MAX_VERIFICATIONS)
    clean_verifications = []
    for v in verifications:
        if (not isinstance(v, dict) or set(v) - {"host", "object", "result", "verified_utc", "method", "source"}
                or not isinstance(v.get("host"), str) or not v.get("host") or len(v["host"]) > 255
                or v.get("object") not in OBJECTS
                or v.get("result") not in ("lost", "partial", "intact") or normal_time(v.get("verified_utc")) is None
                or not all(isinstance(v.get(k, ""), str) and len(v.get(k, "")) <= 200 for k in ("method", "source"))):
            fail("each verification is {host, object (one of the eight objects), result (lost, partial or intact), verified_utc (ISO 8601 UTC, Z), method, source}")
        clean_verifications.append(v)
    if not any(specs.values()) and not clean_verifications:
        fail("name what to correlate: events, vss_inventories, service_keys or verifications")
    unknown = sorted(k for k in args if k not in KNOWN_PARAMS)
    set_deadline(max_seconds)

    ctx = Ctx(only, clocks)
    for name in list(clocks) + [v["host"] for v in clean_verifications]:
        ctx.host(name)
    ctx.page = NoReplacePage(TOOL, ["observations"], limit)
    problems = collections.Counter()
    stopped = {}
    inputs_read = collections.Counter()
    unchecked = collections.Counter()    # inputs whose producer's own status the tool could not see
    inventories = collections.defaultdict(list)
    services = collections.defaultdict(list)

    for kind in KINDS:
        for host, path, extra in specs[kind]:
            if out_of_time():
                stopped["inputs_not_read"] = stopped.get("inputs_not_read", 0) + 1
                continue
            hid = ctx.host(host)
            facts = {"rows": 0, "skipped": 0, "problems": [], "stopped_by_clock": False, "no_command": 0}
            try:
                if kind == "shell_histories":
                    if extra["answer"] is None:
                        unchecked["shell_histories"] += 1
                    else:
                        adoc, awhy = read_doc(extra["answer"])
                        if adoc is None:
                            problems["input_unreadable:shell_histories_answer"] += 1
                        else:
                            check_parser(adoc, kind)
                            if adoc.get("status") != "complete":
                                problems["input_status_not_complete:shell_histories"] += 1
                    stream_file(lambda row: handle_history(ctx, hid, row, facts), path, facts)
                    if facts["no_command"]:
                        problems["history_rows_without_command"] += facts["no_command"]
                    inputs_read[kind] += 1
                    if facts["skipped"]:
                        problems["rows_skipped"] += facts["skipped"]
                    if facts["stopped_by_clock"]:
                        stopped["input_cut_by_clock"] = stopped.get("input_cut_by_clock", 0) + 1
                    continue
                doc, why = read_doc(path)
                if doc is None:
                    problems["input_unreadable:" + kind] += 1
                    continue
                check_parser(doc, kind)
                status = doc.get("status")
                if status != "complete":
                    problems["input_status_not_complete:" + kind] += 1
                if kind == "backup_audits":
                    read_rows(lambda row: handle_audit(ctx, hid, row), doc, "events", extra["rows_file"], facts,
                              lambda d, inline: own_table_cut(d, "events", inline))
                elif kind == "chain_checks":
                    read_rows(lambda row: handle_chain(ctx, hid, row), doc, "chains", extra["rows_file"], facts,
                              lambda d, inline: own_table_cut(d, "chains", inline))
                elif kind == "cloud_trails":
                    read_rows(lambda row: handle_cloud(ctx, hid, row), doc, "records", extra["rows_file"], facts,
                              lambda d, inline: isinstance(d.get("record_count"), int) and d["record_count"] > len(inline))
                elif kind == "events":
                    read_events(ctx, hid, doc, extra["result_file"], facts)
                elif kind == "vss_inventories":
                    stores = doc.get("stores")
                    if not isinstance(stores, list):
                        problems["input_unreadable:" + kind] += 1
                        continue
                    ids = set()
                    for s in stores:
                        if isinstance(s, dict):
                            ident = s.get("identifier")
                            ids.add(ident if isinstance(ident, str) else "store %s %s" % (s.get("store"), s.get("creation_time")))
                    inventories[(hid, extra["volume"])].append((seconds_of(extra["collected"]), extra["collected"], ids, status == "complete"))
                else:
                    vals = doc.get("values") if isinstance(doc.get("values"), dict) else {}
                    start = vals.get("Start")
                    key = doc.get("key") if isinstance(doc.get("key"), str) else ""
                    name = re.split(r"[\\/]", key)[-1] or "service"
                    services[(hid, name)].append((seconds_of(extra["collected"]), extra["collected"], start if isinstance(start, int) and not isinstance(start, bool) else None, status == "complete"))
            except (OSError, ValueError) as exc:
                code, text = why_not_opened(exc)
                problems["input_not_read:" + code] += 1
                continue
            inputs_read[kind] += 1
            if facts["skipped"]:
                problems["rows_skipped"] += facts["skipped"]
            for p in facts["problems"]:
                problems["events_incomplete"] += 1
            if facts["stopped_by_clock"]:
                stopped["input_cut_by_clock"] = stopped.get("input_cut_by_clock", 0) + 1

    # reported outcome: the exit record of each attempted process, matched by host and process id, the first at or after the start
    no_exit, matching_left = match_exits(ctx)
    if matching_left:
        stopped["attempts_not_matched"] = matching_left

    # inventory change: consecutive complete inventories of one host and volume
    for (hid, volume), items in inventories.items():
        items.sort(key=lambda t: (t[0] if t[0] is not None else 0, t[1]))
        for a, b in zip(items, items[1:]):
            if late():
                stopped["comparisons_not_made"] = stopped.get("comparisons_not_made", 0) + 1
                continue
            if not (a[3] and b[3]):
                problems["inventory_not_complete"] += 1
                continue
            s = ctx.summary.setdefault((hid, "shadow_copies"), new_summary())
            s["comparisons"] += 1
            s["span"] = (a[0], b[0]) if s["span"] is None else (min(s["span"][0], a[0]), max(s["span"][1], b[0]))
            removed, added = len(a[2] - b[2]), len(b[2] - a[2])
            if removed or added:
                ctx.observe(hid, "inventory_change_observed", "shadow_copies", None, None, {"kind": "vss_stores inventories", "volume": shown(volume, count=False) if volume else None},
                            {"removed_stores": removed, "added_stores": added, "stores_before": len(a[2]), "stores_after": len(b[2])}, interval=(a[1], b[1]))
    for (hid, name), items in services.items():
        items.sort(key=lambda t: (t[0] if t[0] is not None else 0, t[1]))
        for a, b in zip(items, items[1:]):
            if late():
                stopped["comparisons_not_made"] = stopped.get("comparisons_not_made", 0) + 1
                continue
            if not (a[3] and b[3]):
                problems["inventory_not_complete"] += 1
                continue
            s = ctx.summary.setdefault((hid, SERVICE_OBJECT), new_summary())
            s["comparisons"] += 1
            s["span"] = (a[0], b[0]) if s["span"] is None else (min(s["span"][0], a[0]), max(s["span"][1], b[0]))
            if a[2] != b[2]:
                ctx.observe(hid, "inventory_change_observed", SERVICE_OBJECT, None, None, {"kind": "regkv service key", "service": shown(name, count=False)},
                            {"start_before": a[2], "start_after": b[2], "disabled_after": b[2] == 4}, interval=(a[1], b[1]))

    for v in clean_verifications:
        hid = ctx.host(v["host"])
        if v["result"] == "intact":
            s = ctx.summary.setdefault((hid, v["object"]), new_summary())
            s["intact"] += 1
            continue
        ctx.observe(hid, "recovery_loss_verified", v["object"], normal_time(v["verified_utc"]), None,
                    {"kind": "caller verification", "method": scrub(v.get("method", "")), "source": scrub(v.get("source", ""))},
                    {"result": v["result"], "recorded": "as the caller gave it; this tool did not verify it"})

    # the summary per host and object, ordered as an answer prints names
    entries = print_order([HostEntry(n) for n in ctx.hosts], judged_host)
    rank = {e.name: i for i, e in enumerate(entries)}
    summary_page = NoReplacePage(TOOL, ["summary"], limit)
    flag_counts = collections.Counter()
    for (hid, obj), s in sorted(ctx.summary.items(), key=lambda kv: (rank[ctx.names[kv[0][0]]], kv[0][1])):
        if late():
            stopped["summary_rows_not_written"] = stopped.get("summary_rows_not_written", 0) + 1
            continue
        c = s["counts"]
        flags = []
        acted = c["command_seen"] or c["action_attempted"]
        if c["command_seen"] and s["comparisons"] and not c["inventory_change_observed"]:
            # an inventory that agrees says nothing about a command it does not cover: the order of the command and the inventories decides
            clock = ctx.clocks.get(ctx.names[hid], (0, 0))
            seen = s["times"].get("command_seen")
            if seen and s["span"] and seen[0] - clock[0] - clock[1] > s["span"][1]:
                flags.append("command_seen_after_the_last_inventory")
            elif seen and s["span"] and seen[1] - clock[0] + clock[1] < s["span"][0]:
                flags.append("command_seen_before_the_first_inventory")
            else:
                flags.append("command_seen_without_inventory_change")
        if c["command_seen"] and not s["comparisons"]:
            flags.append("command_seen_nothing_to_compare")
        if c["inventory_change_observed"] and not acted:
            flags.append("inventory_change_without_command")
        if c["reported_outcome"] and not c["recovery_loss_verified"]:
            flags.append("reported_exit_without_verified_loss")
        if c["recovery_loss_verified"] and not acted:
            flags.append("verified_loss_without_command")
        t = s["times"].get("command_seen") or s["times"].get("action_attempted")
        if t and s["interval"]:
            clock = ctx.clocks.get(ctx.names[hid], (0, 0))
            first = t[0] - clock[0]
            if first - clock[1] > s["interval"][1]:
                flags.append("command_after_the_change_interval")
            elif first + clock[1] >= s["interval"][0] and first - clock[1] <= s["interval"][1]:
                flags.append("command_within_the_change_interval")
        for f in flags:
            flag_counts[f] += 1
        summary_page.add({"host_id": "H%d" % hid, "host": shown(ctx.names[hid], count=False), "object": obj,
                          "observations": {cls: c[cls] for cls in CLASSES}, "inventory_comparisons": s["comparisons"], "verified_intact": s["intact"],
                          "flags": [{"flag": f, "meaning": FLAG_TEXT[f]} for f in flags],
                          "note": "the five classes are kept apart: the counts are of observations of each class, and none of them is derived from another"})

    pages = {"observations": finish_page(ctx.page), "summary": finish_page(summary_page)}
    OWN_NAMES.update(p["all_results"] for p in pages.values() if p.get("all_results"))
    reasons = []
    for code, n in sorted(problems.items()):
        reasons.append("%s: %d" % (code, n))
    if ctx.dropped.get("chains_not_followable"):
        reasons.append("%d chains could not be followed (a cycle, an unreadable parent, a mismatch of identity): they are neither a loss nor intact" % ctx.dropped.pop("chains_not_followable"))
    if no_exit:
        reasons.append("%d attempts have no process-exit record in the logs read: their outcome is not reported" % no_exit)
    for code, n in sorted(ctx.dropped.items()):
        reasons.append("%s: %d held back by a bound of the tool" % (code, n))
    if stopped.get("inputs_not_read"):
        reasons.append("the time limit (max_seconds %d) was reached: %d inputs were not read" % (max_seconds, stopped["inputs_not_read"]))
    if stopped.get("attempts_not_matched"):
        reasons.append("the time limit (max_seconds %d, and %d seconds more for the phases after the reading) was reached while exit records were being matched: %d attempts were not matched, so their outcome is neither reported nor counted as missing" % (max_seconds, POST_GRACE, stopped["attempts_not_matched"]))
    if stopped.get("comparisons_not_made"):
        reasons.append("the time limit (max_seconds %d, and %d seconds more for the phases after the reading) was reached while inventories were being compared: %d comparisons were not made" % (max_seconds, POST_GRACE, stopped["comparisons_not_made"]))
    if stopped.get("summary_rows_not_written"):
        reasons.append("the time limit (max_seconds %d, and %d seconds more for the phases after the reading) was reached while the summary was written: %d host and object rows of it are not written" % (max_seconds, POST_GRACE, stopped["summary_rows_not_written"]))
    if stopped.get("input_cut_by_clock"):
        reasons.append("the time limit (max_seconds %d) was reached while %d inputs were being read: the rows after the last one read are not counted" % (max_seconds, stopped["input_cut_by_clock"]))
    if not ctx.serial and not any(inputs_read.values()):
        reasons.append("nothing was read")
    if BOUNDARY["replaced"]:
        reasons.append("%d strings held an identifier-shaped text that the first rule missed and were replaced at the output (see boundary)" % BOUNDARY["replaced"])
    complete = "partial" if reasons else "complete"
    basis = "; ".join(reasons) if reasons else "every input was read to its end, every answer read says complete, and the time limit was not reached"
    if unchecked["shell_histories"]:
        basis += ("; %d shell_histories text files were given without their answer: a text file carries no status of its producer, so they were read to their end and "
                  "whether the producer read its sources to the end is not known" % unchecked["shell_histories"])
    answer = release({
        "parser": PARSER,
        "complete": complete,
        "status": complete,
        "status_basis": basis,
        "partial_reasons": reasons,
        "model": "Five classes of observation per host and object, kept apart: " + ", ".join(CLASSES) + ". A command that ran is not an action that took effect, "
                 "and an action that took effect is not a loss of the backups: only recovery_loss_verified, from a verification made apart from the logs, says "
                 "that a recovery path was lost. No event text is copied into the answer.",
        "observation_counts": {cls: sum(s["counts"][cls] for s in ctx.summary.values()) for cls in CLASSES},
        "flag_counts": dict(flag_counts),
        "inputs_read": dict(inputs_read),
        "inputs_whose_producer_status_is_unknown": dict(unchecked),
        "observations_left_out_by_only_objects": ctx.filtered,
        "time_limit": {"max_seconds": max_seconds, "reached": bool(stopped), **stopped},
        "summary": summary_page.page,
        "observations": ctx.page.page,
        "pages": pages,
        "truncated": any(p["truncated"] for p in pages.values()),
        "paths_withheld": WITHHELD_PATHS[0],
        **({"unrecognised_parameters": unknown} if unknown else {}),
    })
    print_answer(answer, indent=2)


if __name__ == "__main__":
    try:
        main()
    except SystemExit as exc:
        if exc.code not in (0, None):
            drop_temporary_files()
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        drop_temporary_files()
        detail = describe(exc) if isinstance(exc, OSError) else "%s at %s" % (type(exc).__name__, where_it_failed(exc))
        fail("unexpected failure: %s" % detail)
