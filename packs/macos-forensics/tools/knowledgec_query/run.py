#!/usr/bin/env python3
"""Read knowledgeC.db: the application and device-state records macOS keeps for its own features.

CoreDuet records what the machine was doing (Apple's features use it: it is not an
audit log) in one SQLite file per user and one for the system. Streams an examiner
meets:

    /app/inFocus        which application was in front, and for how long
    /app/usage          application use, with the bundle id
    /display/isBacklit  the screen on or off (the state is in ZVALUEINTEGER)
    /device/isLocked    locked or unlocked (the state is in ZVALUEINTEGER)
    /safari/history     browsing
    /app/webUsage       per-application web use, with a domain

Which streams exist, and what they carry, vary by build and by device. This tool
inventories every stream in the file and reads what it finds; it does not assume a
stream is there.

**Every time in the file is Apple absolute: seconds since 2001-01-01 UTC.** Read as
Unix time it lands in 1970; add the wrong constant and it lands somewhere plausible
and wrong. The conversion is +978307200 and is applied here, with the raw value kept
beside the converted one.

What one entry carries (parser knowledgec_query/4): the ZOBJECT row it came from
(`z_pk`, `source_table`), the typed values (`value_string`, `value_integer`,
`value_double`, `value_type_code`), the raw and converted start, end and creation
times, the UUID, every other non-null ZOBJECT column, and, joined on the row's own
foreign keys, every non-null column of its ZSTRUCTUREDMETADATA and ZSOURCE rows under
their own names. The joins are made from the schema the file has (PRAGMA table_info),
not from a fixed column list, and the answer says which tables joined and a
fingerprint of the three tables' columns.

The database is never opened where it lies unless it has no sidecars. A write-ahead
log (-wal) beside it holds committed rows the main file does not. A rollback journal
(-journal) holds the old page images of a transaction that did not commit: it holds no
rows the main file lacks, and opening a copy that has one rolls that transaction back,
which changes the copy and not the main file as acquired. With either sidecar the
database and its sidecars are copied into a private directory, SQLite works on the copy
(the frames applied are counted; a rollback is reported in `source_used.journal` and in
`problems`), and the copy is removed; the evidence directory is not written to (a
read-only open of a WAL database creates a -shm file beside it). With no sidecar the file
is opened read-only and immutable.

Values are bounded when they are read, not after. A statement never loads a TEXT cell (it
asks SQLite for `typeof()` only, which is answered from the record header): a TEXT cell is read
through a blob handle, its first bytes and its byte length, and a BLOB longer than 4096 bytes
is not read at all except its head, through a blob handle too, so one 300 MB cell costs a 16 KiB
read and not 300 MB of memory (on a Python without blob handles, before 3.11, a statement reads
a TEXT cell whole). A cut cell says `_truncated`, its whole length and where the whole is
(`_where`: table, column, rowid in the database as acquired); a BLOB's head is hexadecimal
(`_hex`), so that the boundary can read it. `export_oversize: true`, in a job run as secret
output, streams each whole value to a private file and names it.

The tool has a clock of its own (`max_seconds`, 80 by default): a progress handler aborts the
statement when it passes, the clock is read at every row, and the answer is partial with the
entries read (a prefix in start order, also whole in the file), and `resume` says where to go on.
Every string of an entry passes the boundary below; SIGTERM, SIGINT and SIGHUP end the read the
same way, with the staged copy of the database removed.
"""
import base64
import datetime
import hashlib
import heapq
import json
import math
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

PARSER = "knowledgec_query/4"
APPLE_EPOCH = 978307200
DEFAULT_MAX_STAGE = 2 << 30
VALUE_CAP = 4096
DEFAULT_INLINE_BYTES = 1 << 20
DEFAULT_MAX_EXPORT = 1 << 30
DEFAULT_MAX_SECONDS = 80.0            # the manifest allows 120 s: staging, the stream inventory, the clean-up and the answer come after this clock
MAX_SECONDS_LIMIT = 90.0
SEAL_STOP_SECONDS = 116.5             # no string is judged past this (the rest is withheld whole): the manifest allows 120, less the 3.5 seconds the block asks for
INVENTORY_SECONDS = 8.0               # the list of streams may take this long after the rows
STREAMS_LISTED_MAX = 2000             # the list of streams holds at most this many (the ones with the most entries); the rest are counted (streams_not_listed)
TABLES_LISTED_MAX = 1000              # the tables listed in schema (the three the tool reads are always among them); the rest are counted (tables_not_listed)
PROGRESS_STEPS = 100000               # sqlite virtual-machine steps between two looks at the clock inside a statement
TEXT_HANDLE = -1                      # the length slot of a TEXT cell: it is read through a blob handle, never loaded by a statement
HEAD_BYTES = 4 * VALUE_CAP + 4        # bytes that hold at least VALUE_CAP + 1 characters of UTF-8
HAVE_HANDLES = hasattr(sqlite3.Connection, "blobopen")
REOPEN_EVERY = 20000                  # blob handles opened on one connection before it is replaced (CPython keeps a weak reference to each one, for good)
SELECT_COLUMNS_MAX = 1900
STANDARD = {"Z_PK", "ZSTREAMNAME", "ZVALUESTRING", "ZVALUEINTEGER", "ZVALUEDOUBLE", "ZVALUETYPECODE", "ZSTARTDATE",
            "ZENDDATE", "ZCREATIONDATE", "ZSECONDSFROMGMT", "ZUUID"}


# BEGIN SHARED STOP
# The same text is in every macos-forensics tool (a macos-forensics test holds the copies equal). SIGTERM, SIGINT and SIGHUP end a tool the way its
# time limit does: the work in hand is closed, what was done is kept and named, ONE JSON answer says status partial and `interrupted` (the signal's
# name), and the exit code is 128 plus the signal number. The handler raises Interrupted (a BaseException, so no `except Exception` swallows it) from
# wherever the signal lands; a write that must be whole (a row of a result file, the answer) is made under held(), and the signal is delivered when
# it ends, and hold_signals() holds them for good once the answer is being written; a signal that arrives meanwhile is found by pending_stop_signal() before the
# answer is printed, and the answer says so. The first signal counts: later ones do nothing while the tool cleans up. STOP["hooks"] run first (a database connection's
# interrupt, the kill of the reader process this tool started and of its descendants: its own, never a search by name).
import signal

STOP = {"signal": None, "hooks": []}
STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


class Interrupted(BaseException):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


def signal_name(signum):
    try:
        return signal.Signals(signum).name
    except ValueError:
        return "signal %d" % signum


def _on_stop_signal(signum, _frame):
    if STOP["signal"] is not None:
        return
    STOP["signal"] = signum
    for hook in list(STOP["hooks"]):
        try:
            hook()
        except Exception:
            pass
    raise Interrupted(signum)


def check_stop():
    """Raise Interrupted again when a stop signal was seen but its exception was lost (a callback that sqlite called swallows exceptions)."""
    if STOP["signal"] is not None:
        raise Interrupted(STOP["signal"])


def install_stop_handlers():
    for signum in STOP_SIGNALS:
        signal.signal(signum, _on_stop_signal)


class held:
    """`with held():` the stop signals wait until the outermost block ends, so a row of a result file is written whole or not at all."""
    depth = 0

    def __enter__(self):
        if held.depth == 0:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, set(STOP_SIGNALS))
            except (AttributeError, ValueError, OSError):
                pass
        held.depth += 1
        return self

    def __exit__(self, *exc):
        held.depth -= 1
        if held.depth == 0:
            try:
                signal.pthread_sigmask(signal.SIG_UNBLOCK, set(STOP_SIGNALS))
            except (AttributeError, ValueError, OSError):
                pass
        return False


def pending_stop_signal():
    """The stop signal that arrived while signals were held and was not delivered, or None (how a signal that lands while the answer is sealed is found)."""
    try:
        pending = signal.sigpending()
    except (AttributeError, OSError):
        return None
    for signum in STOP_SIGNALS:
        if signum in pending:
            return signum
    return None


def hold_signals():
    """Hold the stop signals for good: the work is done and the answer is being written, and a signal must not start a second one."""
    held.depth += 1
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, set(STOP_SIGNALS))
    except (AttributeError, ValueError, OSError):
        pass
# END SHARED STOP


def fail(message, **extra):
    close_values()
    emit({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error); nothing was read", **extra})
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place
    outside it, the run directory itself, or anything under inputs/ is refused.

    A string check is not enough: `work/../inputs/x`, an absolute path and a
    symlink that points out all name a place the tool must not write, and none
    of them starts with "inputs/". Resolving first and comparing directories
    is what actually holds, and the read-only inputs are the one place
    extracted bytes must never appear -- a later integrity check would report
    the evidence as modified. In a job $OUT is inside the run directory.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    return str(dest.relative_to(root))


# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, bounded by rows and by bytes, and when there are more
# rows the whole result is written as JSON Lines under work/<agent>/tool-output
# (in a job, $OUT/tool-output) and named. The file name is a digest of the page's
# key (a path), never of a value. Rows are written with ensure_ascii on: a path
# the filesystem gave as bytes that are not UTF-8 reaches Python as lone
# surrogates, which a UTF-8 file cannot hold and an escape can. A rerun that
# would replace a larger earlier file of the same name writes a new name and says
# which earlier file it kept.
class LosslessPage:
    def __init__(self, tool, key, limit, byte_limit=None):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.byte_limit = byte_limit
        self.page = []
        self.page_bytes = 0
        self.full = False
        self.bytes_bound_hit = False
        self.total = 0
        self._out = None
        self._tmp = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(json.dumps(row, default=str))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if not self.full and len(self.page) < self.limit:
            size = len(json.dumps(row, default=str)) if self.byte_limit is not None else 0
            if self.byte_limit is None or self.page_bytes + size <= self.byte_limit:
                self.page.append(row)
                self.page_bytes += size
                return
            self.bytes_bound_hit = True
        # From the first row that does not fit, every later row goes to the file only: the page is a prefix.
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
            target, shown = self.path, self.shown
            if target.exists() and target.stat().st_size > os.path.getsize(self._tmp):
                n = 2
                while target.with_name("%s-%d%s" % (target.stem, n, target.suffix)).exists():
                    n += 1
                target = target.with_name("%s-%d%s" % (target.stem, n, target.suffix))
                shown = self.shown.rsplit("/", 1)[0] + "/" + target.name
                result["kept_earlier_larger_result"] = self.shown
            os.replace(self._tmp, target)
            result["all_results"] = shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


# BEGIN SHARED BOUNDARY
# WINDOWS BOUNDARY v1: the same text is in every windows-forensics tool that prints names, paths, event data, registry data or table
# cells from evidence (a windows-forensics test holds the copies equal), so that the shared-block task can converge it with the other
# withholding blocks. It is the owner-approved HYBRID design: an allow-list for identifier-shaped fields, a deny-list for free text,
# and an independent backstop on the way out.
#
# LAYER 1, an allow-list per field type. A string the evidence supplied is shown as it is only when it fits the plain grammar of the
# type of the field it fills: a name (registry key and value names, event field names, provider and channel names, table and column
# names), a path (file names and paths, a registry path, a URL path), a key, a URL, or a typed id (GUID, SID, MAC, IP address, digest,
# time, number, version). The grammar is: letters of any script, digits, space and `_ - . $ @ ? : ~ + , # ( ) [ ] { } ' < > *`, at
# most 128 characters a component, no user-info shape (a `:` before an `@`), and no chain of 16 or more characters made of
# random-looking pieces (pieces that break into one- and two-character parts, flip between letters and digits, or are letters with
# no pronounceable word in them; a 16-hex id, a GUID or a number up to 18 digits is plain). Below 16 characters a chain is shown
# whatever it looks like: a short random password in a name is not recognised. A path is judged component by component and only the
# offending span is replaced; a string with a format, control or combining character is withheld whole.
#
# LAYER 2, for every kind, and it reads the string FIRST, as the evidence wrote it (the deny-list and the grammar cut spans out of a string
# and take with them the context these rules need: the user of `user:password@host`, the characters glued before `glpat-`): user-info up
# to the last `@` before the host (the password may hold a `/`, not a port); the value after a secret's name (password, secret, token,
# api/access/account/private key, credential, auth) found anywhere, up to a space or quote, and past a `& ; ,` that no `name=` follows;
# a PEM private key; a vendor token with its own prefix (AKIA, gh?_, github_pat_, xox?-, glpat-, sk_live_, SG., AIza, npm_, dop_v1_,
# ya29., sk-, JWT) in any case; a base64 key with its padding; and the same rules on a copy with invisible characters taken out and NFKC
# applied (a hit withholds the whole string). FREE TEXT (event data, messages, command lines, registry data strings, table cells) is on
# the deny-list: the same chain test applied to the text with its typed ids (GUID, SID, IP address, time, labelled digest, number) left
# alone, plus layer 2, and no character grammar.
#
# LAYER 3, the backstop, written apart from the layers above: every key and value of what is about to be written is read once more
# by its own normaliser and patterns (a PEM marker, a named secret, a run of 19 or more digits, a token prefix in any case, user-info, a
# run of 40 or more hex digits outside a typed field, a base64 run, a run that changes class as random text does; a typed field must hold
# the characters of its type; data written as hexadecimal is decoded and its printable text is read as text). It reads the shown string
# AND the original: a window of 12 characters of anything it calls secret in the original that is still in the shown string means the
# layers above left a piece of a secret between two cuts. A string it finds suspect is replaced by <withheld N bytes: backstop: why>,
# counted, its place named in boundary.replaced_at (built from the keys on the way as they are SHOWN, or their positions), and the
# answer is partial. A placeholder is only a placeholder when its reason is one of the fixed list. The names of the components of the Windows
# component store (WinSxS: lower case, a public key token, a language or `none`, a hash) are not judged by the backstop in a name or key slot:
# a real SOFTWARE hive lists them by the thousand and their hash looked random to it; layer 1 judges them as it does every name.
#
# ONE WAY OUT: emit() writes an answer, row_text() a row of a paging file, and both seal every key and value first (a value that is not
# a string, a number or a container is sealed as the text str() makes of it). Binary data written as hex (a REG_BINARY value, an ESE
# binary column) is decoded and its printable views (Latin-1, UTF-16LE and UTF-16BE, and runs holding full-width characters read as UTF-8 and UTF-16LE with
# the width folded) are judged by the free-text rules, by both layers and the
# backstop; hex that holds a secret-shaped text is withheld, and any other hex is shown (random bytes with no text in them are printed).
# What is withheld is a placeholder with its length and the reason; its original goes to the values file only when write_values was
# asked for in a job run as secret output. A list of names is printed in the order of the text shown for each, the placeholders of
# withheld names in a random order that is new every run (print_order); a `contains` filter is applied to the text the answer PRINTS (the
# string after the layers and the backstop, sealed_text), never to what is withheld or replaced, and contains_check says when the needle
# could have been in what is hidden. Every string is judged in linear time (a string is read to 256 KiB, the pieces the backstop compares
# are at most 64, a PEM body at most 20,000 characters), and an answer or a row that takes longer than SEAL_BUDGET seconds to seal, or that is
# still being sealed at the seal stop of the tool (seal_stop_after: a point in time after which nothing is judged, not a stop of the tool's own
# work, which has its own clock), has the rest of its strings replaced whole (<withheld N bytes: backstop: the judging time ran out>) and is
# partial; what stays readable past that point is the names the tool made itself (OWN_NAMES) and strings of 15 characters or fewer of letters,
# digits, `_` and `.` that do not start like a vendor token (and, in a field of a typed kind, fit the grammar of its type). The seal stop is 3.5 seconds before the
# tool's time limit: the string in progress finishes after it, and one string of 256 KiB takes up to 2.3 seconds to judge on a loaded machine (the worst measured).
# NOT RECOGNISED, by design: a secret that does not look like one (a plain password, a pronounceable passphrase, a UUID-shaped key,
# anything under 16 characters in a name, a secret hidden in words or in an encoding this block does not read).
import collections
import hashlib
import signal
import time
import unicodedata

LMIN = 16
MAX_ONE_STRING = 1 << 18
MAX_HEX_JUDGED = 1 << 20
MAX_PIECES = 64                 # the pieces of a string the backstop compares with what was shown (it stops collecting at this many)
MAX_PEM_BODY = 20000            # a PEM body is read to this many characters (a 16,384-bit RSA key is about 13,000)
SEAL_BUDGET = 10.0              # seconds one answer, or one row of a paging file, may take to be sealed; a tool may set another
_CLOCK = {"deadline": None, "stop": None}
_BIGRAMS_TEXT = "aaabacadaeafagahaiajakalamanaoapaqarasatauavawaxayazbabbbcbdbebfbhbibjblbmbnbobpbrbsbtbubvbycacbcccdcecfchcickclcncocqcrcsctcucydadbdcdddedfdgdhdidjdldmdndodpdrdsdtdudvdwdyeaebecedeeefegeheiejekelemeneoepeqereseteuevewexeyezfafbfcfdfefffiflfofrftfufygagbgdgegfggghgiglgmgngogrgsgtgugwgyhahbhchdhehfhhhihlhmhnhohphrhshthuhwhyiaibicidieifigihiiijikiliminioipiqirisitiuiviwixizjajejijojukakbkekfkhkikkklkmknkokpkrksktkukwkylalblcldlelflglhlilklllmlnlolplrlsltlulvlwlymambmemfmimlmmmnmompmrmsmumwmynanbncndnenfngnhninjnknlnmnnnonpnqnrnsntnunvnwnxnynzoaobocodoeofogohoiojokolomonooopoqorosotouovowoxoyozpapbpcpepfphpiplpmpnpoppprpsptpupwpyqurarbrcrdrerfrgrhrirjrkrlrmrnrorprqrrrsrtrurvrwryrzsasbscsdsesfsgshsiskslsmsnsospsqsrssstsusvswsytatbtctdtetftgthtitltmtntotptrtstttutvtwtytzuaubucudueufuguhuiukulumunuoupurusutuvuxuyuzvavevivovuvywawbwdwewfwhwiwkwlwmwnwowrwswtwuwyxaxcxexhxixoxpxtxuxxxyyaybycydyeyfygyhyiylymynyoypyrysytyuywyxyyyzzazezizlzozuzyzz"           # the 474 letter pairs that words and identifiers use (the system word list and Python identifiers)
_BIGRAMS = frozenset(_BIGRAMS_TEXT[i:i + 2] for i in range(0, len(_BIGRAMS_TEXT), 2))
BOUNDARY = {"withheld": 0, "by": collections.Counter(), "replaced": 0, "replaced_by": collections.Counter(), "where": [], "not_listed": 0}
OWN_NAMES = set()               # exact strings this run made and shows as they are (file names of its own results)
FIELDS = {}                     # a JSON key -> the kind of what it holds (a tool fills this in); other keys hold free text
KEY_KINDS = {}                  # a JSON key holding a dict -> the kind of that dict's own keys (registry value names are paths); default: name
MAX_WHERE = 200


class T(str):
    """A string with its field type, made by the tool where it knows the type (a registry type, an event field, a column)."""
    kind = "text"

    def __new__(cls, kind, text):
        self = super().__new__(cls, text)
        self.kind = kind
        return self


def _mark(n, label, unit="characters"):
    return "<withheld %d %s: %s>" % (n, unit, label)


# the reasons a placeholder can give: a fixed list, so that text which only looks like a placeholder is not taken for one (and not skipped by the rules)
_CHECKS = ("a PEM marker", "a named secret", "a token prefix", "user-info", "not the typed grammar", "a long digit run", "a long hexadecimal run",
           "a base64 run with / and +", "a padded base64 run", "a random-looking run", "a part of a secret-shaped text", "the judging time ran out")
_LABELS = ("not a plain name", "token-shaped text", "user-info", "secret value", "private key", "long number", "rest of a long string",
           "binary data over the judged size", "binary data holding a secret-shaped text", "invisible characters in a name", "not a port", "query value", "fragment",
           "not a guid", "not a digest", "not a sid", "not a mac", "not a ip", "not a time", "not a number", "not a version") + \
          tuple("backstop: " + c for c in _CHECKS) + tuple("backstop: in binary data: " + c for c in _CHECKS)
_MARK = re.compile(r"<withheld [0-9]{1,10} (?:characters|bytes)(?:: (?:%s))?>|\[withheld: [0-9]{1,10} (?:characters|bytes)\]"
                   % "|".join(re.escape(x) for x in sorted(_LABELS, key=len, reverse=True)))
_VALUES = {"fh": None, "shown": None, "written": 0, "seen": set(), "count": 0}   # "seen": 16-byte digests of the originals written (at most 200,000)


class ValuesRefused(Exception):
    pass


def bind_values(enabled, tool):
    """The values file: the originals of what the boundary withheld, in a job run as secret output and only when asked for. Decided before
    anything is opened or created (the harness sets SECRET_OUTPUT=1 for a secret job's process)."""
    if not enabled:
        return None
    job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
    if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
        raise ValuesRefused("write_values is refused: the originals of what was withheld are written only in a job the harness runs as secret output "
                            "(job_run with secret_output: true), where the file is a sealed secret output. Nothing was written.")
    name = "%s-values.jsonl" % re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
    path = Path(out) / name
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        raise ValuesRefused("the values file already exists: %s" % path)
    except OSError as exc:
        raise ValuesRefused("the values file could not be created: %s: %s" % (path, exc.strerror or exc))
    _VALUES["fh"] = os.fdopen(fd, "w", encoding="utf-8")
    _VALUES["shown"] = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
    return _VALUES["shown"]


def close_values():
    fh = _VALUES["fh"]
    if fh is not None:
        fh.flush()
        os.fsync(fh.fileno())
        fh.close()
        _VALUES["fh"] = None


def values_summary():
    return {"requested": _VALUES["shown"] is not None, "values_file": _VALUES["shown"], "written": _VALUES["written"], "contains_secret_values": _VALUES["written"] > 0,
            "format": "JSON Lines, mode 0600: id, field, label, length, value (the original text that was withheld)" if _VALUES["shown"] else None}


_EVENTS = [None]               # while a string is judged only to see what the answer would print (sealed_text): its withholdings, counted when the answer prints it
_QUIET = [False]


def _withheld(original, label, field=""):
    n = len(original)
    if _EVENTS[0] is not None:
        _EVENTS[0].append((original, label, field))
        return _mark(n, label)
    BOUNDARY["withheld"] += 1
    BOUNDARY["by"][label] += 1
    fh = _VALUES["fh"]
    digest = hashlib.blake2b(original.encode("utf-8", "surrogatepass"), digest_size=16).digest() if fh is not None else None
    if fh is not None and digest not in _VALUES["seen"]:
        if len(_VALUES["seen"]) < 200000:
            _VALUES["seen"].add(digest)
        _VALUES["count"] += 1
        text = json.dumps({"id": _VALUES["count"], "field": field, "label": label, "length": n, "value": original}, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps({"id": _VALUES["count"], "field": field, "label": label, "length": n, "value": original}, ensure_ascii=True)
        fh.write(text + "\n")
        _VALUES["written"] += 1
    return _mark(n, label)


# ---- normalisation ----------------------------------------------------------------------------------------------------------------
_STRIP_CATS = frozenset(("Cf", "Cc", "Mn", "Me", "Cs", "Co", "Cn", "Zl", "Zp"))
_FILLERS = frozenset((0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800))


class _Strip(dict):
    def __missing__(self, o):
        if len(self) > 20000:
            self.clear()
        keep = unicodedata.category(chr(o)) not in _STRIP_CATS and o not in _FILLERS
        self[o] = o if keep else None
        return self[o]


_STRIP = _Strip()
_ESCAPED = re.compile(r"(?<!\\)\\+(?:u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\})")


def _unescape_invisible(m):
    try:
        c = chr(int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if (unicodedata.category(c) in _STRIP_CATS or ord(c) in _FILLERS) else m.group(0)


def _flat(text):
    """The text with invisible characters (and the escapes of such characters) taken out, and past ASCII in NFKC form."""
    if "\\u" in text or "\\U" in text or "\\x" in text:          # (the escape pattern needs a backslash and one of these)
        text = _ESCAPED.sub(_unescape_invisible, text)
    if text.isascii():
        return text if text.isprintable() else text.translate(_STRIP)
    out = text.translate(_STRIP)
    return unicodedata.normalize("NFKC", out) if not out.isascii() else out


# ---- layer 1: the allow-list ------------------------------------------------------------------------------------------------------
_PIECE = re.compile(r"[A-Z]{2,}s(?![a-z])|[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")        # (GPOs, an acronym in the plural, is one piece)
_GUID = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?|[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}")
_SID = re.compile(r"S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}")
_IPV4 = re.compile(r"(?<![0-9A-Za-z.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9A-Za-z])")
_HEX_NUMBER = re.compile(r"(?<![0-9A-Za-z])0[xX][0-9A-Fa-f]{1,16}(?![0-9A-Za-z])")
# the publisher ids that follow the name of an AppX package family (the hash of the publisher's name), and the assembly public key tokens of Microsoft
_KNOWN_ID_WORDS = ("0x", "8wekyb", "cw5n1h", "kzf8qx", "31bf38", "b77a5c", "b03f5f")
_KNOWN_ID = re.compile(r"(?<![0-9A-Za-z])(?:8wekyb3d8bbwe|cw5n1h2txyewy|kzf8qxf38zg5c|31bf3856ad364e35|b77a5c561934e089|b03f5f7f11d50a3a|0x[0-9A-Fa-f]{1,16})(?![0-9A-Za-z])")
_NAME_SEPS = " _-.$@?:~+,#()[]{}'`<>*"
_PATH_EXTRA = "&!';=^%\""
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_PCT_UNRESERVED = re.compile(r"%((?:4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|3[0-9]|2[DdEe]|5[Ff]|7[Ee]))")
_JOIN_NAME, _JOIN_PATH = "-_+", "-_+/\\"
_CTRL = "\x01\x02\x03\x04\x05\x06\x07\x08\x09"


def _has(words, text):
    """Whether one of `words` is in `text` (a loop: a generator inside any() costs twice as much for the thousands of strings of a hive)."""
    for w in words:
        if w in text:
            return True
    return False


def _pronounceable(piece):
    p = piece.lower()
    bad = sum(1 for a, b in zip(p, p[1:]) if (a + b) not in _BIGRAMS)
    return bad <= 1 + len(p) // 10


_HEX_LOW_OR_UP = re.compile(r"[0-9a-f]+|[0-9A-F]+")
_HEX_ANY = re.compile(r"[0-9A-Fa-f]+")
_SEGMENT_MEMO = {}


def _structure_ok(seg):
    if seg.isdigit() and seg.isascii():
        return len(seg) <= 18
    if len(seg) <= 24 and _HEX_LOW_OR_UP.fullmatch(seg):
        return True                       # a hexadecimal id up to 24 digits (a USB serial, a 16-digit object id, a hash of a few bytes) is plain
    if len(seg) >= 20 and _HEX_ANY.fullmatch(seg):
        return False
    pieces = _PIECE.findall(seg)
    short = sum(1 for p in pieces if len(p) <= 2)
    if short > max(2, 0.4 * len(pieces)):
        return False
    flips = sum(1 for a, b in zip(seg, seg[1:]) if a.isdigit() != b.isdigit())
    if flips > 3 + len(seg) // 16:
        return False
    alpha = [p for p in pieces if p.isalpha()]
    if sum(len(p) for p in alpha) >= 12 and sum(len(p) for p in alpha) < 3.4 * len(alpha):
        return False
    return True


def _plain_segment(seg, lmin=None):
    lmin = LMIN if lmin is None else lmin
    if len(seg) < lmin:
        return True
    memo = (seg, lmin) if len(seg) <= 64 else None          # the same words come again and again in the records of one log
    if memo is not None:
        hit = _SEGMENT_MEMO.get(memo)
        if hit is not None:
            return hit
    if not _structure_ok(seg):
        ok = False
    else:
        ok = all(not (p.isalpha() and len(p) >= 6) or _pronounceable(p) for p in _PIECE.findall(seg))
    if memo is not None:
        if len(_SEGMENT_MEMO) >= 100000:
            _SEGMENT_MEMO.clear()
        _SEGMENT_MEMO[memo] = ok
    return ok


def _prepare(s, typed=True):
    """A same-length copy of `s` in which a GUID, a SID, an IPv4 address and a %XX escape are replaced by `~` and a non-ASCII letter by `e`;
    None when `s` holds a format, control or combining character, a non-NFKC character or a stray space character."""
    if not s.isascii():
        for ch in s:
            cat = unicodedata.category(ch)
            if cat[0] in "CM" or (cat[0] == "Z" and ch != " "):
                return None
        if unicodedata.normalize("NFKC", s) != s:
            return None
        s = "".join(ch if ch.isascii() else "e" for ch in s)
    t = _GUID.sub(lambda m: "~" * len(m.group()), s) if s.count("-") >= 3 else s    # (each pattern is tried only when the text holds what it cannot match without: a GUID has three hyphens or more)
    if typed:
        if "S-1-" in t:
            t = _SID.sub(lambda m: "~" * len(m.group()), t)
        if "." in t:
            t = _IPV4.sub(lambda m: "~" * len(m.group()), t)
        if _has(_KNOWN_ID_WORDS, t):
            t = _KNOWN_ID.sub(lambda m: "~" * len(m.group()), t)
    return _PCT.sub("   ", t) if "%" in t else t


def _unpercent(s):
    if "%" not in s:
        return None
    out = _PCT_UNRESERVED.sub(lambda m: chr(int(m.group(1), 16)), s)
    return out if out != s else None


_CHAINS = {}
_SEGMENT = re.compile(r"[A-Za-z0-9]+")


_SEGMENT_PLAIN = {}


def _is_plain_segment(seg):
    """_plain_segment(seg, 0), remembered for the plain ones only (a dict that is asked a hundred thousand times for the same words)."""
    if not _plain_segment(seg, 0):
        return False
    if len(seg) <= 64:
        if len(_SEGMENT_PLAIN) >= 100000:
            _SEGMENT_PLAIN.clear()
        _SEGMENT_PLAIN[seg] = True
    return True


def _bad_runs(t, join):
    """Intervals of `t` that are not plain, judged on CHAINS: maximal sequences of alphanumeric segments joined only by `join` characters. A
    chain is bad when (A) its random-looking segments, adjacent ones taken together, add up to LMIN characters or more, or (B) it is LMIN
    characters or longer, holds 8 or more characters of letter-and-digit-mixed segments, and holds no word of five or more letters."""
    pattern = _CHAINS.get(join)
    if pattern is None:
        pattern = _CHAINS[join] = re.compile(r"[A-Za-z0-9]+(?:[%s]+[A-Za-z0-9]+)*" % "".join(re.escape(c) for c in join))
    plain = _SEGMENT_PLAIN
    if all(plain.get(seg) or _is_plain_segment(seg) for seg in _SEGMENT.findall(t)):
        return []                                       # no chain holds a random-looking segment, so none is bad (the same answer as the loop below, without building the chains)
    bad = []
    for found in pattern.finditer(t):
        if found.end() - found.start() < LMIN:
            continue                                    # a chain shorter than LMIN is neither a run of LMIN random characters nor a long mixed chain
        chain = [(m.start(), m.end()) for m in _SEGMENT.finditer(t, found.start(), found.end())]
        total = sum(b - a for a, b in chain)
        if total < LMIN:
            continue
        rnd = [not _plain_segment(t[a:b], 0) for a, b in chain]
        if not any(rnd):
            continue
        run = None
        for (a, b), r in zip(chain, rnd):
            if r:
                run = [a, b, b - a] if run is None else [run[0], b, run[2] + (b - a)]
            else:
                if run is not None and run[2] >= LMIN:
                    bad.append((run[0], run[1]))
                run = None
        if run is not None and run[2] >= LMIN:
            bad.append((run[0], run[1]))
        mixed = sum(b - a for a, b in chain if not _structure_ok(t[a:b]))
        if total >= LMIN and mixed >= 8 and not any(len(p) >= 5 and p.isalpha() and _pronounceable(p) for a, b in chain for p in _PIECE.findall(t[a:b])):
            bad.append((chain[0][0], chain[-1][1]))
    return bad


_CHARS = {}


def _chars_ok(comp, extra_ok):
    if comp.isascii():
        pattern = _CHARS.get(extra_ok)
        if pattern is None:
            pattern = _CHARS[extra_ok] = re.compile("[A-Za-z0-9%s]*" % re.escape(_NAME_SEPS + extra_ok))
        return pattern.fullmatch(comp) is not None
    return all(ch.isalnum() or ch in _NAME_SEPS or ch in extra_ok for ch in comp)


def _userinfo_shape(t):
    return ":" in t and "@" in t and t.index(":") < t.rindex("@")


def _plain_name(s, extra_ok=""):
    if not s or len(s) > 128:
        return False
    t = _prepare(s)
    if t is None or not _chars_ok(t, extra_ok) or _userinfo_shape(t):
        return False
    u = _unpercent(s)
    if u is not None:
        pu = _prepare(u)
        if pu is None or _bad_runs(pu, _JOIN_NAME):
            return False
    return not _bad_runs(t, _JOIN_NAME)


def _merge(spans):
    merged = []
    for a, b in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


_SPLIT = re.compile(r"([\\/])")
_DRIVE = re.compile(r"[A-Za-z]:|\?|\.")


def _path_spans(s, extra_ok=_PATH_EXTRA):
    t = _prepare(s)
    if t is None:
        return [(0, len(s))]
    bad, pos = [], 0
    if len(t) <= 255 and "@" not in t and t.isascii() and _chars_ok(t, extra_ok + "\\/"):
        parts = ()                       # (every character is allowed, no part is long and none can hold a user-info shape: no part is bad)
    else:
        parts = _SPLIT.split(t)
    for part in parts:
        a, b = pos, pos + len(part)
        pos = b
        judged = part.lstrip(_CTRL)
        if part in ("\\", "/") or part == "" or _DRIVE.fullmatch(part):
            continue
        if len(part) - len(judged) > 1 or len(part) > 255 or not _chars_ok(judged, extra_ok) or _userinfo_shape(judged):
            bad.append((a, b))
    bad += _bad_runs(t, _JOIN_PATH)
    u = _unpercent(s)
    if u is not None:
        pu = _prepare(u)
        if pu is None or _bad_runs(pu, _JOIN_PATH):
            bad.append((0, len(s)))
    return _merge(bad)


def _replace_spans(s, spans, label, field):
    out, last = [], 0
    for a, b in spans:
        out.append(s[last:a])
        out.append(_withheld(s[a:b], label, field))
        last = b
    out.append(s[last:])
    return "".join(out)


def _show_name(s, field):
    return s if _plain_name(s) else _withheld(s, "not a plain name", field)


def _show_path(s, field, extra_ok=_PATH_EXTRA):
    return _replace_spans(s, _path_spans(s, extra_ok), "not a plain name", field)


def _show_key(s, field):
    return _show_path(s, field, _PATH_EXTRA + "*^<>")


_URL = re.compile(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)(?:([^/?#]*)@)?([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$", re.S)


def _show_host(s, field):
    """A host name is on the deny-list: a random-looking label of a host is evidence (a C2 name), not a secret. Layer 2 reads it first: the deny-list
    would replace a random user of `user:password@host` and leave the context layer 2 needs."""
    return _deny_text(_layer2(s, field), field)


def _show_value(v):
    return v if re.fullmatch(r"[0-9]{1,12}|true|false|null|yes|no", v) or (v.isalpha() and len(v) <= 24 and _plain_name(v)) else None


def _show_url(s, field):
    m = _URL.match(s)
    if not m:
        return _show_path(s, field)
    scheme, userinfo, host, path, query, frag = m.groups()
    out = scheme
    if userinfo is not None:
        out += (userinfo if _MARK.fullmatch(userinfo) else _withheld(userinfo, "user-info", field)) + "@"
    hostname, colon, port = host.partition(":") if not host.startswith("[") else (host, "", "")
    out += _show_host(hostname, field) + (colon + (port if port.isdigit() else _withheld(port, "not a port", field)) if colon else "")
    out += _show_path(path, field)
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            k, eq, v = pair.partition("=")
            kk = _show_name(k, field) if k else k
            if eq:
                sv = _show_value(v)
                pairs.append(kk + "=" + (sv if sv is not None else _withheld(v, "query value", field)))
            else:
                pairs.append(kk)
        out += "?" + "&".join(pairs)
    if frag is not None:
        sv = _show_value(frag)
        out += "#" + (sv if sv is not None else _withheld(frag, "fragment", field))
    return out


_TYPED = {
    "guid": re.compile(_GUID.pattern),
    "digest": re.compile(r"(?:sha256:|sha1:|md5:)?[0-9A-Fa-f]{32,128}|T1[0-9A-Fa-f]{60,72}|[0-9]{1,6}:[A-Za-z0-9+/]{3,}:[A-Za-z0-9+/]{3,}"),
    "sid": re.compile(_SID.pattern),
    "mac": re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"),
    "ip": re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]{2,45}(?:%[0-9A-Za-z_.-]{1,16})?"),
    "time": re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9:.]+(?:Z|[+-][0-9:]+)?)?|D:[0-9]{8,14}(?:[Zz+-][0-9']*)?|[0-9]{1,18}"),
    "number": re.compile(r"-?[0-9]{1,18}(?:\.[0-9]{1,18})?|0x[0-9A-Fa-f]{1,16}|(?:true|false|null)"),
    "version": re.compile(r"v?[0-9]+(?:\.[0-9A-Za-z]+){1,4}(?:[-+][0-9A-Za-z.]+)?"),
}


# ---- layer 2: position and prefix rules -------------------------------------------------------------------------------------------
# user-info whose password holds a `/` (RFC 3986 says to encode it; people do not): after `//`, a user, a `:`, then everything up to the last `@` that is
# followed by a host; not `host:8080/...@...` (a port), whose first word after the colon is a number
_URL_USERINFO_SLASH = re.compile(r"(?<=//)(?![^\s/@:<>\"'`]*:[0-9]{1,5}(?:[/?#@]|$))[^\s/@:<>\"'`]{1,64}:[^\s<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
# a user the deny-list already replaced: `<withheld ...>:password@host`
_MARK_USERINFO = re.compile(r"(?P<mark><withheld \d+ (?:characters|bytes)[^<>]{0,70}>|\[withheld: \d+ characters\]):(?P<pw>[^\s/<>\"'`]{1,128})(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_USERINFO = re.compile(r"(?<![A-Za-z0-9._%+-])(?!mailto:)[^\s/@:<>\"'`]{1,64}:[^\s/<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_URL_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_NAMED = re.compile(r"(?i)(?:(?<![Bb]y)(?<![Cc]om)(?<![Oo]ver)(?<![Uu]nder)(?<![Tt]res)(?<![Ee]ncom)(?<![Ss]ur)(?<![Ii]m)pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|client[_-]?secret|credential|auth(?:orization)?)s?[\"']?[ \t]{0,3}[=:][ \t]{0,3}[\"']?(?P<value>(?:[^\s\"'<>;,&]|[;,&](?![A-Za-z0-9_. -]{1,40}=)){1,512})")
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)", re.S)
_PREFIX = re.compile(r"(?i:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abeprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}"
                     r"|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,}|npm_[A-Za-z0-9]{30,}"
                     r"|dop_v1_[0-9a-f]{40,}|ya29\.[0-9A-Za-z_-]{30,})|sk-(?=[A-Za-z0-9_-]{0,39}[0-9])[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,300}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?")
_BASE64_PADDED = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={1,2}(?![A-Za-z0-9+=])")
_LONG_DIGITS = re.compile(r"(?<![0-9])[0-9]{19,}(?![0-9])")


def _b64_shape(run):
    """Whether a padded run can be base64 of random bytes: its length with the padding is a multiple of 4, and it holds a digit, `+` or `/` (a long
    identifier before an `=` in a line of text, RelatedActivityID=, is not one)."""
    return len(run) % 4 == 0 and re.search(r"[0-9+/]", run) is not None


_NAMED_WORDS = ("pass", "pwd", "secret", "token", "key", "credential", "auth")
_PREFIX_HINTS = ("akia", "asia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xox", "glpat-", "_live_", "_test_", "sg.", "aiza", "npm_", "dop_v1_",
                 "ya29.", "sk-", "eyj")


def _layer2_once(s, field):
    # each rule is tried only when the text holds what it needs (a character or a word it cannot match without): the same result, a lot less reading
    if "withheld" in s:
        s = _MARK_USERINFO.sub(lambda m: m.group("mark") + ":" + _withheld(m.group("pw"), "user-info", field), s)
    if "-----" in s:
        s = _outside(s, _MARK, lambda p: _PEM.sub(lambda m: _withheld(m.group(), "private key", field), p))
    if "@" in s:
        s = _outside(s, _MARK, lambda p: _URL_USERINFO_SLASH.sub(lambda m: _withheld(m.group(), "user-info", field), p))
        s = _outside(s, _MARK, lambda p: _URL_USERINFO.sub(lambda m: _withheld(m.group(), "user-info", field), p))
        s = _outside(s, _MARK, lambda p: _USERINFO.sub(lambda m: _withheld(m.group(), "user-info", field), p))
    low = s.lower()
    if _has(_NAMED_WORDS, low):
        s = _outside(s, _MARK, lambda p: _NAMED.sub(lambda m: m.group()[:m.start("value") - m.start()] + _withheld(m.group("value"), "secret value", field), p))
    if "=" in s:
        s = _outside(s, _MARK, lambda p: _BASE64_PADDED.sub(lambda m: _withheld(m.group(), "token-shaped text", field) if _b64_shape(m.group()) else m.group(), p))
    s = _outside(s, _MARK, lambda p: _LONG_DIGITS.sub(lambda m: _withheld(m.group(), "long number", field), p))
    low = s.lower()
    if _has(_PREFIX_HINTS, low):
        s = _outside(s, _MARK, lambda p: _PREFIX.sub(lambda m: _withheld(m.group(), "token-shaped text", field), p))
    return s


def _outside(text, pattern, fn):
    """`fn` applied to the parts of `text` that `pattern` does not match; the matches are kept as they are."""
    if "withheld" not in text:
        return fn(text)
    out, last = [], 0
    for m in pattern.finditer(text):
        out.append(fn(text[last:m.start()]) if m.start() > last else "")
        out.append(m.group())
        last = m.end()
    out.append(fn(text[last:]) if last < len(text) else "")
    return "".join(out)


def _layer2(s, field):
    out = s
    for _ in range(3):
        nxt = _layer2_once(out, field)
        if nxt == out:
            break
        out = nxt
    return out


# ---- free text: the deny-list ------------------------------------------------------------------------------------------------------
_LABELLED_DIGEST = re.compile(r"(?i)(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|imphash|hashes?|filehash|ssdeep|tlsh)[\"'=:> \t]{1,6}(?:(?:md5|sha-?1|sha-?256|imphash)=)?([0-9a-f]{32,128})")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]{1,9})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])")


def _mask_typed(s):
    """A same-length copy of free text in which what is a typed id (GUID, SID, IPv4, time, labelled digest) is `~`."""
    t = s
    if "-" in s:
        t = _GUID.sub(lambda m: "~" * len(m.group()), t)
        if "S-1-" in s:
            t = _SID.sub(lambda m: "~" * len(m.group()), t)
        if ":" in s:
            t = _TIME.sub(lambda m: "~" * len(m.group()), t)
    if "." in s:
        t = _IPV4.sub(lambda m: "~" * len(m.group()), t)
    low = s.lower()
    if _has(_KNOWN_ID_WORDS, low):
        t = _KNOWN_ID.sub(lambda m: "~" * len(m.group()), t)
    if "ash" in low or "md5" in low or "sha" in low:
        t = _LABELLED_DIGEST.sub(lambda m: m.group().replace(m.group(1), "~" * len(m.group(1))), t)
    return t


def _deny_text(s, field):
    t = _mask_typed(s)
    t = t.replace("\x00", " ")
    spans = _bad_runs(t, _JOIN_PATH)
    spans += [m.span() for m in _HEX_RUN.finditer(t)]
    return _replace_spans(s, _merge(spans), "token-shaped text", field) if spans else s


# ---- the entry point for one string ---------------------------------------------------------------------------------------------------
_MEMO = {}


_WIDE_RUN = re.compile(r"[\x20-\x7e\uff01-\uff5e]{4,}")


def _wide_views(raw):
    """Runs of ASCII and full-width ASCII in `raw` read as UTF-8 and as UTF-16LE (at both byte offsets), when it holds a full-width character at
    all: width is folded afterwards (NFKC), so a full-width token written as hexadecimal is read like a plain one."""
    views = []
    if b"\xef\xbc" in raw or b"\xef\xbd" in raw:
        views += _WIDE_RUN.findall(raw.decode("utf-8", "replace"))
    if b"\xff" in raw:
        for offset in (0, 1):
            views += _WIDE_RUN.findall(raw[offset:len(raw) - (len(raw) - offset) % 2].decode("utf-16-le", "replace"))
    return [unicodedata.normalize("NFKC", v) for v in views]


def _hex_views(s):
    """The printable views of binary data written as hex: Latin-1 runs of 6 or more, UTF-16LE and UTF-16BE runs of 4 or more, and the runs that hold
    full-width characters (UTF-8 and UTF-16LE), width folded."""
    try:
        raw = bytes.fromhex(s[: MAX_HEX_JUDGED])
    except ValueError:
        return None
    views = [m.group().decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{6,}", raw)]
    views += [m.group().decode("utf-16-le", "replace") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", raw)]
    views += [m.group().decode("utf-16-be", "replace") for m in re.finditer(rb"(?:\x00[\x20-\x7e]){4,}", raw)]
    return views + _wide_views(raw)


def _show_hex(s, field):
    if not s or not re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", s):
        return s if re.fullmatch(r"[0-9A-Fa-f]*", s) else _show_text(s, field)
    if len(s) > MAX_HEX_JUDGED:
        return _withheld(s, "binary data over the judged size", field)
    for v in _hex_views(s) or ():
        if _layer2(v, "") != v or _deny_text(v, "") != v or _suspect(v):
            return _withheld(s, "binary data holding a secret-shaped text", field)
    return s


def _show_text(s, field):
    # layer 2 reads the string as the evidence wrote it: the deny-list replaces a span and takes with it the context (`user:` of `user:pw@host`, the
    # characters glued before `glpat-`) the position and prefix rules need; what it leaves is read once more
    out = _layer2(s, field)
    denied = _deny_text(out, field)
    return _layer2(denied, field) if denied != out else out


def _show(s, kind, field):
    if s in OWN_NAMES or _MARK.fullmatch(s):
        return s
    if len(s) > MAX_ONE_STRING:
        return _show(s[:MAX_ONE_STRING], kind, field) + _withheld(s[MAX_ONE_STRING:], "rest of a long string", field)
    if kind in _TYPED:
        return s if len(s) <= 3 or _TYPED[kind].fullmatch(s) else _withheld(s, "not a %s" % kind, field)
    if kind == "hex":
        return _show_hex(s, field)
    flat = _flat(s)
    if flat != s:
        # an invisible character, or the escape of one: identifiers fail closed; free text is judged without it
        if kind in ("name", "path", "key", "url"):
            return _withheld(s, "invisible characters in a name", field)
        sealed = _show_text(flat, field)
        return sealed if sealed != flat else s
    if kind not in ("name", "path", "key", "url", "host"):
        return _show_text(s, field)
    pre = _layer2(s, field)
    if kind == "name":
        base = _show_name(pre, field)
    elif kind == "path":
        base = _show_path(pre, field)
    elif kind == "key":
        base = _show_key(pre, field)
    elif kind == "url":
        base = _show_url(pre, field)
    else:
        base = _show_host(pre, field)
    return _layer2(base, field) if base != pre else base


def show(s, kind="text", field=""):
    """The text the answer may show for the string `s` of a field of type `kind` (a T carries its own)."""
    if not isinstance(s, str) or not s:
        return s
    kind = getattr(s, "kind", kind)
    memo = (kind, field, s) if len(s) <= 512 and kind not in _TYPED else None            # (a typed id is judged by one match: it is not worth a place in the memo)
    quiet = _QUIET[0]
    if memo is not None:
        hit = _MEMO.get(memo)
        if hit is not None:
            out, pending = hit
            if pending and not quiet:
                # judged earlier only to see what would be printed: it is withheld, counted and written to the values file now that it is printed (once)
                for original, label, where in pending:
                    _withheld(original, label, where)
                _MEMO[memo] = (out, None)
            return out
    events = _EVENTS[0] = [] if quiet and memo is not None else None
    try:
        out = _show(str(s), kind, field)
    finally:
        _EVENTS[0] = None
    if memo is not None:
        if len(_MEMO) > 40000:
            _MEMO.clear()
        _MEMO[memo] = (out, events or None)
    return out


_ORDER_SALT = os.urandom(16)


def _quietly(fn):
    """`fn()` with nothing counted, listed or written: judging a string to see what an answer would show of it is not withholding it."""
    saved = (BOUNDARY["withheld"], BOUNDARY["by"].copy(), BOUNDARY["replaced"], BOUNDARY["replaced_by"].copy(), BOUNDARY["where"][:], BOUNDARY["not_listed"], _VALUES["fh"])
    _VALUES["fh"] = None
    was, _QUIET[0] = _QUIET[0], True
    try:
        return fn()
    finally:
        _QUIET[0] = was
        (BOUNDARY["withheld"], BOUNDARY["by"], BOUNDARY["replaced"], BOUNDARY["replaced_by"], BOUNDARY["where"], BOUNDARY["not_listed"], _VALUES["fh"]) = saved


def sealed_text(text, kind="text", field=""):
    """The exact text an answer prints for the string `text` of a field of type `kind`: the layers, then the backstop (a string it replaces comes
    out as its placeholder). Nothing is counted, listed or written to the values file: this is for what must see what the answer shows (a
    `contains` filter, the order of a list)."""
    if not isinstance(text, str) or not text:
        return text
    return _quietly(lambda: _seal(text, kind, field, (), True))


def print_order(items, kind="name", text=str):
    """`items` in the order an answer prints them: by the text the answer PRINTS for each (the layers and the backstop, sealed_text), and the items
    whose text is the same placeholder in a random order that is new for every run. The rank of the withheld texts themselves (the order `sorted`
    would give, the order a directory or a hive lists them in) must never show in what an answer lists. `kind` is the kind of the field the items
    are printed in; `text` gives the string of an item."""
    def judge():
        out = []
        for n, i in enumerate(items):
            raw = text(i)
            shown = _seal(raw, kind, "", (), True) if isinstance(raw, str) and raw else raw
            out.append((shown, hashlib.blake2b(_ORDER_SALT + raw.encode("utf-8", "surrogatepass"), digest_size=8).digest(), n, i))
        return out
    items = list(items)
    keyed = _quietly(judge)
    keyed.sort(key=lambda k: (k[0], k[1], k[2]))
    return [k[3] for k in keyed]


def contains_check(needle_lower, text, kind="text", field=""):
    """(matched, blind) for a `contains` filter: the needle is looked for in the text the answer will PRINT for `text` (sealed_text: after the layers
    AND the backstop), never in what either of them withheld or replaced, so that a count of matches cannot tell a true guess of a hidden piece from
    a wrong one. `blind` is true when it was not found and that text holds a placeholder: the needle may be in what is hidden. It is the same
    whatever the needle, so counting it opens no way to test a guess."""
    sealed = sealed_text(text, kind, field)
    if needle_lower in sealed.lower():
        return True, False
    return False, _MARK.search(sealed) is not None


# ---- layer 3: the backstop, written apart from the layers above ------------------------------------------------------------------------
_S_ESC = re.compile(r"(?<!\\)\\+(?:[uU]\{?([0-9a-fA-F]{4,8})\}?|x([0-9a-fA-F]{2}))")
_S_FILL = "\u115f\u1160\u3164\uffa0\u2800"


def _s_gone(c):
    cat = unicodedata.category(c)
    return cat[0] == "C" or cat in ("Mn", "Me", "Zl", "Zp") or c in _S_FILL


def _s_unesc(m):
    try:
        c = chr(int(m.group(1) or m.group(2), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if _s_gone(c) else m.group(0)


def _s_normal(text):
    if "\\u" in text or "\\U" in text or "\\x" in text:
        text = _S_ESC.sub(_s_unesc, text)
    if text.isascii() and text.isprintable():
        return text
    kept = [c for c in text if not _s_gone(c)]
    return unicodedata.normalize("NFKC", "".join(kept))


_S_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY|PRIVATE KEY-----")
_S_DELIM = re.compile(r"[=:]")
_S_NAME_WORDS = ("pass", "pw", "auth", "sig", "sas", "secret", "token", "credential", "key")        # a name that ends in a word of _S_STRONG or _S_WEAK holds one of these
_S_ARGNAME = re.compile(r"(?<![\w-])--?(?:pass|password|passwd|pwd|secret|token|apikey|api-key)[= ]\S", re.I)
_S_PREFIX_WORDS = ("akia", "asia", "agpa", "aida", "aroa", "anpa", "anva", "aipa", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xox", "xapp-",
                   "sk_live_", "rk_live_", "pk_live_", "sk_test_", "npm_", "pypi-", "shpat_", "dop_v1_", "aiza", "ya29.", "sg.", "sk-", "eyj")
_S_LINE = re.compile(r"[ \t]*line[ \t]+[0-9]")
_S_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_S_STRONG = ("password", "passwd", "passphrase", "passw", "pwd", "secret", "token", "credential", "apikey", "api_key", "api-key", "accesskey", "access_key", "access-key",
             "accountkey", "account_key", "account-key", "privatekey", "private_key", "private-key", "masterkey", "master_key", "sharedkey", "shared_key", "signingkey", "encryptionkey",
             "secretkey", "secret_key", "secret-key")
_S_WEAK = ("pass", "pw", "auth", "sig", "sas")
_S_NOT_PASS = ("bypass", "compass", "overpass", "underpass", "trespass", "encompass", "surpass", "impass")
_S_STRONG_ENDS = tuple(w + p for w in _S_STRONG for p in ("", "s"))       # a name that ends in one of these, or in one of them plural
_S_WEAK_ENDS = tuple(w + p for w in _S_WEAK for p in ("", "s"))
_S_NOT_PASS_ENDS = tuple(w + p for w in _S_NOT_PASS for p in ("", "s"))
_S_DIGITS = re.compile(r"[0-9]{19}")
_S_HEXRUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{40,}(?![0-9A-Za-z])")
_S_B64NOPAD = re.compile(r"[A-Za-z0-9+/]{20,}")
_S_B64PAD = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{15,}={1,2}(?![A-Za-z0-9+=])")
# in any case where an upper-case spelling of a lower-case prefix is a likely leak (the vendors' prefixes with a body of 12 or more characters)
_S_PREFIX = re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{12}|(?i:(?<![A-Za-z0-9])(?:akia|asia)[a-z0-9]{12}|(?:gh[pousr]_|github_pat_|glpat-|xox[a-z]-|xapp-|sk_live_|rk_live_|pk_live_|sk_test_)[A-Za-z0-9_-]{12})"
                       r"|(?:npm_|pypi-|shpat_|dop_v1_|AIza|ya29\.|SG\.)[A-Za-z0-9_-]{12}|sk-(?=[A-Za-z0-9_-]{0,39}[0-9])[A-Za-z0-9_-]{12}|eyJ[A-Za-z0-9_-]{12}")
_S_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_S_USERINFO = re.compile(r"[^\s/@:<>\"']{1,64}:(?P<pw>[^\s/<>\"']{1,128})@[^\s/@<>\"']")
_S_USERINFO_MARK = re.compile(r"<>:(?P<pw>[^\s/<>\"']{1,128})@[^\s/@<>\"']")
_S_USERINFO_URL = re.compile(r"(?<=//)(?![^\s/@:<>\"']*:[0-9]{1,5}(?:[/?#@]|$))[^\s/@:<>\"']{1,64}:(?P<pw>[^\s<>\"']{1,128})@[^\s/@<>\"']")
_S_VALUE = re.compile(r"(?:[^\s\"'<>;,&]|[;,&](?![A-Za-z0-9_. -]{1,40}=)){1,512}")
_S_ARGVAL = re.compile(r"(?<![\w-])--?(?:pass|password|passwd|pwd|secret|token|apikey|api-key)[= ](\S{1,512})", re.I)
_S_PEMLINE = re.compile(r"[A-Za-z0-9+/=]{12,}")
_S_RUN = re.compile(r"[A-Za-z0-9+/_-]{20,}")
_S_HEX = re.compile(r"[0-9A-Fa-f-]+")
_S_IDS = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?|S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}|[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+Z?")
_S_MARK = re.compile(r"<withheld [0-9]{1,10} (?:characters|bytes)(?:: [a-z][a-z ,/+-]{0,60}(?:: [a-z][a-z ,/+-]{0,60})?)?>|\[withheld: [0-9]{1,10} (?:characters|bytes)\]")
_S_DIGEST_LABEL = re.compile(r"(?i)(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|imphash|hashes?|filehash|ssdeep|tlsh)[\"'=:> \t]{1,6}(?:(?:md5|sha-?1|sha-?256|imphash)=)?[0-9a-f]{32,128}")
_TYPED_KINDS = frozenset(("guid", "digest", "sid", "mac", "ip", "time", "number", "version", "hex", "label"))
# what a typed field may hold, by the characters of its type (apart from the grammar the first layer checks, and wider than it)
_S_TYPED = {
    "guid": re.compile(r"[0-9A-Fa-f{}-]{1,64}"), "sid": re.compile(r"[Ss0-9-]{1,400}"), "mac": re.compile(r"[0-9A-Fa-f:-]{1,64}"),
    "ip": re.compile(r"[0-9A-Fa-f:.]{1,64}(?:%[0-9A-Za-z_.-]{1,16})?"), "time": re.compile(r"[0-9TtZzDd:.,+' -]{1,64}"),
    "number": re.compile(r"-?[0-9.]{1,64}|0[xX][0-9A-Fa-f]{1,16}|true|false|null"), "version": re.compile(r"(?=.{1,64}\Z)[vV]?[0-9]+(?:\.[0-9A-Za-z]{1,16}){0,6}(?:[-+][0-9A-Za-z.]{1,32}){0,3}"),
    "digest": re.compile(r"(?:sha256:|sha1:|md5:)?[0-9A-Fa-f]{16,128}|T1[0-9A-Fa-f]{16,80}|[0-9]{1,6}:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+"),
}
_S_LONG = re.compile(r"[A-Za-z0-9+/_-]{19}")           # the shortest run any check below needs (19 digits); the hexadecimal run needs 40, the others 20
_S_PLAIN_NUM = re.compile(r"[0-9TZ:.+ -]+")
_S_HEXONLY = re.compile(r"(?:[0-9A-Fa-f]{2})+")
_S_PRINT_L1 = re.compile(rb"[\x20-\x7e]{6,}")
_S_PRINT_U16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_S_PRINT_U16BE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")


def _class(c):
    return 0 if c.isdigit() else 1 if c.isupper() else 2


def _random_run(run):
    if _S_HEX.fullmatch(run):
        return False
    pieces = [p for p in re.split(r"[/_+-]", run) if p]
    alnum = "".join(pieces)
    if len(alnum) < 20 or max(len(p) for p in pieces) < 12:
        return False
    kinds = {_class(c) for c in alnum}
    if len(kinds) < 2:
        return False
    lower = [len(r) for r in re.findall(r"[a-z]+", alnum)]
    if lower and sum(lower) >= 3 * len(lower) and not re.search(r"[A-Z]{2}", alnum):
        return False
    changes = sum(1 for a, b in zip(alnum, alnum[1:]) if _class(a) != _class(b)) / (len(alnum) - 1)
    digit_runs = len(re.findall(r"[0-9]+", alnum))
    if kinds == {0, 1, 2}:
        return changes >= 0.42 or (changes >= 0.3 and digit_runs >= 4 and len(set(alnum)) >= 0.6 * len(alnum))
    if kinds == {1, 2}:
        return changes >= 0.5 and len(alnum) >= 24
    return changes >= 0.4 and digit_runs >= 5 and len(set(alnum)) >= 0.5 * len(alnum)


def _s_named(flat, values=None):
    """Whether `flat` holds a value after a secret's name; with a list, the values themselves are added to it (until it holds MAX_PIECES)."""
    pos, found = 0, False
    while True:
        m = _S_DELIM.search(flat, pos)
        if not m or (values is not None and len(values) >= MAX_PIECES):
            return found
        i = m.start()
        pos = m.end()
        after = flat[i + 1:i + 6].lstrip(" \t\"'\\")
        if not after or after[0] in "<>" or _S_LINE.match(flat, i + 1):
            continue
        j = i
        while j > 0 and flat[j - 1] in " \t\"'\\" and i - j < 5:
            j -= 1
        k = j
        while k > 0 and j - k < 64 and flat[k - 1] in _S_NAME_CHARS:
            k -= 1
        low = flat[k:j].lower()
        if low.endswith(_S_STRONG_ENDS) or (low.endswith(_S_WEAK_ENDS) and not low.endswith(_S_NOT_PASS_ENDS)):
            if values is None:
                return True
            found = True
            v = i + 1
            while v < len(flat) and flat[v] in " \t\"'\\" and v - i <= 6:
                v += 1
            vm = _S_VALUE.match(flat, v)
            if vm:
                values.append(vm.group())


def _s_hex_views(text):
    """The printable text inside data written as hexadecimal (Latin-1 runs of 6 or more, UTF-16LE and UTF-16BE runs of 4 or more), or None when `text` is not such data."""
    if len(text) < 2 or not _S_HEXONLY.fullmatch(text[:MAX_HEX_JUDGED]):
        return None
    try:
        raw = bytes.fromhex(text[:MAX_HEX_JUDGED])
    except ValueError:
        return None
    return ([m.group().decode("latin-1") for m in _S_PRINT_L1.finditer(raw)] + [m.group().decode("utf-16-le", "replace") for m in _S_PRINT_U16.finditer(raw)]
            + [m.group().decode("utf-16-be", "replace") for m in _S_PRINT_U16BE.finditer(raw)] + _wide_views(raw))


def _suspect(text, kind="text"):
    """The name of the check a string fails, or None. A string of a typed kind is not tested for runs of hexadecimal digits or random-looking runs, but
    for the characters of its type; data written as hexadecimal is decoded and its printable text is tested as text."""
    if not text or text in OWN_NAMES:
        return None
    if len(text) > MAX_ONE_STRING:
        text = text[:MAX_ONE_STRING]
    if kind == "hex":
        views = _s_hex_views(text)
        if views is not None:
            for view in views:
                hit = _suspect(view, "text")
                if hit:
                    return "in binary data: " + hit
            return None
        kind = "text"
    if kind in _S_TYPED and len(text) <= 64 and _S_PLAIN_NUM.fullmatch(text):
        # digits, `. : + -`, a space, T and Z: no rule above the typed grammar can fire on these (no name, no prefix, no `@`), so the grammar alone decides
        return None if len(text) <= 3 or _S_TYPED[kind].fullmatch(text) else "not the typed grammar"
    flat = _s_normal(text)
    if "withheld" in flat:
        flat = _S_MARK.sub("<>", flat)
    low = flat.lower()
    if "private key" in low and _S_PEM.search(flat):
        return "a PEM marker"
    bare = _S_IDS.sub(" ", flat) if "-" in flat else flat            # (all three kinds of id hold a `-`)
    named_words = _has(_S_NAME_WORDS, low)
    if (named_words and ("=" in bare or ":" in bare) and _s_named(bare)) or ("-" in flat and named_words and _S_ARGNAME.search(flat)):
        return "a named secret"
    if _has(_S_PREFIX_WORDS, low) and _S_PREFIX.search(flat):
        return "a token prefix"
    if "@" in flat:
        flat_user = re.sub("(?i)mailto:", "mailto ", flat)
        if _S_USERINFO.search(flat_user) or _S_USERINFO_URL.search(flat_user) or _S_USERINFO_MARK.search(flat_user):       # (the last: a user that was replaced is still a user)
            return "user-info"
    if kind in _TYPED_KINDS:
        grammar = _S_TYPED.get(kind)
        return "not the typed grammar" if grammar is not None and len(text) > 3 and not grammar.fullmatch(text) else None
    if "=" not in bare and not _S_LONG.search(bare):
        return None                       # no run of 19 characters of these, and no `=` for a padded run: none of the checks below can find anything
    if _S_DIGITS.search(bare):
        return "a long digit run"
    labelled = _S_DIGEST_LABEL.sub(" ", bare) if "ash" in low or "sha" in low or "md5" in low else bare
    if _S_HEXRUN.search(labelled):
        return "a long hexadecimal run"
    for m in _S_B64NOPAD.finditer(labelled):
        if "/" in m.group() and "+" in m.group() and len({_class(c) for c in m.group() if c.isalnum()}) == 3:
            return "a base64 run with / and +"
    for m in _S_B64PAD.finditer(labelled):
        body = m.group().rstrip("=")
        if len(m.group()) % 4 == 0 and re.search(r"[0-9+/]", body) and len({_class(c) for c in body}) >= 2 and (("/" in body or "+" in body) or len(body) >= 20):
            return "a padded base64 run"
    for m in _S_RUN.finditer(labelled):
        if _random_run(m.group()):
            return "a random-looking run"
    return None


def _where_text(where, names=True):
    return "/" + "/".join((w[0][:60] if names else str(w[1])) for w in where)


def _replace(value, where, check, positions=False):
    BOUNDARY["replaced"] += 1
    BOUNDARY["replaced_by"][check] += 1
    if len(BOUNDARY["where"]) < MAX_WHERE:
        # the place is the keys on the way, each of them already sealed; their joining is read once more, and when it is not clean the place is the
        # positions (a key that was replaced or withheld must never come back whole through the report of where something was replaced)
        at = _where_text(where, False) if positions else _where_text(where)
        if not positions and _suspect(at, "label"):
            at = _where_text(where, False)
        BOUNDARY["where"].append({"at": at, "check": check})
    else:
        BOUNDARY["not_listed"] += 1
    return _mark(len(value.encode("utf-8", "replace")), "backstop: %s" % check, "bytes")


_CHECKED = {}
_SHORT_PLAIN = re.compile(r"[A-Za-z0-9_.]{0,15}")      # what the late path may print unjudged: 15 characters or fewer of letters, digits, `_` and `.` (no space, no `-`, so no
                                                          # argument after a flag and no `xox?-` token), and not starting like a vendor token (_unjudged)


def _unjudged(text, kind=None):
    """Whether a string may be printed past the judging time: a name this run made itself (OWN_NAMES: its schema keys, its file names), or a short plain
    string that does not start like one of the vendor tokens the block knows (a prefix and 12 characters are 15) and, in a field of a typed kind (a SID, a
    GUID, a digest ...), fits the grammar of that type as the backstop checks it."""
    if text in OWN_NAMES:
        return True
    if _SHORT_PLAIN.fullmatch(text) is None or text.lower().startswith(_S_PREFIX_WORDS):
        return False
    grammar = _S_TYPED.get(kind)
    return grammar is None or len(text) <= 3 or grammar.fullmatch(text) is not None


def _late():
    deadline = _CLOCK["deadline"]
    return deadline is not None and time.monotonic() > deadline


def seal_stop_after(seconds):
    """The seal stop of a tool: no seal runs on past `seconds` from now (its manifest's time limit less 3.5 seconds); what is left is withheld whole,
    except what _unjudged lets through. It stops the judging only, not the tool's own work: that has its own clock, which must run out first."""
    _CLOCK["stop"] = time.monotonic() + seconds


def _timed(fn):
    """`fn()` with the clock of the seal running: SEAL_BUDGET seconds from the outermost call, and never past the seal stop of the tool."""
    first = _CLOCK["deadline"] is None
    if first:
        _CLOCK["deadline"] = time.monotonic() + SEAL_BUDGET
        if _CLOCK["stop"] is not None:
            _CLOCK["deadline"] = min(_CLOCK["deadline"], _CLOCK["stop"])
    try:
        return fn()
    finally:
        if first:
            _CLOCK["deadline"] = None


# the name of a component of the Windows component store (WinSxS), as a whole name or as a component of a key or a path: architecture, words (lower case, letters up
# to 40 or letters and digits up to 16, with `.`, `-` or `_` between them, never a hexadecimal hash), the 16-digit public key token, a four-part version (not always
# there), a language or `none`, and a hash of 8 to 16 hexadecimal digits; a placeholder that layer 1 put in the place of a word, or of the architecture and a word (a
# 32-digit hash), stands for it. A real SOFTWARE hive lists them by the thousand and the backstop took their hash for a random run, so it judges the text with such a
# component taken out; layer 1 judges them as it does every name. Names, keys and paths only, lower case only; every alternative starts with a different character,
# so that a failing match is not retried in a second way.
_WORD = r"(?:[a-z]{1,40}|(?=[a-z0-9]*[0-9])[a-z0-9]{1,16}|<withheld [0-9]{1,10} (?:characters|bytes): not a plain name>)"
_WINSXS = re.compile(r"(?<![^\\/])(?:(?:amd64|x86|wow64|msil|arm64|arm|ia64)_(?![0-9a-f]+_)%s(?:[._-]{1,3}%s){0,12}|<withheld [0-9]{1,10} (?:characters|bytes): not a plain name>)"
                     r"_[0-9a-f]{16}(?:_[0-9]{1,5}(?:\.[0-9]{1,5}){3})?_[a-z0-9-]{2,12}_[0-9a-f]{8,16}(?![^\\/])" % (_WORD, _WORD))


def _without_components(text, kind):
    """`text` as the backstop judges a name, key or path: a component of the component store is one plain word."""
    return _WINSXS.sub("w", text) if kind in ("name", "key", "path") and text.count("_") >= 3 else text


def _verdict(text, kind):
    memo = (kind, text) if len(text) <= 512 and kind not in _S_TYPED else None
    hit = _CHECKED.get(memo, False) if memo else False
    if hit is False:
        hit = None if _MARK.fullmatch(text) else _suspect(_without_components(text, kind), kind)
        if memo:
            if len(_CHECKED) >= 30000:
                _CHECKED.clear()
            _CHECKED[memo] = hit
    return hit


# ---- the backstop reads the original too: what of a secret-shaped text is still in what was shown
def _pem_pieces(flat, found):
    """The base64 lines of the bodies of PEM keys: after each `PRIVATE KEY-----` (found with str.find, at most MAX_PIECES of them) up to the next
    `-----END` or MAX_PEM_BODY characters."""
    pos, bodies = 0, 0
    while bodies < MAX_PIECES and len(found) < MAX_PIECES:
        i = flat.find("PRIVATE KEY-----", pos)
        if i < 0:
            return
        start = i + 16
        end = flat.find("-----END", start, start + MAX_PEM_BODY)
        stop = start + MAX_PEM_BODY if end < 0 else end
        bodies += 1
        for m in _S_PEMLINE.finditer(flat, start, stop):
            found.append(m.group())
            if len(found) >= MAX_PIECES:
                return
        pos = max(stop, start)


def _s_pieces(flat, kind):
    """The parts of `flat` (the original text, normalised) the backstop's own rules call secret: a value after a secret's name, the password of
    user-info, a vendor token, a key's base64, and (outside typed fields) the long random-looking runs. At most MAX_PIECES of them, in this
    order; every walk over the text stops when the list is full."""
    found = []
    bare = _S_IDS.sub(" ", flat)
    _s_named(bare, found)
    for pattern, group in ((_S_ARGVAL, 1), (_S_USERINFO, "pw"), (_S_USERINFO_URL, "pw")):
        for m in pattern.finditer(flat):
            if len(found) >= MAX_PIECES:
                return found
            found.append(m.group(group))
    for m in _S_PREFIX.finditer(flat):
        if len(found) >= MAX_PIECES:
            return found
        end = m.end()
        stop = min(len(flat), end + 512)
        while end < stop and flat[end] in _S_TOKEN_CHARS:
            end += 1
        found.append(flat[m.start():end])
    _pem_pieces(flat, found)
    if kind not in _TYPED_KINDS:
        labelled = _S_DIGEST_LABEL.sub(" ", bare) if "ash" in bare or "sha" in bare.lower() or "md5" in bare.lower() or "ASH" in bare else bare
        for m in _S_B64PAD.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if _b64_shape(m.group()):
                found.append(m.group())
        for m in _S_HEXRUN.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            found.append(m.group())
        for m in _S_B64NOPAD.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if "/" in m.group() and "+" in m.group():
                found.append(m.group())
        for m in _S_RUN.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if _random_run(m.group()):
                found.append(m.group())
    return found


_RESIDUE = {}


def _residue(original, shown, kind):
    """A window of 12 characters (the whole piece when it is shorter, from 8) of something the backstop calls secret in the ORIGINAL that is still
    in what was shown: the layers above cut spans out of a string and can leave a piece of a secret between two cuts."""
    memo = (kind, original) if len(original) <= 512 else None
    if memo is not None and memo in _RESIDUE:
        return _RESIDUE[memo]
    verdict = None
    flat = _s_normal(original[:MAX_ONE_STRING])
    pieces = _s_pieces(flat, kind)[:MAX_PIECES]
    if pieces:
        kept = _S_MARK.sub("\x00", _s_normal(shown[:MAX_ONE_STRING]))
        rest = flat                                    # the original without those parts: a window that is also here is the text's own words, not the secret
        for piece in sorted(set(pieces), key=len, reverse=True):
            rest = rest.replace(piece, "\x00")
        for piece in pieces:
            n = len(piece)
            if n < 8:
                continue
            w = min(12, n)
            step = 1 if n * len(kept) <= 4000000 else max(1, (n - w + 1) // 64)       # a long piece in a long string: 64 windows, spread over it
            if any(piece[i:i + w] in kept and piece[i:i + w] not in rest for i in range(0, n - w + 1, step)):
                verdict = "a part of a secret-shaped text"
                break
    if memo is not None:
        if len(_RESIDUE) >= 30000:
            _RESIDUE.clear()
        _RESIDUE[memo] = verdict
    return verdict


# ---- the walker ----------------------------------------------------------------------------------------------------------------------------
_SCALARS = (bool, int, float)
_SCALAR_TYPES = frozenset(_SCALARS)


_KEYS = {}


def _seal(value, kind, field, where, guard, fname=""):
    """`value` with every string sealed by the type of its field, and (guard) read back by the backstop. Keys are names. FIELDS maps a JSON key to the
    kind of what it holds, or to a function of the key of one item for a dict whose items have kinds of their own (event data, registry values).
    `where` is the tuple of (sealed key or position, position) on the way down."""
    if isinstance(value, str):
        k = getattr(value, "kind", kind)
        if _late():
            # past the budget the rest is withheld whole, fail closed; what is let through is only a name of this run's own and a short plain string (_unjudged)
            return value if _unjudged(value, k) else _replace(value, where, "the judging time ran out", True)
        out = show(value, k, field)
        if guard:
            check = _verdict(out, k)
            if not check and out != value:
                check = _residue(str(value), out, k)
            if check:
                return _replace(out, where, check)
        return out
    if value is None or isinstance(value, _SCALARS):
        return value
    if isinstance(value, dict):
        hook = FIELDS.get(fname)
        hook = hook if callable(hook) else None
        kk = KEY_KINDS.get(fname, "name")
        out, dupes = {}, {}
        for idx, (key, v) in enumerate(value.items()):
            if isinstance(key, str):
                if _late():
                    sk = key if _unjudged(key) else _replace(key, where + (("(key)", idx),), "the judging time ran out", True)
                else:
                    sk = _KEYS.get((kk, field, key, guard))
                    if sk is None:
                        sk = show(key, kk, field)
                        if guard:
                            check = _verdict(sk, kk)
                            if check:
                                sk = _replace(sk, where + (("(key)", idx),), check)
                        if sk == key and len(key) <= 128:
                            # a key that comes out as it went in changed nothing (no count, no list): its judging is not repeated for the next row
                            if len(_KEYS) >= 20000:
                                _KEYS.clear()
                            _KEYS[(kk, field, key, guard)] = sk
            elif key is None or isinstance(key, _SCALARS):
                sk = key
            else:
                key = str(key)
                sk = show(key, "name", field)
            if sk in out:
                # many names become one placeholder: the next free " #n" of that placeholder, counted (a probe from the first would be quadratic)
                n = dupes.get(sk, 1)
                while True:
                    n += 1
                    renamed = "%s #%d" % (sk, n)
                    if renamed not in out:
                        break
                dupes[sk] = n
                sk = renamed
            if v is None or type(v) in _SCALAR_TYPES:
                out[sk] = v                               # (a number, a truth value or nothing: there is no string to seal)
                continue
            fk = key if isinstance(key, str) else ""
            sub_kind = (hook(key) if hook else None) or _kind_of(fk, kind)
            label = sk if isinstance(sk, str) else str(sk)
            out[sk] = _seal(v, sub_kind, (field + "." + fk) if field and fk else (fk or field), where + ((label, idx),), guard, fk)
        return out
    if isinstance(value, (list, tuple)):
        return [_seal(v, kind, field, where + ((str(i), i),), guard, fname) for i, v in enumerate(value)]
    return _seal(str(value), "text", field, where, guard, fname)       # anything else the serialiser would have printed with str()


def _kind_of(field, inherited):
    k = FIELDS.get(field)
    return k if isinstance(k, str) else inherited


def seal(value, kind="text", field=""):
    return _timed(lambda: _seal(value, kind, field, (), True))


_ROW_TYPES = frozenset((str, int, float, bool))
_ROW = [None, None]             # the last row of plain scalars that was sealed without anything being replaced, and what it came out as


def row_object(row):
    """A row of a paging file, sealed and read back: what the file may hold. A tool that writes the same row to two files (every key listed, and
    the nodes of a walk) has it judged once: the second is the first's result, the same judging with nothing to count or list."""
    key = None
    if isinstance(row, dict):
        for k, v in row.items():
            if type(k) is not str or (v is not None and type(v) not in _ROW_TYPES):
                break
        else:
            # (the type is part of the key: 1, True and 1.0 are equal and print differently; a float by its repr, as -0.0 equals 0.0)
            key = tuple((k, type(v), repr(v) if type(v) is float else v) for k, v in row.items())
    if key is not None and _ROW[0] == key:
        return dict(_ROW[1])
    replaced = BOUNDARY["replaced"]
    out = _timed(lambda: _seal(row, "text", "", (), True))
    if key is not None and BOUNDARY["replaced"] == replaced:
        _ROW[0], _ROW[1] = key, dict(out)
    return out


def boundary_summary():
    return {"strings_withheld": BOUNDARY["withheld"], "withheld_by_reason": dict(BOUNDARY["by"]),
            "strings_replaced_by_the_backstop": BOUNDARY["replaced"], "replaced_by_check": dict(BOUNDARY["replaced_by"]),
            "replaced_at": list(BOUNDARY["where"]), "replaced_not_listed": BOUNDARY["not_listed"], "values": values_summary(),
            "note": "every key and value of this answer and of its paging files was judged by the type of its field: a name, path, key or URL is shown only when it "
                    "fits a plain grammar (a path component by component), free text has token-shaped runs, user-info and the value after a secret's name withheld, "
                    "and a second check written apart from both read it back. A withheld text is <withheld N characters: reason>. Not recognised: a secret that does "
                    "not look like one (a plain password or passphrase, a UUID-shaped key, anything under 16 characters in a name)."}


def _last_look(obj):
    """What this block adds to an answer after the walker (the report of what it did) is read once more by the backstop, keys and values."""
    if isinstance(obj, str):
        return _mark(len(obj), "backstop: a part of a secret-shaped text") if _suspect(obj, "label") else obj
    if isinstance(obj, dict):
        return {_last_look(k): _last_look(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_last_look(v) for v in obj]
    return obj


def answer_object(doc):
    """The answer (or an error answer), sealed and read back. A string the backstop had to replace makes a complete answer partial."""
    out = _timed(lambda: _seal(doc, "text", "", (), True))
    if isinstance(out, dict):
        out["boundary"] = _last_look(boundary_summary())
        if BOUNDARY["replaced"] > 0 and out.get("status") == "complete":
            out["status"] = "partial"
            basis = out.get("status_basis")
            out["status_basis"] = "%s%d string(s) still held a secret-shaped text when the answer was checked on its way out and were replaced (see boundary)" % (
                basis + "; " if isinstance(basis, str) and basis else "", BOUNDARY["replaced"])
    return out


def emit(doc, **dumps_kwargs):
    """Print an answer through the boundary (the only way an answer leaves a tool that carries this block)."""
    obj = answer_object(doc)
    try:
        text = json.dumps(obj, ensure_ascii=False, default=str, **dumps_kwargs)
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = json.dumps(obj, ensure_ascii=True, default=str, **dumps_kwargs)
    try:
        # a signal that arrives while the answer is being written must not start a second one: signals are held from here (the answer is whole)
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    print(text, flush=True)
# END SHARED BOUNDARY


# BEGIN SHARED GUARD
# The same text is in fsevents_parse, knowledgec_query and unified_log (a macos-forensics test holds the copies equal). The boundary block above is a copy of the
# windows-forensics pack's and is not edited here; these are the two checks this pack makes around it until the block itself is revised, and they call only what
# the block already has.
#  - guard_hex: data written as hexadecimal is judged by the block as printable runs of the bytes as they are, so a token that a NUL, an invisible character or a
#    control character cuts into pieces of 15 characters or fewer shows no run that looks like a secret, and is printed whole. A field that is hex (a BLOB's head,
#    a UUID, the raw bytes of a path) is judged here once more on the text the bytes make with the NULs and the invisible characters (format characters, combining
#    marks, private-use and unassigned code points, fillers) taken out, in UTF-8 and in UTF-16 (both byte orders and offsets), the way the block reads a text; and
#    once more for every control character that occurs in that text, with that one character taken out. It is withheld when one of these
#    texts holds a secret-shaped run. (Taking out all control characters at once would join the printable bytes of random data into runs: 1% of 4 KB of random
#    bytes then held a random-looking run. A token cut by two or more different control characters is not read through.) A field so long and so full of control
#    characters that this would take more than _VIEW_WORK characters of reading is withheld.
#  - guard_text: a FileVault personal recovery key (six groups of four capitals and digits, 2-9, joined by `-`) is not a shape the block knows; it is withheld here.
#    The id of a user's temporary folder (`/var/folders/xx/` and 30 characters) that the block would withhold as a token is shown as an alias of its sha256.
#  - emit_answer: the answer is printed as emit() prints it, but a stop signal that arrived while it was sealed is named in it; one that arrives while the text is
#    made or written cannot be (the text is out), and is found afterwards: the exit code is the signal's and stderr says that the answer is whole.
#  - print_order_until: print_order() under a clock, for a list that may be as long as a hostile file makes it.
# Both withhold through the block's own _withheld, so they are counted, listed and written to the values file like everything else it withholds.
import random

_VAULT = re.compile(r"[A-Z2-9]{4}(?:-[A-Z2-9]{4}){5}")          # (no look-around: a key that stands next to other letters or digits in a BLOB, a name or a path is a key too)
_ASCII_RUN = re.compile(r"[\x20-\x7e]{6,}")
_CONTROL = re.compile(r"[\x01-\x1f\x7f-\x9f]")
_NOT_PRINTABLE = re.compile(rb"[^\x20-\x7e]")
_INVISIBLE_CATS = frozenset(("Cf", "Mn", "Me", "Zl", "Zp", "Co", "Cn", "Cs"))
_CONTROLS = tuple(chr(c) for c in list(range(1, 32)) + list(range(0x7F, 0xA0)))
_VIEW_WORK = 1 << 21                                # characters read for the control-character views of one field; a field over it is withheld


class _Invisible(dict):
    """A translation table that drops what cuts a token without showing: the NUL, the format characters, the combining marks, the private-use and unassigned
    code points and the fillers. The control characters stay (hex_text_views reads a text once more for each one that may be a separator, one at a time):
    dropping them all as well joins the printable bytes of random data into runs (1% of 4 KB of random bytes then held a random-looking run)."""

    def __missing__(self, o):
        if len(self) > 20000:
            self.clear()
        self[o] = None if o == 0 or unicodedata.category(chr(o)) in _INVISIBLE_CATS or o in _FILLERS else o
        return self[o]


_INVISIBLE = _Invisible()


_TMP_FOLDER = re.compile(r"(?<=var/folders/)([a-z0-9_]{2})/([a-z0-9_]{30})(?=/|\Z)")


def _tmp_alias(m):
    if shown_text(m.group(2), "name", "path") == m.group(2):
        return m.group(0)                                       # the block prints this id as it is: so does the tool
    _withheld(m.group(2), "token-shaped text", "path")          # (counted, and kept in the values file of a secret job: what is printed is the alias)
    return "%s/tmp-id-%s" % (m.group(1), hashlib.sha256(m.group(2).encode("utf-8")).hexdigest()[:12])


def guard_text(s, field=""):
    """`s` with every FileVault-shaped recovery key withheld, and the id of a user's temporary folder under /var/folders (30 characters of a typed id that the
    block takes for a token, on most paths of a Mac that has run a program) shown as a short alias of its sha256 when the block would withhold it, the same alias
    for the same id; anything else as it is."""
    if not isinstance(s, str):
        return s
    if "var/folders/" in s:
        s = _TMP_FOLDER.sub(_tmp_alias, s)
    if len(s) < 29 or "-" not in s:
        return s
    return _VAULT.sub(lambda m: _withheld(m.group(), "secret value", field), s)


def _ascii_runs(text):
    text = text.translate(_INVISIBLE)
    if "\u0131" in text or "\u0130" in text:
        text = text.replace("\u0131", "I").replace("\u0130", "I")      # (the block reads the Turkish dotted and dotless i as the letter)
    return _ASCII_RUN.findall(unicodedata.normalize("NFKC", text))


def _hex_text_views(raw):
    """(views, whole): the ASCII runs (6 or more) of `raw` read as text with the NULs and the invisible characters taken out, as UTF-8 and as UTF-16 (both byte
    orders, both offsets), and again with one control character taken out, for each that occurs in a text. `whole` is false when the
    second reading would pass _VIEW_WORK characters: the views are then not all there."""
    texts = [raw.decode("utf-8", "replace")]
    for codec in ("utf-16-le", "utf-16-be"):
        for offset in (0, 1):
            part = raw[offset:]
            texts.append(part[:len(part) - len(part) % 2].decode(codec, "replace"))
    views, work = [], 0
    for text in texts:
        views += _ascii_runs(text)
        if _CONTROL.search(text) is None:
            continue
        for c in _CONTROLS:
            if c in text:
                work += len(text)
                if work > _VIEW_WORK:
                    return views, False
                views += _ascii_runs(text.replace(c, ""))
    return views, True


def guard_hex(s, field=""):
    """`s` (data written as hexadecimal) or, when its text with the NULs and the invisible characters taken out holds a secret-shaped run, the placeholder."""
    if not isinstance(s, str) or len(s) < 12 or len(s) > MAX_HEX_JUDGED or len(s) % 2:
        return s
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return s
    if _NOT_PRINTABLE.search(raw) is None:
        # all printable: the block read it as one run; only the key it does not know is looked for
        return _withheld(s, "binary data holding a secret-shaped text", field) if _VAULT.search(raw.decode("ascii")) else s
    views, whole = _hex_text_views(raw)
    if not whole:
        return _withheld(s, "binary data over the judged size", field)
    if views and _quietly(lambda: any(_layer2(v, "") != v or _deny_text(v, "") != v or _suspect(v) or _VAULT.search(v) for v in views)):
        return _withheld(s, "binary data holding a secret-shaped text", field)
    return s


def shown_text(s, kind, field=""):
    """The text the answer prints for `s` once guard_text has been applied: what a filter or a sort over a name must look at."""
    return _quietly(lambda: sealed_text(guard_text(s, field), kind, field))

def print_order_until(items, kind="name", text=str, until=None):
    """(items in the order print_order() gives, whole), judged under a clock: when `until` (a time.monotonic() value) passes first, the items judged by then
    come in print order and the rest after them in a random order, and `whole` is false. The items are taken in a random order, so that which ones were judged
    says nothing about their names or their place in a listing."""
    items = list(items)
    random.shuffle(items)
    keyed = []

    def judge():
        for n, i in enumerate(items):
            if until is not None and n % 16 == 0 and time.monotonic() > until:
                return n
            raw = text(i)
            shown = _seal(raw, kind, "", (), True) if isinstance(raw, str) and raw else raw
            keyed.append((shown, hashlib.blake2b(_ORDER_SALT + raw.encode("utf-8", "surrogatepass"), digest_size=8).digest(), n, i))
        return len(items)

    judged = _quietly(judge)
    keyed.sort(key=lambda k: (k[0], k[1], k[2]))
    return [k[3] for k in keyed] + items[judged:], judged == len(items)


def emit_answer(doc, interrupted=None, **dumps_kwargs):
    """emit() with one addition: the answer is sealed first, and a stop signal that arrived while it was sealed (held until the answer is out, on purpose) is
    reported in it: the status is partial, `interrupted` names the signal. Prints the answer and returns the signal number for the exit code (or None)."""
    obj = answer_object(doc)
    late = pending_stop_signal() if interrupted is None else None
    if late is not None and isinstance(obj, dict):
        interrupted = late
        obj["interrupted"] = signal_name(late)
        if obj.get("status") == "complete":
            obj["status"] = "partial"
        basis = obj.get("status_basis")
        obj["status_basis"] = "%s%s arrived while the answer was being sealed; the answer below is whole" % (basis + "; " if isinstance(basis, str) and basis else "", signal_name(late))
    try:
        text = json.dumps(obj, ensure_ascii=False, default=str, **dumps_kwargs)
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = json.dumps(obj, ensure_ascii=True, default=str, **dumps_kwargs)
    print(text, flush=True)
    if interrupted is None:
        # a signal that landed while the text was being made or written cannot change what is printed; it is found now, and the exit code and stderr say it
        late = pending_stop_signal()
        if late is not None:
            interrupted = late
            sys.stderr.write("%s arrived while the answer was being written; the answer on stdout is whole and was not marked\n" % signal_name(late))
            sys.stderr.flush()
    return interrupted
# END SHARED GUARD


OWN_NAMES.update((
    "db", "parser", "status", "status_basis", "interrupted", "problems", "entries", "entry_count", "entries_inline", "complete_entries", "inline_limited",
    "inline_bounded_by_bytes", "inline_byte_limit", "kept_earlier_larger_result", "values", "filters_applied", "filters_unapplied", "schema", "source_used",
    "streams", "streams_total", "streams_pages", "note", "resume", "limits", "error", "type", "reason", "sql", "tables", "columns", "table", "column", "rowid",
    "source_table", "z_pk", "stream", "value_string", "value_integer", "value_double", "value_type_code", "start_raw", "end_raw", "created_raw", "start", "end",
    "created", "duration_seconds", "utc_offset_seconds", "uuid", "zobject_other", "metadata", "source", "joins", "fingerprint", "zobject_columns", "cap",
    "truncated", "exported", "exported_bytes", "export_requested", "database", "staged", "sidecars", "bytes", "sha256", "open_mode", "database_sha256",
    "database_bytes", "wal", "wal_checkpoint", "journal", "staged_copy", "count", "first_start_raw", "last_start_raw", "first_start", "last_start", "matched",
    "returned", "all_results", "all_results_format", "_text_head", "_text_bytes", "_truncated", "_where", "_blob_bytes", "_hex", "_whole_value_file",
    "_whole_value_bytes_written", "_export", "_float", "state", "frames_valid", "frames_committed", "frames_in_file", "page_size", "checkpoint_sequence",
    "busy", "log", "checkpointed", "rollback_applied", "journal_present_after_open", "database_sha256_as_acquired", "database_sha256_after_open",
    "boundary", "max_seconds", "max_seconds_requested", "seconds_used", "stopped_after_z_pk", "last_z_pk", "last_start", "resume_since", "rows_read",
    "to_go_on", "after_start_raw", "after_z_pk", "streams_in_file", "streams_not_listed", "tables_not_listed", "stream_blind_rows", "stream_blind_streams", "ZOBJECT", "ZSTRUCTUREDMETADATA", "ZSOURCE", "write_values", "export_oversize", "max_stage_bytes", "max_export_bytes", "contains_secret_values",
))
FIELDS.update({
    "db": "path", "database": "path", "stream": "path", "value_string": "text", "start": "time", "end": "time", "created": "time",
    "first_start": "time", "last_start": "time", "resume_since": "time", "uuid": "hex", "_hex": "hex", "_text_head": "text", "_whole_value_file": "path",
    "complete_entries": "path", "all_results": "path", "database_sha256": "digest", "database_sha256_as_acquired": "digest",
    "database_sha256_after_open": "digest", "sha256": "digest", "fingerprint": "digest", "values_file": "path",
})


class SealedPage(LosslessPage):
    """A page whose rows are written through the boundary (the inline page is sealed with the answer)."""

    def _write(self, row):
        super()._write(row_object(row))

    def add(self, row):
        with held():                      # a row reaches the page and its file whole, or the signal waits for it
            super().add(row)

    def finish(self):
        with held():
            result = super().finish()
        for name in ("all_results", "kept_earlier_larger_result"):
            if result.get(name):
                OWN_NAMES.add(result[name])
        return result


def when(value):
    if value is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(
            float(value) + APPLE_EPOCH, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def to_apple(text, name):
    try:
        parsed = datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        fail("since and until must be ISO 8601, e.g. 2026-02-14T00:00:00Z", **{name: text})
    if not parsed.tzinfo:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.timestamp() - APPLE_EPOCH


def quote(name):
    return '"%s"' % name.replace('"', '""')


def plain(value):
    """A non-text, non-BLOB SQLite value as JSON: an infinite REAL as its name (JSON has none)."""
    if isinstance(value, float) and not math.isfinite(value):
        return {"_float": repr(value)}
    return value


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(text))[:80]


class Shaper:
    """Turns the bounded columns of a row into JSON cells, fetches the head of a TEXT or large BLOB value through a blob handle, and streams
    an oversize value to a file when asked. Nothing here reads a whole cell into memory: a statement never touches a TEXT cell (only its
    type, which SQLite answers from the record header), so a 300 MB cell costs a 16 KiB read."""

    def __init__(self, connection, export, max_export, opener=None):
        self.connection = connection
        self.opener = opener              # makes a second connection for blob handles: CPython's sqlite3 keeps a weak reference to every handle a
        self.handles = None               # connection opened, until the connection closes, so the handles of a long read go through connections that are replaced
        self.opened = 0
        self.export = export
        self.max_export = max_export
        self.exported_bytes = 0
        self.truncated = 0
        self.exported = 0
        self.export_refused = 0
        self.head_unavailable = 0
        self.loaded_by_statement = 0      # cells a statement had to load because no blob handle could be had (Python before 3.11, WITHOUT ROWID)
        self.dir = None
        self.shown = None

    def handle_source(self):
        """The connection a blob handle is opened on: a second one, replaced every REOPEN_EVERY handles (the main connection when none can be made)."""
        if self.opener is None:
            return self.connection
        if self.handles is None or self.opened >= REOPEN_EVERY:
            try:
                if self.handles is not None:
                    self.handles.close()
                self.handles = self.opener()
                self.opened = 0
            except (sqlite3.Error, UnicodeError):
                self.opener = None
                return self.connection
        self.opened += 1
        return self.handles

    def head(self, table, column, rowid):
        """The first VALUE_CAP bytes of one stored value, without loading the rest when a blob handle can be had."""
        try:
            with self.handle_source().blobopen(table, column, rowid, readonly=True) as blob:
                return blob.read(VALUE_CAP)
        except (AttributeError, sqlite3.Error):
            pass
        try:
            row = self.connection.execute("SELECT substr(%s,1,%d) FROM %s WHERE rowid = ?" % (quote(column), VALUE_CAP, quote(table)),
                                          (rowid,)).fetchone()
            value = row[0] if row else None
            self.loaded_by_statement += 1
            return value.encode("utf-8", "backslashreplace") if isinstance(value, str) else value
        except sqlite3.Error:
            self.head_unavailable += 1
            return None

    def text(self, table, column, rowid):
        """A TEXT cell: whole when it is at most VALUE_CAP characters, else its head and its byte length. Read through a blob handle, which
        loads only what is asked for; the head is HEAD_BYTES, enough for VALUE_CAP + 1 characters of UTF-8."""
        try:
            with self.handle_source().blobopen(table, column, rowid, readonly=True) as blob:
                size = len(blob)
                raw = blob.read(min(size, HEAD_BYTES))
        except (AttributeError, sqlite3.Error, TypeError):
            raw, size = None, None
        whole = True                      # whether `value` is the whole cell
        if raw is None:
            # no blob handle (a WITHOUT ROWID table, a view): a statement reads the cell, which loads it whole
            try:
                row = self.connection.execute("SELECT substr(%s,1,%d), length(CAST(%s AS BLOB)) FROM %s WHERE rowid = ?"
                                              % (quote(column), VALUE_CAP + 1, quote(column), quote(table)), (rowid,)).fetchone()
            except sqlite3.Error:
                self.head_unavailable += 1
                return {"_text_head": "", "_text_bytes": None, "_truncated": True, "_where": {"table": table, "column": column, "rowid": rowid}}
            self.loaded_by_statement += 1
            value, size = row[0] or "", row[1]
            whole = len(value) <= VALUE_CAP
        else:
            value = raw.decode("utf-8", "backslashreplace")
            whole = size <= len(raw)
        if whole and len(value) <= VALUE_CAP:
            return value
        return self.oversize("text", value[:VALUE_CAP], size, table, column, rowid)

    def write_whole(self, table, column, rowid, kind):
        """Stream one stored value to a new file (1 MiB at a time); its name, or why it was not written."""
        if not hasattr(self.connection, "blobopen"):
            return {"_export": "not written: this Python has no blob handles (3.11 or later is needed)"}
        try:
            with self.handle_source().blobopen(table, column, rowid, readonly=True) as blob:
                size = len(blob)
                if self.exported_bytes + size > self.max_export:
                    self.export_refused += 1
                    return {"_export": "not written: it would pass max_export_bytes (%d)" % self.max_export}
                if self.dir is None:
                    # a secret job only (checked before anything was read): the file is a sealed secret output under $OUT
                    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
                    self.dir = Path(out) / "tool-output" / "knowledgec-values"
                    self.shown = "store/jobs/%s/out/tool-output/knowledgec-values" % safe_name(job)
                    self.dir.mkdir(parents=True, exist_ok=True)
                base = "%s.%s.%s" % (safe_name(table), safe_name(column), rowid)
                n = 0
                while True:
                    name = "%s%s.%s" % (base, "" if n == 0 else "-%d" % n, "txt" if kind == "text" else "bin")
                    try:
                        fd = os.open(str(self.dir / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                        break
                    except FileExistsError:
                        n += 1
                with os.fdopen(fd, "wb") as out:
                    done = 0
                    while done < size:
                        block = blob.read(min(1 << 20, size - done))
                        if not block:
                            break
                        out.write(block)
                        done += len(block)
                self.exported_bytes += done
                self.exported += 1
                return {"_whole_value_file": "%s/%s" % (self.shown, name), "_whole_value_bytes_written": done}
        except (OSError, sqlite3.Error) as exc:
            return {"_export": "not written: %s" % (type(exc).__name__ if not isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc.strerror or "error"))}

    def cell(self, value, length, table, column, rowid):
        return guarded(self.cell_unguarded(value, length, table, column, rowid))

    def cell_unguarded(self, value, length, table, column, rowid):
        if length == TEXT_HANDLE and rowid is not None:
            return self.text(table, column, rowid)
        if isinstance(value, str):
            if len(value) <= VALUE_CAP:
                return value
            return self.oversize("text", value[:VALUE_CAP], length, table, column, rowid)
        if value is None and length is not None and length > VALUE_CAP:
            head = self.head(table, column, rowid)
            return self.oversize("blob", head if head is not None else b"", length, table, column, rowid)
        if isinstance(value, (bytes, bytearray)):
            return {"_blob_bytes": len(value), "_hex": bytes(value).hex(), "_truncated": False}
        return plain(value)

    def oversize(self, kind, head, length, table, column, rowid):
        self.truncated += 1
        if kind == "text":
            out = {"_text_head": head, "_text_bytes": length, "_truncated": True}
        else:
            out = {"_blob_bytes": length, "_hex": bytes(head).hex(), "_truncated": True}
        out["_where"] = {"table": table, "column": column, "rowid": rowid}
        if self.export and rowid is not None:
            out.update(self.write_whole(table, column, rowid, kind))
        return out


def guarded(cell):
    """A cell as the guard block sees it before the boundary does: a recovery key in text, and a token cut by NULs or invisible characters in the hex of a BLOB."""
    if isinstance(cell, str):
        return guard_text(cell, "value_string")
    if isinstance(cell, dict):
        if isinstance(cell.get("_text_head"), str):
            cell["_text_head"] = guard_text(cell["_text_head"], "_text_head")
        if isinstance(cell.get("_hex"), str):
            cell["_hex"] = guard_hex(cell["_hex"], "_hex")
    return cell


def bounded_select(alias, prefix, column):
    """Two select terms for one column: its value, and its length slot. A BLOB longer than VALUE_CAP is not read at all (typeof() and
    length() are answered from the record header); a TEXT cell is not read by the statement either, its slot says TEXT_HANDLE and the
    cell is read through a blob handle. Without blob handles (Python before 3.11) a TEXT value is cut with substr(), which loads it."""
    c = "%s.%s" % (alias, quote(column))
    if HAVE_HANDLES:
        value = ("CASE typeof(%s) WHEN 'text' THEN NULL WHEN 'blob' THEN CASE WHEN length(%s) > %d THEN NULL ELSE %s END ELSE %s END"
                 % (c, c, VALUE_CAP, c, c))
        length = "CASE typeof(%s) WHEN 'blob' THEN length(%s) WHEN 'text' THEN %d END" % (c, c, TEXT_HANDLE)
        return ["%s AS %s" % (value, quote(prefix + "|" + column)), "%s AS %s" % (length, quote(prefix + "#" + column))]
    value = ("CASE typeof(%s) WHEN 'text' THEN substr(%s,1,%d) WHEN 'blob' THEN "
             "CASE WHEN length(%s) > %d THEN NULL ELSE %s END ELSE %s END" % (c, c, VALUE_CAP + 1, c, VALUE_CAP, c, c))
    length = ("CASE typeof(%s) WHEN 'blob' THEN length(%s) WHEN 'text' THEN "
              "CASE WHEN length(substr(%s,1,%d)) > %d THEN length(CAST(%s AS BLOB)) END END" % (c, c, c, VALUE_CAP + 1, VALUE_CAP, c))
    return ["%s AS %s" % (value, quote(prefix + "|" + column)), "%s AS %s" % (length, quote(prefix + "#" + column))]


class StageTimeUp(Exception):
    """The tool's own clock (max_seconds) ran out while the database was being copied into the private directory."""


def sha256_copy(src, dst, deadline=None):
    """Copy `src` to a new file `dst` (mode 0600: the copy is the evidence's bytes) and return the sha256 of what was copied; StageTimeUp past `deadline`."""
    digest = hashlib.sha256()
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with open(src, "rb") as read, os.fdopen(fd, "wb") as write:
        for block in iter(lambda: read.read(1 << 20), b""):
            digest.update(block)
            write.write(block)
            if deadline is not None and time.monotonic() > deadline:
                raise StageTimeUp()
    return digest.hexdigest()


STAGE_LOCK = ".lock"


def lock_stage(stage):
    """Hold an exclusive lock on a file in the private directory until the process ends (the kernel drops it when the process dies, SIGKILL included), so that
    a later run can tell a live run's directory from a dead one's without a process number: those are reused, and mean nothing in another PID namespace."""
    try:
        import fcntl
        fd = os.open(os.path.join(stage, STAGE_LOCK), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except (ImportError, OSError):
        return None


def stage_is_live(entry):
    """Whether the directory `entry` of an earlier run still belongs to a running tool: its lock file is locked; or, with no lock file (an older run, or one
    that is only now being made), the process it is named for exists."""
    try:
        import fcntl
        fd = os.open(os.path.join(entry.path, STAGE_LOCK), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except ImportError:
        fd = None
    except OSError:
        fd = None
    if fd is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # the lock is free: nobody holds it, the run is over (unless the file was made this very moment, before its maker took the lock)
            return time.time() - os.fstat(fd).st_mtime < 2.0
        except OSError:
            return True
        finally:
            os.close(fd)
    m = re.fullmatch(r"knowledgec-([0-9]+)-[A-Za-z0-9_]+", entry.name)
    try:
        os.kill(int(m.group(1)), 0)
        return True                                    # alive (or not ours to signal)
    except PermissionError:
        return True
    except (ProcessLookupError, OverflowError, ValueError):
        return False


def remove_dead_stages(parent):
    """Remove the private copies an earlier run of this tool left behind when it was killed without a chance to clean up (SIGKILL): a directory of
    `parent` named for a run that is over (its lock is free). A live run's directory, a link and anything else are left alone."""
    try:
        entries = list(os.scandir(parent))
    except OSError:
        return
    for entry in entries:
        if re.fullmatch(r"knowledgec-([0-9]+)-[A-Za-z0-9_]+", entry.name) is None or entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            continue
        if not stage_is_live(entry):
            shutil.rmtree(entry.path, ignore_errors=True)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def wal_inventory(path):
    """What the WAL says about itself, from its header and its frame headers: the frames of its current
    generation (their salts match the header's) and the last commit among them. Checksums are not verified."""
    size = os.path.getsize(path)
    info = {"bytes": size}
    if size < 32:
        info.update(state="empty or shorter than its 32-byte header", frames_valid=0, frames_committed=0)
        return info
    with open(path, "rb") as fh:
        head = fh.read(32)
        magic, _version, page, seq, salt1, salt2 = struct.unpack(">IIIIII", head[:24])
        if magic not in (0x377F0682, 0x377F0683) or not 512 <= page <= 65536 or page & (page - 1):
            info.update(state="not a WAL header (magic %08x, page size %d)" % (magic, page), frames_valid=0, frames_committed=0)
            return info
        stride = 24 + page
        total = (size - 32) // stride
        valid, committed = 0, 0
        for i in range(total):
            fh.seek(32 + i * stride)
            frame = fh.read(24)
            if len(frame) < 24:
                break
            pgno, commit, s1, s2 = struct.unpack(">IIII", frame[:16])
            if s1 != salt1 or s2 != salt2 or pgno == 0:
                break
            valid += 1
            if commit:
                committed = valid
    info.update(page_size=page, checkpoint_sequence=seq, frames_in_file=total, frames_valid=valid, frames_committed=committed,
                state="frames of the current generation counted from their salts; checksums not verified")
    return info


def stream_key(name):
    """A stream name as one string whatever SQLite stored (the key the filter and the stored value are compared by)."""
    if isinstance(name, str):
        return name
    if isinstance(name, (bytes, bytearray)):
        return bytes(name).decode("utf-8", "backslashreplace")
    return str(name)


def printed_stream(name):
    """The text the answer prints for a stream name (a name longer than VALUE_CAP is printed as its head, a TEXT head)."""
    text = stream_key(name)
    if len(text) > VALUE_CAP:
        return shown_text(text[:VALUE_CAP], "text", "_text_head")
    return shown_text(text, "path", "stream")


def read_inventory(connection, st, columns, visit=None):
    """The streams of the file, in one streamed pass (GROUP BY), under the clock of the statement and of `st["until"]` (sqlite3.Error when it ran out or
    failed): {"total": the number of distinct streams, "top": the STREAMS_LISTED_MAX with the most entries, ties cut at random}. `visit(name, count)` is called
    for every stream (the stream filter judges each one). Nothing but the top is kept, so a file of a million stream names costs a pass, not a list. Read
    once: the stream filter needs it before the rows, the list of streams after them."""
    if st["inventory"] is None:
        start_col = "ZSTARTDATE" if "ZSTARTDATE" in columns else "NULL"
        top, total = [], 0
        for number, row in enumerate(connection.execute("SELECT ZSTREAMNAME, COUNT(*), MIN(%s), MAX(%s) FROM ZOBJECT GROUP BY 1" % (start_col, start_col))):
            if number % 64 == 0 and (STOP["signal"] is not None or time.monotonic() > st["until"]):
                st["abort"] = "signal" if STOP["signal"] is not None else (st["abort"] or "time")
                raise sqlite3.OperationalError("interrupted")
            total += 1
            if visit is not None:
                visit(row[0], row[1])
            item = ((row[1], random.random(), number), tuple(row))
            if len(top) < STREAMS_LISTED_MAX:
                heapq.heappush(top, item)
            elif item[0] > top[0][0]:
                heapq.heapreplace(top, item)
        st["inventory"] = {"total": total, "top": [t for _k, t in top]}
    return st["inventory"]


def list_tables(connection, deadline):
    """(the tables of the file as the answer lists them, how many there are, the names of ZOBJECT, ZSTRUCTUREDMETADATA and ZSOURCE that exist): at most
    TABLES_LISTED_MAX, the three the tool reads always among them and the others a random pick, in the order they are printed (print_order_until)."""
    own, others, total, seen = ("ZOBJECT", "ZSTRUCTUREDMETADATA", "ZSOURCE"), [], 0, set()
    for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        total += 1
        if name in own:
            seen.add(name)
        elif len(others) < TABLES_LISTED_MAX - len(own):
            others.append(name)
        else:
            pick = random.randrange(total)
            if pick < len(others):
                others[pick] = name
    listed, _whole = print_order_until([guard_text(n, "table") for n in others + sorted(seen)], "text", text=lambda t: t if isinstance(t, str) else "", until=deadline)
    return listed, total, seen


def stage_parent():
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        return Path(out) / "knowledgec-stage"
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    return Path("work") / agent


def secret_job():
    """Whether this process is a job the harness runs as secret output: the only place a value is written to a file."""
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT") and os.environ.get("SECRET_OUTPUT") == "1")


def run_query(args):
    started = time.monotonic()
    db = args.get("db")
    if not isinstance(db, str) or not db:
        fail("db is required: a knowledgeC.db")
    if not os.path.isfile(db):
        fail("no such database", db=db)
    OWN_NAMES.add(db)

    def positive(name, default):
        value = args.get(name, default)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            fail("%s must be a positive integer" % name, **{name: value})
        return value

    limit = positive("limit", 500)
    max_stage = positive("max_stage_bytes", DEFAULT_MAX_STAGE)
    inline_bytes = positive("max_inline_bytes", DEFAULT_INLINE_BYTES)
    max_export = positive("max_export_bytes", DEFAULT_MAX_EXPORT)
    max_seconds = args.get("max_seconds", DEFAULT_MAX_SECONDS)
    if not isinstance(max_seconds, (int, float)) or isinstance(max_seconds, bool) or max_seconds <= 0:
        fail("max_seconds must be a positive number", max_seconds=max_seconds)
    requested_seconds = max_seconds
    max_seconds = min(max_seconds, MAX_SECONDS_LIMIT)
    deadline = started + max_seconds
    export = args.get("export_oversize", False)
    if not isinstance(export, bool):
        fail("export_oversize must be true or false")
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    for flag, asked in (("export_oversize", export), ("write_values", write_values)):
        if asked and not secret_job():
            # the manifest declares secret_output for these arguments and the harness then runs the job as secret output; this holds when it does not
            fail("%s is refused: whole values and the originals of what was withheld are written only in a job the harness runs as secret output "
                 "(job_run with secret_output: true), where the file is a sealed secret output. Nothing was written." % flag, **{flag: True})
    out_name = args.get("out_file")
    if out_name is not None and (not isinstance(out_name, str) or not out_name):
        fail("out_file must be a non-empty string")
    if out_name is not None:
        resolve_output(out_name, "out_file")   # refuses a place outside the run, or under inputs/
    since = to_apple(args["since"], "since") if args.get("since") else None
    until = to_apple(args["until"], "until") if args.get("until") else None
    if args.get("stream") is not None and not isinstance(args["stream"], str):
        fail("stream must be a string (an SQL LIKE pattern)", stream=args["stream"])
    keyset = None
    if "after_z_pk" in args or "after_start_raw" in args:
        pk, start = args.get("after_z_pk"), args.get("after_start_raw")
        if not isinstance(pk, int) or isinstance(pk, bool) or not -(1 << 63) <= pk < (1 << 63):
            fail("after_z_pk must be an integer SQLite can hold (resume.after_z_pk of the stopped run), given together with after_start_raw", after_z_pk=pk if isinstance(pk, (int, float, str, type(None))) and len(str(pk)) < 40 else None)
        if "after_start_raw" not in args:
            fail("after_z_pk is given without after_start_raw: both come from resume of the stopped run (after_start_raw is null when the last row read had no start)")
        if start is not None:
            wrong = not isinstance(start, (int, float)) or isinstance(start, bool)
            if not wrong and isinstance(start, int):
                wrong = not -(1 << 63) <= start < (1 << 63)
            elif not wrong:
                wrong = not math.isfinite(start)
            if wrong:
                fail("after_start_raw must be a number SQLite can hold, or null when the last row read had no start (resume.after_start_raw of the stopped run)",
                     after_start_raw=start if isinstance(start, (int, float, str)) and len(str(start)) < 40 else None)
        keyset = (start, pk)
    try:
        bind_values(write_values, "knowledgec_query")
    except ValuesRefused as exc:
        fail(str(exc), write_values=True)

    # The sidecars decide how the file is opened. A WAL holds committed rows the main file lacks; a hot rollback
    # journal holds the old pages of a transaction that did not commit and is rolled back when the copy is opened.
    sidecars = {}
    for suffix in ("-wal", "-shm", "-journal"):
        beside = db + suffix
        if os.path.isfile(beside):
            sidecars[suffix] = {"bytes": os.path.getsize(beside)}
    # Everything the reading finds goes into `st`, so that a stop at any point (the clock, a signal) still has a truthful answer to give.
    st = {"stage": None, "sink": None, "paging": None, "streams": None, "shaper": None, "connection": None, "tables": [], "zobject": [], "joins": {},
          "fingerprint": None, "applied": [], "unapplied": [], "reasons": [], "problems": [], "count": 0, "unconverted": 0, "stopped": None,
          "interrupted": None, "last": {"z_pk": None, "start_raw": None}, "inline": [], "inline_state": {"bytes": 0, "full": False, "bounded_by_bytes": False},
          "source": {"database": db, "staged": False, "sidecars": sidecars}, "abort": None, "until": deadline, "schema_read": False, "opener": None,
          "inventory": None, "stream_blind": None, "streams_in_file": None, "streams_listed_from": 0, "tables_total": 0}
    problems = st["problems"]
    source = st["source"]

    def progress():
        if STOP["signal"] is not None:
            st["abort"] = "signal"
            return 1
        if time.monotonic() > st["until"]:
            st["abort"] = st["abort"] or "time"
            return 1
        return 0

    def read():
        if "-wal" in sidecars or "-journal" in sidecars:
            total = os.path.getsize(db) + sum(v["bytes"] for v in sidecars.values())
            if total > max_stage:
                fail("the database and its sidecars (%d bytes) are over max_stage_bytes (%d): nothing was read; raise it, or query the "
                     "files with a tool that applies the WAL" % (total, max_stage), db=db, sidecars=sidecars)
            try:
                parent = stage_parent()
                parent.mkdir(parents=True, exist_ok=True)
                remove_dead_stages(parent)
                st["stage"] = stage = tempfile.mkdtemp(prefix="knowledgec-%d-" % os.getpid(), dir=str(parent))
                st["stage_lock"] = lock_stage(stage)            # (an open file, held until the process ends)
                staged_db = os.path.join(stage, os.path.basename(db))
                source["database_sha256"] = sha256_copy(db, staged_db, deadline)
                source["database_bytes"] = os.path.getsize(db)
                for suffix in sidecars:
                    sidecars[suffix]["sha256"] = sha256_copy(db + suffix, staged_db + suffix, deadline)
                if "-wal" in sidecars:
                    source["wal"] = wal_inventory(db + "-wal")
                source["staged"] = True
                source["open_mode"] = "a private copy of the database and its sidecars, read-write so SQLite works on them, removed at the end"
                connection = sqlite3.connect(staged_db)
                st["opener"] = lambda: sqlite3.connect(staged_db)
            except StageTimeUp:
                st["stopped"] = "time"           # the copy used the whole of max_seconds: nothing was read, and the private copy is removed below
                return
            except (OSError, sqlite3.Error, UnicodeError) as exc:
                fail("the database could not be opened or staged", db=db,
                     reason=("%s: %s" % (type(exc).__name__, exc.strerror or "error")) if isinstance(exc, OSError) else type(exc).__name__)
        else:
            source["open_mode"] = "read-only and immutable, in place (no WAL or journal beside it)"
            try:
                uri = "file:%s?mode=ro&immutable=1" % urllib.parse.quote(os.path.abspath(db))
                connection = sqlite3.connect(uri, uri=True)
                st["opener"] = lambda: sqlite3.connect(uri, uri=True)
            except (sqlite3.Error, UnicodeError) as exc:
                fail("the database could not be opened", db=db, reason=type(exc).__name__)
        st["connection"] = connection
        connection.row_factory = sqlite3.Row
        # Text that is not UTF-8 comes back with its bytes escaped, every byte still said.
        connection.text_factory = lambda b: b.decode("utf-8", "backslashreplace")
        try:
            # (listed in the order the answer prints them: by the text printed, the withheld names in an order that is new every run, never by the bytes of a name)
            tables, tables_total, own_present = list_tables(connection, deadline)
        except UnicodeError as exc:
            # SQLite's own error message can hold a name that is not UTF-8, and Python then cannot even build the exception
            fail("this file is not a usable SQLite database: its schema holds text that is not UTF-8 and SQLite refused to read it", db=db, reason=type(exc).__name__)
        except sqlite3.Error as exc:
            fail("this file is not a SQLite database", db=db, reason=str(exc))
        st["tables"], st["tables_total"] = tables, tables_total
        if "ZOBJECT" not in own_present:
            fail("this is not a knowledgeC database: there is no ZOBJECT table", db=db, tables=tables, **({"tables_not_listed": tables_total - len(tables)} if tables_total > len(tables) else {}))
        if source["staged"] and "-journal" in sidecars:
            after = sha256_file(os.path.join(st["stage"], os.path.basename(db)))
            present = os.path.exists(os.path.join(st["stage"], os.path.basename(db)) + "-journal")
            rolled = after != source["database_sha256"]
            source["journal"] = {"bytes": sidecars["-journal"]["bytes"], "sha256": sidecars["-journal"]["sha256"],
                                 "rollback_applied": rolled, "journal_present_after_open": present,
                                 "database_sha256_as_acquired": source["database_sha256"], "database_sha256_after_open": after}
            if rolled:
                problems.append("a rollback journal was beside the database and SQLite rolled back the uncommitted transaction it held in the "
                                "private copy: the rows below are the database as it stands after that rollback, which is not the main file "
                                "as acquired (its state changed in the copy)")
            elif not present:
                problems.append("a rollback journal was beside the database and SQLite removed it from the private copy without changing the database "
                                "(it was not a valid hot journal): it added nothing to the rows below")
            else:
                problems.append("a rollback journal was beside the database and SQLite did not roll it back (it is not a hot journal): "
                                "it adds nothing to the rows below")
        if source["staged"] and "-wal" in sidecars:
            try:
                busy, log, done = connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
                source["wal_checkpoint"] = {"busy": busy, "log": log, "checkpointed": done}
            except sqlite3.Error as exc:
                source["wal_checkpoint"] = {"error": type(exc).__name__}
        try:
            connection.execute("PRAGMA query_only=ON")
        except sqlite3.Error:
            pass
        connection.set_progress_handler(progress, PROGRESS_STEPS)

        def info(table, required):
            try:
                return [(r["name"], r["type"]) for r in connection.execute("PRAGMA table_info(%s)" % quote(table))]
            except (sqlite3.Error, UnicodeError) as exc:
                check_stop()
                # (a schema error names a table, a column or a module of the file, never a cell value; a name that is not UTF-8 is only a class)
                why = type(exc).__name__ if isinstance(exc, UnicodeError) else str(exc)
                if required:
                    fail("the schema of %s could not be read" % table, db=db, table=table, reason=why)
                problems.append("the schema of %s could not be read (%s): its rows are not joined" % (table, why))
                return []

        zobject = st["zobject"] = info("ZOBJECT", True)
        columns = {n for n, _t in zobject}
        meta_cols = info("ZSTRUCTUREDMETADATA", False) if "ZSTRUCTUREDMETADATA" in own_present else []
        src_cols = info("ZSOURCE", False) if "ZSOURCE" in own_present else []
        joins = st["joins"] = {"ZSTRUCTUREDMETADATA": bool(meta_cols) and "ZSTRUCTUREDMETADATA" in columns and any(n == "Z_PK" for n, _ in meta_cols),
                               "ZSOURCE": bool(src_cols) and "ZSOURCE" in columns and any(n == "Z_PK" for n, _ in src_cols)}
        st["fingerprint"] = hashlib.sha256("\n".join(
            "%s|%s|%s" % (t, n, ty) for t, cols in (("ZOBJECT", zobject), ("ZSOURCE", src_cols), ("ZSTRUCTUREDMETADATA", meta_cols))
            for n, ty in sorted(cols)).encode("utf-8")).hexdigest()
        st["schema_read"] = True

        select = [t for n, _t in zobject for t in bounded_select("o", "o", n)] + ['o.rowid AS "o!rowid"']
        if joins["ZSTRUCTUREDMETADATA"]:
            select += [t for n, _t in meta_cols for t in bounded_select("m", "m", n)] + ['m.rowid AS "m!rowid"']
        if joins["ZSOURCE"]:
            select += [t for n, _t in src_cols for t in bounded_select("s", "s", n)] + ['s.rowid AS "s!rowid"']
        if len(select) > SELECT_COLUMNS_MAX:
            fail("this schema has %d columns to read (two terms each) and SQLite will not select more than %d: nothing was read; "
                 "query the part you need with sqlite_query" % (len(select), SELECT_COLUMNS_MAX), db=db, columns=len(select))
        sql = "SELECT %s FROM ZOBJECT AS o" % ", ".join(select)
        if joins["ZSTRUCTUREDMETADATA"]:
            sql += " LEFT JOIN ZSTRUCTUREDMETADATA AS m ON o.ZSTRUCTUREDMETADATA = m.Z_PK"
        if joins["ZSOURCE"]:
            sql += " LEFT JOIN ZSOURCE AS s ON o.ZSOURCE = s.Z_PK"
        where, params = [], []
        applied, unapplied, reasons = st["applied"], st["unapplied"], st["reasons"]
        if args.get("stream"):
            if "ZSTREAMNAME" in columns:
                # `stream` is an SQL LIKE pattern over the stream name AS THE ANSWER PRINTS IT, never over the stored name: a name that is withheld in the answer
                # must not answer a probe (a count of 1 or 0 for a prefix would give it away, a character at a time). The streams are listed first (one pass), the
                # pattern is tried on each printed name, and the rows are selected by the stored names of the streams that matched.
                keep, blind = set(), [0, 0]

                def visit(name, n):
                    if name is None:
                        return
                    shown = printed_stream(name)
                    try:
                        matched = connection.execute("SELECT ? LIKE ?", (shown, args["stream"])).fetchone()[0]
                    except sqlite3.Error as exc:
                        check_stop()
                        if st["abort"] is not None:
                            raise                                  # (the clock ran out inside the statement: the caller says so)
                        fail("stream is not a LIKE pattern SQLite will run", reason=type(exc).__name__)
                    if matched:
                        keep.add(stream_key(name))
                    elif _MARK.search(shown):
                        blind[0] += 1
                        blind[1] += n

                try:
                    read_inventory(connection, st, columns, visit)
                except sqlite3.Error as exc:
                    check_stop()
                    if st["abort"] is None:
                        fail("the query failed", reason=type(exc).__name__)
                    st["stopped"] = st["abort"]
                    return
                connection.create_function("kc_stream_kept", 1, lambda b: b is not None and b.decode("utf-8", "backslashreplace") in keep, deterministic=True)
                where.append("kc_stream_kept(CAST(o.ZSTREAMNAME AS BLOB))")
                applied.append("stream")
                st["stream_blind"] = {"streams": blind[0], "rows": blind[1]}
                if blind[1]:
                    reasons.append("%d row(s) of %d stream(s) were not selected by stream and have a stream name that is withheld in this answer, so the pattern may match "
                                   "what is withheld (stream_blind_rows); stream is matched against the name as printed, never against what is withheld" % (blind[1], blind[0]))
            else:
                unapplied.append("stream")
                reasons.append("stream could not be applied: this database has no ZSTREAMNAME column, so the rows are not filtered by stream")
        if keyset is not None:
            if "ZSTARTDATE" in columns and "Z_PK" in columns:
                # the keyset of the order (ZSTARTDATE, Z_PK) the rows are read in: the rows after the last one a stopped run read, none read twice, none skipped (a
                # NULL start sorts first)
                if keyset[0] is None:
                    where.append("(o.ZSTARTDATE IS NOT NULL OR o.Z_PK > ?)")
                    params.append(keyset[1])
                else:
                    where.append("(o.ZSTARTDATE > ? OR (o.ZSTARTDATE = ? AND o.Z_PK > ?))")
                    params += [keyset[0], keyset[0], keyset[1]]
                applied.append("after_z_pk")
            else:
                unapplied.append("after_z_pk")
                reasons.append("after_z_pk could not be applied: this database has no ZSTARTDATE and Z_PK to order the rows by, so the read starts at the first row")
        for name, value, op in (("since", since, ">="), ("until", until, "<=")):
            if value is None:
                continue
            if "ZSTARTDATE" in columns:
                where.append("o.ZSTARTDATE %s ?" % op)
                params.append(value)
                applied.append(name)
            else:
                unapplied.append(name)
                reasons.append("%s could not be applied: this database has no ZSTARTDATE column, so the rows are not filtered by time" % name)
        if where:
            sql += " WHERE " + " AND ".join(where)
        order = "o.ZSTARTDATE, o.Z_PK" if "ZSTARTDATE" in columns and "Z_PK" in columns else (
            "o.ZSTARTDATE" if "ZSTARTDATE" in columns else ("o.Z_PK" if "Z_PK" in columns else "o.rowid"))
        sql += " ORDER BY " + order

        if out_name:
            try:
                Path(out_name).parent.mkdir(parents=True, exist_ok=True)
                # The name as the caller gave it: O_EXCL refuses a name that exists, a link (a dangling one included) as much as a file.
                fd = os.open(out_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError:
                fail("out_file already exists; the tool does not overwrite: use a new name", out_file=out_name)
            except OSError as exc:
                fail("out_file could not be created", out_file=out_name, reason="%s: %s" % (type(exc).__name__, exc.strerror or "error"))
            st["sink"] = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
            OWN_NAMES.add(out_name)
        else:
            st["paging"] = SealedPage("knowledgec_query", [db, args.get("stream"), args.get("since"), args.get("until"), keyset], limit, inline_bytes)
        sink, paging = st["sink"], st["paging"]
        inline, inline_state, last = st["inline"], st["inline_state"], st["last"]
        shaper = st["shaper"] = Shaper(connection, export, max_export, st["opener"] if HAVE_HANDLES else None)
        try:
            cursor = connection.execute(sql, params)
        except sqlite3.Error as exc:
            check_stop()
            if st["abort"] is None:
                fail("the query failed", reason=type(exc).__name__, sql=" ".join(sql.split())[:2000])
            st["stopped"] = st["abort"]
            return
        names = [d[0] for d in cursor.description]
        groups = {"o": ("ZOBJECT", [n for n, _t in zobject]), "m": ("ZSTRUCTUREDMETADATA", [n for n, _t in meta_cols]),
                  "s": ("ZSOURCE", [n for n, _t in src_cols])}
        rows = iter(cursor)
        while True:
            try:
                raw = next(rows)
            except StopIteration:
                break
            except sqlite3.Error:
                # the progress handler aborted the statement (sqlite swallows an exception raised in it, so the signal is looked for here)
                check_stop()
                if st["abort"] is None:
                    raise
                st["stopped"] = st["abort"]
                break
            row = dict(zip(names, raw))
            shaped = {}
            for prefix, (table, cols) in groups.items():
                if prefix + "!rowid" not in row:
                    continue
                rowid = row[prefix + "!rowid"]
                shaped[prefix] = {c: (row[prefix + "|" + c], row[prefix + "#" + c], rowid) for c in cols}
            o = {c: v for c, (v, _n, _r) in shaped["o"].items()}
            start_raw, end_raw, created_raw = o.get("ZSTARTDATE"), o.get("ZENDDATE"), o.get("ZCREATIONDATE")
            duration = None
            if (isinstance(start_raw, (int, float)) and isinstance(end_raw, (int, float))
                    and math.isfinite(start_raw) and math.isfinite(end_raw)):
                duration = round(float(end_raw) - float(start_raw), 3)
            for r in (start_raw, end_raw, created_raw):
                if r is not None and when(r) is None:
                    st["unconverted"] += 1

            def cell(prefix, c):
                v, n, rowid = shaped[prefix][c]
                return shaper.cell(v, n, groups[prefix][0], c, rowid)

            uuid = o.get("ZUUID")
            entry = {
                "parser": PARSER, "source_table": "ZOBJECT", "z_pk": o.get("Z_PK"), "stream": cell("o", "ZSTREAMNAME") if "ZSTREAMNAME" in o else None,
                "value_string": cell("o", "ZVALUESTRING") if "ZVALUESTRING" in o else None,
                "value_integer": plain(o.get("ZVALUEINTEGER")), "value_double": plain(o.get("ZVALUEDOUBLE")),
                "value_type_code": plain(o.get("ZVALUETYPECODE")),
                "start_raw": plain(start_raw), "end_raw": plain(end_raw), "created_raw": plain(created_raw),
                "start": when(start_raw), "end": when(end_raw), "created": when(created_raw),
                "duration_seconds": duration, "utc_offset_seconds": o.get("ZSECONDSFROMGMT"),
                "uuid": None,
            }
            if isinstance(uuid, (bytes, bytearray)):
                entry["uuid"] = guard_hex(bytes(uuid).hex(), "uuid")
            elif uuid is not None:
                entry["uuid"] = cell("o", "ZUUID")
            other = {c: cell("o", c) for c, (v, n, _r) in shaped["o"].items() if c not in STANDARD and (v is not None or n is not None)}
            if other:
                entry["zobject_other"] = other
            for key, prefix in (("metadata", "m"), ("source", "s")):
                if prefix in shaped:
                    got = {c: cell(prefix, c) for c, (v, n, _r) in shaped[prefix].items() if v is not None or n is not None}
                    if got:
                        entry[key] = got
            line = json.dumps(row_object(entry), default=str, sort_keys=True) if sink else None   # (judged before the signals are held: a signal waits for a write, not for a judging)
            with held():                    # a row is counted, written and kept whole, or not at all
                st["count"] += 1
                last["z_pk"], last["start_raw"] = o.get("Z_PK"), start_raw
                if sink:
                    sink.write(line + "\n")
                    if not inline_state["full"] and len(inline) < limit:
                        if inline_state["bytes"] + len(line) <= inline_bytes:
                            inline.append(entry)
                            inline_state["bytes"] += len(line)
                        else:
                            inline_state["bounded_by_bytes"] = True
                            inline_state["full"] = True
                    else:
                        inline_state["full"] = True
                else:
                    paging.add(entry)
            if time.monotonic() > deadline:        # (every row: a row of a few hundred cells of 4,000 characters takes a fifth of a second to judge, and 256 of them a minute)
                st["stopped"] = "time"
                break

        # The list of streams: every stream in the file, whatever the filters. After a stop on the clock it gets a few seconds of its own.
        streams = st["streams"] = SealedPage("knowledgec_streams", [db], 200, 256 << 10)
        if "ZSTREAMNAME" in columns:
            st["until"] = time.monotonic() + INVENTORY_SECONDS if st["stopped"] == "time" else max(st["until"], time.monotonic() + INVENTORY_SECONDS)
            st["abort"] = None
            try:
                listed = read_inventory(connection, st, columns)
            except sqlite3.Error as exc:
                check_stop()
                listed = None
                why = "it ran past its time" if st["abort"] else type(exc).__name__
                problems.append("the stream inventory could not be %s (%s): the list of streams is %s" % (
                    "made" if st["stopped"] is None else "finished", why, "not complete" if st["stopped"] else "not complete (the entries are)"))
            if listed is not None:
                # listed by count, most first; streams of one count in the order they are printed (print_order_until: the text printed, a random order among the
                # withheld names that is new every run), so the place of a withheld name says nothing about its bytes. At most STREAMS_LISTED_MAX streams are
                # listed (the ones with the most entries, ties cut at random), and every step is under the clock: a file of a million stream names is a pass and
                # a list of 2,000, never an answer that runs past the time the tool has.
                st["streams_in_file"] = listed["total"]
                st["streams_listed_from"] = len(listed["top"])
                finished = True
                shown_rows = []
                for name, n, first, last_start in listed["top"]:
                    if time.monotonic() > st["until"]:
                        finished = False
                        break
                    shown_rows.append((guard_text(stream_key(name), "stream") if name is not None else None, n, first, last_start))
                ordered, whole = print_order_until(shown_rows, "path", text=lambda r: r[0] if isinstance(r[0], str) else "", until=st["until"])
                ordered.sort(key=lambda r: -r[1])
                for number, (name, n, first, last_start) in enumerate(ordered):
                    if time.monotonic() > st["until"]:
                        finished = False
                        break
                    streams.add({"stream": name, "count": n, "first_start_raw": plain(first), "last_start_raw": plain(last_start),
                                 "first_start": when(first), "last_start": when(last_start)})
                if not (finished and whole):
                    problems.append("the list of streams was not finished in the time it has (%s s after the rows): %d of the %d streams to list are in it" % (
                        INVENTORY_SECONDS, streams.total, len(listed["top"])))
                if listed["total"] > len(listed["top"]):
                    problems.append("the list of streams holds the %d streams with the most entries (ties cut at random): %d further stream(s) of the %d in the file are "
                                    "not listed (streams_not_listed); use stream to read the rows of one" % (len(listed["top"]), listed["total"] - len(listed["top"]), listed["total"]))
        else:
            problems.append("this database has no ZSTREAMNAME column, so there is no stream inventory and no entry has a stream")

    try:
        try:
            read()
        except Interrupted as stop:
            st["interrupted"] = stop.signum
            st["stopped"] = "signal"
    finally:
        # Close what was opened before the private copy goes: Python 3.13 and later warn (ResourceWarning) about a connection left to the garbage collector.
        for opened in (st["shaper"] and st["shaper"].handles, st["connection"]):
            try:
                if opened is not None:
                    opened.close()
            except sqlite3.Error:
                pass
        if st["stage"]:
            shutil.rmtree(st["stage"], ignore_errors=True)
            if os.environ.get("JOB_ID") and os.environ.get("OUT"):
                try:
                    os.rmdir(str(stage_parent()))      # an empty directory is not a sealed output
                except OSError:
                    pass
    if source["staged"]:
        source["staged_copy"] = "removed"
    interrupted, stopped, count = st["interrupted"], st["stopped"], st["count"]
    sink, paging, shaper = st["sink"], st["paging"], st["shaper"]

    with held():
        if sink:
            sink.flush()
            os.fsync(sink.fileno())
            sink.close()
            shown, complete, limited = st["inline"], out_name, count > len(st["inline"])
            page = {"inline_bounded_by_bytes": st["inline_state"]["bounded_by_bytes"]}
        elif paging is not None:
            page = paging.finish()
            shown, complete, limited = paging.page, page.get("all_results"), page["truncated"]
        else:
            page, shown, complete, limited = {}, [], None, False
        streams = st["streams"]
        streams_page = streams.finish() if streams is not None else {"matched": 0}

    problems_all = st["reasons"] + problems
    wal = source.get("wal")
    if wal and not wal.get("frames_valid"):
        problems_all.append("a -wal file is beside the database and holds no frame of its current generation (%s): it added nothing" % wal.get("state"))
    cp = source.get("wal_checkpoint")
    if wal and wal.get("frames_valid") and cp and (cp.get("error") or cp.get("log", 0) < 1 or cp.get("busy")):
        problems_all.append("the WAL has frames of its current generation but SQLite did not apply them (checkpoint %s): rows committed only "
                            "in the WAL are not in this result" % json.dumps(cp))
    if st["unconverted"]:
        problems_all.append("%d time value(s) could not be converted from the Apple epoch; their raw values are in the entries" % st["unconverted"])
    if shaper is not None and shaper.head_unavailable:
        problems_all.append("%d large value(s) could not be read even for their first bytes; their length is given" % shaper.head_unavailable)
    if shaper is not None and shaper.export_refused:
        problems_all.append("%d oversize value(s) were not written to a file: they would pass max_export_bytes (%d)" % (shaper.export_refused, max_export))
    resume = None
    if stopped is not None:
        last = st["last"]
        when_text = ("the clock (max_seconds %s)" % max_seconds) if stopped == "time" else "%s" % signal_name(interrupted)
        problems_all.append("the tool stopped on %s after %d entr%s: the entries below are a prefix of the result in start order (the whole prefix is in %s), "
                            "and the rest of the table was not read" % (when_text, count, "y" if count == 1 else "ies", complete or "the answer"))
        resume = {"rows_read": count, "stopped_after_z_pk": last["z_pk"], "last_start_raw": last["start_raw"]}
        zcols = {n for n, _t in st["zobject"]}
        finite = isinstance(last["start_raw"], (int, float)) and not isinstance(last["start_raw"], bool) and math.isfinite(last["start_raw"])
        if count and "ZSTARTDATE" in zcols and "Z_PK" in zcols and isinstance(last["z_pk"], int) and (finite or last["start_raw"] is None):
            resume["after_start_raw"] = last["start_raw"]
            resume["after_z_pk"] = last["z_pk"]
            if finite:
                resume["resume_since"] = when(last["start_raw"] - 0.000001)
            resume["to_go_on"] = ("run again with after_start_raw and after_z_pk set to these two values (and the same db, stream, since and until, and a larger max_seconds "
                                  "if the database is large): the read goes on with the next row of the order (start, then Z_PK), no row twice and none skipped, "
                                  "also when many rows share one start. resume_since, a microsecond before the last start, is the older way: it reads the rows of that start again")
        elif count == 0:
            resume["to_go_on"] = ("no entry was read before the stop (the database was being copied, or the statement was still sorting the rows by start time): run again "
                                  "with a larger max_seconds (at most %d), or narrow the read with stream, since and until" % MAX_SECONDS_LIMIT)
        else:
            resume["to_go_on"] = "this database has no usable start time to resume from: narrow the read with stream, or read the table with sqlite_query"
    if interrupted is not None:
        status = "partial" if st["schema_read"] else "failed"
        basis = "the tool was stopped by %s; %d entr%s read before it are kept" % (signal_name(interrupted), count, "y was" if count == 1 else "ies were")
    elif stopped == "time":
        status = "partial"
        basis = "max_seconds (%s) passed after %d entries: the rest of the table was not read (resume tells where to go on)" % (max_seconds, count)
    elif problems_all:
        status = "partial"
        basis = "%d problem(s) are named under problems; the entries are what was read" % len(problems_all)
    else:
        status = "complete"
        basis = "every row of ZOBJECT that the filters select was read, with its joined metadata and source rows, and every stream was inventoried"
    OWN_NAMES.add(basis)
    note = ("Times are converted from the Apple epoch (2001-01-01 UTC) and returned as UTC, with the raw value beside each. "
            "The streams list is every stream in the database, whatever the filters. since and until select rows by start time, "
            "so a record that began before the window and overlapped it is not in it. A write-ahead log beside the database is "
            "applied in a private copy and counted in source_used; a rollback journal is rolled back in the copy and reported; a "
            "-shm file is a derived index and adds nothing. These are "
            "records of application and device state the machine kept for its own features: foreground application and screen "
            "or lock state do not show a person at the keyboard, and retention varies by OS version and device, so scope an "
            "absence to the earliest and latest rows of the stream in this database. Every string of an entry is judged by the boundary before it "
            "is printed or written (see boundary): a value that looks like a token is withheld, and a BLOB's head is hexadecimal (_hex).")
    OWN_NAMES.add(note)
    result = {
        "db": db,
        "parser": PARSER,
        "status": status,
        "status_basis": basis,
        **({"interrupted": signal_name(interrupted)} if interrupted is not None else {}),
        "problems": problems_all,
        "entries": shown,
        "entry_count": count,
        "entries_inline": len(shown),
        "complete_entries": complete,
        "inline_limited": bool(limited),
        "inline_bounded_by_bytes": bool(page.get("inline_bounded_by_bytes")),
        "inline_byte_limit": inline_bytes,
        **({"kept_earlier_larger_result": page["kept_earlier_larger_result"]} if page.get("kept_earlier_larger_result") else {}),
        **({"resume": resume} if resume else {}),
        "values": {"cap": VALUE_CAP, "truncated": shaper.truncated if shaper else 0, "exported": shaper.exported if shaper else 0,
                   "exported_bytes": shaper.exported_bytes if shaper else 0, "export_requested": export,
                   "note": "A TEXT or BLOB cell longer than the cap shows its first %d characters or bytes (a BLOB as hexadecimal), its whole byte length and "
                           "where the whole is in the database (_where); a TEXT cell is read through a blob handle, so only its head is loaded; "
                           "export_oversize: true (a secret job) writes each whole value to a file and names it." % VALUE_CAP},
        "filters_applied": st["applied"],
        **({"stream_blind_rows": st["stream_blind"]["rows"], "stream_blind_streams": st["stream_blind"]["streams"]} if st["stream_blind"] is not None else {}),
        **({"filters_unapplied": st["unapplied"]} if st["unapplied"] else {}),
        "limits": {"max_seconds": max_seconds, **({"max_seconds_requested": requested_seconds} if requested_seconds != max_seconds else {}),
                   "seconds_used": round(time.monotonic() - started, 1)},
        "schema": {"tables": st["tables"], **({"tables_not_listed": st["tables_total"] - len(st["tables"])} if st["tables_total"] > len(st["tables"]) else {}), "joins": st["joins"], "fingerprint": st["fingerprint"],
                   "zobject_columns": [n for n, _t in st["zobject"]]},
        "source_used": source,
        "streams": streams.page if streams is not None else [],
        "streams_total": streams_page["matched"],
        **({"streams_in_file": st["streams_in_file"], "streams_not_listed": st["streams_in_file"] - st["streams_listed_from"]}
           if st["streams_in_file"] is not None and st["streams_in_file"] > st["streams_listed_from"] else {}),
        "streams_pages": streams_page,
        "note": note,
    }
    hold_signals()                     # the work is done: a signal now waits for the answer instead of replacing it (judging takes seconds at most)
    interrupted = emit_answer(result, interrupted, indent=2)       # (a signal that arrives while the answer is sealed is named in it)
    close_values()
    if interrupted is not None:
        sys.exit(128 + interrupted)


def main():
    seal_stop_after(SEAL_STOP_SECONDS)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")
    run_query(args)


if __name__ == "__main__":
    install_stop_handlers()
    try:
        main()
    except SystemExit:
        raise
    except Interrupted as stop:
        close_values()
        emit({"error": "the tool was stopped by %s before it had read anything" % signal_name(stop.signum), "status": "failed",
              "status_basis": "stopped by %s during start-up: nothing was read" % signal_name(stop.signum), "interrupted": signal_name(stop.signum)})
        sys.exit(128 + stop.signum)
    except Exception as exc:                 # whatever hostile input does, the answer is JSON (the class only: a message can quote the evidence)
        close_values()
        emit({"error": "the tool stopped on an unexpected error", "type": type(exc).__name__, "status": "failed",
              "status_basis": "the tool stopped with an unexpected error: nothing is complete"})
        sys.exit(1)
