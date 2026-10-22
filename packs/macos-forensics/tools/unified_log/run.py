#!/usr/bin/env python3
"""Read Apple unified logs without hiding parser failures or dropping output.

Two readers, by platform. On macOS Apple's own `log show --archive` reads a
.logarchive. Elsewhere Mandiant's `unifiedlog_iterator` (declared in requires) reads a
.logarchive, or a copy of /private/var/db (diagnostics and uuidtext side by side),
which this tool stages as one archive first. Both keep every decoded entry as a
file in out_dir (nothing is cut: the answer's `entries` is only a preview).

What `status` means, and what it does not. `status` is about this run: the reader exited cleanly, wrote its output, and every line of that output parsed as a JSON
record carrying the fields an entry has. It says nothing about whether the acquired files were all decodable, whether uuidtext covered every message, whether timesync
covered the interval, or whether retention kept the period asked about: those are `decoded_coverage` (counts of what was read) and `support_files` (an inventory of
what the input holds), and a skill judges them against the case. A reader exiting 0 with no output file is `failed`; an output with no entries is `partial` (the reader's
outcome, `reader_outcome`, is `empty`); malformed lines, a reader that exits non-zero, overruns its time or is stopped by a signal leave `partial` with what was written
kept; `complete` is none of those, and is still not a coverage claim. The status is one of complete, partial and failed, with `status_basis` saying what it rests on.

`timeout_seconds` is one budget for staging, the census and the reader (the reader gets what is left), and counting the output has a few more seconds of its own, so
the tool ends below the manifest's limit. The preview of entries passes the boundary below; the reader's own output file does not.

The whole output is read once, in a stream, so counts cover the whole of it and only
the preview is held in memory.
"""
import hashlib
import json
import os
import platform
import shutil
import stat
import re
import subprocess
import sys
import time
from pathlib import Path

PARSER = "unified_log/4"
DEFAULT_TIMEOUT = 900
MAX_TIMEOUT = 1100            # the manifest's outer limit is 1200; this covers staging, the census and the reader, then counting gets COUNT_SECONDS
COUNT_SECONDS = 70            # counting the reader's output may take this long after the budget (MAX_TIMEOUT at most) is used; its sha256 gets until DIGEST_SECONDS
DIGEST_SECONDS = 85           # the output's sha256 is given up past this long after the budget (the manifest allows 1200 seconds in all)
SEAL_STOP_SECONDS = 1196.5     # no string is judged past this (the rest is withheld whole): the manifest allows 1200, less the 3.5 seconds the block asks for
MIN_READER_SECONDS = 0.5      # a reader is not started with less time than this left of the budget
INTERRUPT_COUNT_SECONDS = 5   # after a stop signal the output is counted for this long at most
DEFAULT_MAX_STAGE_FILES = 1_000_000
DEFAULT_MAX_STAGE_BYTES = 16 << 30
# The fields of an entry that the preview shows, under both readers' names (Apple's ndjson, Mandiant's JSONL: `time`, `message`, `raw_message`,
# `thread_id`, `pid`, `event_type`, `log_type`, `library`, `euid`, `activity_id`, `boot_uuid`, `timezone_name`). Every name an entry is
# recognised by is in this list, so a preview row is never empty for a record counted as an entry.
KEEP = ["timestamp", "time", "processImagePath", "process", "subsystem", "category",
        "senderImagePath", "library", "eventMessage", "message", "raw_message", "messageType", "log_type", "processID", "pid",
        "threadID", "thread_id", "activityIdentifier", "activity_id", "eventType", "event_type", "euid", "boot_uuid", "timezone_name"]
# A record is an entry when it carries at least one of these (Apple's ndjson and Mandiant's JSONL
# name their fields differently); a JSON record with none is counted apart, not as an entry.
ENTRY_KEYS = {"timestamp", "time", "eventMessage", "message", "raw_message", "process", "subsystem"}
OUTPUT_NAMES = ("unifiedlogs.jsonl", "unifiedlogs.ndjson", "unifiedlog.stderr", ".logarchive-input")
FIRST = 10
PREDICATE_TEXT = re.compile(r"(?i)\b(?:event|composed)?message\b|formatstring")     # the fields of a predicate that hold the text of a message
UNREADABLE_KEPT = 10000       # unreadable directories kept to list the first FIRST of them in the order printed (they are all counted)


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
    emit({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error); the reader did not run", **extra})
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
    "path", "parser", "engine", "reader", "version", "platform", "status", "status_basis", "interrupted", "exit_code", "timed_out", "command", "output",
    "output_sha256", "entry_count", "entries", "entries_inline", "unparsed_lines", "decoded_coverage", "staging", "problems", "warnings", "stderr",
    "stderr_bytes", "timeout_seconds_used", "timeout_clamped", "timeout_requested", "note", "error", "type", "reason", "lines", "json_records",
    "entry_records", "records_without_entry_fields", "array_delimiter_lines", "first_unparsed_lines", "first_records_without_entry_fields", "line", "keys",
    "support_files", "tracev3_files", "timesync_files", "uuidtext_files", "dsc_files", "other_files", "directories_unreadable", "first_directories_unreadable",
    "directory", "stopped_at_files", "staged", "files", "bytes", "duplicates_identical", "sources", "counting_stopped_at_line", "reader_outcome",
    "budget", "seconds_used", "seconds_for_reader", "staging_seconds", "census_seconds", "boundary", "max_stage_files", "max_stage_bytes", "out_dir", "holds",
    "looked_for", "link", "found_as", "conflicts", "conflict_count", "directory", "files", "bytes", "predicate_names_message_text",
))
FIELDS.update({
    "path": "path", "output": "path", "stderr": "path", "out_dir": "path", "sources": "path", "directory": "path", "link": "path", "command": "text",
    "processImagePath": "path", "senderImagePath": "path", "process": "path", "library": "path", "subsystem": "name", "category": "name",
    "messageType": "name", "log_type": "name", "eventType": "name", "event_type": "name", "timestamp": "time", "output_sha256": "digest",
    "time": "time", "eventMessage": "text", "message": "text", "raw_message": "text", "keys": "name", "boot_uuid": "guid", "timezone_name": "name",
})


def digest(path, deadline=None):
    """The sha256 of a file, or None when `deadline` (a monotonic time) passes before it is read to the end."""
    value = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            value.update(block)
            if deadline is not None and time.monotonic() > deadline:
                return None
    return value.hexdigest()


def same_bytes(a, b):
    if os.path.getsize(a) != os.path.getsize(b):
        return False
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            x, y = fa.read(1 << 20), fb.read(1 << 20)
            if x != y:
                return False
            if not x:
                return True


def walk_tree(root, rel_to, on_file):
    """Every entry under `root`, not followed through links: a link, a special file, or a directory or file
    that cannot be read is refused by name, and nothing is staged (a directory left out would be a silent gap)."""
    def unreadable(exc):
        fail("a directory in the tree to be staged could not be read, so nothing was staged: a tree with a part left out is not the evidence",
             directory=getattr(exc, "filename", None), reason="%s: %s" % (type(exc).__name__, exc))

    for dirpath, dirs, names in os.walk(root, followlinks=False, onerror=unreadable):
        dirs.sort()
        for name in sorted(dirs) + sorted(names):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, rel_to)
            try:
                st = os.lstat(full)
            except OSError as exc:
                fail("an entry in the tree to be staged could not be examined, so nothing was staged",
                     path=full, reason="%s: %s" % (type(exc).__name__, exc))
            if stat.S_ISLNK(st.st_mode):
                fail("a link in the tree to be staged: the reader would be handed a way out of it, so nothing was staged",
                     link=full, found_as=rel)
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                fail("a file that is not a regular file in the tree to be staged; nothing was staged", file=full)
            on_file(full, rel, st.st_size)


def inventory(path, budget):
    """What the input holds, by name: a census, not a verdict on whether it is complete. A directory that
    cannot be read is counted and named, never left out silently."""
    census = {"tracev3_files": 0, "timesync_files": 0, "uuidtext_files": 0, "dsc_files": 0, "other_files": 0,
              "directories_unreadable": 0, "first_directories_unreadable": []}

    def unreadable(exc):
        census["directories_unreadable"] += 1
        if len(census["first_directories_unreadable"]) < UNREADABLE_KEPT:
            census["first_directories_unreadable"].append({"directory": getattr(exc, "filename", None),
                                                           "reason": "%s: %s" % (type(exc).__name__, exc)})

    def listed():
        # the first FIRST of them in the order the answer prints their names (the order of a walk is the directory's: it would give the place of a withheld name away)
        census["first_directories_unreadable"] = print_order(census["first_directories_unreadable"], "path",
                                                              text=lambda d: d["directory"] if isinstance(d.get("directory"), str) else "")[:FIRST]
        return census

    seen = 0
    for dirpath, _dirs, names in os.walk(path, followlinks=False, onerror=unreadable):
        parts = os.path.relpath(dirpath, path).split(os.sep)
        for name in names:
            seen += 1
            if seen > budget:
                census["stopped_at_files"] = budget
                return listed()
            low = name.lower()
            if low.endswith(".tracev3"):
                census["tracev3_files"] += 1
            elif low.endswith(".timesync") or "timesync" in parts:
                census["timesync_files"] += 1
            elif "dsc" in parts:
                census["dsc_files"] += 1
            elif "uuidtext" in parts or (parts and len(parts[0]) == 2 and all(c in "0123456789ABCDEFabcdef" for c in parts[0])):
                census["uuidtext_files"] += 1
            else:
                census["other_files"] += 1
    return listed()


def stage(path, scratch, max_files, max_bytes, deadline):
    """Merge diagnostics and uuidtext into one archive under `scratch`: counted, bounded, refusing a link,
    a special file or a member that is in both trees with different bytes. Nothing is cut: over a bound it refuses."""
    diagnostics = os.path.join(path, "diagnostics")
    uuidtext = os.path.join(path, "uuidtext")
    for root in (diagnostics, uuidtext):
        if os.path.islink(root):
            fail("diagnostics or uuidtext is itself a link: the reader would be handed a way out of the tree, so nothing was staged", link=root)
    totals = {"files": 0, "bytes": 0}
    held = {}
    plan = []

    def take(tree):
        def on_file(full, rel, size):
            totals["files"] += 1
            totals["bytes"] += size
            if totals["files"] > max_files or totals["bytes"] > max_bytes:
                which = "max_stage_files" if totals["files"] > max_files else "max_stage_bytes"
                fail("staging this tree would pass %s (%d): nothing was staged and the reader did not run; raise it or point the tool at "
                     "a .logarchive" % (which, max_files if which == "max_stage_files" else max_bytes),
                     files=totals["files"], bytes=totals["bytes"], max_stage_files=max_files, max_stage_bytes=max_bytes)
            plan.append((tree, full, rel))
        return on_file

    walk_tree(uuidtext, uuidtext, take("uuidtext"))
    for tree, full, rel in plan:
        held[rel] = full
    first = len(plan)
    walk_tree(diagnostics, diagnostics, take("diagnostics"))
    conflicts, duplicates = [], set()
    for tree, full, rel in plan[first:]:
        if rel in held:
            try:
                same = same_bytes(held[rel], full)
            except OSError as exc:
                fail("a member in both trees could not be compared, so nothing was staged", path=full, reason="%s: %s" % (type(exc).__name__, exc))
            if same:
                duplicates.add(full)
            else:
                conflicts.append(rel)
    if conflicts:
        fail("a member is in both diagnostics and uuidtext with different bytes; nothing was staged: which one the reader should see is "
             "not for this tool to choose", conflicts=print_order(conflicts, "text", text=lambda c: c)[:FIRST], conflict_count=len(conflicts))
    try:
        os.makedirs(scratch, exist_ok=False)
    except OSError as exc:
        fail("the staging directory could not be created, so nothing was staged", path=scratch, reason="%s: %s" % (type(exc).__name__, exc))
    copied, size = 0, 0
    try:
        for tree, full, rel in plan:
            if full in duplicates:
                continue
            if time.monotonic() > deadline:
                fail("staging used the whole time budget (timeout_seconds): the reader did not run and the staged copy was removed; raise "
                     "timeout_seconds (at most %d) or point the tool at a .logarchive" % MAX_TIMEOUT, files_copied=copied, files_to_copy=len(plan))
            target = os.path.join(scratch, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copyfile(full, target)
            copied += 1
            size += os.path.getsize(full)
    except OSError as exc:
        shutil.rmtree(scratch, ignore_errors=True)
        fail("a file could not be copied into the staging directory, so nothing was staged and the reader did not run",
             path=getattr(exc, "filename", None), reason="%s: %s" % (type(exc).__name__, exc))
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
    return {"staged": True, "files": copied, "bytes": size, "duplicates_identical": len(duplicates),
            "sources": [diagnostics, uuidtext]}


def reader_version(argv_first):
    try:
        proc = subprocess.run([argv_first, "--version"], capture_output=True, text=True, timeout=10)
        line = (proc.stdout or proc.stderr).strip().splitlines()
        return line[0][:200] if proc.returncode == 0 and line else None
    except (OSError, subprocess.SubprocessError):
        return None


def count_output(path, limit, deadline):
    """Read the whole output once, in a stream. Only the preview is held. Past `deadline` the counting stops, says at which line, and what
    was counted is a prefix."""
    cov = {"lines": 0, "json_records": 0, "entry_records": 0, "unparsed_lines": 0, "records_without_entry_fields": 0,
           "array_delimiter_lines": 0}
    entries, first_unparsed, first_without = [], [], []
    with open(path, "rb") as fh:
        for number, raw in enumerate(fh, 1):
            if number % 4096 == 0 and time.monotonic() > deadline:
                cov["counting_stopped_at_line"] = number
                break
            line = raw.strip()
            if not line:
                continue
            cov["lines"] += 1
            if line in (b"[", b"]"):
                cov["array_delimiter_lines"] += 1
                continue
            try:
                row = json.loads(line)
            except ValueError:
                row = None
            if not isinstance(row, dict):
                cov["unparsed_lines"] += 1
                if len(first_unparsed) < FIRST:
                    first_unparsed.append(number)
                continue
            cov["json_records"] += 1
            if not (ENTRY_KEYS & row.keys()):
                cov["records_without_entry_fields"] += 1
                if len(first_without) < FIRST:
                    first_without.append({"line": number, "keys": print_order_until(list(row), "name", until=deadline)[0][:20]})
                continue
            cov["entry_records"] += 1
            if len(entries) < limit:
                kept = {k: (guard_text(row[k], k) if isinstance(row.get(k), str) else row[k]) for k in KEEP if row.get(k) is not None}
                entries.append(kept or {"keys": print_order_until(list(row), "name", until=deadline)[0][:20]})
    cov["first_unparsed_lines"] = first_unparsed
    cov["first_records_without_entry_fields"] = first_without
    return cov, entries


def descendants(pid):
    """The processes below `pid` in the process tree (its children, theirs, and so on), from the table of parent pids; empty when `ps` cannot say. Followed from the
    reader this tool started: its own descendants, never a search by name."""
    table = None
    for ps in (shutil.which("ps"), "/bin/ps", "/usr/bin/ps"):
        if not ps:
            continue
        try:
            table = subprocess.run([ps, "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=5).stdout
            break
        except (OSError, subprocess.SubprocessError):
            continue
    if table is None:
        return []
    children = {}
    for line in table.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            children.setdefault(int(parts[1]), []).append(int(parts[0]))
    found, stack = [], list(children.get(pid, []))
    while stack:
        child = stack.pop()
        if child in found or child == os.getpid():
            continue
        found.append(child)
        stack.extend(children.get(child, []))
    return found


def kill_reader(proc):
    """End the reader this tool started and what it started (its own child and that child's descendants, never a search by name): a reader that runs helpers
    leaves them behind when only its own pid is killed. The reader is stopped first so that it starts no more while its tree is read."""
    try:
        if proc.poll() is None:
            try:
                os.kill(proc.pid, signal.SIGSTOP)
            except OSError:
                pass
            below = descendants(proc.pid)
            proc.kill()
            for pid in below:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
    except OSError:
        pass


def run_reader(argv, stdout, stderr, seconds):
    """(exit code, timed out): the reader runs for at most `seconds` and is killed when the time is up or a stop signal arrives."""
    proc = subprocess.Popen(argv, stdout=stdout, stderr=stderr)
    hook = lambda: kill_reader(proc)       # noqa: E731 (a stop signal ends the reader before the exception unwinds)
    STOP["hooks"].append(hook)
    try:
        try:
            return proc.wait(timeout=seconds), False
        except subprocess.TimeoutExpired:
            kill_reader(proc)
            proc.wait()
            return None, True
    except BaseException:
        kill_reader(proc)
        try:
            proc.wait(timeout=10)
        except (subprocess.TimeoutExpired, OSError):
            pass
        raise
    finally:
        if hook in STOP["hooks"]:
            STOP["hooks"].remove(hook)


def run_log(args):
    started = time.monotonic()
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a .logarchive or a directory holding diagnostics and uuidtext")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)
    OWN_NAMES.add(path)
    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ for the reader's complete output")
    out_dir = resolve_output(out_dir, "out_dir")
    OWN_NAMES.add(out_dir)
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    requested = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(requested, int) or isinstance(requested, bool) or requested < 1:
        fail("timeout_seconds must be a positive integer")
    timeout = min(requested, MAX_TIMEOUT)
    # The budget covers everything before the reader's output is counted: staging, the census, the reader. Counting and the digest follow, for COUNT_SECONDS at most.
    budget_end = started + timeout
    max_files = args.get("max_stage_files", DEFAULT_MAX_STAGE_FILES)
    max_bytes = args.get("max_stage_bytes", DEFAULT_MAX_STAGE_BYTES)
    for name, value in (("max_stage_files", max_files), ("max_stage_bytes", max_bytes)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            fail("%s must be a positive integer" % name, **{name: value})

    apple = shutil.which("log") if sys.platform == "darwin" else None
    iterator = shutil.which("unifiedlog_iterator")
    if not apple and not iterator:
        fail("no unified log reader on PATH", looked_for=["log (macOS)", "unifiedlog_iterator"],
             note="Linux images should install Mandiant macos-UnifiedLogs v0.7.0 or later.")
    if not apple and any(args.get(k) for k in ("predicate", "start", "end")):
        fail("predicate/start/end require Apple's log command; unifiedlog_iterator keeps the full JSONL for downstream queries")
    for key in ("predicate", "start", "end"):
        if args.get(key) is not None and not isinstance(args[key], str):
            fail("%s must be a string" % key, **{key: args[key]})
    predicate_warning = None
    if apple and args.get("predicate"):
        # Apple's `log` evaluates the predicate over the messages as decoded, and entry_count is the count of what it matched: a predicate that names the text of a
        # message tells a true guess of a piece the preview withholds from a false one, by the count (the tool cannot judge text inside the reader).
        if PREDICATE_TEXT.search(args["predicate"]) and os.environ.get("SECRET_OUTPUT") == "1":
            fail("predicate is refused in a job run as secret output when it names the text of a message (eventMessage, composedMessage, formatString): entry_count "
                 "would answer guesses of text that the preview withholds. Select by process, subsystem, category, sender or time here, and look for the text in the "
                 "reader's output file inside a job of its own", predicate_names_message_text=True)
        predicate_warning = ("predicate was evaluated by Apple's log over the messages as it decoded them, not over the text this answer prints: when it names the text "
                             "of a message, entry_count is a count of matches that a preview with withheld text does not show (a count can tell a guess of withheld text "
                             "from a wrong one); a job run as secret output refuses such a predicate")

    # Where every file this run writes would land, checked before the directory is touched; a name that
    # already exists (a file, or a link) is an earlier run's output and is not overwritten.
    names = {n: resolve_output(os.path.join(out_dir, n), "out_dir") for n in OUTPUT_NAMES}
    OWN_NAMES.update(names.values())
    job, job_out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and job_out:
        # A job writes only $OUT; the rest of the run directory is read-only to it. The harness gives a
        # path under work/<your id>/ as a place under $OUT, so one that is not there is a mistake worth a reason.
        dest, root = (Path.cwd() / out_dir).resolve(), Path(job_out).resolve()
        if dest != root and root not in dest.parents:
            fail("as a job this tool writes only under $OUT, and out_dir is not there: give it as work/<your id>/<name>, which the job "
                 "maps to $OUT/<name>", out_dir=out_dir, out=str(root))
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as exc:
        fail("out_dir could not be created", out_dir=out_dir, reason="%s: %s" % (type(exc).__name__, exc.strerror or "error"))
    held_names = [n for n in OUTPUT_NAMES if os.path.lexists(os.path.join(out_dir, n))]
    if held_names:
        fail("out_dir already holds %s from an earlier run; the tool does not overwrite it: use a new directory" % ", ".join(held_names),
             out_dir=out_dir, holds=held_names)
    stderr_path = names["unifiedlog.stderr"]
    scratch = os.path.join(out_dir, ".logarchive-input")
    problems, warnings = [], []
    if predicate_warning:
        warnings.append(predicate_warning)
    staging = None
    timed_out = False
    returncode = None
    interrupted = None
    census = None
    reader_seconds = None
    marks = {"staged": 0.0, "census": 0.0}

    if apple:
        engine = "log"
        output_path = names["unifiedlogs.ndjson"]
        reader = {"path": apple, "version": None, "platform": "macOS %s" % (platform.mac_ver()[0] or "unknown")}
        if os.path.isdir(os.path.join(path, "diagnostics")) and os.path.isdir(os.path.join(path, "uuidtext")):
            warnings.append("the input holds diagnostics and uuidtext, not a .logarchive: this tool stages such a copy only for "
                            "unifiedlog_iterator, and `log show --archive` may refuse it")
        argv = [apple, "show", "--archive", path, "--style", "ndjson", "--info", "--debug"]
        for flag, key in (("--predicate", "predicate"), ("--start", "start"), ("--end", "end")):
            if args.get(key):
                argv += [flag, str(args[key])]
        input_seen = path
    else:
        engine = "unifiedlog_iterator"
        output_path = names["unifiedlogs.jsonl"]
        reader = {"path": iterator, "version": reader_version(iterator), "platform": platform.platform()}
        input_seen = path
        argv = [iterator, "--mode", "log-archive", "--input", input_seen, "--output", output_path, "--format", "jsonl"]
    OWN_NAMES.add(output_path)

    try:
        try:
            if not apple and os.path.isdir(os.path.join(path, "diagnostics")) and os.path.isdir(os.path.join(path, "uuidtext")):
                begun = time.monotonic()
                staging = stage(path, scratch, max_files, max_bytes, budget_end)
                marks["staged"] = time.monotonic() - begun
                input_seen = scratch
                argv = [iterator, "--mode", "log-archive", "--input", input_seen, "--output", output_path, "--format", "jsonl"]
            begun = time.monotonic()
            census = inventory(input_seen, max_files) if os.path.isdir(input_seen) else None
            marks["census"] = time.monotonic() - begun
            if census is not None:
                if census["directories_unreadable"]:
                    warnings.append("%d director%s under the input could not be read by this tool, so they are not in the census "
                                    "(the reader may not have read them either; the first: %s)" % (census["directories_unreadable"], "y" if census["directories_unreadable"] == 1 else "ies",
                                                         census["first_directories_unreadable"][0]["directory"]))
                if not census["tracev3_files"]:
                    warnings.append("no .tracev3 file was found under the input: the reader had no log to decode")
                if not census["timesync_files"]:
                    warnings.append("no timesync file was found under the input: timestamps may not be placed in wall time")
                if not census["uuidtext_files"] and not census["dsc_files"]:
                    warnings.append("no uuidtext or dsc file was found under the input: message text may not render")
            # The reader gets what is left of the budget: staging and the census came out of the same clock.
            left = budget_end - time.monotonic()
            if left < MIN_READER_SECONDS:
                fail("staging and the census used the whole time budget (timeout_seconds %d, %.0f s left): the reader did not run and the staged copy "
                     "was removed; raise timeout_seconds (at most %d) or point the tool at a .logarchive" % (timeout, max(left, 0), MAX_TIMEOUT),
                     staging_seconds=round(marks["staged"], 1), census_seconds=round(marks["census"], 1))
            reader_seconds = left
            with open(stderr_path, "xb") as err:
                if apple:
                    with open(output_path, "xb") as out:
                        returncode, timed_out = run_reader(argv, out, err, reader_seconds)
                else:
                    returncode, timed_out = run_reader(argv, subprocess.DEVNULL, err, reader_seconds)
        except OSError as exc:
            fail("the reader's output could not be created or started, and it did not run", out_dir=out_dir,
                 reason="%s: %s" % (type(exc).__name__, exc.strerror or "error"))
        except Interrupted as stop:
            interrupted = stop.signum
    finally:
        if staging:
            shutil.rmtree(scratch, ignore_errors=True)

    count_deadline = (time.monotonic() + INTERRUPT_COUNT_SECONDS) if interrupted is not None else budget_end + COUNT_SECONDS
    stderr_bytes = os.path.getsize(stderr_path) if os.path.isfile(stderr_path) else 0
    if not stderr_bytes:
        try:
            os.unlink(stderr_path)
        except OSError:
            pass
        stderr_path = None
    output_exists = os.path.isfile(output_path)
    if output_exists:
        coverage, entries = count_output(output_path, limit, count_deadline)
    else:
        coverage, entries = {"lines": 0, "json_records": 0, "entry_records": 0, "unparsed_lines": 0,
                             "records_without_entry_fields": 0, "array_delimiter_lines": 0,
                             "first_unparsed_lines": [], "first_records_without_entry_fields": []}, []
    coverage["support_files"] = census
    got = coverage["entry_records"]
    outcome = None

    if interrupted is not None:
        status = "partial" if got else "failed"
        problems.append("the tool was stopped by %s; the reader was ended and what it had written is kept and counted%s" % (
            signal_name(interrupted), " (the count may be short: it was given %d s)" % INTERRUPT_COUNT_SECONDS if coverage.get("counting_stopped_at_line") else ""))
    elif timed_out:
        status = "partial" if got else "failed"
        problems.append("the reader did not finish in the %d second(s) left of the budget and was stopped; what it had written is kept and counted" % round(reader_seconds))
    elif returncode != 0:
        status = "partial" if got else "failed"
        problems.append("the reader exited with code %s" % returncode)
    elif not output_exists:
        status = "failed"
        problems.append("the reader exited 0 and wrote no output file: nothing was decoded")
    elif not got:
        status = "partial"
        outcome = "empty"
        problems.append("the output holds no entries (%d line(s), %d JSON record(s) without an entry's fields): this is not a negative "
                        "about the logs" % (coverage["lines"], coverage["records_without_entry_fields"]))
    elif coverage["unparsed_lines"]:
        status = "partial"
    else:
        status = "complete"
    if coverage.get("counting_stopped_at_line") and interrupted is None:
        status = "partial"
        problems.append("counting the output stopped at line %d because its time ran out: the counts and the preview cover the lines before it" % coverage["counting_stopped_at_line"])
    if coverage["unparsed_lines"]:
        problems.append("%d line(s) of the output are not JSON records (the first at line %s)"
                        % (coverage["unparsed_lines"], ", ".join(str(n) for n in coverage["first_unparsed_lines"][:3])))
    if coverage["records_without_entry_fields"] and got:
        warnings.append("%d JSON record(s) have none of an entry's fields (timestamp, time, message, process, subsystem) and are not "
                        "counted as entries: read them before relying on entry_count" % coverage["records_without_entry_fields"])
    if stderr_bytes and not (timed_out or interrupted is not None or returncode != 0):
        warnings.append("the reader wrote %d byte(s) to its error stream (%s) although it exited 0: read it before relying on the output" % (stderr_bytes, stderr_path))

    digest_text = None
    if output_exists:
        digest_text = digest(output_path, (time.monotonic() + INTERRUPT_COUNT_SECONDS) if interrupted is not None else budget_end + DIGEST_SECONDS)
        if digest_text is None:
            problems.append("the sha256 of the output was not computed: the time for it ran out")
            if status == "complete":
                status = "partial"
    if status == "complete":
        basis = "the reader exited 0, wrote its output, and every one of its %d line(s) parsed as a JSON record (%d of them entries); the archive's coverage is for the examiner (decoded_coverage)" % (coverage["lines"], got)
    else:
        basis = "; ".join(problems) if problems else "see problems"
    OWN_NAMES.add(basis)
    note = ("The complete reader output is named in output, and it is the reader's own: it holds every message as decoded, and is not judged by the boundary; "
            "inline entries are only a preview, and their strings are. status says what happened to this run, "
            "not that the archive was fully decoded: decoded_coverage counts what was read and support_files is a census of "
            "what the input holds. Retention varies with log volume and policy, so absence must be scoped to the archive "
            "actually acquired. Messages can carry command lines, paths and account names.")
    OWN_NAMES.add(note)
    result = {
        "path": path,
        "parser": PARSER,
        "engine": engine,
        "reader": reader,
        "status": status,
        "status_basis": basis,
        **({"reader_outcome": outcome} if outcome else {}),
        **({"interrupted": signal_name(interrupted)} if interrupted is not None else {}),
        "exit_code": returncode,
        "timed_out": timed_out,
        "command": " ".join(argv),
        "output": output_path if output_exists else None,
        "output_sha256": digest_text,
        "entry_count": got,
        "entries": entries,
        "entries_inline": len(entries),
        "unparsed_lines": coverage["unparsed_lines"],
        "decoded_coverage": coverage,
        "staging": staging,
        "problems": problems,
        "warnings": warnings,
        "stderr": stderr_path,
        "stderr_bytes": stderr_bytes,
        "timeout_seconds_used": timeout,
        "budget": {"seconds_for_reader": round(reader_seconds) if reader_seconds is not None else None, "staging_seconds": round(marks["staged"], 1),
                   "census_seconds": round(marks["census"], 1), "seconds_used": round(time.monotonic() - started, 1)},
        **({"timeout_clamped": True, "timeout_requested": requested} if timeout != requested else {}),
        "note": note,
    }
    hold_signals()                     # the work is done: a signal now waits for the answer instead of replacing it (judging takes seconds at most)
    interrupted = emit_answer(result, interrupted, indent=2)       # (a signal that arrives while the answer is sealed is named in it)
    close_values()
    if interrupted is not None:
        sys.exit(128 + interrupted)
    if status == "failed" or timed_out or returncode not in (0,):
        raise SystemExit(1)


def main():
    seal_stop_after(SEAL_STOP_SECONDS)
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")
    run_log(args)


if __name__ == "__main__":
    install_stop_handlers()
    try:
        main()
    except SystemExit:
        raise
    except Interrupted as stop:
        close_values()
        emit({"error": "the tool was stopped by %s before the reader had run" % signal_name(stop.signum), "status": "failed",
              "status_basis": "stopped by %s during start-up: nothing was decoded" % signal_name(stop.signum), "interrupted": signal_name(stop.signum)})
        sys.exit(128 + stop.signum)
    except Exception as exc:                 # whatever hostile input does, the answer is JSON (the class only: a message can quote the evidence)
        close_values()
        emit({"error": "the tool stopped on an unexpected error", "type": type(exc).__name__, "status": "failed",
              "status_basis": "the tool stopped with an unexpected error: nothing is complete"})
        sys.exit(1)
