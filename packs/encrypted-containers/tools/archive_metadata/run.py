#!/usr/bin/env python3
"""Say what protects a 7-Zip or RAR archive, structurally and through 7z, and what a ZIP's listing shows; never extract.

The question is not only "can it be opened": it is whether the HEADERS are encrypted (the member names need the password) and whether
the members are (their data does). They are two findings, and this tool reports both where it can.

    7-Zip   the 32-byte start header (both CRCs checked), the next header's place against the file's size, and, when the header is
            packed, the coder list: 7-Zip's AES coder there means the header (the names) is encrypted. Then 7z lists the members
            with an impossible password and no prompt (-y, -spd, a bounded run): each member's encryption flag, method and sizes.
    RAR     RAR 4 and RAR 5 block headers read from the bytes: the main header's volume and password flags, the archive encryption
            header of RAR 5, every file header (name, sizes, the encrypted flag; a RAR 5 file's encryption record), each header's
            CRC, and the end-of-archive block. 7z is run on it as a second reader where its build reads RAR (Debian's drop the
            codecs), and a disagreement in the member count is named.
    ZIP     listed through 7z only. The structure of a ZIP (the central directory, the AES extra field 0x9901, the data descriptors,
            the bytes in front) is archive_probe's, from the bytes; this tool does not read it a second time.

A set of volumes: when the archive says another volume follows (RAR's end block or a member continued in the next volume, a 7-Zip
header past the end of the file), the next volume's name is derived and looked for beside the file; a missing one is named.
Nothing is extracted or executed: sizes are what the headers declare, and members declared very much larger than their packed size
are counted as high ratio (the zip-bomb shape) without any data being unpacked. Names and paths are printed through the SHARED NAMES
block below. The tool's own clock (`max_seconds`) is below the manifest's, and it stops on SIGTERM, SIGINT and SIGHUP with one JSON
answer and the exit status 128 + the signal, ending the 7z it started first.
"""


import errno
import hashlib
import json
import os
import re
import resource
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from pathlib import Path



# BEGIN SHARED STOP
# The same text is in recovery_key_scan, archive_probe and crypto_id (a pack test holds the copies equal). SIGTERM, SIGINT and SIGHUP end the
# tool with ONE JSON answer and the exit status 128 + the signal, with no traceback and no temporary file left. A tool that scans
# (cooperative) only notes the signal: the scan reads stop_wanted() between windows and files, finishes its pages and prints a partial
# answer. If it is not finished GRACE_SECONDS later (a read that never returns), or a second signal comes, the stop is hard: the cleanup
# steps run (a program the tool started is killed, a values file is closed), the temporary files of the pages are removed, the last word
# is printed and the process ends. The tool's own clock (set_deadline) is below the manifest's timeout and is backed by the same hard stop:
# GRACE_SECONDS after the deadline a read that has not returned (a file on a volume that is not there, a pipe nobody writes) no longer holds
# the tool. SIGALRM ends it when the read can be interrupted, and a watchdog thread, which needs neither a signal nor the read to return,
# ends it when not; either prints ONE JSON answer, status partial, and exits 0. A page fault in a mapped file can be ended by neither (it
# holds the interpreter): a tool that maps a file reads the part it maps through a descriptor first, where the thread can run.
# The last word of a stop by signal says status failed and interrupted true (the statuses are complete, partial and failed; a stop is not a status).
import signal
import threading
import time

GRACE_SECONDS = 5
STOP = {"signal": None, "deadline": None, "limit": None, "last_word": None, "cooperative": False, "cleanup": [], "answered": False,
        "owner": None, "hard_due": None}
_STOP_LOCK = threading.RLock()
_STOP_DONE = threading.Event()


def set_deadline(seconds):
    STOP["limit"] = seconds
    STOP["deadline"] = time.monotonic() + seconds
    arm_hard_stop(seconds + GRACE_SECONDS)
    threading.Thread(target=_watchdog, name="hard-stop", daemon=True).start()


def arm_hard_stop(seconds):
    """The hard stop is due in `seconds` at the latest (an earlier one stays): as SIGALRM, and as the time the watchdog waits for."""
    due = time.perf_counter() + seconds
    if STOP["hard_due"] is None or due < STOP["hard_due"]:
        STOP["hard_due"] = due
    left = signal.getitimer(signal.ITIMER_REAL)[0]
    signal.setitimer(signal.ITIMER_REAL, seconds if left <= 0 else min(seconds, left))


def disarm_stop():
    """No hard stop is wanted any more (the answer is going out, or the tool ends with an error): the timer and the watchdog stand down."""
    STOP["hard_due"] = None
    _STOP_DONE.set()
    signal.setitimer(signal.ITIMER_REAL, 0)


def _watchdog():
    while not _STOP_DONE.wait(0.2):
        due = STOP["hard_due"]
        if due is not None and time.perf_counter() >= due:
            hard_stop(STOP["signal"])


def stand_by():
    """When another thread is ending the tool, wait for it to do so: nothing else may print."""
    if STOP["owner"] not in (None, threading.get_ident()):
        while True:
            time.sleep(3600)


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def stop_wanted():
    return STOP["signal"] is not None or out_of_time()


def stop_cause():
    if STOP["signal"] is not None:
        return "stopped by signal %d" % STOP["signal"]
    return "the time limit (max_seconds %s) was reached" % STOP["limit"]


def remove_pending_pages():
    """Remove the temporary file of every page that is still being written."""
    for page in list(globals().get("PAGES", [])):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def hard_stop(signum):
    """End the tool now. `signum` is the signal that asked for it; None when the clock did: the answer is then partial and the exit status 0."""
    with _STOP_LOCK:
        if signum is None and STOP["answered"]:     # the answer is being written: let it be written
            STOP["hard_due"] = None
            return
        if STOP["owner"] in (None, threading.get_ident()):
            STOP["owner"] = threading.get_ident()
            mine = True
        else:
            mine = False
    if not mine:
        stand_by()
    for step in list(STOP["cleanup"]):
        try:
            step()
        except Exception:  # noqa: BLE001 - a cleanup step is best effort
            pass
    remove_pending_pages()
    if STOP["last_word"] and not STOP["answered"]:
        try:
            STOP["last_word"](signum)
        except Exception:  # noqa: BLE001
            pass
    os._exit(128 + signum if signum else 0)


def _on_stop_signal(signum, _frame):
    if STOP["cooperative"] and STOP["signal"] is None:
        STOP["signal"] = signum
        arm_hard_stop(GRACE_SECONDS)
        return
    hard_stop(STOP["signal"] or signum)


def _on_stop_alarm(_signum, _frame):
    hard_stop(STOP["signal"])


def install_stop(last_word=None, cooperative=False):
    STOP["last_word"], STOP["cooperative"] = last_word, cooperative
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_stop_signal)
    signal.signal(signal.SIGALRM, _on_stop_alarm)


def interrupted_answer(signum, **extra):
    if signum is None:       # the clock ran out, and then GRACE_SECONDS more, with a read that had not returned
        print(json.dumps({"status": "partial", "partial": True, "interrupted": True, "hard_stopped": True,
                          "stopped_by": "the tool's time limit (%s seconds) was reached" % STOP["limit"],
                          "status_basis": "the tool's time limit (%s seconds) and %d seconds more passed while a read had not returned (a file on a "
                                          "volume or share that is not available, or a pipe); the tool was ended there, and nothing it had read is "
                                          "an answer" % (STOP["limit"], GRACE_SECONDS), **extra}), flush=True)
        return
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "failed", "interrupted": True,
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)


def claim_answer():
    """Take the one answer (an answer or an error): the stop is disarmed, the stop signals are held back, and `answered` is set under the
    lock, so that a watchdog that has read its due time but not yet taken the lock finds the answer claimed and prints nothing. When the
    stop was claimed first, wait for the thread that has it to end the tool."""
    disarm_stop()
    held = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGALRM}
    signal.pthread_sigmask(signal.SIG_BLOCK, held)
    with _STOP_LOCK:
        mine = STOP["owner"] in (None, threading.get_ident())
        if mine:
            STOP["answered"] = True
    if not mine:
        stand_by()


def emit(answer):
    """Print the answer once, with the stop signals held back until it is out, and leave with 128 + the signal if one was noted."""
    claim_answer()
    text = json.dumps(seal(answer), indent=2, ensure_ascii=True)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()
    if STOP["signal"] is not None:
        os._exit(128 + STOP["signal"])


# The handlers are in as soon as the module has run as far as this block (a hard stop with the generic last word, until main() installs the
# tool's own): only the start of the interpreter and the compiling of the file come before it.
install_stop(lambda signum: interrupted_answer(signum))
# END SHARED STOP


def own_dir(path):
    """Create the tool-output directory and return None, or say why it is not used: a symbolic link anywhere on the way (the directory itself,
    or work/ or the agent's directory under it) would send the tables and the private names file somewhere else, and O_NOFOLLOW guards only
    the last name of a file. In a job only the part under $OUT is checked ($OUT is the job service's)."""
    path = Path(path)
    out = os.environ.get("OUT")
    start = len(Path(out).parts) if out and path.parts[:len(Path(out).parts)] == Path(out).parts else 0
    for i in range(max(start, 1), len(path.parts) + 1):
        step = Path(*path.parts[:i])
        if os.path.islink(step):
            return "%s is a symbolic link: refused, nothing written through it" % step
    path.mkdir(parents=True, exist_ok=True)
    return None


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
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
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
            "status_basis": "the whole result could not be written, so the tool stopped with an error and returned no result",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                reason = own_dir(self.path.parent)
                if reason is not None:
                    self._cannot_write(OSError(reason))
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
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


# BEGIN SHARED WITHHOLDING
# The same text is in every tool that withholds identifier-shaped strings (the network, base, virtualization and
# reverse-engineering packs), so that they withhold the same strings; the tests that hold the copies equal are
# tests/pack-network-withholding.test.ts, tests/pack-base-shared.test.ts, tests/pack-virtualization-shared.test.ts and
# tests/pack-re-process.test.ts. An identifier-shaped string is withheld wherever the tool would print one: a name, a
# path component, a URL, a message that quotes either.
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
TEXT_LIMIT = 65536


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


def scrub(text, kind="text"):
    """The text with every token-shaped run and every user-info withheld."""
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
    return "".join(out)


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
# The same text is in recovery_key_scan, archive_probe and crypto_id (a pack test holds the copies equal). It decides what a name,
# a path, a header string or a diagnostic from evidence may show. Layer 1 (shown, withhold) cuts out of a string the spans that are
# shaped like an identifier or a secret and puts a fixed placeholder where each was (no length, no fragment); layer 2 (seal) reads
# every string of what is about to be printed or paged once more, by rules of its own, and replaces a string the first layer let
# through that still looks like a secret.
#
# WITHHELD, by shape: a recovery password (eight groups of six digits, joined by none to three characters that are not letters or digits)
# in a path component, whole component, and across the components of a path (the separators of a path join its groups); a run of 10 or
# more digits; a run of 8 or more letters and digits that has a digit in it (System32 and a few such names of Windows are let through); a
# letters-only run of 8 or more that is not one word, a camel-case word or all capitals; groups of 4 to 6 characters joined by one `-`, `_`
# or `.` (3 or more digit-only groups, or 4 or more groups that each hold a digit or are all capitals), and four or more groups of exactly
# six digits joined by spaces; the value after password, secret, token, api key, credential, auth (`password=...`); user-info; and the
# token shapes of the shared WITHHOLDING block above (vendor prefixes, JWT, long hex, long mixed runs, base64 with `/`). A string is also
# judged after NFKC, with invisible characters taken out and with the Cyrillic and Greek letters that look like Latin ones read as Latin,
# and a hit there that the string as written does not show withholds the whole string.
# NOT WITHHELD, by design: an identifier of 7 characters or fewer, a lowercase-only random run (it reads as a word), a secret that does
# not look like one, an all-capital letters-only run of any length, groups of other sizes (three groups of 4 to 6 letters and digits are
# printed), a recovery password cut into pieces by anything else than the separators above, and anything in the data a tool reads rather
# than prints.
# BOUNDED: the token rule of the WITHHOLDING block re-reads the text in front of a `/` once for each flagged piece after it, so its time
# grows with the square of a long run of name characters. What that block is given is therefore bounded first (_unjudgeable): a string of
# more than MAX_JUDGED characters, as written or after NFKC, or one that holds a `/` and a run of name characters of more than MAX_RUN, is
# withheld whole and not judged. The block itself is repaired at its source in a change of its own, for every pack that copies it.
# Measured on random draws and on real directory trees: tests/pack-encrypted-containers-names.test.ts and the manifests give the rates.
import unicodedata

NAMES = {"strings": 0, "replaced": 0}      # printed strings in which something was withheld; strings the output check replaced
RECOVERY_NAME = "<recovery-password-shaped name withheld>"
ID_TEXT = "<identifier-shaped text withheld>"
SECRET_TEXT = "<secret-shaped text withheld>"
LONG_TEXT = "<text too long to judge withheld>"
CHECKED = "<withheld by the output check>"
MAX_JUDGED = 4096        # characters judged in one string (a name, a component, a header string); longer is withheld whole
MAX_RUN = 256            # the longest run of name characters judged in a string that holds a `/`
_NAME_RUN = re.compile(r"[A-Za-z0-9_+%-]+")
_RECOVERY_SHAPE = re.compile(r"[0-9]{6}(?:[^0-9A-Za-z]{0,3}[0-9]{6}){7}")      # no look-arounds: a digit glued to the first or last group hides nothing
_SIX_SPACED = re.compile(r"(?<![0-9])(?:[0-9]{6} ){3,}[0-9]{6}(?![0-9])")
_GROUP = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{4,6}(?![A-Za-z0-9])")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]{8,}")
_KNOWN_RUNS = frozenset(("System32", "SysWOW64", "Wow6432Node", "Windows10", "Windows11", "Windows7", "Windows8", "Windows2000", "Windows2003"))
_WORD_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")
_NAMED = re.compile(r"(?i)(?<![A-Za-z0-9])(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)"
                    r"[A-Za-z0-9_-]{0,16}[ \t]*[=:][ \t]*([^\s\"'&;,/\\<][^\s\"'&;,/\\]*)")
_CACHE = {}
_CACHE_BYTES = [0]


def _chains(text):
    """Spans of groups of 4 to 6 characters joined by one `-`, `_` or `.`: 3 or more digit-only groups, or 4 or more that each hold a digit or are all capitals."""
    chain = []
    for m in _GROUP.finditer(text):
        g = m.group()
        joins = any(c.isdigit() for c in g) or g.isupper()
        if chain and joins and m.start() == chain[-1][1] + 1 and text[chain[-1][1]] in "-_.":
            chain.append((m.start(), m.end(), g.isdigit()))
            continue
        yield from _close(chain)
        chain = [(m.start(), m.end(), g.isdigit())] if joins else []
    yield from _close(chain)


def _close(chain):
    if len(chain) >= 4 or (len(chain) >= 3 and all(c[2] for c in chain)):
        yield chain[0][0], chain[-1][1]


def _wordy(run, caps=1 << 30):
    """A letters-only run that reads as words: one lowercase word (22 letters at most), one all-capital run, or camel case: capitalised
    words and capital runs (acronyms), of which at most a quarter are shorter than 3 letters (one short part is let through in a two-part name whose second part has 5 letters or more: MyDocument)."""
    if run.islower():
        return len(run) <= 22
    if run.isupper():
        return len(run) <= caps
    tokens = _WORD_TOKEN.findall(run)
    return "".join(tokens) == run and all(len(t) <= 22 for t in tokens) and sum(1 for t in tokens if len(t) < 3) <= max(len(tokens) // 4, 1 if len(tokens) == 2 and len(tokens[1]) >= 5 else 0)


def _runs(text):
    for m in _ALNUM_RUN.finditer(text):
        t = m.group()
        if t in _KNOWN_RUNS:
            continue
        if t.isdigit():
            if len(t) >= 10:
                yield m.span()
        elif any(c.isdigit() for c in t) or not _wordy(t):
            yield m.span()


def _spans(text):
    """(start, end, secret) of what a string shows that is shaped like an identifier (secret False) or like a secret (True), merged."""
    found = []
    for m in _NAMED.finditer(text):
        found.append((m.start(1), m.end(1), True))
    for rx in (_USERINFO, _BARE_USERINFO):
        for m in rx.finditer(text):
            found.append((m.start(), m.end(), True))
    for m in _SIX_SPACED.finditer(text):
        found.append((m.start(), m.end(), False))
    for a, b in list(token_spans(text)) + list(_chains(text)) + list(_runs(text)):
        found.append((a, b, False))
    found.sort()
    merged = []
    for a, b, secret in found:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b), merged[-1][2] or secret)
        else:
            merged.append((a, b, secret))
    return merged


# Cyrillic and Greek letters that are written like Latin ones: a pair is (the letter, the Latin letter it is read as).
_LOOKALIKE_PAIRS = ("\u0430a\u0441c\u0435e\u043eo\u0440p\u0445x\u0443y\u0456i\u0458j\u0455s\u0501d\u04bbh\u0410A\u0412B\u0415E\u041aK\u041cM\u041dH"
                    "\u041eO\u0420P\u0421C\u0422T\u0425X\u0406I\u0408J\u0405S\u0423Y\u0391A\u0392B\u0395E\u0396Z\u0397H\u0399I\u039aK\u039cM"
                    "\u039dN\u039fO\u03a1P\u03a4T\u03a5Y\u03a7X\u03bfo\u03bdv\u03b9i\u03c1p")
_LOOKALIKES = {ord(_LOOKALIKE_PAIRS[i]): _LOOKALIKE_PAIRS[i + 1] for i in range(0, len(_LOOKALIKE_PAIRS), 2)}


def _fold(text):
    if text.isascii():
        return text
    return unicodedata.normalize("NFKC", "".join(c for c in text if unicodedata.category(c) != "Cf")).translate(_LOOKALIKES)


def _unjudgeable(text):
    """A string the token rule of the WITHHOLDING block must not be given: too long, or a long run of name characters beside a `/`."""
    return len(text) > MAX_JUDGED or ("/" in text and any(len(run) > MAX_RUN for run in _NAME_RUN.findall(text)))


def _judge(text, whole):
    """(the text as it may be shown, whether anything was withheld). `whole`: a recovery-password shape withholds the whole string."""
    if len(text) < 6:
        return text, False
    if _unjudgeable(text):
        return LONG_TEXT, True
    key = (text, whole)
    if key in _CACHE:
        return _CACHE[key]
    folded = _fold(text)
    if folded is not text and _unjudgeable(folded):
        return _remember(key, (LONG_TEXT, True))
    hit = False
    if _RECOVERY_SHAPE.search(text) or _RECOVERY_SHAPE.search(folded):
        if whole:
            return _remember(key, (RECOVERY_NAME, True))
        text, hit = _RECOVERY_SHAPE.sub(RECOVERY_NAME, folded), True
        folded = text
    spans = _spans(text)
    if folded != text and sum(b - a for a, b, _s in _spans(folded)) > sum(b - a for a, b, _s in spans):
        return _remember(key, (ID_TEXT, True))
    if spans:
        parts, last = [], 0
        for a, b, secret in spans:
            parts.append(text[last:a])
            parts.append(SECRET_TEXT if secret else ID_TEXT)
            last = b
        parts.append(text[last:])
        text, hit = "".join(parts), True
    return _remember(key, (text, hit))


def _remember(key, out):
    # bounded by the number of strings and by their size: 100,000 strings of a few kilobytes each are not a cache
    if len(_CACHE) < 100000 and _CACHE_BYTES[0] < (16 << 20):
        _CACHE[key] = out
        _CACHE_BYTES[0] += len(key[0]) + len(out[0])
    return out


def withhold(text):
    """A string of evidence text (a header field, a diagnostic, a string from a header) as it may be printed."""
    if not isinstance(text, str):
        return text
    out, hit = _judge(text, False)
    if hit:
        NAMES["strings"] += 1
    return out


def shown(path, count=True):
    """A path or a member name as it may be printed: every component judged by itself, a separator kept."""
    if not isinstance(path, str):
        return path
    if len(path) > 2 * MAX_JUDGED:      # a path is judged piece by piece: a name of a few such pieces is not a name
        NAMES["strings"] += 1 if count else 0
        return LONG_TEXT
    hit = False
    # A recovery password cut at the separators of the path ("123456-123456/123456-..."): the separators of a path join its groups.
    for candidate in ((path,) if path.isascii() else (path, _fold(path))):
        cut = _RECOVERY_SHAPE.sub(lambda m: RECOVERY_NAME if ("/" in m.group() or "\\" in m.group()) else m.group(), candidate)
        if cut != candidate:
            path, hit = cut, True
            break
    pieces = re.split(r"([/\\])", path)
    for i in range(0, len(pieces), 2):
        pieces[i], one = _judge(pieces[i], True)
        hit = hit or one
    if hit and count:
        NAMES["strings"] += 1
    return "".join(pieces)


# Layer 2: written apart from the rules above, over everything that is written. A string it finds suspect is replaced whole.
_CHECK_QUICK = re.compile(r"(?i)[0-9]{6}|PRIVATE KEY|[A-Za-z0-9+_=-]{24}|[0-9a-f]{16}|//[^/?#\s@]+@|pass|pwd|secret|token|api[_-]?key|AKIA|ASIA|gh.?_|github_pat|xox|eyJ|sk-|AIza|glpat|npm_")
_CHECK_PREFIX = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{12}|gh[pousr]_[A-Za-z0-9]{16}|github_pat_[A-Za-z0-9_]{16}|xox[abeprs]-[A-Za-z0-9]{8}|eyJ[A-Za-z0-9_-]{8}"
                           r"|sk-[A-Za-z0-9_-]{16}|AIza[0-9A-Za-z_-]{16}|glpat-[A-Za-z0-9_-]{12}|npm_[A-Za-z0-9]{16}")
_CHECK_DIGITS = re.compile(r"(?<![0-9])(?:[0-9]{6}[-_. ]?){8}(?![0-9])|[0-9]{6}(?:[-_. ][0-9]{6}){7}")
_CHECK_PEM = re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY|PRIVATE KEY-----")
_CHECK_RUN = re.compile(r"[A-Za-z0-9+_=-]{24,}")
_CHECK_HEX = re.compile(r"(?<![0-9A-Za-z])(?=[0-9]*[a-fA-F])(?=[a-fA-F]*[0-9])[0-9a-fA-F]{16,}(?![0-9A-Za-z])")     # 16 or more hex digits, letters and digits both
_CHECK_USERINFO = re.compile(r"(?<=//)[^/?#\s@]{1,128}@")
_CHECK_VALUE = re.compile(r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key)[A-Za-z0-9_-]{0,16}[ \t]*[=:][ \t]*[^\s\"'<>]{6,}")
OWN_KEYS = {"all_results", "values_file", "paths_note"}      # strings the tool made itself


_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _suspect(text):
    if not text.isascii():      # full-width and invisible forms are read as the text they imitate
        text = unicodedata.normalize("NFKC", "".join(c for c in text if unicodedata.category(c) != "Cf"))
    if not _CHECK_QUICK.search(text) or _UUID.fullmatch(text):
        return False
    if _CHECK_DIGITS.search(text) or _CHECK_PEM.search(text) or _CHECK_VALUE.search(text) or _CHECK_PREFIX.search(text) \
            or _CHECK_HEX.search(text) or _CHECK_USERINFO.search(text):
        return True
    for m in _CHECK_RUN.finditer(text):
        run = m.group()
        if re.fullmatch(r"[0-9a-fA-F]{32,}", run):
            return True
        flips = sum(1 for a, b in zip(run, run[1:]) if a.isdigit() != b.isdigit() and a.isalnum() and b.isalnum())
        if flips >= 6:
            return True
    return False


def seal(value, key=None):
    """The value with every string the check finds suspect replaced (a dict's keys too). Counted in NAMES['replaced']."""
    if isinstance(value, str):
        if key in OWN_KEYS or len(value) < 8 or not _suspect(value):
            return value
        NAMES["replaced"] += 1
        return CHECKED
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and len(k) >= 8 and _suspect(k):
                NAMES["replaced"] += 1
                k = CHECKED + "#%d" % NAMES["replaced"]
            out[k] = seal(v, k)
        return out
    if isinstance(value, (list, tuple)):
        return [seal(v, key) for v in value]
    return value
# END SHARED NAMES


# BEGIN SHARED PROCESS
# The same text is in pcap_extract, zeek_run, suricata_run, the network-capture recipe and computer-forensics-base's
# archive_extract; tests/pack-network-withholding.test.ts holds the four network copies equal and tests/pack-base-shared.test.ts
# holds archive_extract's to them. A program an engine tool runs is started in THIS tool's process group, never in a session of
# its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid,
# SIGKILL)), and an engine in a group of its own goes on writing into the output directory after the tool is gone. On
# Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it started by
# walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word. Only what is
# below a program this tool started and has not yet waited for is ever signalled: the walk starts at that program's pid
# and nowhere else, and a program that has been waited for (its pid may be another process's by now) is left alone. The
# walk is bounded (MAX_ROUNDS and WALK_SECONDS, below). A stop signal is the one case that reaches further: it also
# ends everything below the tool itself (a program that was forked a moment before it was entered in ACTIVE is among it) and what
# the tool started and lost (reap_orphans): a process that was seen below the tool, in the tool's own group, and whose parent has since
# ended. Nothing else is ever ended: a process the tool never saw in its tree (the next stage of a pipeline the tool heads, a process a
# launcher put in the group) is left alone, whoever leads the group. A program that has ended while something it started still
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds and goes on without them.
# The walk below a program is bounded: MAX_ROUNDS rounds and WALK_SECONDS seconds. Each process is stopped (SIGSTOP) as the walk finds it,
# so one that forks fast cannot outrun the walk; the walk is repeated for what the stopped ones had already forked, and the stopped set is
# then killed. A tree that is still growing at the bound is left, and process_notes() says so.
# Before a pid other than the program itself is signalled, its identity is read again (same_process(pid, ident)): the start time, from
# /proc/<pid>/stat (field 22, counted after the last ")") on Linux, from libproc's PROC_PIDTBSDINFO (pbi_start_tvsec, pbi_start_tvusec;
# written from <sys/proc_info.h>, not run on macOS in this repository's tests) on macOS, and from `ps -o lstart=` (to the second: coarse)
# where neither answers. The parent is no part of it: a child is re-parented when its parent ends, and is still the process that was
# listed. A pid that is gone, or whose start time is not the listed one, is left alone; a pid whose start time could not be read when it
# was listed is signalled only if it can be read now and is in the tool's own group; a ps listing that gave no start time (a minimal ps) is
# checked only for the pid still being there.
# A tree that cannot be listed (ps fails, lists nothing or needs more than PS_WAIT seconds, /proc cannot be read or takes more than
# TABLE_SECONDS) is never taken as an empty one: list_descendants raises TreeNotListed, the program itself is still ended, and a sentence
# in process_notes() says that the tree could not be listed (communicate_bounded also appends it to the stderr bytes it returns when it
# ended the program at its deadline). descendants() is list_descendants for a caller that cannot take an exception (a signal handler): its
# list is empty and has not_listed = True when the tree could not be listed.
# Open: a pid that ends and is reused between the identity check and the signal (two calls) is signalled; the Linux rule that a member of
# the tool's own group that holds the tool's pipe is ended; on macOS a daemon that holds the pipes of a finished program is not found (no
# /proc/<pid>/fd); a tool SIGKILLed between the stop and the kill leaves the program and the stopped set stopped (the harness ends the
# tool's group, and with it the stopped ones that are in it); a carrier's answer says what process_notes() holds only where that carrier's
# own code reads it; the start of the interpreter, before any handler is in, is a window a signal can land in.
import time

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now
SEEN = set()                   # the pids seen below a program this tool started: the only ones reap_orphans may end once their parent is gone
SEEN_IDENT = {}                # what each pid in SEEN was (its start time) when it was seen below the tool: a pid that ended and was reused does not match
NOTES = []                     # what this block could not do, as sentences for an answer (process_notes())
MAX_ROUNDS, WALK_SECONDS = 8, 15   # the bound of the walk below a program: rounds, and seconds
TABLE_SECONDS = 10             # the longest reading of /proc (or of a process table) is given
SEEN_MAX = 1 << 16             # the most pids SEEN holds

def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    proc = subprocess.Popen(argv, **kwargs)
    SEEN.add(proc.pid)
    started = _read_ident(proc.pid, "proc" if os.path.isdir("/proc/self") else "libproc")
    if started is not None:
        SEEN_IDENT[proc.pid] = started
    return proc


class TreeNotListed(Exception):
    """The processes could not be listed: ps failed, listed nothing or needed more than PS_WAIT seconds, /proc could not be read, or reading
    it took more than TABLE_SECONDS. It is never to be read as a tree with nothing below it."""


class _Listing(list):
    """The pids below a process, as a list; .ident holds each pid's identity from the same reading, .not_listed says the tree could not be listed."""
    ident = None
    not_listed = False


class _Table(dict):
    """{pid: (parent pid, process group)}; .ident holds each pid's identity from the same reading."""
    ident = None


def _note(text):
    """Record a sentence about what this block could not do (once, at most 20) and return it."""
    if text not in NOTES and len(NOTES) < 20:
        NOTES.append(text)
    return text


def process_notes():
    """What this block could not do so far, as sentences (a tree that could not be listed, a walk that was cut), for an answer."""
    return list(NOTES)


def _libproc_start(pid):
    """(seconds, microseconds) of the start of `pid` from libproc's PROC_PIDTBSDINFO (macOS), or None. Written from <sys/proc_info.h>
    (struct proc_bsdinfo, 136 bytes, flavor 3); not run on macOS in this repository's tests."""
    try:
        import ctypes.util

        class BsdInfo(ctypes.Structure):
            _fields_ = [("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32), ("pbi_xstatus", ctypes.c_uint32),
                        ("pbi_pid", ctypes.c_uint32), ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
                        ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32), ("pbi_rgid", ctypes.c_uint32),
                        ("pbi_svuid", ctypes.c_uint32), ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
                        ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32), ("pbi_nfiles", ctypes.c_uint32),
                        ("pbi_pgid", ctypes.c_uint32), ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
                        ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32), ("pbi_start_tvsec", ctypes.c_uint64),
                        ("pbi_start_tvusec", ctypes.c_uint64)]

        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        lib.proc_pidinfo.restype = ctypes.c_int
        info = BsdInfo()
        if lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
            return None
        return (int(info.pbi_start_tvsec), int(info.pbi_start_tvusec))
    except Exception:  # noqa: BLE001 - no library, no symbol, a sandbox: the caller falls back
        return None


def _ps_start(pid):
    """The start time `ps -o lstart= -p <pid>` prints, to the second (coarse), or None when ps fails, takes more than PS_WAIT seconds or prints none."""
    try:
        done = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True, timeout=PS_WAIT)
    except (OSError, subprocess.SubprocessError):
        return None
    text = " ".join(done.stdout.split())
    return text if done.returncode == 0 and text else None


def _read_ident(pid, kind):
    """The identity of `pid` read the way `kind` ("proc", "libproc" or "ps") says, or None when the process is gone or the way fails."""
    if kind == "proc":
        try:
            with open("/proc/%d/stat" % pid, "rb") as fh:
                data = fh.read()
            return ("proc", int(data[data.rindex(b")") + 2:].split()[19]))   # field 22, counted after the last ")": the name may hold one
        except (OSError, ValueError, IndexError):
            return None
    if kind == "libproc":
        started = _libproc_start(pid)
        return None if started is None else ("libproc", started)
    started = _ps_start(pid)
    return None if started is None else ("ps", started)


def process_ident(pid):
    """What tells the process that has `pid` now from a later one that gets the same pid: its start time. Linux: field 22 of /proc/<pid>/stat;
    macOS: libproc's pbi_start_tvsec and pbi_start_tvusec; where neither answers, the start time ps prints (to the second). The parent is no
    part of it: a child is re-parented when its parent ends, and is still the process that was listed. None where the process is gone or
    cannot be read."""
    if os.path.isdir("/proc/self"):
        return _read_ident(pid, "proc")
    return _read_ident(pid, "libproc") or _read_ident(pid, "ps")


def same_process(pid, ident):
    """Whether `pid` is still the process `ident` was read from (process_ident, or the listing a walk made): a pid that is gone, or that
    another process has taken since (another start time), is not. An `ident` of None (it could not be read when the process was listed) is
    not vouched for either: the pid is signalled only if it can be read now and is in this process's own group. A listing by plain ps that
    gave no start time ("listed") can only be checked for the pid still being there."""
    if ident is None:
        try:
            return process_ident(pid) is not None and os.getpgid(pid) == os.getpgrp()
        except OSError:
            return False
    if ident[0] == "listed":
        try:
            os.kill(pid, 0)
        except PermissionError:
            return True
        except OSError:
            return False
        return True
    return _read_ident(pid, ident[0]) == ident


def _seen_below(pids, ident):
    """Enter pids seen below the tool in SEEN, with the identity the listing that showed them gave."""
    for pid in pids:
        if pid in SEEN or len(SEEN) < SEEN_MAX:
            SEEN.add(pid)
            if ident.get(pid) is not None:
                SEEN_IDENT[pid] = ident[pid]


def _ps_rows(columns):
    """The rows of `ps -A -o <columns>` as lists of fields. Raises TreeNotListed when ps cannot be run, fails, takes more than PS_WAIT seconds
    or lists nothing."""
    try:
        done = subprocess.run(["ps", "-A", "-o", columns], capture_output=True, text=True, timeout=PS_WAIT)
    except subprocess.TimeoutExpired as exc:
        raise TreeNotListed("ps took more than %d seconds" % PS_WAIT) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise TreeNotListed("ps could not be run: %s" % type(exc).__name__) from exc
    rows = [line.split() for line in done.stdout.splitlines() if line.split()]
    if done.returncode != 0 or not rows:
        raise TreeNotListed("ps %s" % ("exited %d" % done.returncode if done.returncode != 0 else "listed nothing"))
    return rows


def _children_libproc(pid):
    """The direct children of `pid` on macOS, from libproc (macOS only: proc_listchildpids is not a symbol of the other
    BSDs; a library call, so no program is started and nothing can be slow); None when the library, the symbol or the
    call is not there."""
    try:
        import ctypes.util
        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        lib.proc_listchildpids.restype = ctypes.c_int
        size = 256
        while size <= 1 << 16:
            buf = (ctypes.c_int * size)()
            if lib.proc_listchildpids(pid, buf, ctypes.sizeof(buf)) < 0:
                return None
            found = []
            for value in buf:
                if value <= 0:
                    break
                found.append(int(value))
            if len(found) < size:
                return found
            size *= 4
        return found
    except Exception:  # noqa: BLE001 - no library, no symbol: the caller falls back
        return None


PS_WAIT = 10    # seconds the ps fallback is given: ps is slow on a heavily loaded host, and a tree that is not found is a program left running


def _below(kids, pid):
    """Every process below `pid` in `kids` ({parent: [children]}), a parent before its children."""
    found, seen, queue = [], {pid}, [pid]
    for parent in queue:
        for child in kids.get(parent, []):
            if child not in seen:
                seen.add(child)
                found.append(child)
                queue.append(child)
    return found


def _libproc_works(pid):
    """Whether an empty libproc answer for `pid` can be believed: libproc has just listed `pid` as this tool's own child, or, when `pid`
    is the tool itself, has just listed the tool as its parent's child. A library that lists nothing for a live process is not working
    (as in a sandbox that denies it)."""
    if pid in (_children_libproc(os.getpid()) or []):
        return True
    return pid == os.getpid() and os.getpid() in (_children_libproc(os.getppid()) or [])


def list_descendants(pid):
    """Every process below `pid` (never one beside it): from /proc where there is one, else from libproc, else from ps (given PS_WAIT
    seconds). libproc is believed when it lists a child; an empty answer is believed only when libproc has just listed this tool's own child
    `pid` (a library that answers nothing for a live child is not working, as in a sandbox that denies it), and otherwise ps is asked. The
    list carries .ident, the identity of each pid from the same reading. Raises TreeNotListed when the processes cannot be listed: that is
    never an empty list."""
    kids, ident = {}, {}
    try:
        if os.path.isdir("/proc/self"):
            started = time.monotonic()
            for entry in os.listdir("/proc"):
                if time.monotonic() - started > TABLE_SECONDS:
                    raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        kids.setdefault(int(fields[1]), []).append(int(entry))
                        ident[int(entry)] = ("proc", int(fields[19]))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            first = _children_libproc(pid)
            if first:
                found, seen, stack = list(first), {pid, *first}, list(first)
                while stack:
                    for child in _children_libproc(stack.pop()) or []:
                        if child not in seen:
                            seen.add(child)
                            found.append(child)
                            stack.append(child)
                listing = _Listing(found)
                listing.ident = {}
                for child in found:
                    started = _libproc_start(child)
                    if started is not None:
                        listing.ident[child] = ("libproc", started)
                return listing
            if first is not None and _libproc_works(pid):
                listing = _Listing()
                listing.ident = {}
                return listing
            for row in _ps_rows("pid=,ppid=,lstart="):
                if len(row) >= 2 and row[0].isdigit() and row[1].isdigit():
                    kids.setdefault(int(row[1]), []).append(int(row[0]))
                    ident[int(row[0])] = ("ps", " ".join(row[2:])) if len(row) >= 6 else ("listed", None)
    except OSError as exc:
        raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    listing = _Listing(_below(kids, pid))
    listing.ident = {child: ident[child] for child in listing if child in ident}
    return listing


def descendants(pid):
    """list_descendants for a caller that cannot take an exception (a signal handler): the same list, but when the tree cannot be listed the
    list is empty, has not_listed = True, and process_notes() says so."""
    try:
        return list_descendants(pid)
    except TreeNotListed as exc:
        _note("the processes below pid %d could not be listed (%s)" % (pid, exc))
        listing = _Listing()
        listing.ident = {}
        listing.not_listed = True
        return listing


def _process_table():
    """{pid: (parent pid, process group)} for every process, from /proc where there is one, else from ps (given PS_WAIT seconds); .ident holds
    each pid's identity from the same reading. Raises TreeNotListed when neither answers."""
    table, ident = _Table(), {}
    try:
        if os.path.isdir("/proc/self"):
            started = time.monotonic()
            for entry in os.listdir("/proc"):
                if time.monotonic() - started > TABLE_SECONDS:
                    raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        table[int(entry)] = (int(fields[1]), int(fields[2]))
                        ident[int(entry)] = ("proc", int(fields[19]))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            for row in _ps_rows("pid=,ppid=,pgid=,lstart="):
                if len(row) >= 3 and all(part.isdigit() for part in row[:3]):
                    table[int(row[0])] = (int(row[1]), int(row[2]))
                    ident[int(row[0])] = ("ps", " ".join(row[3:])) if len(row) >= 8 else ("listed", None)
    except OSError as exc:
        raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    table.ident = ident
    return table


def _sample(pid):
    """Remember what is below `pid` now, by the cheap routes only (/proc, or libproc on macOS; never a program): a process that is seen
    here and later loses its parent is the tool's to end, and one that was never seen is not."""
    try:
        if os.path.isdir("/proc/self"):
            table = _process_table()
            kids = {}
            for child, (parent, _group) in table.items():
                kids.setdefault(parent, []).append(child)
            _seen_below(_below(kids, pid), table.ident)
        else:
            seen, stack = {pid}, [pid]
            while stack:
                for child in _children_libproc(stack.pop()) or []:
                    if child not in seen:
                        seen.add(child)
                        stack.append(child)
            idents = {child: ("libproc", started) for child in seen - {pid} for started in [_libproc_start(child)] if started is not None}
            _seen_below(seen - {pid}, idents)
    except Exception:  # noqa: BLE001 - a sample is best effort
        pass


def _pipe_inodes(proc):
    """The inodes of the pipes the tool holds with `proc` (Linux: /proc names a pipe by it; elsewhere the answer is not used)."""
    found = set()
    for handle in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if handle is not None:
                found.add(os.fstat(handle.fileno()).st_ino)
        except (OSError, ValueError):
            pass
    return found


def _holds_pipe(pid, inodes):
    """Whether `pid` holds one of the pipes (Linux only, from /proc/<pid>/fd): the pipes are private to the tool and what it started."""
    try:
        for name in os.listdir("/proc/%d/fd" % pid):
            try:
                link = os.readlink("/proc/%d/fd/%s" % (pid, name))
            except OSError:
                continue
            if link.startswith("pipe:[") and link.endswith("]") and int(link[6:-1]) in inodes:
                return True
    except (OSError, ValueError):
        pass
    return False


def reap_orphans(inodes=None):
    """Kill what this tool started and lost: a process of the tool's own group that is no longer below the tool (its parent ended and
    init adopted it, so the walk from a program's pid cannot find it) and that the tool knows to be its own: it was seen below the tool
    (SEEN: the programs it started, the trees it listed, the samples taken while it waited), or, on Linux, it holds one of `inodes`,
    the pipes the tool made. A process the tool never saw in its tree is not touched, whoever leads the group: the next stage of a
    pipeline the tool heads, or a process a launcher put in the group, is not the tool's. A process outside the group is never looked
    at, and a pid is checked against the group, and against the identity it had when it was seen (same_process), at the moment it is
    signalled. Returns the pids signalled; when the processes cannot be listed it signals none and process_notes() says so."""
    me = os.getpid()
    try:
        if os.getpgrp() != me:
            return []
    except OSError:
        return []
    try:
        table = _process_table()
    except TreeNotListed as exc:
        _note("what the tool started and lost could not be looked for: the processes could not be listed (%s)" % exc)
        return []
    kids = {}
    for pid, (parent, _group) in table.items():
        kids.setdefault(parent, []).append(pid)
    below = set(_below(kids, me))
    on_linux = os.path.isdir("/proc/self")
    killed = []
    started = time.monotonic()
    for pid, (_parent, group) in table.items():
        if time.monotonic() - started > TABLE_SECONDS:
            _note("the look for what the tool started and lost was cut after %d seconds" % TABLE_SECONDS)
            break
        if group != me or pid == me or pid in below:
            continue
        listed = table.ident.get(pid)
        holder = False
        if pid in SEEN:
            before = SEEN_IDENT.get(pid)
            if before is not None and listed is not None and before != listed:
                continue                           # the pid is another process's now: one the tool never saw
        elif inodes and on_linux and _holds_pipe(pid, inodes):
            holder = True
        else:
            continue
        try:
            if os.getpgid(pid) != me:
                continue
            if not same_process(pid, listed) or (holder and not _holds_pipe(pid, inodes)):
                continue
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except OSError:
            pass
    return killed


def _stop_below(root, stopped):
    """Stop (SIGSTOP) every process below `root` as the walk finds it, so one that forks fast cannot outrun the walk, and repeat the walk
    for what the stopped ones had already forked, for at most MAX_ROUNDS rounds and WALK_SECONDS seconds. `stopped` gets {pid: identity}.
    Returns None, or the sentence that says the tree could not be listed or that the walk was cut."""
    began = time.monotonic()
    for _round in range(MAX_ROUNDS):
        try:
            found = list_descendants(root)
        except TreeNotListed as exc:
            return _note("the processes below pid %d could not be listed (%s): the program itself was ended, nothing below it" % (root, exc))
        listed = getattr(found, "ident", None) or {}
        _seen_below(found, listed)
        fresh = [pid for pid in found if pid not in stopped]
        if not fresh:
            return None
        for pid in fresh:
            if not same_process(pid, listed.get(pid)):
                continue
            try:
                os.kill(pid, signal.SIGSTOP)
                stopped[pid] = listed.get(pid)
            except OSError:
                pass
        if time.monotonic() - began > WALK_SECONDS:
            break
    return _note("the walk below pid %d was cut at %d rounds or %d seconds: a process started after it may be running" % (root, MAX_ROUNDS, WALK_SECONDS))


def _end(stopped):
    """Kill the stopped set, each pid only if it is still the process that was stopped."""
    for pid, ident in list(stopped.items()):
        if same_process(pid, ident):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def kill_tree(proc):
    """Kill the program and everything it started. The program is stopped first and then each process below it as the walk finds it
    (_stop_below), so the tree does not grow while it is listed; the stopped set is killed after the program. A pid is killed only if it
    is still the process that was listed (same_process). A program already waited for is not touched: its pid is free to be another
    process's, and the walk below it would be that process's children. Returns None, or a sentence when the tree could not be listed or
    the walk was cut."""
    if proc.poll() is not None:
        return None
    try:
        proc.send_signal(signal.SIGSTOP)    # a program that is stopped forks nothing more while its tree is listed
    except OSError:
        pass
    stopped, note = {}, None
    try:
        note = _stop_below(proc.pid, stopped)
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        _end(stopped)
    return note


PIPE_GRACE = 1.0    # seconds the pipes of a program that has ended are given to reach end of file


def communicate_bounded(proc, seconds, input=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes. At `seconds` the program and what it started
    are killed (timed out). A program that has ended while something it started still holds its pipes (a daemon, a helper that
    inherited them) does not hold the tool: the pipes are given PIPE_GRACE seconds, what the program wrote is kept, what the tool
    lost is killed (reap_orphans), and the pipes are let go. The pipes are read here and by nothing else, so letting them go is safe."""
    deadline = time.monotonic() + max(0.1, seconds)
    out = err = b""
    started, timed_out, note = False, False, None
    while proc.poll() is None:
        now = time.monotonic()
        if now >= deadline:
            timed_out = True
            note = kill_tree(proc)
            break
        _sample(proc.pid)
        try:
            out, err = proc.communicate(None if started else input, timeout=max(0.01, min(0.2, deadline - now)))
            return out or b"", err or b"", False
        except subprocess.TimeoutExpired as exc:
            started = True
            out, err = exc.stdout or b"", exc.stderr or b""
    try:
        out, err = proc.communicate(None if started else input, timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired as exc:
        out, err = exc.stdout or b"", exc.stderr or b""
        reap_orphans(_pipe_inodes(proc))
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if pipe is not None:
                    pipe.close()
            except (OSError, ValueError):
                pass
    try:
        proc.wait(timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired:
        pass
    err = err or b""
    if note:
        err = err + (b"\n" if err else b"") + note.encode("utf-8", "replace")
    return out or b"", err, timed_out


def kill_all():
    """End every program the tool has running, with what each started. Then everything below the tool itself, which is the tool's own: a
    program forked a moment before it was entered in ACTIVE is among it. Then what an earlier program started and lost (reap_orphans).
    Returns the sentences for what could not be done (also in process_notes())."""
    notes = []
    for proc in list(ACTIVE):
        note = kill_tree(proc)
        if note:
            notes.append(note)
    stopped = {}
    try:
        note = _stop_below(os.getpid(), stopped)
        if note:
            notes.append(note)
    finally:
        _end(stopped)
    reap_orphans()
    return notes


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)     # the first signal counts: a second one starts no second answer
    kill_all()
    last_word = STATE.get("last_word")
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def preflight(argv, seconds):
    """Run a short program, bounded; (exit code or None, stdout bytes, stderr bytes, timed out)."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, b"", describe(exc).encode("utf-8", "replace"), False
    ACTIVE.append(proc)
    try:
        out, err, timed_out = communicate_bounded(proc, max(1.0, seconds))
        return (None if timed_out else proc.returncode), out, err, timed_out
    finally:
        ACTIVE.remove(proc)


def run_to_files(argv, stdout_path, stderr_path, seconds, cwd=None):
    """One program with its output in files, killed with what it started at `seconds`. (exit code, timed out)."""
    with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
        proc = spawn(argv, stdout=stdout, stderr=stderr, cwd=cwd)
        ACTIVE.append(proc)
        try:
            return proc.wait(timeout=max(0.1, seconds)), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            proc.wait()
            return None, True
        finally:
            ACTIVE.remove(proc)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


class SealedPage(NoReplacePage):
    """A page whose every row passes the output check before it is kept or written."""

    def add(self, row: object) -> None:
        super().add(seal(row))


PARSER = "archive_metadata/1"
LIMIT_CEILING = 1000            # as archive_probe's: a page kept in memory is bounded, whatever the caller asks
DEFAULT_SECONDS = 90            # the manifest allows 120; the tool stops at this and still answers
MAX_SECONDS = 100
FILE_CAP = 256 << 20            # RLIMIT_FSIZE: no file this tool or 7z writes grows past it
HEADER_CAP = 4 << 20            # the most of one header (7-Zip's next header, a RAR5 block header) this tool reads
RATIO_FLAG = 1000               # a member declared this many times larger than its packed size, and RATIO_MIN_BYTES or more, is counted as high ratio
RATIO_MIN_BYTES = 1 << 30

SEVENZIP_AES = b"\x06\xf1\x07\x01"
SEVENZIP_PROGRAMS = ("7z", "7zz", "7za")
SEVENZIP_TIMEOUT = 60
# Given to 7z so that it never stops to ask for one: an archive whose header is
# encrypted then fails to open, which is the answer wanted. It is not a secret.
NO_PASSWORD = "dfirswarm-no-password"

# A line of 7z's output that is a warning or an error (the footers `Warnings: n`, `WARNINGS:`, `ERROR: ...`), and an archive property that says
# the file is not just the archive (`Tail Size` is data after its end, `Headers Error`, `Unexpected End`, ...).
SEVENZIP_ISSUE = re.compile(r"(?i)^(warnings?|errors?)\b")
SEVENZIP_ARCHIVE_ISSUE = re.compile(r"(?i)^(tail size|headers? error|data error|unexpected end|unavailable|is not archive|warnings?|errors?)")
ENCRYPTED_ARCHIVE = re.compile(r"(?i)(can ?not|can't) open encrypted archive|wrong password")

def fail(message, **extra):
    claim_answer()
    remove_pending_pages()
    print(json.dumps(seal({"error": message, "status": "failed",
                           "status_basis": "the tool stopped with an error (see error); no archive was read", **extra}), ensure_ascii=True))
    raise SystemExit(1)


def describe(exc):
    return withhold("%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or str(exc)))

class CountedPage:
    """What list_with_7z fills when only the counts are wanted: nothing is kept, nothing is written."""

    def __init__(self):
        self.total = 0

    def add(self, _row):
        self.total += 1

    def finish(self):
        return {"matched": self.total}

def find_7z():
    for name in SEVENZIP_PROGRAMS:
        found = shutil.which(name)
        if found:
            return found
    return None


def pipe_lines(proc):
    """Lines of `proc`'s stdout (bytes, split on \\n, decoded utf-8 with replacement), read as 7z writes them. A read
    ends when 7z itself has ended and PIPE_GRACE seconds have passed with nothing more to read: a child 7z forks that
    inherits the pipe (ffmpeg-style helpers, a decompression filter) and keeps writing or just keeps the write end
    open does not hold this read open to its own end of file, the way `communicate_bounded` does not for a captured
    run. What held the pipe past that point is ended (reap_orphans), not merely ignored."""
    fd = proc.stdout.fileno()
    buf = b""
    grace_until = None
    while True:
        if stop_wanted() and grace_until is None:
            grace_until = time.monotonic() + PIPE_GRACE
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            chunk = os.read(fd, 65536)
            if chunk:
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    yield line.decode("utf-8", "replace")
                continue
            # EOF: every writer, including one that outlived 7z, has let go.
            break
        if proc.poll() is not None:
            if grace_until is None:
                grace_until = time.monotonic() + PIPE_GRACE
            elif time.monotonic() >= grace_until:
                break
    if buf:
        yield buf.decode("utf-8", "replace")
    reap_orphans(_pipe_inodes(proc))


def list_with_7z(path, limit, counts_only=False):
    """List an archive through 7z, bounded in time, never asking for a password.

    Returns (listing, members): `listing` says what happened (status, exit code,
    the first diagnostic lines); `members` is the LosslessPage of members.
    """
    exe = find_7z()
    if exe is None:
        return {"status": "unavailable", "reason": "none of %s is on PATH" % ", ".join(SEVENZIP_PROGRAMS)}, None
    # -spd: no wildcard matching in file names. Without it 7-Zip expands `*` and `?` in the ARCHIVE name too (after `--` as well), so a file
    # called ?.7z listed every sibling that matched, and their members and paths were read as this archive's.
    cmd = [exe, "l", "-slt", "-y", "-p" + NO_PASSWORD, "-spd", "--", path]
    members = CountedPage() if counts_only else SealedPage("archive_metadata", [os.path.realpath(path), "7z members"], limit)
    seconds = max(1.0, min(SEVENZIP_TIMEOUT, STOP["deadline"] - time.monotonic() if STOP["deadline"] else SEVENZIP_TIMEOUT))
    info = {"via": os.path.basename(exe), "timeout_seconds": round(seconds)}
    try:
        proc = spawn(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as exc:
        return {**info, "status": "unavailable", "reason": "7z could not be started: %s" % describe(exc)}, None
    ACTIVE.append(proc)
    timed_out = []
    timer = threading.Timer(seconds, lambda: (timed_out.append(True), kill_tree(proc)))
    timer.start()
    archive, current, in_members, diagnostics, encrypted_message = {}, {}, False, [], False
    seen = {"members": 0, "encrypted": 0, "not_encrypted": 0, "flag_missing": 0}
    # What is not how 7z prints one archive: a second `----------` (a second archive listed: the archive name matched more than one
    # file), a line of a member's record with no Path before it, or a key twice in one record (a name with a line break in it, from a
    # build that prints the break as it is, can forge lines). Counted; any of them and the listing is not taken as the archive's.
    odd = {"sections": 0, "orphan_lines": 0, "repeated_keys": 0, "stray_lines": 0}
    # A warning or an error anywhere in 7z's output, judged on every line: the lines kept for display are capped at five, and a member name
    # (from a build that prints a line break as it is) can fill the cap before the real footer (`Warnings: 1`, `Tail Size`).
    warned = False

    def flush():
        nonlocal current
        if current.get("Path") is not None:
            flag = current.get("Encrypted")
            seen["members"] += 1
            seen["encrypted" if flag == "+" else "not_encrypted" if flag == "-" else "flag_missing"] += 1
            if counts_only:
                members.add(None)
                current = {}
                return
            members.add({"index": members.total, "name": shown(current["Path"]),
                         "bytes": int(current["Size"]) if current.get("Size", "").isdigit() else None,
                         "packed": int(current["Packed Size"]) if current.get("Packed Size", "").isdigit() else None,
                         "modified_as_printed": withhold(current.get("Modified")) or None, "timezone_unknown": True,
                         "encrypted": True if flag == "+" else (False if flag == "-" else None),
                         "method": withhold(current.get("Method")), "crc": withhold(current.get("CRC")) or None,
                         "attributes": withhold(current.get("Attributes")) or None})
        current = {}

    try:
        for raw in pipe_lines(proc):
            if stop_wanted():
                timed_out.append(True)
                kill_tree(proc)
                break
            line = raw.rstrip("\r\n")
            # 7z's own error line, with the archive's path taken out of it: the path is echoed by 7z, and a file called `wrong password.7z` says
            # what its name says.
            if not in_members and line[:5].upper() == "ERROR" and ENCRYPTED_ARCHIVE.search(line.replace(path, "").replace(os.path.basename(path), "")):
                encrypted_message = True
            if SEVENZIP_ISSUE.match(line):
                warned = True
                if len(diagnostics) < 5:
                    diagnostics.append(withhold(line))
            if line == "----------":
                in_members = True
                odd["sections"] += 1
                continue
            if line == "--" and not in_members:
                continue
            if not line.strip():
                if in_members:
                    flush()
                continue
            key, sep, value = line.partition(" = ")
            if not sep:
                if in_members and current.get("Path") is not None:
                    odd["stray_lines"] += 1         # a line inside a member's record that is no `key = value`
                continue
            if not in_members:
                archive.setdefault(key, value)
                if SEVENZIP_ARCHIVE_ISSUE.match(key):
                    warned = True
            else:
                if key == "Path" and current.get("Path") is not None:
                    flush()
                elif key != "Path" and current.get("Path") is None:
                    odd["orphan_lines"] += 1
                elif key in current:
                    odd["repeated_keys"] += 1
                current[key] = value
        flush()
        code = proc.wait()
    finally:
        timer.cancel()
        kill_tree(proc)
        if proc in ACTIVE:
            ACTIVE.remove(proc)
    info["exit_code"] = code
    info["members_seen"] = seen
    if diagnostics:
        info["diagnostics"] = diagnostics
    if archive:
        info["archive"] = {k: withhold(archive[k]) for k in ("Type", "Physical Size", "Headers Size", "Method", "Solid", "Blocks", "Offset", "Tail Size") if k in archive}
    if timed_out:
        return {**info, "status": "timed_out", "reason": "7z was stopped after %d seconds or at the tool's own time limit; %d members were read before it" % (seconds, members.total)}, members
    if odd["sections"] > 1 or odd["orphan_lines"] or odd["repeated_keys"] or odd["stray_lines"]:
        return {**info, "status": "listing_not_one_archive", "odd_output": odd,
                "reason": "7z's output is not the listing of one archive (%d member sections, %d lines outside a member's record, %d repeated keys, "
                          "%d lines in a record that are no key = value): the members are not taken as this archive's"
                          % (odd["sections"], odd["orphan_lines"], odd["repeated_keys"], odd["stray_lines"])}, members
    if code in (0, 1) and archive.get("Type"):
        # Exit 0 can still come with a warning (data after the end of the archive: a second archive appended, or junk): not "without warnings".
        return {**info, "status": "listed" if code == 0 and not warned else "listed_with_warnings"}, members
    if archive.get("Type") and seen["members"]:
        # 7z exits 2 on a header error and still prints a listing: it is a listing with errors, to be compared and never believed whole.
        return {**info, "status": "listed_with_errors", "reason": "7z listed %d members and exited with %s" % (seen["members"], code)}, members
    if encrypted_message:
        return {**info, "status": "header_encrypted",
                "reason": "7z reports that it cannot open the archive without a password"}, None
    return {**info, "status": "failed", "reason": "7z could not list this file (exit %s)" % code}, None


def tick():
    if out_of_time():
        raise Late()


class Late(Exception):
    """The tool's own clock ran out between two steps: the answer so far is partial."""


def last_word(signum):
    interrupted_answer(signum, path=PATH_SHOWN[0])


PATH_SHOWN = ["(not read yet)"]


def kill_active():
    kill_all()


def pread_all(fd, size, at):
    chunks, got = [], 0
    while got < size:
        tick()
        block = os.pread(fd, min(size - got, 1 << 20), at + got)
        if not block:
            break
        chunks.append(block)
        got += len(block)
    return b"".join(chunks)


# ---- 7-Zip: the start header and, when the header is packed, the coder it names -------------------------------------------------

def sevenzip_number(buf, i):
    first = buf[i]
    mask, value = 0x80, 0
    for n in range(8):
        if not first & mask:
            return value + ((first & (mask - 1)) << (8 * n)), i + 1 + n
        value |= buf[i + 1 + n] << (8 * n)
        mask >>= 1
    return value, i + 9


def sevenzip_coders(buf):
    """The coder ids of the first folder of an encoded header (7-Zip's format description): PackInfo (0x06), then UnpackInfo (0x07) with its folders (0x0B)."""
    i = 1
    if buf[i] != 0x06:
        return None
    _pos, i = sevenzip_number(buf, i + 1)
    streams, i = sevenzip_number(buf, i)
    while buf[i] != 0x00:
        if buf[i] == 0x09:
            i += 1
            for _ in range(streams):
                _size, i = sevenzip_number(buf, i)
        elif buf[i] == 0x0A:
            defined = buf[i + 1]
            i += 2
            if not defined:
                bits = (streams + 7) // 8
                i += bits
            i += 4 * streams
        else:
            return None
    i += 1
    if buf[i] != 0x07 or buf[i + 1] != 0x0B:
        return None
    folders, i = sevenzip_number(buf, i + 2)
    i += 1                                   # the external byte
    ids = []
    for _ in range(min(folders, 1)):
        coders, i = sevenzip_number(buf, i)
        for _c in range(min(coders, 32)):
            flag = buf[i]
            i += 1
            size = flag & 0x0F
            ids.append(bytes(buf[i:i + size]))
            i += size
            if flag & 0x10:
                _n, i = sevenzip_number(buf, i)
                _m, i = sevenzip_number(buf, i)
            if flag & 0x20:
                psize, i = sevenzip_number(buf, i)
                i += psize
    return ids


def structural_7z(fd, size):
    out = {"version": None, "start_header_crc_ok": None, "next_header_offset": None, "next_header_size": None, "next_header_crc_ok": None,
           "physical_size": None, "header_kind": None, "header_encrypted": None}
    problems = []
    head = pread_all(fd, 32, 0)
    if len(head) < 32:
        problems.append("the file ends inside the 32-byte start header")
        return out, problems
    out["version"] = "%d.%d" % (head[6], head[7])
    start_crc, = struct.unpack_from("<I", head, 8)
    out["start_header_crc_ok"] = (zlib.crc32(head[12:32]) & 0xFFFFFFFF) == start_crc
    offset, length, next_crc = struct.unpack_from("<QQI", head, 12)
    out["next_header_offset"], out["next_header_size"] = offset, length
    if not out["start_header_crc_ok"]:
        problems.append("the start header's CRC does not match: its offsets are not trusted")
        return out, problems
    out["physical_size"] = 32 + offset + length
    if out["physical_size"] > size:
        problems.append("the next header ends at byte %d, past the end of the %d-byte file: the archive is cut short or is one volume of a set" % (out["physical_size"], size))
        out["truncated"] = True
        return out, problems
    if out["physical_size"] < size:
        out["tail_bytes"] = size - out["physical_size"]
        problems.append("%d bytes follow the end of the archive" % out["tail_bytes"])
    if length == 0:
        out["header_kind"] = "empty archive"
        out["header_encrypted"] = False
        return out, problems
    if length > HEADER_CAP:
        problems.append("the next header is %d bytes, more than the %d this tool reads" % (length, HEADER_CAP))
        return out, problems
    header = pread_all(fd, length, 32 + offset)
    if len(header) < length:
        problems.append("the next header could not be read in full")
        return out, problems
    out["next_header_crc_ok"] = (zlib.crc32(header) & 0xFFFFFFFF) == next_crc
    if not out["next_header_crc_ok"]:
        problems.append("the next header's CRC does not match")
        return out, problems
    if header[0] == 0x01:
        out["header_kind"] = "plain header (names are readable without a password)"
        out["header_encrypted"] = False
    elif header[0] == 0x17:
        out["header_kind"] = "encoded header"
        try:
            ids = sevenzip_coders(header)
        except IndexError:
            ids = None
        if ids is None:
            problems.append("the encoded header's coder list could not be read")
        else:
            out["header_coders"] = [i.hex() for i in ids]
            out["header_encrypted"] = SEVENZIP_AES in ids
    else:
        problems.append("the next header starts with byte 0x%02x, which is neither a header (0x01) nor an encoded header (0x17)" % header[0])
    return out, problems


# ---- RAR ------------------------------------------------------------------------------------------------------------------------

def rar_name(raw):
    return shown(raw.split(b"\x00", 1)[0].decode("utf-8", "replace"))


def scan_rar4(fd, size, add):
    out = {"version": 4, "blocks": 0, "crc_bad": 0, "files": 0, "volume": False, "headers_encrypted": False, "end_block": False, "end_next_volume": False,
           "continued_in_next": False}
    problems = []
    pos = 7
    while True:
        tick()
        if pos == size and not out["end_block"]:
            problems.append("the file ends without an end-of-archive block (a cut copy, or one volume of a set)")
            break
        if pos + 7 > size:
            problems.append("the file ends inside a block header at byte %d" % pos)
            break
        crc, typ, flags, hsize = struct.unpack("<HBHH", pread_all(fd, 7, pos))
        if hsize < 7 or pos + hsize > size:
            problems.append("a block at byte %d has a size (%d) that does not fit" % (pos, hsize))
            break
        hdr = pread_all(fd, hsize, pos)
        out["blocks"] += 1
        if (zlib.crc32(hdr[2:]) & 0xFFFF) != crc:
            out["crc_bad"] += 1
        extra = 0
        if typ == 0x73:
            out["volume"] = bool(flags & 0x0001)
            out["new_numbering"] = bool(flags & 0x0010)
            if flags & 0x0080:
                out["headers_encrypted"] = True
                break
        elif typ == 0x74 and hsize >= 32:
            pack, unp = struct.unpack_from("<II", hdr, 7)
            namesize, = struct.unpack_from("<H", hdr, 26)
            at = 32
            if flags & 0x0100 and hsize >= 40:
                hp, hu = struct.unpack_from("<II", hdr, 32)
                pack, unp, at = pack | (hp << 32), unp | (hu << 32), 40
            extra = pack
            out["files"] += 1
            if flags & 0x0002:
                out["continued_in_next"] = True
            add({"kind": "member", "index": out["files"], "name": rar_name(hdr[at:at + namesize]), "encrypted": bool(flags & 0x0004),
                 "bytes": unp, "packed": pack, "continued_from_previous": bool(flags & 0x0001), "continues_in_next": bool(flags & 0x0002),
                 "directory": (flags & 0x00E0) == 0x00E0})
        elif typ == 0x7B:
            out["end_block"] = True
            out["end_next_volume"] = bool(flags & 0x0001)
            break
        elif flags & 0x8000 and hsize >= 11:
            extra = struct.unpack_from("<I", hdr, 7)[0]
        pos += hsize + extra
        if pos > size:
            problems.append("a block's data runs past the end of the file")
            break
    return out, problems


def rar5_vint(buf, i):
    value, shift = 0, 0
    for n in range(10):
        b = buf[i + n]
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, i + n + 1
        shift += 7
    raise IndexError("vint")


def scan_rar5(fd, size, add):
    out = {"version": 5, "blocks": 0, "crc_bad": 0, "files": 0, "services": 0, "volume": False, "headers_encrypted": False, "end_block": False,
           "end_next_volume": False, "continued_in_next": False}
    problems = []
    pos = 8
    while True:
        tick()
        if pos == size and not out["end_block"]:
            problems.append("the file ends without an end-of-archive block (a cut copy, or one volume of a set)")
            break
        if pos + 7 > size:
            problems.append("the file ends inside a block header at byte %d" % pos)
            break
        lead = pread_all(fd, 16, pos)
        try:
            hsize, p = rar5_vint(lead, 4)
        except IndexError:
            problems.append("a block header at byte %d has a size that is not a number" % pos)
            break
        if hsize == 0 or hsize > HEADER_CAP or pos + p + hsize > size:
            problems.append("a block at byte %d has a header size (%d) that does not fit" % (pos, hsize))
            break
        whole = pread_all(fd, p + hsize, pos)
        out["blocks"] += 1
        if (zlib.crc32(whole[4:]) & 0xFFFFFFFF) != struct.unpack_from("<I", whole, 0)[0]:
            out["crc_bad"] += 1
        body = whole[p:]
        try:
            typ, i = rar5_vint(body, 0)
            flags, i = rar5_vint(body, i)
            extra_size = data_size = 0
            if flags & 1:
                extra_size, i = rar5_vint(body, i)
            if flags & 2:
                data_size, i = rar5_vint(body, i)
            if typ == 4:
                out["headers_encrypted"] = True
                break
            if typ == 1:
                aflags, i = rar5_vint(body, i)
                out["volume"] = bool(aflags & 1)
            elif typ in (2, 3):
                fflags, i = rar5_vint(body, i)
                unp, i = rar5_vint(body, i)
                _attrs, i = rar5_vint(body, i)
                if fflags & 2:
                    i += 4
                if fflags & 4:
                    i += 4
                _comp, i = rar5_vint(body, i)
                _os, i = rar5_vint(body, i)
                nlen, i = rar5_vint(body, i)
                name = body[i:i + nlen]
                i += nlen
                encrypted = False
                if extra_size and extra_size <= len(body):
                    j = len(body) - extra_size
                    while j < len(body):
                        rsize, j2 = rar5_vint(body, j)
                        rtype, _j3 = rar5_vint(body, j2)
                        if rtype == 1:
                            encrypted = True
                        if rsize == 0:
                            break
                        j = j2 + rsize
                if typ == 3:
                    out["services"] += 1
                else:
                    out["files"] += 1
                    if flags & 0x10:
                        out["continued_in_next"] = True
                    add({"kind": "member", "index": out["files"], "name": rar_name(name), "encrypted": encrypted, "bytes": None if fflags & 8 else unp,
                         "packed": data_size, "continued_from_previous": bool(flags & 0x08), "continues_in_next": bool(flags & 0x10), "directory": bool(fflags & 1)})
            elif typ == 5:
                eflags, i = rar5_vint(body, i)
                out["end_block"] = True
                out["end_next_volume"] = bool(eflags & 1)
                break
        except IndexError:
            problems.append("a block at byte %d is shorter than its own fields" % pos)
            break
        pos += p + hsize + data_size
        if pos > size:
            problems.append("a block's data runs past the end of the file")
            break
    return out, problems


# ---- the other volumes of a set ---------------------------------------------------------------------------------------------

def next_volume_name(base, rar_info):
    """The name of the volume that should follow this one, or None when the name does not say."""
    m = re.fullmatch(r"(.*\.part)([0-9]+)(\.rar)", base, re.I)
    if m:
        return "%s%0*d%s" % (m.group(1), len(m.group(2)), int(m.group(2)) + 1, m.group(3))
    m = re.fullmatch(r"(.*\.)([0-9]{3,})", base)
    if m:
        return "%s%0*d" % (m.group(1), len(m.group(2)), int(m.group(2)) + 1)
    m = re.fullmatch(r"(.*\.)r([0-9]{2})", base, re.I)
    if m:
        n = int(m.group(2)) + 1
        return "%sr%02d" % (m.group(1), n) if n < 100 else "%ss00" % m.group(1)
    m = re.fullmatch(r"(.*\.)rar", base, re.I)
    if m and rar_info is not None and not rar_info.get("new_numbering"):
        return m.group(1) + "r00"
    return None


def volume_report(path, expected, rar_info):
    base = os.path.basename(path)
    report = {"next_volume_expected": expected}
    if not expected:
        return report
    name = next_volume_name(base, rar_info)
    if name is None:
        report.update({"next_volume_name": None, "next_volume_present": None, "note": "the archive says another volume follows, and its name does not say which file that is"})
        return report
    report["next_volume_name"] = shown(name)
    try:
        st = os.lstat(os.path.join(os.path.dirname(os.path.abspath(path)), name))
        report["next_volume_present"] = (st.st_mode & 0o170000) == 0o100000
    except OSError:
        report["next_volume_present"] = False
    return report


# ---- the run ------------------------------------------------------------------------------------------------------------------

def format_of(head):
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:8] == b"Rar!\x1a\x07\x01\x00":
        return "RAR5"
    if head[:7] == b"Rar!\x1a\x07\x00":
        return "RAR4"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "ZIP"
    return None


def main():
    install_stop(last_word, cooperative=False)
    STOP["cleanup"].append(kill_active)
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=withhold(str(exc))[:200])
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    os.umask(0o077)
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if not isinstance(seconds, int) or isinstance(seconds, bool) or not 1 <= seconds <= MAX_SECONDS:
        fail("max_seconds must be an integer from 1 to %d (the tool's own time limit; the manifest allows 120)" % MAX_SECONDS)
    set_deadline(seconds)
    path = args.get("path")
    if not isinstance(path, str) or not path or len(path) > 4096 or "\x00" in path:
        fail("path is required: an archive (a non-empty string without NUL, at most 4096 characters)")
    try:
        os.fsencode(path)
    except (UnicodeError, ValueError):
        fail("path is not a usable file name (it cannot be encoded for the file system)")
    PATH_SHOWN[0] = shown(path)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= LIMIT_CEILING:
        fail("limit must be an integer from 1 to %d" % LIMIT_CEILING)
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_CAP, FILE_CAP))
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    except (ValueError, OSError):
        pass
    try:
        st = os.lstat(path)
    except OSError as exc:
        fail("the file could not be read: %s" % describe(exc), path=shown(path))
    if (st.st_mode & 0o170000) == 0o120000:
        fail("path is a symbolic link: name the file it resolves to (evidence is not followed through a link)", path=shown(path))
    if (st.st_mode & 0o170000) != 0o100000:
        fail("not a regular file (a directory, a device, a pipe or a socket): name an archive file", path=shown(path))
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        fail("the file could not be read: %s" % describe(exc), path=shown(path))
    fst = os.fstat(fd)
    if (fst.st_mode & 0o170000) != 0o100000 or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
        os.close(fd)
        fail("the file changed while it was opened: nothing was read", path=shown(path))
    size = fst.st_size
    answer = {"parser": PARSER, "path": shown(path), "bytes": size, "max_seconds": seconds}
    problems = []
    members = None
    structural = {}
    rar_info = None
    status_note = []
    try:
        if size == 0:
            fail("the file is empty", path=shown(path), bytes=0)
        head = pread_all(fd, 16, 0)
        fmt = format_of(head)
        if fmt is None:
            answer.update({"format": None, "supported": False, "status": "partial",
                           "status_basis": "this is not a ZIP, 7-Zip or RAR archive by its first bytes, so nothing was read",
                           "next_reader": "crypto_id names other schemes; archive_probe reads PDF and OLE markers"})
            return finish(answer, None, None, 0)
        answer["format"] = fmt
        answer["supported"] = True
        records = None
        if fmt == "7z":
            structural, problems = structural_7z(fd, size)
        elif fmt in ("RAR4", "RAR5"):
            records = SealedPage("archive_metadata", [os.path.realpath(path), "rar members"], limit)
            scan = scan_rar4 if fmt == "RAR4" else scan_rar5
            structural, problems = scan(fd, size, records.add)
            rar_info = structural
            if structural["crc_bad"]:
                problems.append("%d block header(s) fail their CRC" % structural["crc_bad"])
            if structural["headers_encrypted"]:
                problems = [p for p in problems if "without an end-of-archive" not in p]
        else:
            structural = {"structural_reader": "archive_probe reads the central directory, the AES extra field 0x9901 and the data descriptors of a ZIP from its bytes; "
                                               "this tool lists a ZIP through 7z only"}
        answer["structural"] = structural
        expected_next = bool(structural.get("end_next_volume") or structural.get("continued_in_next") or structural.get("truncated"))
        answer["volumes"] = volume_report(path, expected_next, rar_info)
        if answer["volumes"].get("next_volume_present") is False:
            problems.append("another volume follows, and %s is not beside this file: the set is incomplete" % answer["volumes"].get("next_volume_name"))
        elif expected_next and answer["volumes"].get("next_volume_present") is None:
            problems.append("another volume follows, and its name is not known")
        tick()
        listing, listed = list_with_7z(path, limit, counts_only=records is not None)
        answer["lister"] = listing
        header_encrypted = structural.get("header_encrypted") if fmt == "7z" else (structural.get("headers_encrypted") if records is not None else None)
        if listing.get("status") == "header_encrypted":
            if header_encrypted is False:
                problems.append("7z cannot open the archive without a password, while its start header shows a plain header")
            header_encrypted = True if header_encrypted is None else header_encrypted
        if fmt == "ZIP" and listing.get("status") in ("listed", "listed_with_warnings"):
            header_encrypted = False          # 7z read the member names without a password
        answer["protection"] = {"header_encrypted": header_encrypted}
        answer["protection"]["basis"] = ("the packed header's coder list holds 7-Zip's AES coder" if fmt == "7z" and structural.get("header_encrypted") else
                                         "the archive's own headers are marked encrypted" if header_encrypted and records is not None else
                                         "7z cannot open the archive without a password" if header_encrypted else
                                         "no encryption of the headers was found" if header_encrypted is False else "not determined")
        if records is not None and listed is not None and listing.get("status") in ("listed", "listed_with_warnings") and not structural.get("headers_encrypted"):
            if listed.total != structural.get("files"):
                problems.append("7z lists %d members and this tool's reading of the headers found %d" % (listed.total, structural.get("files")))
        page = records if records is not None else listed
        members_listed = page is not None and (records is not None or listing.get("status") in ("listed", "listed_with_warnings"))
        if page is not None and page is not records:
            seen = listing.get("members_seen", {})
            answer["protection"]["members_encrypted"] = seen.get("encrypted")
            answer["protection"]["members_not_encrypted"] = seen.get("not_encrypted")
            answer["protection"]["member_flag_missing"] = seen.get("flag_missing")
        elif records is not None:
            rows = records.page
            answer["protection"]["members_encrypted"] = sum(1 for r in rows if r.get("encrypted")) if not records.total > len(rows) else None
        answer["members_listed"] = bool(members_listed)
        if members_listed:
            ratio = 0
            declared = 0
            for row in page.page:
                b, k = row.get("bytes"), row.get("packed")
                if isinstance(b, int):
                    declared += b
                if isinstance(b, int) and isinstance(k, int) and k > 0 and b // k >= RATIO_FLAG and b >= RATIO_MIN_BYTES:
                    ratio += 1
            answer["declared_unpacked_bytes_in_page"] = declared
            answer["high_ratio_members_in_page"] = ratio
            answer["extraction_note"] = ("Nothing is extracted: sizes are what the headers declare. A member whose declared size is at least %d times its packed size "
                                         "(and %d bytes or more) is counted as high ratio; extraction belongs to archive_extract, with its own bounds." % (RATIO_FLAG, RATIO_MIN_BYTES))
        # status
        lst = listing.get("status")
        if fmt == "ZIP":
            if lst == "unavailable":
                answer.update({"status": "unavailable", "status_basis": "7z is not on PATH, and a ZIP is listed through 7z only by this tool: %s" % listing.get("reason", ""),
                               "next_reader": "archive_probe reads a ZIP's central directory and encryption flags from its bytes"})
            elif lst in ("listed", "listed_with_warnings", "header_encrypted") and not problems and lst != "listed_with_warnings":
                answer.update({"status": "complete", "status_basis": "7z listed the archive without a warning; the structure of a ZIP is archive_probe's"})
            else:
                answer.update({"status": "partial", "status_basis": "7z's listing was %s%s" % (lst, (": " + listing["reason"]) if listing.get("reason") else "")})
        elif fmt == "7z":
            if problems:
                answer.update({"status": "partial", "status_basis": "the structure has a problem: " + "; ".join(problems)})
            elif header_encrypted is True:
                answer.update({"status": "complete", "status_basis": "the start header and the packed header were read and the packed header is encrypted: the member list needs the password"})
            elif lst in ("listed",):
                answer.update({"status": "complete", "status_basis": "the start header was read and checked, and 7z listed the members without a warning"})
            elif lst == "unavailable":
                answer.update({"status": "partial", "status_basis": "the headers were read, but 7z is not on PATH, so the members were not listed: %s" % listing.get("reason", "")})
            else:
                answer.update({"status": "partial", "status_basis": "7z's listing was %s%s" % (lst, (": " + listing["reason"]) if listing.get("reason") else "")})
        else:
            if problems:
                answer.update({"status": "partial", "status_basis": "the structure has a problem: " + "; ".join(problems)})
            elif structural.get("headers_encrypted"):
                answer.update({"status": "complete", "status_basis": "the archive's own headers are encrypted: the member list needs the password"})
            elif structural.get("end_block"):
                answer.update({"status": "complete", "status_basis": "every block header was read to the end-of-archive block and checked against its CRC"})
            else:
                answer.update({"status": "partial", "status_basis": "the block chain did not reach an end-of-archive block"})
            if lst in ("failed", "unavailable", "timed_out"):
                answer["lister_note"] = "7z did not list this RAR (%s); the builds that drop the RAR codecs cannot, and the member list above is this tool's own reading of the headers" % lst
        if problems:
            answer["inconsistencies"] = problems
        return finish(answer, page, members_listed, size)
    except Late:
        answer.update({"status": "partial", "status_basis": "the tool's own time limit (%d seconds) was reached before the archive was read to the end" % seconds})
        return finish(answer, None, False, size)
    finally:
        os.close(fd)


def finish(answer, page, members_listed, size):
    if page is not None and members_listed:
        paged = page.finish()
        answer["records"] = getattr(page, "page", [])
        answer.update(paged)
    answer["extraction"] = "this tool never extracts; archive_extract (the computer-forensics-base pack) extracts, within its own bounds"
    answer["names_withheld"] = NAMES["strings"]
    if stop_wanted() and answer.get("status") == "complete":
        answer["status"], answer["status_basis"] = "partial", "%s before the answer was complete" % stop_cause()
    sealed = seal(answer)
    if NAMES["replaced"]:
        sealed["output_check"] = {"replaced": NAMES["replaced"], "note": "a string the first layer let through was replaced by the output check"}
        sealed["status"] = "partial"
        sealed["status_basis"] = "%s; %d string(s) were replaced by the output check" % (sealed.get("status_basis", ""), NAMES["replaced"])
    emit(sealed)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure, and never a traceback
        fail("unexpected failure: %s: %s" % (type(exc).__name__, withhold(str(exc))))
