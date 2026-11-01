#!/usr/bin/env python3
"""Read the encryption metadata of a volume through the program that reads it, and say what that metadata does and does not show.

The tool takes a file (an image of a disk or a partition) and a byte offset, names the scheme from the signatures at that offset (the
same ones crypto_id reads; the logic is copied here, not imported), and runs the reader for it: `cryptsetup luksDump` (with
--dump-json-metadata for LUKS2) on a copy of the volume's first bytes that this tool makes under its output directory, `bdeinfo` for
BitLocker, `fvdeinfo` for Core Storage, `fsapfsinfo` for an APFS container. The answer carries the validated scheme with its basis, the
fixed fields this tool read from the bytes itself, the reader's program, argv, version and exit code, and one record per key slot,
segment, digest and token (LUKS), per key protector (BitLocker) or per count the reader prints (Core Storage, APFS): the first `limit`
inline, all of them in the file the answer names. A reader that is not installed answers `unavailable`, naming the program; a reader
that fails, times out or prints what this tool cannot read answers `partial` and says so. It is never an empty list of protectors.

Metadata only. A key, a salt, the digest of a verifier, a volume or protector identifier, a label, a description and any text of a
key file are never printed: their presence is. What a reader prints is read through a whitelist of its labels; a line not on it is
counted and not shown. Evidence is hostile input: nothing is executed or extracted, the file is opened without following a link and
without waiting (a pipe or a device is refused), what is read is bounded, and the tool's own clock is below the manifest's. It stops on
SIGTERM, SIGINT and SIGHUP with one JSON answer and the exit status 128 + the signal, ending the reader first.
"""


import errno
import hashlib
import json
import os
import re
import resource
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
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


PARSER = "crypto_metadata/1"
LIMIT_CEILING = 1000            # a page kept in memory is bounded, whatever the caller asks
DEFAULT_SECONDS = 60            # the manifest allows 120; the tool stops at this and still answers
MAX_SECONDS = 100
PREFLIGHT_SECONDS = 5
HEAD_BYTES = 8192
OUTPUT_CAP = 8 << 20            # the most of one reader's output this tool reads (a LUKS2 JSON area is at most 4 MiB)
SLICE_CAP = 32 << 20            # the most of a volume's start copied for cryptsetup
FILE_CAP = 256 << 20            # RLIMIT_FSIZE: no file this tool or a reader writes grows past it
MAX_OFFSET = 1 << 62
EXTRA_PATH = "/usr/sbin:/sbin:/usr/local/sbin"
LUKS_MAGIC = b"LUKS\xba\xbe"
LUKS1_FIXED = 208
LUKS1_HEADER = 592
LUKS2_BINARY = 4096
SLOT_ENABLED = 0x00AC71F3
SLOT_DISABLED = 0x0000DEAD
APFS_FLAGS_AT = 1264            # nx_flags in the container superblock (the Apple File System Reference)
APFS_FS_OID_AT = 184
APFS_FS_OIDS = 100
NX_CRYPTO_SW = 0x4
UNRECOGNISED = "<unrecognised reader text withheld>"
# The names cryptsetup and the kernel use (the same closed lists as crypto_id): a header text field that is not one of them is not printed.
HASHES = ("sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512", "ripemd160", "rmd160", "whirlpool",
          "wp512", "md5", "blake2b-256", "blake2b-512", "blake2s-256", "streebog256", "streebog512", "sm3", "tgr192")
CIPHERS = ("aes", "serpent", "twofish", "anubis", "arc4", "blowfish", "camellia", "cast5", "cast6", "chacha20", "des", "des3_ede", "fcrypt",
           "khazad", "seed", "sm4", "tea", "xchacha12", "xchacha20", "xeta", "xtea", "aria", "kuznyechik", "lea")
_ALT = lambda names: "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))   # noqa: E731 - longest first
CIPHER_NAME = re.compile(_ALT(CIPHERS))
HASH_NAME = re.compile(_ALT(HASHES))
_MODE_NAMES = ("ecb", "cbc", "ctr", "xts", "lrw", "cfb", "ofb", "gcm", "ccm", "cts", "plain64be", "plain64", "plain", "benbi", "null", "eboiv",
               "tcw", "random", "adiantum")
_MODE = "(?:%s|essiv(?::(?:%s))?)" % (_ALT(_MODE_NAMES), _ALT(HASHES))
CIPHER_MODE = re.compile(r"%s(?:-%s)*" % (_MODE, _MODE))
READERS = {"luks": "cryptsetup", "bitlocker": "bdeinfo", "corestorage": "fvdeinfo", "apfs": "fsapfsinfo"}

SAFE_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+()/-]{0,63}")
DIGITS = re.compile(r"[0-9]{1,20}")
PROTECTOR_TYPES = ("clear key", "tpm", "startup key", "tpm and pin", "tpm and startup key", "tpm, pin and startup key",
                   "recovery password", "password", "smart card")
STATE = {"last_source": "(not read yet)"}
SCRATCH = []                    # files this tool made for a reader: removed on every way out
OUT_ANSWER = {}


class Late(Exception):
    """The tool's own clock ran out between two steps: the answer so far is partial."""


def fail(message, **extra):
    claim_answer()
    print(json.dumps(seal({"error": message, "status": "failed",
                           "status_basis": "the tool stopped with an error (see error); no metadata was read", **extra}), ensure_ascii=True))
    remove_scratch()
    raise SystemExit(1)


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return withhold("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def remove_scratch():
    while SCRATCH:
        name = SCRATCH.pop()
        try:
            os.unlink(name)
        except OSError:
            pass


def tick():
    if out_of_time():
        raise Late()


def last_word(signum):
    remove_scratch()
    interrupted_answer(signum, source=shown(STATE["last_source"]))


def kill_active():
    kill_all()


def remaining(margin=2.0):
    return max(1.0, STOP["deadline"] - time.monotonic() - margin)


# ---- the bytes: what this tool reads itself ------------------------------------------------------------------------------

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


def text_of(raw):
    return raw.split(b"\x00", 1)[0]


def present(raw):
    return bool(text_of(raw))


def name_of(raw, pattern):
    """A header name field as it may be printed: only a name from the closed list."""
    value = text_of(raw).decode("ascii", "replace")
    return value if value == "" or pattern.fullmatch(value) else UNRECOGNISED


def identify(head):
    """The scheme the first bytes show, by the same signatures crypto_id reads (copied, not imported)."""
    if head[3:11] == b"-FVE-FS-":
        return "bitlocker", "BitLocker", "\"-FVE-FS-\" at offset 3 of the volume"
    if head[0:6] == LUKS_MAGIC:
        if len(head) < 8:
            return "luks", "LUKS (version not readable)", "the LUKS magic at offset 0, and the file ends before the version"
        version = struct.unpack_from(">H", head, 6)[0]
        return "luks", "LUKS%d" % version if version in (1, 2) else "LUKS version %d" % version, \
            "the LUKS magic at offset 0 and version %d at offset 6" % version
    if head[3:11] == b"MSWIN4.1" and b"-FVE-FS-" in head[:4096]:
        return "bitlocker", "BitLocker To Go", "a FAT header (OEM \"MSWIN4.1\") with an FVE block in the first 4 KiB"
    if head[88:96] == b"CS\x00\x00\x00\x00\x00\x00":
        return "corestorage", "Apple Core Storage", "the Core Storage signature at offset 88"
    if head[32:36] == b"NXSB":
        return "apfs", "APFS container", "\"NXSB\" at offset 32"
    return None, "no scheme this tool reads", "no BitLocker, LUKS, Core Storage or APFS signature in the first %d bytes at the offset" % len(head)


def structural_luks(head, size_left):
    """The LUKS header fields at fixed places (the LUKS1 on-disk specification; cryptsetup's luks2_hdr_disk). No salt, digest, UUID or label text."""
    version = struct.unpack_from(">H", head, 6)[0] if len(head) >= 8 else None
    out = {"version": version}
    problems = []
    if version == 1:
        if len(head) < LUKS1_HEADER:
            problems.append("the header is cut short: %d of %d bytes" % (len(head), LUKS1_HEADER))
            return out, problems
        out["cipher"] = name_of(head[8:40], CIPHER_NAME)
        out["cipher_mode"] = name_of(head[40:72], CIPHER_MODE)
        out["hash"] = name_of(head[72:104], HASH_NAME)
        out["payload_offset_sectors"], out["key_bytes"] = struct.unpack_from(">II", head, 104)
        out["uuid_present"] = present(head[168:208])
        slots = []
        for i in range(8):
            at = LUKS1_FIXED + i * 48
            active, iterations = struct.unpack_from(">II", head, at)
            offset, stripes = struct.unpack_from(">II", head, at + 40)
            state = "enabled" if active == SLOT_ENABLED else ("disabled" if active == SLOT_DISABLED else "unrecognised (0x%x)" % active)
            slots.append({"slot": i, "state": state, "iterations": iterations, "key_material_offset_sectors": offset, "stripes": stripes})
        out["slots"] = slots
        out["enabled_slots"] = sum(1 for s in slots if s["state"] == "enabled")
    elif version == 2:
        if len(head) < LUKS2_BINARY:
            problems.append("the header is cut short: %d of %d bytes of the binary header" % (len(head), LUKS2_BINARY))
            return out, problems
        out["header_size_bytes"], out["sequence_id"] = struct.unpack_from(">QQ", head, 8)
        out["label_present"] = present(head[24:72])
        out["checksum_alg"] = name_of(head[72:104], HASH_NAME)
        out["uuid_present"] = present(head[168:208])
        out["subsystem_present"] = present(head[208:256])
        size = out["header_size_bytes"]
        out["header_size_valid"] = 0x4000 <= size <= 0x400000 and size & (size - 1) == 0
        if not out["header_size_valid"]:
            problems.append("the header size field (%d) is not a size LUKS2 uses (a power of two from 16 KiB to 4 MiB)" % size)
    return out, problems


def structural_bitlocker(fd, offset, size, head, to_go):
    out = {}
    problems = []
    if to_go:
        out["fve_signature_offset_in_first_4k"] = head[:4096].find(b"-FVE-FS-")
        return out, problems
    if len(head) < 200:
        problems.append("the boot sector is cut short (%d bytes)" % len(head))
        return out, problems
    out["bytes_per_sector"] = struct.unpack_from("<H", head, 11)[0]
    blocks = []
    for i in range(3):
        tick()
        at = struct.unpack_from("<Q", head, 176 + 8 * i)[0]
        item = {"index": i, "offset_in_volume": at}
        if at == 0 or at + 64 > size - offset:
            item["valid"] = False
            item["why"] = "zero or beyond the end of the file"
        else:
            block = pread_all(fd, 64, offset + at)
            if block[0:8] == b"-FVE-FS-":
                item["valid"] = True
                item["version"] = struct.unpack_from("<H", block, 10)[0]
                item["file_offset"] = offset + at
            else:
                item["valid"] = False
                item["why"] = "no \"-FVE-FS-\" signature at that offset"
        blocks.append(item)
    out["metadata_blocks"] = blocks
    if not any(b["valid"] for b in blocks):
        problems.append("none of the three metadata block offsets in the boot sector points at an FVE metadata block")
    return out, problems


def structural_apfs(head):
    out = {}
    problems = []
    if len(head) < APFS_FLAGS_AT + 8:
        problems.append("the container superblock is cut short (%d bytes)" % len(head))
        return out, problems
    block_size = struct.unpack_from("<I", head, 36)[0]
    out["block_size"] = block_size
    out["block_size_valid"] = 4096 <= block_size <= 65536 and block_size & (block_size - 1) == 0
    out["block_count"] = struct.unpack_from("<Q", head, 40)[0]
    out["max_file_systems"] = struct.unpack_from("<I", head, 180)[0]
    out["volume_slots_in_use"] = sum(1 for i in range(APFS_FS_OIDS) if struct.unpack_from("<Q", head, APFS_FS_OID_AT + 8 * i)[0])
    flags = struct.unpack_from("<Q", head, APFS_FLAGS_AT)[0]
    out["container_flags"] = "0x%x" % flags
    out["software_crypto_flag"] = bool(flags & NX_CRYPTO_SW)
    if not out["block_size_valid"]:
        problems.append("the block size field (%d) is not a size APFS uses" % block_size)
    return out, problems


# ---- the programs ---------------------------------------------------------------------------------------------------------

def find_program(name):
    found = shutil.which(name)
    if found:
        return found
    return shutil.which(name, path=EXTRA_PATH)


def program_env():
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin") + ":" + EXTRA_PATH, "LC_ALL": "C", "LANG": "C"}


def program_version(path):
    code, out, _err, timed_out = preflight([path, "--version" if os.path.basename(path) == "cryptsetup" else "-V"], PREFLIGHT_SECONDS)
    if timed_out or code not in (0, None):
        return "not reported by this build"
    for line in out.decode("utf-8", "replace").splitlines()[:6]:
        line = line.strip()
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{0,30} [0-9][A-Za-z0-9._+~:-]{0,30}", line):
            return line
    return "not reported by this build"


def run_program(argv, seconds, scratch):
    """One reader, in the tool's group, with its output in files that are read back at most OUTPUT_CAP bytes. A dict with the exit code,
    whether it timed out, its stdout (bytes, capped), whether more was written than was read, and whether stderr held anything."""
    paths = []
    for tag in ("out", "err"):
        fd, name = tempfile.mkstemp(dir=scratch, prefix=".cm-%s-" % tag)
        os.close(fd)
        SCRATCH.append(name)
        paths.append(name)
    code, timed_out = None, False
    with open(paths[0], "wb") as stdout, open(paths[1], "wb") as stderr:
        proc = spawn(argv, stdout=stdout, stderr=stderr, env=program_env())
        ACTIVE.append(proc)
        try:
            code = proc.wait(timeout=max(0.1, seconds))
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_tree(proc)
            proc.wait()
        finally:
            ACTIVE.remove(proc)
    result = {"code": code, "timed_out": timed_out, "stdout": b"", "stdout_bytes": 0, "capped": False, "stderr_bytes": 0, "stderr_text": b""}
    for key, name in (("stdout", paths[0]), ("stderr", paths[1])):
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                continue
            if key == "stdout":
                result["stdout_bytes"] = st.st_size
                result["capped"] = st.st_size > OUTPUT_CAP
                result["stdout"] = os.pread(fd, OUTPUT_CAP, 0) if st.st_size else b""
            else:
                result["stderr_bytes"] = st.st_size
                result["stderr_text"] = os.pread(fd, 4096, 0) if st.st_size else b""
        finally:
            os.close(fd)
    return result


def reader_notes(run):
    """What the reader's stderr says in kind, never in words: the text may quote the volume."""
    text = run["stderr_text"].decode("utf-8", "replace").lower()
    return bool(re.search(r"unrecogni[sz]ed option|unknown option|invalid option|illegal option|unrecognized arguments|usage:", text[:4096]))


def num(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if abs(value) < (1 << 64) else None
    if isinstance(value, str) and DIGITS.fullmatch(value):
        return int(value)
    return None


KNOWN_WORDS = {"pbkdf2", "argon2i", "argon2id", "luks1", "luks2", "raw", "checksum", "crypt", "linear", "journal", "reencrypt", "luks2-keyring",
               "no-journal", "no-read-workqueue", "no-write-workqueue", "allow-discards", "same-cpu-crypt", "submit-from-crypt-cpus",
               "inline-crypt", "sector-size-4096", "offline-reencrypt", "online-reencrypt", "online-reencrypt-v2", "offline-reencrypt-v2",
               "opal", "dynamic"}
SPEC = re.compile(r"(?:%s)-(?:%s)(?:-(?:%s))?" % (CIPHER_NAME.pattern, CIPHER_MODE.pattern, HASH_NAME.pattern))


def word(value, pattern=SAFE_WORD):
    """A reader's name or type as it may be printed: a name from the lists LUKS and the kernel use as it is, any other word through the
    withholding rule (a part shaped like an identifier or a secret is replaced), anything that is not a short word not at all."""
    if isinstance(value, str) and pattern.fullmatch(value):
        low = value.lower()
        if low in KNOWN_WORDS or SPEC.fullmatch(low) or HASH_NAME.fullmatch(low):
            return value
        return withhold(value)
    return None if value is None else UNRECOGNISED


def slot_key(key):
    return key if isinstance(key, str) and re.fullmatch(r"[0-9]{1,6}", key) else UNRECOGNISED


def ints(value, cap=64):
    if not isinstance(value, list):
        return None
    out = [num(v) for v in value[:cap]]
    return out if all(v is not None for v in out) else None


def luks2_rows(doc, add, counts):
    """The LUKS2 JSON metadata as records: keyslots (type, key size, area, KDF parameters without the salt, AF), segments, digests (the
    hash algorithm and which keyslots and segments they cover; never the salt or the digest) and tokens (the type only)."""
    for section, kind in (("keyslots", "keyslot"), ("segments", "segment"), ("digests", "digest"), ("tokens", "token")):
        items = doc.get(section)
        counts[kind] = 0
        if not isinstance(items, dict):
            counts[kind + "_section"] = "missing" if items is None else "not an object"
            continue
        for key, val in items.items():
            tick()
            counts[kind] += 1
            if not isinstance(val, dict):
                add({"kind": kind, "index": slot_key(key), "problem": "the entry is not an object"})
                continue
            row = {"kind": kind, "index": slot_key(key), "type": word(val.get("type"))}
            if kind == "keyslot":
                row["key_size"] = num(val.get("key_size"))
                row["priority"] = num(val.get("priority"))
                area = val.get("area")
                if isinstance(area, dict):
                    row["area"] = {"type": word(area.get("type")), "offset": num(area.get("offset")), "size": num(area.get("size")),
                                   "encryption": word(area.get("encryption")), "key_size": num(area.get("key_size"))}
                kdf = val.get("kdf")
                if isinstance(kdf, dict):
                    row["kdf"] = {"type": word(kdf.get("type")), "hash": word(kdf.get("hash")), "iterations": num(kdf.get("iterations")),
                                  "time": num(kdf.get("time")), "memory": num(kdf.get("memory")), "cpus": num(kdf.get("cpus"))}
                af = val.get("af")
                if isinstance(af, dict):
                    row["af"] = {"type": word(af.get("type")), "stripes": num(af.get("stripes")), "hash": word(af.get("hash"))}
            elif kind == "segment":
                size = val.get("size")
                row.update({"offset": num(val.get("offset")), "size": "dynamic" if size == "dynamic" else num(size),
                            "iv_tweak": num(val.get("iv_tweak")), "encryption": word(val.get("encryption")),
                            "sector_size": num(val.get("sector_size"))})
                flags = val.get("flags")
                if isinstance(flags, list):
                    row["flags"] = [word(f) for f in flags[:16]]
            elif kind == "digest":
                row.update({"hash": word(val.get("hash")), "iterations": num(val.get("iterations")),
                            "keyslots": ints(val.get("keyslots")), "segments": ints(val.get("segments"))})
            else:
                keyslots = val.get("keyslots")
                row["keyslots_linked"] = len(keyslots) if isinstance(keyslots, list) else None
            add(row)
    config = doc.get("config")
    if isinstance(config, dict):
        counts["config"] = {"json_size": num(config.get("json_size")), "keyslots_size": num(config.get("keyslots_size")),
                            "flags": [word(f) for f in config["flags"][:16]] if isinstance(config.get("flags"), list) else None,
                            "requirements": [word(f) for f in config["requirements"][:16]] if isinstance(config.get("requirements"), list) else None}


LUKS1_LINES = (("version", re.compile(r"Version:\s+([0-9]{1,3})")), ("payload_offset_sectors", re.compile(r"Payload offset:\s+([0-9]{1,20})")),
               ("key_bits", re.compile(r"MK bits:\s+([0-9]{1,6})")), ("mk_iterations", re.compile(r"MK iterations:\s+([0-9]{1,12})")))
LUKS1_NAMES = (("cipher", re.compile(r"Cipher name:\s+(\S{1,40})")), ("cipher_mode", re.compile(r"Cipher mode:\s+(\S{1,80})")),
               ("hash", re.compile(r"Hash spec:\s+(\S{1,40})")))


def luks1_rows(text, add, counts):
    """`cryptsetup luksDump` of a LUKS1 header: the fixed fields and each key slot's state, iterations, key material offset and stripes. The
    MK digest, MK salt and each slot's salt lines are never read into a value."""
    fields = {}
    slot = None
    seen = set()
    lines = text.splitlines()
    counts["slot"] = 0
    for line in lines:
        tick()
        line = line.strip()
        if len(line) > 4096:
            continue
        for key, pattern in LUKS1_LINES:
            m = pattern.fullmatch(line)
            if m:
                fields[key] = int(m.group(1))
        for key, pattern in LUKS1_NAMES:
            m = pattern.fullmatch(line)
            if m:
                pat = {"cipher": CIPHER_NAME, "cipher_mode": CIPHER_MODE, "hash": HASH_NAME}[key]
                fields[key] = m.group(1) if pat.fullmatch(m.group(1)) else UNRECOGNISED
        if line.startswith("UUID:"):
            fields["uuid_present"] = True
        m = re.fullmatch(r"Key Slot ([0-9]{1,3}): (ENABLED|DISABLED)", line)
        if m:
            if slot is not None:
                add(slot)
            slot = {"kind": "keyslot", "index": m.group(1), "state": m.group(2).lower()}
            counts["slot"] += 1
            seen.add(m.group(1))
            continue
        if slot is not None:
            for key, pattern in (("iterations", r"Iterations:\s+([0-9]{1,12})"), ("key_material_offset_sectors", r"Key material offset:\s+([0-9]{1,20})"),
                                 ("af_stripes", r"AF stripes:\s+([0-9]{1,12})")):
                m = re.fullmatch(pattern, line)
                if m:
                    slot[key] = int(m.group(1))
    if slot is not None:
        add(slot)
    return fields


LABEL = re.compile(r"[A-Za-z][A-Za-z0-9 ,()/'-]{0,60}")


def split_line(line):
    """(label, value) of a "label : value" line: the label lower-cased with its blanks folded, at most 61 characters of the usual label
    alphabet; the value at most 300 characters. A line longer than 600 characters, or without such a label, is None."""
    if len(line) > 600:
        return None
    label, sep, value = line.partition(":")
    label = label.strip()
    if not sep or not LABEL.fullmatch(label) or len(value) > 300:
        return None
    return " ".join(label.lower().split()), value.strip()


METHOD = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ./()+,-]{0,79}")


def bde_rows(text, add, counts):
    """`bdeinfo`: the encryption method, the number of key protectors and, per protector, its type. The volume and protector identifiers, the
    description and any salt, digest or key line are never read into a value: their presence is all that is said."""
    fields = {}
    protector = None
    counts["protector"] = 0
    lines = text.splitlines()
    for line in lines:
        tick()
        if len(line) > 600:
            continue
        header = re.fullmatch(r"Key protector ([0-9]{1,4}):?", line.strip())
        if header:
            if protector is not None:
                add(protector)
            protector = {"kind": "key_protector", "index": header.group(1)}
            counts["protector"] += 1
            continue
        kv = split_line(line)
        if kv is None:
            continue
        label, value = kv
        if protector is not None:
            if label == "identifier":
                protector["identifier_present"] = bool(value)
            elif label == "type":
                low = value.lower()
                protector["type"] = low if low in PROTECTOR_TYPES else UNRECOGNISED
            continue
        if label == "encryption method":
            fields["encryption_method"] = withhold(value) if METHOD.fullmatch(value) else UNRECOGNISED
        elif label == "number of key protectors":
            fields["reader_protector_count"] = int(value) if DIGITS.fullmatch(value) else None
        elif label == "volume identifier":
            fields["volume_identifier_present"] = bool(value)
        elif label == "description":
            fields["description_present"] = bool(value)
        elif label == "creation time":
            fields["creation_time_as_printed"] = withhold(value)[:100] if re.fullmatch(r"[A-Za-z0-9 :,./+()-]{1,100}", value) else UNRECOGNISED
    if protector is not None:
        add(protector)
    return fields


COUNT_LABEL = re.compile(r"number of [a-z ]{3,40}")
STATE_LABEL = {"encryption method": METHOD, "encrypted": re.compile(r"(?i:yes|no|true|false)"), "is encrypted": re.compile(r"(?i:yes|no|true|false)"),
               "locked": re.compile(r"(?i:yes|no|true|false)")}


def libyal_rows(text, add, counts):
    """`fvdeinfo` or `fsapfsinfo`: only the lines the library prints as counts ("number of ...") and the encryption method or state lines
    are shown. Every other line is counted and not shown; what the installed build prints is not established here."""
    fields = {}
    counts["lines_total"] = counts["lines_shown"] = 0
    index = 0
    for line in text.splitlines():
        tick()
        if not line.strip():
            continue
        counts["lines_total"] += 1
        kv = split_line(line)
        if kv is None:
            continue
        label, value = kv
        if COUNT_LABEL.fullmatch(label) and DIGITS.fullmatch(value):
            index += 1
            counts["lines_shown"] += 1
            add({"kind": "reader_count", "index": str(index), "label": label, "value": int(value)})
        elif label in STATE_LABEL and STATE_LABEL[label].fullmatch(value):
            index += 1
            counts["lines_shown"] += 1
            fields[label.replace(" ", "_")] = withhold(value)
    return fields


# ---- the run ---------------------------------------------------------------------------------------------------------------

def open_source(path):
    try:
        st = os.lstat(path)
    except OSError as exc:
        fail("the file could not be read: %s" % describe(exc), path=shown(path))
    if stat.S_ISLNK(st.st_mode):
        fail("path is a symbolic link: name the file it resolves to (evidence is not followed through a link)", path=shown(path))
    if stat.S_ISDIR(st.st_mode):
        fail("path is a directory, not a file or an image", path=shown(path))
    if not stat.S_ISREG(st.st_mode):
        fail("not a regular file (a device, a pipe or a socket): this tool reads a file, so read an image made from the device", path=shown(path))
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        fail("the file could not be read: %s" % describe(exc), path=shown(path))
    fst = os.fstat(fd)
    if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
        os.close(fd)
        fail("the file changed while it was opened: nothing was read", path=shown(path))
    return fd, fst.st_size


def write_slice(fd, offset, length, scratch):
    fd2, name = tempfile.mkstemp(dir=scratch, prefix=".cm-slice-")
    SCRATCH.append(name)
    try:
        done = 0
        while done < length:
            tick()
            block = os.pread(fd, min(1 << 20, length - done), offset + done)
            if not block:
                break
            os.write(fd2, block)
            done += len(block)
    finally:
        os.close(fd2)
    return name, done


def main():
    install_stop(last_word, cooperative=False)
    STOP["cleanup"].append(kill_active)
    STOP["cleanup"].append(remove_scratch)
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
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_CAP, FILE_CAP))
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    except (ValueError, OSError):
        pass

    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a volume image (a file made from a disk or a partition)")
    if len(path) > 4096 or "\x00" in path:
        fail("path is not a usable file name (a NUL, or longer than 4096 characters)")
    try:
        os.fsencode(path)
    except (UnicodeError, ValueError):
        fail("path is not a usable file name (it cannot be encoded for the file system)")
    STATE["last_source"] = path
    offset = args.get("offset", 0)
    if offset is None:
        offset = 0
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= MAX_OFFSET:
        fail("offset must be a byte offset (an integer from 0), not a sector offset")
    limit = args.get("limit", 100)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= LIMIT_CEILING:
        fail("limit must be an integer from 1 to %d" % LIMIT_CEILING)

    fd, size = open_source(path)
    if size == 0:
        fail("the file is empty", path=shown(path), bytes=0)
    if offset >= size:
        fail("the offset is past the end of the file", offset=offset, bytes=size)
    absolute = os.path.abspath(path)
    page = SealedPage("crypto_metadata", [os.path.realpath(path), offset, "metadata records"], limit)
    answer = {"parser": PARSER, "path": shown(path), "offset_bytes": offset, "bytes": size, "max_seconds": seconds}
    counts = {}
    problems = []
    basis_extra = []
    try:
        head = pread_all(fd, HEAD_BYTES, offset)
        family, scheme, basis = identify(head)
        answer.update({"scheme": scheme, "scheme_basis": basis})
        if family is None:
            answer.update({"supported": False, "status": "partial",
                           "status_basis": "no signature this tool reads was found at the offset, so no reader was run and nothing about protection was read",
                           "next_reader": "crypto_id names other schemes (and says why a missing signature is not 'not encrypted')"})
            return finish(answer, page)
        if family == "luks":
            structural, problems = structural_luks(head, size - offset)
            version = structural.get("version")
            if version not in (1, 2):
                answer.update({"supported": False, "structural": structural, "status": "partial",
                               "status_basis": "this tool reads LUKS versions 1 and 2 only, so no reader was run for version %s" % version})
                return finish(answer, page)
        elif family == "bitlocker":
            structural, problems = structural_bitlocker(fd, offset, size, head, scheme == "BitLocker To Go")
        elif family == "apfs":
            structural, problems = structural_apfs(head)
        else:
            structural = {}
        answer["structural"] = structural
        answer["supported"] = True
        program = READERS[family]
        reader = {"program": program}
        answer["reader"] = reader
        path_to = find_program(program)
        if not path_to:
            reader.update({"status": "unavailable"})
            answer.update({"status": "unavailable",
                           "status_basis": "%s is not on PATH, so its listing of the protectors was not made; the fields above are this tool's own read of the "
                                           "bytes and are no list of the key slots or key protectors" % program,
                           "protectors_listed": None})
            return finish(answer, page, problems)
        tick()
        reader["version"] = program_version(path_to)
        if family == "luks" and (problems or (structural["version"] == 2 and not structural.get("header_size_valid"))):
            answer.update({"status": "partial",
                           "status_basis": "the header is damaged or forged (%s), so cryptsetup was not run on it" % "; ".join(problems)})
            return finish(answer, page, problems)
        scratch = page.path.parent
        reason = own_dir(scratch)
        if reason is not None:
            fail(reason)
        if family == "luks":
            if structural["version"] == 2:
                length = min(2 * structural["header_size_bytes"], SLICE_CAP)
            else:
                length = min(max(LUKS1_HEADER, structural["payload_offset_sectors"] * 512), SLICE_CAP)
            copy, copied = write_slice(fd, offset, length, scratch)
            argv = [path_to, "luksDump"] + (["--dump-json-metadata"] if structural["version"] == 2 else []) + [copy]
            reader["input"] = "the first %d bytes of the volume, copied to a file of this tool's own under the output directory and removed" % copied
        else:
            argv = [path_to] + (["-o", str(offset)] if offset else []) + [absolute]
        reader["argv"] = [shown(a) for a in argv]
        run = run_program(argv, remaining(), scratch)
        reader.update({"exit_code": run["code"], "timed_out": run["timed_out"], "stdout_bytes": run["stdout_bytes"],
                       "stderr_present": run["stderr_bytes"] > 0, "stderr_bytes": run["stderr_bytes"]})
        if run["timed_out"]:
            answer.update({"status": "partial", "status_basis": "the time budget was reached before %s answered; nothing about the protectors was read" % program})
            return finish(answer, page, problems)
        if run["code"] != 0:
            reader["rejected_option"] = reader_notes(run)
            answer.update({"status": "partial",
                           "status_basis": "%s exited %s%s, so it listed nothing: this is not an empty list of protectors" % (
                               program, run["code"], " and rejected an option (an older build?)" if reader["rejected_option"] else "")})
            return finish(answer, page, problems)
        if run["capped"]:
            answer.update({"status": "partial",
                           "status_basis": "%s wrote %d bytes, more than the %d this tool reads, so its output was not parsed" % (program, run["stdout_bytes"], OUTPUT_CAP)})
            return finish(answer, page, problems)
        text = run["stdout"].decode("utf-8", "replace")
        fields = {}
        if family == "luks" and structural["version"] == 2:
            try:
                doc = json.loads(text)
            except (ValueError, RecursionError):
                doc = None
            if not isinstance(doc, dict):
                answer.update({"status": "partial",
                               "status_basis": "cryptsetup exited 0 but its output is not the JSON metadata this tool reads: nothing is said about the keyslots"})
                return finish(answer, page, problems)
            luks2_rows(doc, page.add, counts)
            config = counts.get("config") or {}
            expected = structural["header_size_bytes"] - LUKS2_BINARY
            if config.get("json_size") is not None and config["json_size"] != expected:
                problems.append("the JSON area size cryptsetup reports (%s) differs from the header's size field minus 4096 (%d)" % (config["json_size"], expected))
        elif family == "luks":
            fields = luks1_rows(text, page.add, counts)
            if counts.get("slot") != 8:
                problems.append("cryptsetup listed %s key slots; a LUKS1 header has eight" % counts.get("slot"))
            else:
                enabled = sum(1 for r in page.page if r.get("state") == "enabled")
                if page.total == counts["slot"] and enabled != structural.get("enabled_slots"):
                    problems.append("the key slots cryptsetup lists as enabled (%d) differ from the header's slot table (%d)" % (enabled, structural.get("enabled_slots")))
        elif family == "bitlocker":
            fields = bde_rows(text, page.add, counts)
            wanted = fields.get("reader_protector_count")
            if wanted is not None and wanted != counts.get("protector"):
                problems.append("bdeinfo says %d key protectors and lists %d" % (wanted, counts.get("protector")))
            if any(r.get("type") == "clear key" for r in page.page):
                answer["clear_key_protector_listed"] = True
        else:
            fields = libyal_rows(text, page.add, counts)
        if page.total == 0 and not fields:
            answer.update({"status": "partial",
                           "status_basis": "%s exited 0 but printed none of the fields this tool reads: nothing is said about the protectors" % program})
            return finish(answer, page, problems, counts, fields)
        answer.update({"status": "complete",
                       "status_basis": "%s ran to completion and its output was read to the end" % program})
        return finish(answer, page, problems, counts, fields)
    except Late:
        answer.update({"status": "partial", "status_basis": "the tool's own time limit (%d seconds) was reached before the reader's output was read to the end" % seconds})
        return finish(answer, page, problems, counts)
    finally:
        os.close(fd)
        remove_scratch()


def finish(answer, page, problems=(), counts=None, fields=None):
    paged = page.finish()
    if counts:
        answer["counts"] = counts
    if fields:
        answer["fields"] = fields
    answer["records"] = page.page
    answer.update(paged)
    if problems:
        answer["inconsistencies"] = list(problems)
        if answer.get("status") == "complete":
            answer["status"] = "partial"
            answer["status_basis"] += "; but the bytes and the reader do not agree (see inconsistencies)"
    answer["confidence"] = ("high: the signature, this tool's read of the fixed fields and the reader agree" if answer.get("status") == "complete"
                            else "medium: the signature and the fixed fields are read; the reader's listing is missing or in doubt" if answer.get("supported")
                            else "low: no scheme was read")
    answer["limits"] = ["metadata only: no key, salt, digest of a verifier, volume or protector identifier, label or description is printed (their presence is)",
                        "a listing is what the installed build parsed for that metadata version; an absent line is not an absent protector",
                        "a signature is a lead for a reader, not a finding about the data"]
    if answer.get("scheme") == "Apple Core Storage":
        answer["limits"].append("whether the installed fvdeinfo reads an APFS volume is not established here")
    if answer.get("scheme") == "APFS container":
        answer["limits"].append("fsapfsinfo's documented limits apply: no snapshots, no Fusion, no T2 encryption")
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
        remove_scratch()
        fail("unexpected failure: %s: %s" % (type(exc).__name__, withhold(str(exc))))
