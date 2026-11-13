#!/usr/bin/env python3
"""Decrypt the logins a Chromium-family browser saved (Chrome, Edge, Brave, Opera, Vivaldi): Login Data, Local State and a key source.

A profile's `Login Data` is an SQLite database whose `logins` table holds one row per saved login: the origin, the user name, Chromium's times
(microseconds since 1601-01-01 UTC) and the password as the browser stored it. Since Chrome 80 on Windows the stored value is 'v10', a 12-byte
nonce, the cipher text and a 16-byte tag: AES-256-GCM under the profile key. The profile key is in `User Data/Local State`, at
os_crypt.encrypted_key, as base64 of 'DPAPI' and a DPAPI blob: the user's master key opens it, and the user's password (or its SHA-1 or NT
hash) with the SID opens the master key. Before Chrome 80 the stored value was a DPAPI blob itself. Since Chrome 127 a value may be 'v20'
(app-bound encryption), which this reader does not open and says so.

The key comes from one of: a 32-byte profile key in a file (where the case already holds it: a note, an export, a memory finding); the DPAPI
material (master key file or files, the SID, and a password file, a hash file or an empty password); or the sealed keys of an earlier
dpapi_masterkey job. No secret is ever an argument: each is a file the call names.

Nothing is guessed and nothing raises on a wrong key: a row whose tag does not verify says decrypted false and why, and the answer is partial.
The answer holds no password and no key: they go to a sealed values file, and only in a job run as secret output. The database is opened
read-only and immutable with an authorizer that lets only the read of the logins table through; a write-ahead log or a journal beside it is
named and makes the answer partial, because this reader replays nothing. Every call runs the self-test first: a negative from a reader that
does not reproduce its known answers is not a finding.
"""

# BEGIN SHARED ENDS
# The same text is in every pack tool and recipe and in their tool-library twins, before the file's own imports (tests/shared-blocks-census.test.ts
# holds the copies equal): the two ends of a call, where a stop signal (SIGTERM, SIGINT, SIGHUP) found no handler, or one that did harm.
# * The start. From here a stop is answered by ONE JSON document and exit 128 + the signal, until the tool installs its own handlers (which then
#   answer it), and for good for a signal the tool never takes. Only the start of the interpreter and the compiling of the file come before
#   it: a stop there ends the process with no answer, before anything was read. answer_a_stop() is that document: a handler whose own last word
#   wrote nothing on standard output calls it before it ends the process, so that a stop is never answered by silence.
# * The end. The interpreter's own teardown resets the handlers to their defaults before it frees what the call held, and a stop that landed
#   there killed a process that had printed its whole answer; a handler that raises, writes a last word or ends the process, run once the
#   answer was decided, wrote a second document, a traceback, or nothing at all. Python runs a handler on the main thread whichever thread the
#   signal reached, so a mask of the main thread alone holds nothing while another thread runs. hold_stop_signals() holds the stop signals for
#   good: blocked in this thread and given a handler that does nothing, which is the hold whatever thread the signal reaches; an error Python
#   can only report from then on (a file left open whose last write the file system refuses, closed when the frame that held it is freed) is
#   not printed (3.11 and 3.12 say nothing of it, 3.14 a traceback). A handler that was due runs on the way in: what it raises reaches the
#   writer that asked (the tool's own handling then answers the stop, before any byte of the answer), or, quietly, is dropped (the end of a
#   call, an error branch). Every writer of a final answer calls it before it commits to writing, every error branch at the end calls it
#   quietly, and, when the file runs as a program, standard output is wrapped so that its first write calls it too. _code(stop) is a
#   SystemExit's exit code (its text, if it has one, goes to standard error as the interpreter puts it), and _leave(code) ends the call: both
#   hold the signals first, quietly; _leave flushes
#   standard output (a write that fails there makes a 0 an exit 120, as the interpreter does) and standard error, runs the atexit hooks (a hook
#   that removes a temporary file), each step on its own and none able to raise, and ends the process with os._exit, never through the teardown.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import json
import os
import signal
import sys

_ENDING = {"held": False, "program": __name__ == "__main__"}      # imported (a test that loads the file as a module), the block holds nothing
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def answer_a_stop(signum, when="before it had answered"):
    """The one document of a stop that ends the call before any answer was begun (nothing once one has): status failed, interrupted, and
    no claim about what was read or written. A handler whose own last word printed nothing calls it before it ends the process. It writes
    only when the file runs as a program: its wrapped standard output is what knows whether an answer was begun."""
    if _ENDING["held"] or not isinstance(sys.stdout, _AnswerStream):
        return
    _ENDING["held"] = True
    name = {signal.SIGTERM: "SIGTERM", signal.SIGINT: "SIGINT", signal.SIGHUP: "SIGHUP"}.get(signum, "signal %d" % signum)
    text = json.dumps({"error": "the tool was stopped by %s %s" % (name, when), "status": "failed", "interrupted": name,
                       "status_basis": "stopped by %s %s: no answer was made, and what it had read or written by then is not described" % (name, when)})
    try:
        os.write(1, (text + "\n").encode("ascii"))
    except OSError:
        pass


def _stopped_without_handler(signum, _frame):
    for other in _ENDING_SIGNALS:
        try:
            signal.signal(other, signal.SIG_IGN)
        except (ValueError, OSError):
            pass
    answer_a_stop(signum, "while it was being loaded, or at a point where it has no stop handling of its own")
    os._exit(128 + signum)


def _ending_nothing(*_ignored):
    """The stop signals' handler, and sys.unraisablehook, once the answer has begun: nothing."""


def hold_stop_signals(quietly=False):
    """Hold the stop signals for good. A handler that was due runs on the way in, before the hold and before any byte of the answer, and what
    it raises is raised here, so that the tool's own handling of a stop answers it; quietly (the end of a call, an error branch, where nothing
    may escape) it is dropped and the hold is made all the same. Called by a thread that is not the main one, it blocks the signals there and
    leaves the rest to the main thread's next call."""
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        if _ENDING["held"] or not _ENDING["program"]:
            return
        try:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, _ENDING_SIGNALS)
            except (AttributeError, ValueError, OSError):
                pass                  # no pthread_sigmask here: the handler below is the hold
            main_thread = True
            for signum in _ENDING_SIGNALS:
                try:
                    signal.signal(signum, _ending_nothing)
                except (ValueError, OSError):
                    main_thread = False
            sys.unraisablehook = _ending_nothing
            _ENDING["held"] = main_thread
            return
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in, and raised
            if not quietly:
                raise



class _AnswerStream:
    """Standard output of a call: the first write holds the stop signals (above); everything else is the stream's own."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        if not _ENDING["held"]:
            hold_stop_signals()
        return self._stream.write(text)

    def writelines(self, lines):
        if not _ENDING["held"]:
            hold_stop_signals()
        return self._stream.writelines(lines)

    def __getattr__(self, name):
        if name == "_stream":
            raise AttributeError(name)
        return getattr(self._stream, name)


def _code(stop):
    hold_stop_signals(quietly=True)
    code = getattr(stop, "code", 1)
    if isinstance(code, int):
        return code
    if code is not None:
        try:
            sys.stderr.flush()
            os.write(2, ("%s\n" % (code,)).encode("utf-8", "backslashreplace"))
        except BaseException:  # noqa: BLE001
            pass
    return 0 if code is None else 1


def _leave(code):
    hold_stop_signals(quietly=True)
    code = code if isinstance(code, int) else 1
    try:
        sys.stdout.flush()
    except BaseException:  # noqa: BLE001 - a reader that is gone: the answer did not reach it
        code = code or 120
    try:
        sys.stderr.flush()
    except BaseException:  # noqa: BLE001
        pass
    try:
        atexit._run_exitfuncs()
    except BaseException:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    os._exit(code)


if __name__ == "__main__":
    if sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
        sys.stdout = _AnswerStream(sys.stdout)
    for _signum in _ENDING_SIGNALS:
        signal.signal(_signum, _stopped_without_handler)
# END SHARED ENDS


import collections
import datetime
import json
import math
import os
import sqlite3
import struct
import sys
import urllib.parse
from pathlib import Path

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


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
        # The hidden temp file goes first: a page that cannot be written leaves nothing behind (a full disk, a quota).
        out, self._out = self._out, None
        try:
            if out is not None:
                out.close()
        except BaseException:
            pass
        try:
            if self._tmp is not None:
                os.unlink(self._tmp)
        except OSError:
            pass
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
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
                self.path.parent.mkdir(parents=True, exist_ok=True)
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

    def add(self, row: object, *rest) -> object:
        """The hidden temporary file is made, and registered in `_tmp`, with the stop signals held: a stop that landed between mkstemp and the
        registration found no file to remove and left a hidden one behind (the SIGTERM case of tests/pack-windows-forensics-fs-contract.test.ts, 1 run
        in many on a loaded Mac). A signal that comes in meanwhile waits and is answered, by the handler that removes the file, as soon as the
        registration is in."""
        if self._out is not None or len(self.page) < self.limit:
            return super().add(row, *rest)
        before = None
        try:
            before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
        except (AttributeError, ValueError, OSError):
            pass
        try:
            return super().add(row, *rest)
        finally:
            if before is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, before)

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
    if "answer_a_stop" in globals():     # (a block run on its own, by a test, has no ENDS block)
        answer_a_stop(signum)
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
    answer cut. A signal that is held is not answered once the answer is out (the shared ENDS block): the answer stands, and the call ends
    with its own exit code."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    hold_stop_signals()
    STOP["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


install_signal_handlers(lambda signum: interrupted_answer(signum))
# END SHARED STOP


# BEGIN WINCRYPT
# The same text is in chromium_logins and dpapi_masterkey (tests/pack-windows-credentials.test.ts holds the copies equal): the primitives the two
# tools decrypt with, in the standard library alone, so that neither depends on a module an image may not hold. AES (FIPS 197) with CBC and GCM
# (SP 800-38D, the tag verified before a byte is returned), MD4 (RFC 1320, for the NT hash; OpenSSL 3 no longer gives it), and DPAPI as Windows
# 10 writes it: the master key file, the three pre-keys a password gives, the master key's own HMAC, and a blob with its signature.
# Only SHA-512 with AES-256 is read (what Windows 10 and 11 write for a local or a Microsoft account); a file or a blob of other algorithm ids is
# named unsupported, never attempted. Nothing here guesses: a master key is returned only when its HMAC verifies, a blob's clear text only when its
# signature verifies, a GCM clear text only when its tag verifies. wincrypt_selftest() runs every primitive against a known answer (the published
# vectors for AES, GCM and MD4; for DPAPI and the Chromium value, vectors made by a forward implementation written apart from this one, with
# another AES) and a wrong key against each, so that a call can show the reader works before a negative from it is believed.
import base64
import binascii
import hashlib
import hmac
import struct

CALG_SHA_512 = 0x800E
CALG_AES_256 = 0x6610
CALG_NAMES = {0x8003: "MD5", 0x8004: "SHA-1", 0x8009: "HMAC (SHA-1)", 0x800C: "SHA-256", 0x800D: "SHA-384", 0x800E: "SHA-512",
              0x6601: "DES", 0x6603: "3DES", 0x6609: "3DES-112", 0x660E: "AES-128", 0x660F: "AES-192", 0x6610: "AES-256", 0x6801: "RC4"}
MASTERKEY_FILE_HEADER = 128
MASTERKEY_HEADER = 32
MASTERKEY_CLEAR = 16 + 64 + 64         # HMAC salt, HMAC (SHA-512), the 64-byte key
MASTERKEY_FILE_MAX = 1 << 20           # a master key file is a few hundred bytes
PBKDF2_ROUNDS_MAX = 1_000_000          # Windows writes 4,000 to 24,000; a file that declares more is not attempted (a hostile count is hours of work)
DPAPI_BLOB_MAX = 256 << 10              # a blob is some hundreds of bytes to a few KiB; this AES is Python's, and a megabyte of it is seconds
MASTERKEY_ENCRYPTED_MAX = 1024         # the encrypted master key is 144 bytes; a block that declares far more is not a master key
DPAPI_PROVIDER = bytes.fromhex("d08c9ddf0115d1118c7a00c04fc297eb")
SID_TEXT = r"\AS-1-[0-9]{1,14}(?:-[0-9]{1,10}){1,14}\Z"   # \Z, not $: '$' also matches before a trailing line break, and a SID with one derives another key


class Unsupported(Exception):
    """The input is well formed and of a kind this reader does not read (an algorithm id, a version)."""


class Malformed(Exception):
    """The input is not what its format says (too short, a length past its end)."""


def _aes_tables():
    sbox, p, q = [0] * 256, 1, 1
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    inverse = [0] * 256
    for i, v in enumerate(sbox):
        inverse[v] = i

    def mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ 0x11B) if a & 0x80 else (a << 1)
            b >>= 1
        return r & 0xFF
    return bytes(sbox), bytes(inverse), {n: bytes(mul(i, n) for i in range(256)) for n in (2, 3, 9, 11, 13, 14)}


_SBOX, _INV_SBOX, _MUL = _aes_tables()


def aes_expand(key):
    """The round keys of an AES key of 16, 24 or 32 bytes, as a list of 16-byte strings."""
    if len(key) not in (16, 24, 32):
        raise ValueError("an AES key is 16, 24 or 32 bytes")
    nk = len(key) // 4
    rounds = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        t = list(words[i - 1])
        if i % nk == 0:
            t = [_SBOX[t[1]] ^ rcon, _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            rcon = ((rcon << 1) ^ 0x11B) if rcon & 0x80 else (rcon << 1)
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        words.append([a ^ b for a, b in zip(words[i - nk], t)])
    return [bytes(b for w in words[4 * r:4 * r + 4] for b in w) for r in range(rounds + 1)]


def aes_encrypt_block(round_keys, block):
    m2, m3 = _MUL[2], _MUL[3]
    s = [a ^ b for a, b in zip(block, round_keys[0])]
    last = len(round_keys) - 1
    for r in range(1, last + 1):
        s = [_SBOX[b] for b in s]
        s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]
        if r != last:
            t = []
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c:c + 4]
                t += [m2[a0] ^ m3[a1] ^ a2 ^ a3, a0 ^ m2[a1] ^ m3[a2] ^ a3, a0 ^ a1 ^ m2[a2] ^ m3[a3], m3[a0] ^ a1 ^ a2 ^ m2[a3]]
            s = t
        s = [a ^ b for a, b in zip(s, round_keys[r])]
    return bytes(s)


def aes_decrypt_block(round_keys, block):
    m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
    last = len(round_keys) - 1
    s = [a ^ b for a, b in zip(block, round_keys[last])]
    for r in range(last - 1, -1, -1):
        s = [s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11], s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3]]
        s = [_INV_SBOX[b] for b in s]
        s = [a ^ b for a, b in zip(s, round_keys[r])]
        if r:
            t = []
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c:c + 4]
                t += [m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3], m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3],
                      m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3], m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]]
            s = t
    return bytes(s)


def aes_cbc_decrypt(key, iv, data):
    """AES-CBC without padding: the data is whole blocks (ValueError otherwise)."""
    if len(iv) != 16 or len(data) % 16:
        raise ValueError("CBC needs a 16-byte IV and whole 16-byte blocks")
    round_keys, out, prev = aes_expand(key), bytearray(), iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(aes_decrypt_block(round_keys, block), prev))
        prev = block
    return bytes(out)


def _gf_mult(x, h):
    z, v = 0, h
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z


def aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=b""):
    """The clear text of an AES-GCM message with a 96-bit nonce and a 128-bit tag, or None when the tag does not verify (a wrong key, or a
    changed message). Nothing is decrypted before the tag has verified."""
    if len(nonce) != 12 or len(tag) != 16:
        raise ValueError("this GCM takes a 12-byte nonce and a 16-byte tag")
    round_keys = aes_expand(key)
    h = int.from_bytes(aes_encrypt_block(round_keys, bytes(16)), "big")
    y = 0
    for data in (aad, ciphertext):
        for i in range(0, len(data), 16):
            y = _gf_mult(y ^ int.from_bytes(data[i:i + 16].ljust(16, b"\x00"), "big"), h)
    y = _gf_mult(y ^ ((len(aad) * 8) << 64 | (len(ciphertext) * 8)), h)
    expected = (y ^ int.from_bytes(aes_encrypt_block(round_keys, nonce + b"\x00\x00\x00\x01"), "big")).to_bytes(16, "big")
    if not hmac.compare_digest(expected, tag):
        return None
    out = bytearray()
    for n, i in enumerate(range(0, len(ciphertext), 16)):
        stream = aes_encrypt_block(round_keys, nonce + struct.pack(">I", n + 2))
        out += bytes(a ^ b for a, b in zip(ciphertext[i:i + 16], stream))
    return bytes(out)


def md4(data):
    """MD4 (RFC 1320): the NT hash is the MD4 of the password in UTF-16LE."""
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    message = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + struct.pack("<Q", len(data) * 8)
    for off in range(0, len(message), 64):
        x = struct.unpack_from("<16I", message, off)
        aa, bb, cc, dd = a, b, c, d
        for i in range(16):
            k, s = i, (3, 7, 11, 19)[i % 4]
            a, b, c, d = d, rol((a + ((b & c) | (~b & d)) + x[k]) & 0xFFFFFFFF, s), b, c
        for i in range(16):
            k, s = (i % 4) * 4 + i // 4, (3, 5, 9, 13)[i % 4]
            a, b, c, d = d, rol((a + ((b & c) | (b & d) | (c & d)) + x[k] + 0x5A827999) & 0xFFFFFFFF, s), b, c
        for i in range(16):
            k, s = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[i], (3, 9, 11, 15)[i % 4]
            a, b, c, d = d, rol((a + (b ^ c ^ d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s), b, c
        a, b, c, d = (a + aa) & 0xFFFFFFFF, (b + bb) & 0xFFFFFFFF, (c + cc) & 0xFFFFFFFF, (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


def alg_name(alg_id):
    return "%s (0x%04X)" % (CALG_NAMES.get(alg_id, "unknown"), alg_id)


def parse_masterkey_file(data):
    """The fields of a DPAPI master key file (Protect/<SID>/<GUID>): the file header of 128 bytes, then the master key block the user's password
    opens (version, 16-byte salt, PBKDF2 rounds, hash and cipher algorithm ids, the encrypted key). The backup key, the credential history link
    and the domain key that follow are measured, not read. Malformed when a length passes the end of the file."""
    if len(data) < MASTERKEY_FILE_HEADER + MASTERKEY_HEADER:
        raise Malformed("the file is %d bytes: shorter than a master key file's header and one key block (%d)" % (len(data), MASTERKEY_FILE_HEADER + MASTERKEY_HEADER))
    version = struct.unpack_from("<I", data, 0)[0]
    guid = data[12:84].decode("utf-16-le", "replace").split("\x00", 1)[0]
    policy, flags = struct.unpack_from("<II", data, 88)
    key_len, backup_len, credhist_len, domain_len = struct.unpack_from("<QQQQ", data, 96)
    if key_len < MASTERKEY_HEADER or MASTERKEY_FILE_HEADER + key_len > len(data):
        raise Malformed("the header declares a master key block of %d bytes in a file of %d" % (key_len, len(data)))
    block = data[MASTERKEY_FILE_HEADER:MASTERKEY_FILE_HEADER + key_len]
    block_version = struct.unpack_from("<I", block, 0)[0]
    rounds, hash_alg, cipher_alg = struct.unpack_from("<III", block, 20)
    return {"version": version, "guid": guid if all(c in "0123456789abcdefABCDEF-" for c in guid) and len(guid) == 36 else None, "policy": policy, "flags": flags,
            "masterkey_bytes": key_len, "backupkey_bytes": backup_len, "credhist_bytes": credhist_len, "domainkey_bytes": domain_len,
            "sizes_fit_file": MASTERKEY_FILE_HEADER + key_len + backup_len + credhist_len + domain_len <= len(data),
            "block_version": block_version, "salt": block[4:20], "rounds": rounds, "hash_alg": hash_alg, "cipher_alg": cipher_alg, "encrypted": block[32:]}


def masterkey_supported(mk):
    """None when this reader reads the master key block; otherwise why it does not (in the tool's words, with the ids)."""
    if mk["hash_alg"] != CALG_SHA_512 or mk["cipher_alg"] != CALG_AES_256:
        return ("the master key is protected with %s and %s: this reader reads SHA-512 (0x800E) with AES-256 (0x6610) only, what Windows 10 and 11 write; "
                "it was not attempted" % (alg_name(mk["hash_alg"]), alg_name(mk["cipher_alg"])))
    if not 1 <= mk["rounds"] <= PBKDF2_ROUNDS_MAX:
        return "the master key declares %d PBKDF2 rounds: outside 1 to %d, it was not attempted" % (mk["rounds"], PBKDF2_ROUNDS_MAX)
    if len(mk["encrypted"]) < MASTERKEY_CLEAR or len(mk["encrypted"]) % 16 or len(mk["encrypted"]) > MASTERKEY_ENCRYPTED_MAX:
        return ("the encrypted master key is %d bytes: not whole AES blocks of %d to %d bytes, it was not attempted"
                % (len(mk["encrypted"]), MASTERKEY_CLEAR, MASTERKEY_ENCRYPTED_MAX))
    return None


def dpapi_prekeys(sid, password=None, sha1=None, nt=None):
    """The pre-keys a user's secret gives for a SID, each with the name of its derivation: HMAC-SHA1 over the SID in UTF-16LE with its terminator,
    keyed by the SHA-1 of the password in UTF-16LE (a local or a Microsoft account), by its NT hash (a domain account), and by the NT hash put
    through PBKDF2-HMAC-SHA256 with the SID as salt, 10,000 rounds and then one (a domain account of the newer scheme). A password gives all
    three; a SHA-1 gives the first; an NT hash the other two."""
    sid_z = (sid + "\x00").encode("utf-16-le")
    if password is not None:
        raw = password.encode("utf-16-le")
        sha1, nt = hashlib.sha1(raw).digest(), md4(raw)
    out = []
    if sha1 is not None:
        out.append(("the SHA-1 of the password", hmac.new(sha1, sid_z, hashlib.sha1).digest()))
    if nt is not None:
        out.append(("the NT hash of the password", hmac.new(nt, sid_z, hashlib.sha1).digest()))
        salt = sid.encode("utf-16-le")
        stretched = hashlib.pbkdf2_hmac("sha256", hashlib.pbkdf2_hmac("sha256", nt, salt, 10000), salt, 1)[:16]
        out.append(("the NT hash of the password through PBKDF2-SHA256 (the newer domain scheme)", hmac.new(stretched, sid_z, hashlib.sha1).digest()))
    return out


def decrypt_masterkey(mk, prekey):
    """The 64-byte master key when `prekey` opens the block AND the block's own HMAC verifies; None otherwise. PBKDF2-HMAC-SHA512 over the
    file's salt with the file's rounds gives the AES-256 key and the IV; the clear text is a 16-byte HMAC salt, a SHA-512 HMAC and the key, and
    the HMAC of the key under HMAC(prekey, salt) must equal the one stored. masterkey_supported(mk) must have said None."""
    derived = hashlib.pbkdf2_hmac("sha512", prekey, mk["salt"], mk["rounds"], 48)
    clear = aes_cbc_decrypt(derived[:32], derived[32:48], mk["encrypted"])
    key = clear[-64:]
    inner = hmac.new(prekey, clear[:16], hashlib.sha512).digest()
    if hmac.compare_digest(hmac.new(inner, key, hashlib.sha512).digest(), clear[16:80]):
        return key
    return None


def parse_dpapi_blob(data):
    """The fields of a DPAPI blob (the output of CryptProtectData): version, provider GUID, master key GUID, description, cipher and hash
    algorithm ids, salt, HMAC key, cipher text and signature. Malformed when a length passes the end."""
    def take(n):
        nonlocal at
        if n < 0 or at + n > len(data):
            raise Malformed("a length in the blob passes its end (at byte %d of %d)" % (at, len(data)))
        piece = data[at:at + n]
        at += n
        return piece

    def u32():
        return struct.unpack("<I", take(4))[0]
    at = 0
    version = u32()
    provider = take(16)
    if provider != DPAPI_PROVIDER:
        raise Malformed("the blob does not carry the DPAPI provider GUID (df9d8cd0-1501-11d1-8c7a-00c04fc297eb) at byte 4")
    key_version = u32()
    guid = take(16)
    flags = u32()
    description = take(u32())
    cipher_alg, cipher_bits = u32(), u32()
    salt = take(u32())
    strong = take(u32())
    hash_alg, hash_bits = u32(), u32()
    hmac_key = take(u32())
    cipher_text = take(u32())
    signed_to = at
    signature = take(u32())
    d = struct.unpack("<IHH", guid[:8])
    return {"version": version, "masterkey_version": key_version, "flags": flags, "description_bytes": len(description),
            "masterkey_guid": "%08x-%04x-%04x-%s-%s" % (d[0], d[1], d[2], guid[8:10].hex(), guid[10:16].hex()),
            "cipher_alg": cipher_alg, "cipher_bits": cipher_bits, "hash_alg": hash_alg, "hash_bits": hash_bits, "salt": salt, "strong": strong,
            "hmac_key": hmac_key, "cipher_text": cipher_text, "signature": signature, "to_sign": data[20:signed_to], "bytes_used": at, "trailing_bytes": len(data) - at}


def blob_supported(blob):
    if blob["hash_alg"] != CALG_SHA_512 or blob["cipher_alg"] != CALG_AES_256:
        return ("the blob is protected with %s and %s: this reader reads SHA-512 (0x800E) with AES-256 (0x6610) only; it was not attempted"
                % (alg_name(blob["hash_alg"]), alg_name(blob["cipher_alg"])))
    if not blob["cipher_text"] or len(blob["cipher_text"]) % 16 or len(blob["cipher_text"]) > DPAPI_BLOB_MAX:
        return "the blob's cipher text is %d bytes: not whole AES blocks of at most %d bytes in all, it was not attempted" % (len(blob["cipher_text"]), DPAPI_BLOB_MAX)
    return None


def decrypt_dpapi_blob(blob, masterkey, entropy=None):
    """The clear text of a blob when `masterkey` (the 64 bytes decrypt_masterkey gives) opens it AND its signature verifies; None otherwise.
    The session key is HMAC-SHA512 over the blob's salt (and the caller's entropy) keyed by the SHA-1 of the master key; its first 32 bytes are
    the AES-256 key, the IV is zero and the padding PKCS#7. The signature is the HMAC over the blob's own bytes from its master key version to
    its cipher text, in either of the two forms Windows has written. blob_supported(blob) must have said None."""
    key_hash = hashlib.sha1(masterkey).digest()
    extra = entropy or b""
    session = hmac.new(key_hash, blob["salt"] + extra, hashlib.sha512).digest()
    clear = aes_cbc_decrypt(session[:32], bytes(16), blob["cipher_text"])
    pad = clear[-1]
    if not 1 <= pad <= 16 or clear[-pad:] != bytes([pad]) * pad:
        return None
    newer = hmac.new(key_hash, blob["hmac_key"] + extra + blob["to_sign"], hashlib.sha512).digest()
    padded = key_hash + b"\x00" * (128 - len(key_hash))
    inner = hashlib.sha512(bytes(b ^ 0x36 for b in padded) + blob["hmac_key"]).digest()
    older = hashlib.sha512(bytes(b ^ 0x5C for b in padded) + inner + extra + blob["to_sign"]).digest()
    if hmac.compare_digest(newer, blob["signature"]) or hmac.compare_digest(older, blob["signature"]):
        return clear[:-pad]
    return None


def chromium_scheme(value):
    """How a Chromium-family browser stored a secret, by the bytes it begins with: 'v10' or 'v11' (AES-256-GCM under the profile key: a 12-byte
    nonce, the cipher text and a 16-byte tag), 'v20' (app-bound encryption, which this reader does not open), 'dpapi' (a bare DPAPI blob, what
    Chrome wrote before version 80), 'empty' or 'unknown'."""
    if not value:
        return "empty"
    if value[:3] in (b"v10", b"v11"):
        return value[:3].decode("ascii")
    if value[:3] == b"v20":
        return "v20"
    if value[:4] == b"\x01\x00\x00\x00" and value[4:20] == DPAPI_PROVIDER:
        return "dpapi"
    return "unknown"


def chromium_decrypt(value, profile_key):
    """The clear text of a 'v10' or 'v11' value under a 32-byte profile key, or None when the tag does not verify or the value is too short."""
    if len(value) < 3 + 12 + 16:
        return None
    return aes_gcm_decrypt(profile_key, value[3:15], value[15:-16], value[-16:])


SELFTEST_VECTORS = {
    # FIPS 197 appendix C.3; the GCM specification's test cases 14 and 16 (McGrew and Viega); RFC 1320; the NT hash of "password".
    "aes256_block": ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
    "gcm_14": ("00" * 32, "00" * 12, "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919", "", "00" * 16),
    "gcm_16": ("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
               "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
               "76fc6ece0f4e1768cddf8853bb2d551b", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
    "md4_abc": ("616263", "a448017aaf21d8525fc10ae87aa6729d"),
    "nt_password": ("password", "8846f7eaee8fb117ad06bdd830b7586c"),
    # Made by a forward implementation written apart from this reader, with another AES (see the tool's tests): a master key file for the SID
    # and the password below, a blob under that master key, and a Chromium 'v10' value under the 32 bytes the blob holds.
    "dpapi_sid": "S-1-5-21-1111111111-2222222222-3333333333-1001",
    "dpapi_password": "password",
    "dpapi_masterkey_file": "020000000000000000000000300066003000650030006400300063002d0030006200300061002d0034003900300038002d0038003700300036002d00300035003000340030003300300032003000310030003000000000000000000005000000b000000000000000900000000000000014000000000000000000000000000000020000009e831cc9842d44695b2758a222002070401f00000e800000106600006d3674185197da6da47a349bc323eb1cb51d1b4fa058390f920e2e57497960050c9b2022f326d3718b60eb66af244a8a0e90cfbcc8de4556510b45ee6b87ddeb296971c16dd2881d26edef8f206797fc2dc655dc03c8a22b8b9d20baccd04c28fb4b268cb2df709883925cf42f7582c30ac1cb3b57aa2070c18ab5c37d6708689bb920a177cdce0c40d03a6a82f3e90402000000d73166cc99f2787642a46b01eb0a7b68fc156fe5c419b5b8b1b4fb8d4951500734a7913adf961ced9f43594878b6c1f5ee6e88f8bbe0b19d400a5fc3fafcc6b046f21ce998d6f01b7e38bd9d3bc066227d078f455f150d15fb55e9913a92ade5e5666c80f1b385b7fe89886f75ed39c522f6aca87959c8f44ea992a030b10b4709bec8b84e3220e7975ec81a03000000239e2577be667c4cf962c98e76842b32",
    "dpapi_masterkey_nt_file": "020000000000000000000000300066003000650030006400300063002d0030006200300061002d0034003900300038002d0038003700300036002d00300035003000340030003300300032003000310030003000000000000000000005000000b00000000000000090000000000000001400000000000000000000000000000002000000644f679bf2f9e8e0147edd5f0c9a1ea6401f00000e80000010660000b6439aff2305eb57c254d1433816722ca388975bb3a0022562870bf8b44056f567b91de6e1197247641a5bd3f46c963f22846d97cf904214fbc98912259bdce1bd7ce5a0bf010ee2429c1aa3847f30cbb71153a5a94dce8225d1fbac3a21c27cb7f329afe9872a848f4932b3b71502613c21dd5db9dacdc27241eb26f36d31245ef510ada2debdf83846061d9e74cbde020000003a7942d7706aed544102eb135ff2bb09c360aa68e6beb4ea7e2519725207096746c8290dece5702b562df6e504fde6ab9b545f80e5e3fbdb77d6861c4ccef8e4430c7d8e4c765658394756af821476540498ef76203afa7b60fcd726fb2469327709d660099f2622e97501b3231e413fb22c0321e3e2b82cf9388353a5aea568cbe52b9e36e18d3ccba9b73e0300000057d06798a5445f52445ae80c0c3dec16",
    "dpapi_masterkey_sha256": "8780da169fe103f05664178116c95ca01747e58379a9673ff0a28e3ea799f964",
    "dpapi_blob": "01000000d08c9ddf0115d1118c7a00c04fc297eb010000000c0d0e0f0a0b084987060504030201000000000024000000770069006e00630072007900700074002000730065006c00660074006500730074000000106600000001000020000000cd3c4db3690a1bddbd8111f0fa9484b6c10c2c0af7d90b4cc6a3c0d76f5b5a94000000000e8000000002000020000000448f79862bf365f0bfc1807dbc43f2baf04d62e6ea4ad3118ad404ae595a02ed300000005122cba7bc50528e1ca0fdae3b3b430218a2e03d143413374db6de4e65d5eb1fb648d16d78dc9059b284700309ff726140000000b25f0fa26b01f0f443bc11323d200088d9c88fb634b73a9801b8395f4e25d77064101d8043c5c9b89a20d529a045858bea2024c27d44ef2b28d57a7bc1c995a7",
    "dpapi_blob_clear": "67d0a71b64acac000f4f12ecc980cdd7650e186041a3edb87b03533aedc7bc98",
    "chromium_v10": "763130d8aa59adc1b097b85e123103d6d56e89faba5320813f1efa61967f81f3082fc4be5a7534e5b0bdf07ca33b7d6ca581433472d328159c41b7bfc04953b64e7e749806d199a0d0",
    "chromium_clear": "6b6e6f776e2d616e737765723a20636f727265637420686f727365206261747465727920737461706c65",
}


def wincrypt_selftest():
    """Every primitive against its known answer, and a wrong key against each: a list of {name, passed}. A check that raises has not passed."""
    v = SELFTEST_VECTORS
    unhex = bytes.fromhex

    def aes_block():
        key, clear, cipher = (unhex(x) for x in v["aes256_block"])
        keys = aes_expand(key)
        return aes_encrypt_block(keys, clear) == cipher and aes_decrypt_block(keys, cipher) == clear

    def gcm(name):
        key, nonce, cipher, tag, aad, clear = (unhex(x) for x in v[name])
        wrong = bytes([key[0] ^ 1]) + key[1:]
        return (aes_gcm_decrypt(key, nonce, cipher, tag, aad) == clear and aes_gcm_decrypt(wrong, nonce, cipher, tag, aad) is None
                and aes_gcm_decrypt(key, nonce, cipher, bytes([tag[0] ^ 1]) + tag[1:], aad) is None)

    def masterkey(name, right, wrong):
        mk = parse_masterkey_file(unhex(v[name]))
        if masterkey_supported(mk) is not None:
            return None
        found = [decrypt_masterkey(mk, prekey) for _how, prekey in dpapi_prekeys(v["dpapi_sid"], password=v["dpapi_password"])]
        refused = [decrypt_masterkey(mk, prekey) for _how, prekey in dpapi_prekeys(v["dpapi_sid"], password=v["dpapi_password"] + "x")]
        other_sid = [decrypt_masterkey(mk, prekey) for _how, prekey in dpapi_prekeys(v["dpapi_sid"] + "1", password=v["dpapi_password"])]
        ok = found[right] is not None and hashlib.sha256(found[right]).hexdigest() == v["dpapi_masterkey_sha256"] and all(found[i] is None for i in wrong)
        return found[right] if ok and not any(refused) and not any(other_sid) else None

    def blob():
        key = masterkey("dpapi_masterkey_file", 0, (1, 2))
        parsed = parse_dpapi_blob(unhex(v["dpapi_blob"]))
        wrong = bytes([key[0] ^ 1]) + key[1:]
        return (blob_supported(parsed) is None and decrypt_dpapi_blob(parsed, key) == unhex(v["dpapi_blob_clear"]) and decrypt_dpapi_blob(parsed, wrong) is None
                and decrypt_dpapi_blob(parsed, key, entropy=b"x") is None)

    def chromium():
        key, value = unhex(v["dpapi_blob_clear"]), unhex(v["chromium_v10"])
        wrong = bytes([key[0] ^ 1]) + key[1:]
        return (chromium_scheme(value) == "v10" and chromium_decrypt(value, key) == unhex(v["chromium_clear"]) and chromium_decrypt(value, wrong) is None
                and chromium_decrypt(value[:-1] + bytes([value[-1] ^ 1]), key) is None)

    checks = (
        ("AES-256 block, both directions (FIPS 197 C.3)", aes_block),
        ("AES-256-GCM, test case 14, and a wrong key and a wrong tag refused", lambda: gcm("gcm_14")),
        ("AES-256-GCM with associated data, test case 16, and a wrong key and a wrong tag refused", lambda: gcm("gcm_16")),
        ("MD4 (RFC 1320) and the NT hash of a known password", lambda: md4(unhex(v["md4_abc"][0])).hex() == v["md4_abc"][1]
            and md4(v["nt_password"][0].encode("utf-16-le")).hex() == v["nt_password"][1]),
        ("DPAPI master key from a password by its SHA-1, HMAC verified; a wrong password and a wrong SID refused", lambda: masterkey("dpapi_masterkey_file", 0, (1, 2)) is not None),
        ("DPAPI master key from a password by its NT hash, HMAC verified; a wrong password and a wrong SID refused", lambda: masterkey("dpapi_masterkey_nt_file", 1, (0, 2)) is not None),
        ("DPAPI blob under that master key, signature verified; a wrong key and a wrong entropy refused", blob),
        ("Chromium v10 value under the key the blob holds, tag verified; a wrong key and a changed tag refused", chromium),
    )
    results = []
    for name, check in checks:
        try:
            passed = bool(check())
        except Exception:  # noqa: BLE001 - a check that raises has not passed
            passed = False
        results.append({"name": name, "passed": passed})
    return results
# END WINCRYPT


# BEGIN CREDENTIAL IO
# The same text is in chromium_logins and dpapi_masterkey (tests/pack-windows-credentials.test.ts holds the copies equal): how the two tools take a
# secret in and put one out. A secret comes in as a FILE the call names (a password, a hash, a key, the sealed output of an earlier job), never
# as a value in the arguments, which the trace records; it goes out only into a file under $OUT that is created first, exclusively and with
# mode 0600, in a job the harness runs as secret output (SECRET_OUTPUT=1). The answer says where the values are and how many, never what they are.
import re
import stat

SECRET_FILE_MAX = 4096                 # a password, a hash or a key file
KEYS_FILE_MAX = 4 << 20                # the sealed keys file of an earlier call
MASTERKEY_FILES_MAX = 64               # master key files tried in one call
GUID_NAME = re.compile(r"\A[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\Z")
SID_NAME = re.compile(SID_TEXT)


class Refused(Exception):
    """An argument or an input file the call cannot use; the text is the tool's own and holds nothing read from a secret."""


def is_secret_job():
    return os.environ.get("SECRET_OUTPUT") == "1" and bool(os.environ.get("OUT")) and bool(os.environ.get("JOB_ID"))


def shown_output(name):
    return "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("JOB_ID") or ""), name)


def read_regular(path, what, limit):
    """The bytes of a named input: a regular file, never a link, a pipe, a device or a directory, opened without waiting and without following a
    link, and at most `limit` bytes. Refused, in the tool's words, otherwise."""
    if not isinstance(path, str) or not path or "\x00" in path:
        raise Refused("%s must be a path to a file" % what)
    try:
        if stat.S_ISLNK(os.lstat(path).st_mode):
            raise Refused("%s is a symbolic link: name the file it resolves to (nothing is followed through a link)" % what)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise Refused("%s could not be opened (%s)" % (what, type(exc).__name__)) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refused("%s is not a regular file (a pipe, a device, a socket or a directory is not read)" % what)
        if info.st_size > limit:
            raise Refused("%s is %d bytes, over the %d this tool reads for it" % (what, info.st_size, limit))
        parts = []
        while True:
            piece = os.read(fd, 1 << 16)
            if not piece:
                break
            parts.append(piece)
            if sum(len(p) for p in parts) > limit:
                raise Refused("%s is over the %d bytes this tool reads for it" % (what, limit))
        return b"".join(parts)
    except OSError as exc:
        raise Refused("%s could not be read (%s)" % (what, type(exc).__name__)) from None
    finally:
        os.close(fd)


def read_password(path):
    """A password from its file: UTF-8, one trailing line break dropped. An empty file is refused (an empty password is said with
    empty_password: true, so that a file that failed to be written is not taken for one)."""
    raw = read_regular(path, "password_file", SECRET_FILE_MAX)
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw:
        raise Refused("password_file is empty: for an account with no password say empty_password: true")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("password_file is not UTF-8 text") from None


def read_hash(path):
    """('sha1' | 'nt', bytes) from a hash file: 40 hexadecimal digits (the SHA-1 of the password in UTF-16LE) or 32 (its NT hash), or the 20 or
    16 raw bytes. What kind it is follows from its length alone."""
    raw = read_regular(path, "hash_file", SECRET_FILE_MAX)
    text = raw.strip()
    if len(text) in (40, 32) and all(c in b"0123456789abcdefABCDEF" for c in text):
        raw = bytes.fromhex(text.decode("ascii"))
    if len(raw) == 20:
        return "sha1", raw
    if len(raw) == 16:
        return "nt", raw
    raise Refused("hash_file must hold a SHA-1 (20 bytes, or 40 hexadecimal digits) or an NT hash (16 bytes, or 32 digits)")


def read_key32(path, what="key_file"):
    """32 bytes from a key file: the raw bytes, 64 hexadecimal digits, or base64 of 32 bytes (white space around the text is dropped)."""
    raw = read_regular(path, what, SECRET_FILE_MAX)
    if len(raw) == 32:
        return raw
    text = raw.strip()
    if len(text) == 64 and all(c in b"0123456789abcdefABCDEF" for c in text):
        return bytes.fromhex(text.decode("ascii"))
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        decoded = b""
    if len(decoded) == 32:
        return decoded
    raise Refused("%s must hold 32 bytes: raw, as 64 hexadecimal digits, or as base64" % what)


class SealedFile:
    """The values file of a call: JSON Lines under $OUT, mode 0600, made exclusively before anything is read (a file or a link already at the
    name is refused by name). With nothing to write it stays an empty file and the answer says written: 0."""

    def __init__(self, name):
        self.name, self.written = name, 0
        self.path = os.path.join(os.environ["OUT"], name)
        self.shown = shown_output(name)
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise Refused("the values file %s is already there: nothing is replaced, and nothing was read" % self.shown) from None
        except OSError as exc:
            raise Refused("the values file %s could not be made (%s): nothing was read" % (self.shown, type(exc).__name__)) from None
        self._out = os.fdopen(fd, "w", encoding="ascii")

    def add(self, row):
        self._out.write(json.dumps(row, ensure_ascii=True) + "\n")
        self._out.flush()
        self.written += 1

    def close(self):
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
            except OSError:
                pass
            self._out.close()
            self._out = None

    def said(self):
        return {"values_file": self.shown, "written": self.written, "contains_secret_values": self.written > 0, "mode": "0600",
                "format": "JSON Lines, one value per line with what it belongs to"}


def path_list(value, what):
    """A parameter that names one path or several: a string is one path (a tool is often handed a string where a list was meant)."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value or not all(isinstance(p, str) and p and "\x00" not in p for p in value):
        raise Refused("%s must be a path or a list of paths" % what)
    return value


def masterkey_paths(value):
    """The master key files a call names: each path is a file, or a directory (a user's Protect/<SID>) whose files named by a GUID are taken, in
    name order. Links are not followed."""
    out = []
    named = path_list(value, "masterkey")
    for number, path in enumerate(named, 1):
        if os.path.islink(path):
            raise Refused("a masterkey path is a symbolic link: name what it resolves to")
        if not os.path.lexists(path):
            raise Refused("masterkey path %d of %d does not exist: no file or directory is at that name (a user's master keys are in "
                          "AppData/Roaming/Microsoft/Protect/<SID>/<GUID>)" % (number, len(named)))
        if os.path.isdir(path):
            try:
                names = sorted(os.listdir(path))
            except OSError as exc:
                raise Refused("a masterkey directory could not be listed (%s)" % type(exc).__name__) from None
            found = [os.path.join(path, n) for n in names if GUID_NAME.match(n) and os.path.isfile(os.path.join(path, n)) and not os.path.islink(os.path.join(path, n))]
            if not found:
                raise Refused("a masterkey directory holds no file named by a GUID (a user's master keys are in AppData/Roaming/Microsoft/Protect/<SID>/<GUID>)")
            out.extend(found)
        else:
            out.append(path)
    if len(out) > MASTERKEY_FILES_MAX:
        raise Refused("%d master key files were named: at most %d in one call" % (len(out), MASTERKEY_FILES_MAX))
    return out


def sid_of(args, files):
    """The SID the master keys belong to and where it came from: the `sid` argument, or the name of the directory the first file is in (Windows
    keeps a user's master keys in a directory named by the SID)."""
    sid = args.get("sid")
    if sid is not None:
        if not isinstance(sid, str) or not SID_NAME.match(sid):
            raise Refused("sid must be a security identifier such as S-1-5-21-1111111111-2222222222-3333333333-1001, and nothing else: a space or a line "
                          "break before or after it is not dropped, because the SID is part of the key derivation")
        return sid, "the sid argument"
    for path in files:
        parent = os.path.basename(os.path.dirname(os.path.abspath(path)))
        if SID_NAME.match(parent):
            return parent, "the name of the directory the master key file is in"
    raise Refused("sid is required: the master key file is not in a directory named by a SID, and the SID is part of the key derivation "
                  "(it is the name of the user's directory under AppData/Roaming/Microsoft/Protect, and the profile's key in the SOFTWARE hive's ProfileList)")


def user_secret(args):
    """What opens the master keys, from exactly one of password_file, hash_file and empty_password: (kind, keyword arguments for dpapi_prekeys)."""
    given = [k for k in ("password_file", "hash_file", "empty_password") if args.get(k) not in (None, False)]
    if len(given) != 1:
        raise Refused("name exactly one of password_file (the user's password), hash_file (its SHA-1 or its NT hash) and empty_password: true; %s"
                      % ("none was given" if not given else "%d were given" % len(given)))
    if given[0] == "empty_password":
        if args["empty_password"] is not True:
            raise Refused("empty_password must be true or false")
        return "an empty password", {"password": ""}
    if given[0] == "password_file":
        return "a password", {"password": read_password(args["password_file"])}
    kind, value = read_hash(args["hash_file"])
    return ("the SHA-1 of the password" if kind == "sha1" else "the NT hash of the password"), {kind: value}


def open_masterkeys(files, sid, secret, time_is_up):
    """Try every master key file with every pre-key the secret gives. Returns (one report per file, {guid: 64-byte key} of the ones whose HMAC
    verified). A report holds what the file's header says and the outcome, never a byte of a key."""
    prekeys = dpapi_prekeys(sid, **secret)
    reports, keys = [], {}
    for path in files:
        report = {"file": path, "attempted": False, "verified": False}
        reports.append(report)
        if time_is_up():
            report["error"] = "the tool's own clock ran out before this file was tried"
            report["not_tried_for_time"] = True
            continue
        try:
            mk = parse_masterkey_file(read_regular(path, "a master key file", MASTERKEY_FILE_MAX))
        except (Refused, Malformed) as exc:
            report["error"] = str(exc)
            continue
        guid, guid_from = mk["guid"], "the file's header"
        if guid is None:
            # The header's GUID field is not a GUID. Windows names the file by the same GUID, and a blob names its master key by it: the file's
            # name is used, and said, so that a key that verifies still opens the blobs that name it.
            name = os.path.basename(path)
            if GUID_NAME.match(name):
                guid, guid_from = name.lower(), "the file's name (the GUID field of the file's header is not a GUID)"
            else:
                guid_from = "nowhere: neither the file's header nor its name holds a GUID, so no blob can be matched to this key by GUID"
        report.update(guid=guid, guid_from=guid_from, version=mk["version"], policy=mk["policy"], flags=mk["flags"], rounds=mk["rounds"],
                      hash_algorithm=alg_name(mk["hash_alg"]), cipher_algorithm=alg_name(mk["cipher_alg"]), masterkey_block_bytes=mk["masterkey_bytes"],
                      backupkey_bytes=mk["backupkey_bytes"], credhist_bytes=mk["credhist_bytes"], domainkey_bytes=mk["domainkey_bytes"],
                      sizes_fit_file=mk["sizes_fit_file"])
        why = masterkey_supported(mk)
        report["supported"] = why is None
        if why:
            report["unsupported_why"] = why
            continue
        report["attempted"], report["derivations_tried"] = True, []
        for how, prekey in prekeys:
            if time_is_up():
                report["not_tried_for_time"] = True
                report["error"] = ("the tool's own clock ran out after %d of the %d derivation(s) were tried: this file is neither verified nor refused"
                                   % (len(report["derivations_tried"]), len(prekeys)))
                break
            report["derivations_tried"].append(how)
            key = decrypt_masterkey(mk, prekey)
            if key is not None:
                report["verified"], report["verified_with"] = True, how
                keys[(guid or "").lower()] = key
                break
    return reports, keys


def read_keys_file(path):
    """{guid: 64-byte key} from the sealed keys file an earlier dpapi_masterkey call wrote (JSON Lines; the rows of kind 'masterkey')."""
    keys = {}
    for line in read_regular(path, "keys_file", KEYS_FILE_MAX).splitlines():
        try:
            row = json.loads(line)
            if isinstance(row, dict) and row.get("kind") == "masterkey":
                key = bytes.fromhex(row["key_hex"])
                if len(key) == 64 and isinstance(row.get("guid"), str):
                    keys[row["guid"].lower()] = key
        except (ValueError, KeyError, TypeError):
            continue
    if not keys:
        raise Refused("keys_file holds no master key row: it is the dpapi_masterkey-keys.jsonl a dpapi_masterkey job wrote")
    return keys
# END CREDENTIAL IO


PARSER = "chromium_logins/2"
DEADLINE_SECONDS = 45             # the manifest allows 60: the reads stop here, so that the page is placed and the answer printed before the harness ends the tool
VALUES_NAME = "chromium_logins-values.jsonl"
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000                  # the largest inline page; the whole result is in the file the answer names
MAX_ROWS = 1_000_000
LOCAL_STATE_MAX = 64 << 20
CELL_MAX = 8 << 20                # SQLITE_LIMIT_LENGTH for this read: a cell over it is not taken into memory; it is read as its type and its length alone
V10_MIN = 3 + 12 + 16             # 'v10' or 'v11', a 12-byte nonce and a 16-byte tag: a shorter value holds no message to verify
VALUE_MAX = 64 << 10              # a stored secret longer than this is not decrypted (a password is tens of bytes; this AES is Python's, and a megabyte of it is seconds)
TEXT_SHOWN = 512                  # characters of a user name or an origin shown inline; the whole is in the sealed file
WEBKIT_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
SQLITE_MAGIC = b"SQLite format 3\x00"
KNOWN_ARGS = {"selftest", "login_data", "local_state", "key_file", "masterkey", "sid", "password_file", "hash_file", "empty_password", "masterkey_keys_file", "limit"}
COLUMNS = ("id", "origin_url", "action_url", "signon_realm", "username_value", "password_value", "date_created", "date_last_used", "date_password_modified",
           "times_used", "blacklisted_by_user")
PROGRESS = {"stage": "before anything was read", "rows": 0}
SEALED = []

REFUSED_NOT_SECRET = (
    "chromium_logins is refused outside a job run as secret output: the passwords it decrypts and the profile key are written to a sealed file, and "
    "the key, the password or the hash is read from a file of the job. Run it as job_run(tool: \"chromium_logins\", args: {...}); the manifest's "
    "secret_output: \"required\" makes every job of this tool one, and the harness then sets SECRET_OUTPUT=1, JOB_ID and OUT for the job's process, "
    "which this process does not have. Nothing was read and nothing was written. selftest: true alone runs anywhere: it reads no evidence. For the "
    "saved logins without their passwords (origin, user name, dates), browser_history reads Login Data anywhere."
)
VERIFIED_NOTE = ("The v10 reader (AES-256-GCM, the tag verified) was run against a Login Data and its profile key from a real Windows 10 Chrome profile. The DPAPI "
                 "steps (a master key from a password, the profile key from Local State) are checked against vectors made by a forward implementation written apart "
                 "from this reader, not against a master key whose password is known from Windows.")


def close_sealed():
    for sealed in SEALED:
        sealed.close()


def drop_pages():
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            page._tmp = None


def fail(message, **extra):
    drop_pages()
    close_sealed()
    if SEALED:                        # a values file this call made stays a sealed output of the job: a failed answer names it and counts its lines
        extra = {"secret_values": SEALED[0].said(), "contains_secret_values": SEALED[0].written > 0, **extra}
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}, indent=2)
    raise SystemExit(1)


def last_word(signum):
    interrupted_answer(signum, stopped=PROGRESS["stage"], rows_read=PROGRESS["rows"],
                       note="a values file made by this call holds the whole lines written before the stop, and stays a sealed output of the job")


def selftest_report():
    checks = wincrypt_selftest()
    return {"passed": all(c["passed"] for c in checks) and len(checks) > 0, "checks": checks}


def webkit_time(value):
    """(ISO 8601 UTC with six fractional digits, the raw value) of a Chromium time: microseconds since 1601-01-01 UTC. None for 0, for a value
    that is not a whole number and for one past year 9999; the raw value is kept beside it in every case."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    try:
        whole, micro = divmod(value, 1_000_000)
        return (WEBKIT_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%06dZ" % micro
    except (OverflowError, ValueError):
        return None


def origin_shown(url):
    """An origin as the answer prints it: scheme, host, port and path. User-info, the query and the fragment are where a URL carries a secret, so
    they are left out and counted; the whole URL is in the sealed values file. A text that is not a URL is shown by its length alone."""
    if not isinstance(url, str):
        return None, None
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return None, {"not_a_url_characters": len(url)}
    if not parts.scheme or not all(c.isprintable() for c in url):
        return None, {"not_a_url_characters": len(url)}
    # '//' is printed only where the URL has an authority part: 'javascript:alert(1)' and 'mailto:a@b' have none, and are shown without one.
    slashes = "//" if url.lstrip()[len(parts.scheme):len(parts.scheme) + 3] == "://" else ""
    shown = "%s:%s%s%s%s" % (parts.scheme, slashes, host, ":%d" % port if port else "", parts.path)
    left_out = {k: n for k, n in (("user_info_characters", len(parts.netloc.rsplit("@", 1)[0]) if "@" in parts.netloc else 0),
                                  ("query_characters", len(parts.query)), ("fragment_characters", len(parts.fragment))) if n}
    if len(shown) > TEXT_SHOWN:
        left_out["characters_past_%d" % TEXT_SHOWN] = len(shown) - TEXT_SHOWN
        shown = shown[:TEXT_SHOWN]
    return shown, left_out or None


def text_shown(value):
    if value is None:
        return None, None
    if isinstance(value, bytes):
        return None, {"bytes_not_text": len(value)}
    text = str(value)
    shown = "".join(c if c.isprintable() else "?" for c in text[:TEXT_SHOWN])
    return shown, ({"characters_past_%d" % TEXT_SHOWN: len(text) - TEXT_SHOWN} if len(text) > TEXT_SHOWN else None)


def sidecars(path):
    """The files SQLite keeps beside a database, looked for by name: a write-ahead log or a rollback journal that is not empty holds changes
    the database file does not, and this reader opens the database file alone (immutable, nothing replayed)."""
    looked, found = [path + s for s in ("-wal", "-journal")], []
    for name in looked:
        try:
            info = os.lstat(name)
            if stat.S_ISREG(info.st_mode) and info.st_size > 0:
                found.append({"file": name, "bytes": info.st_size})
        except OSError:
            pass
    return looked, found


def login_records(conn, columns):
    """Every row of the logins table in rowid order, as (fields, cells over the limit). `columns` is [(the reader's name, the table's own name)].
    A cell over CELL_MAX (SQLITE_LIMIT_LENGTH) ends a statement that selects it, so the row that holds one is read cell by cell: every cell
    that fits is read as it is, and the one that does not is None in the fields and is described by its type and, for a BLOB, its length
    (SQLite gives both without loading the value; the length of a TEXT is a count of characters, which needs the value, so it stays None).
    The rows after it are read by a new statement that starts past it, so one such cell loses no other row and no other cell."""
    names = ["rowid"] + [name for name, _real in columns]
    select = "SELECT rowid, %s FROM logins" % ", ".join('"%s"' % real for _name, real in columns)
    last = None
    while True:
        try:
            # (the statement's first step is taken by execute itself, so it is inside the try as well)
            cursor = conn.execute(select + " ORDER BY rowid") if last is None else conn.execute(select + " WHERE rowid > ? ORDER BY rowid", (last,))
            for record in cursor:
                last = record[0]
                yield dict(zip(names, record)), {}
            return
        except sqlite3.DataError:
            pass                                               # SQLITE_TOOBIG: the next row holds a cell over the limit
        found = (conn.execute("SELECT rowid FROM logins ORDER BY rowid LIMIT 1") if last is None else
                 conn.execute("SELECT rowid FROM logins WHERE rowid > ? ORDER BY rowid LIMIT 1", (last,))).fetchone()
        if found is None:
            return
        last = found[0]
        fields, over = {"rowid": last}, {}
        for name, real in columns:
            try:
                got = conn.execute('SELECT "%s" FROM logins WHERE rowid = ?' % real, (last,)).fetchone()
                fields[name] = got[0] if got else None
            except sqlite3.DataError:
                fields[name] = None
                about = {"type": None, "length": None}
                for what in ("typeof", "length"):
                    try:
                        got = conn.execute('SELECT %s("%s") FROM logins WHERE rowid = ?' % (what, real), (last,)).fetchone()
                        about["type" if what == "typeof" else "length"] = got[0] if got else None
                    except sqlite3.DataError:
                        pass
                over[name] = about
        yield fields, over


def profile_key_from(args, local_state, masterkeys, report):
    """The 32-byte profile key and where it came from, or None with report['why_not'] saying which step it stopped at. Never raises for a
    wrong key or a wrong password: those are answers."""
    if args.get("key_file") is not None:
        report.update(source="key_file", obtained=True)
        return read_key32(args["key_file"])
    if local_state is None:
        report.update(obtained=False, why_not="no key_file and no local_state: a v10 or v11 value needs the profile key, which Local State holds under DPAPI")
        return None
    report["source"] = "Local State os_crypt.encrypted_key, opened with a DPAPI master key"
    encoded = (local_state.get("os_crypt") or {}).get("encrypted_key") if isinstance(local_state.get("os_crypt"), dict) else None
    report["local_state"] = {"encrypted_key_present": isinstance(encoded, str),
                             "app_bound_encrypted_key_present": isinstance(local_state.get("os_crypt"), dict) and "app_bound_encrypted_key" in local_state["os_crypt"]}
    if not isinstance(encoded, str):
        report.update(obtained=False, why_not="Local State has no os_crypt.encrypted_key")
        return None
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        report.update(obtained=False, why_not="os_crypt.encrypted_key is not base64")
        return None
    if raw[:5] != b"DPAPI":
        report.update(obtained=False, why_not="os_crypt.encrypted_key does not begin with 'DPAPI': not the Windows form this reader opens")
        return None
    try:
        blob = parse_dpapi_blob(raw[5:])
    except Malformed as exc:
        report.update(obtained=False, why_not="the DPAPI blob in os_crypt.encrypted_key is malformed: %s" % exc)
        return None
    report["local_state"].update(masterkey_guid=blob["masterkey_guid"], hash_algorithm=alg_name(blob["hash_alg"]), cipher_algorithm=alg_name(blob["cipher_alg"]))
    why = blob_supported(blob)
    if why:
        report.update(obtained=False, why_not=why)
        return None
    key = masterkeys.get(blob["masterkey_guid"])
    if key is None:
        report.update(obtained=False, why_not="the profile key is under master key %s, and no verified key of that GUID is at hand (masterkeys says what was tried): "
                                              "name that file under masterkey with the user's password or hash, or give the profile key as key_file" % blob["masterkey_guid"])
        return None
    clear = decrypt_dpapi_blob(blob, key)
    if clear is None:
        report.update(obtained=False, why_not="the DPAPI blob's signature did not verify under the master key of its GUID")
        return None
    if len(clear) != 32:
        report.update(obtained=False, why_not="the DPAPI blob opened to %d bytes, not the 32 of a profile key" % len(clear))
        return None
    report["obtained"] = True
    return clear


def main():
    set_deadline(DEADLINE_SECONDS)
    install_signal_handlers(last_word)
    try:
        args = json.load(sys.stdin)
    except ValueError:
        fail("arguments are not valid JSON")
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    unknown = sorted(str(k) for k in set(args) - KNOWN_ARGS)
    if unknown:
        fail("unknown argument(s): %s" % ", ".join(re.sub(r"[^A-Za-z0-9_]", "?", k)[:40] for k in unknown[:10]),
             hint="a key, a password or a hash is never given as a value: name the file that holds it (key_file, password_file, hash_file, masterkey_keys_file)")
    selftest = args.get("selftest", False)
    if not isinstance(selftest, bool):
        fail("selftest must be true or false")
    PROGRESS["stage"] = "during the self-test"
    test = selftest_report()
    if selftest and len([k for k, v in args.items() if v not in (None, False)]) == 1:
        print_answer({"parser": PARSER, "status": "complete" if test["passed"] else "failed",
                      "status_basis": ("every primitive gave its known answer and refused a wrong key (%d checks): a row this reader does not decrypt is a finding "
                                       "about the key, not about the reader, as far as the checks go" % len(test["checks"])) if test["passed"] else
                                      "a primitive did not give its known answer (self_test.checks): nothing this reader says on this host can be believed",
                      "self_test": test, "verification_note": VERIFIED_NOTE}, indent=2)
        raise SystemExit(0 if test["passed"] else 1)
    if not is_secret_job():
        print_answer({"error": REFUSED_NOT_SECRET, "status": "failed", "status_basis": "the call was refused before anything was read or written: not a secret_output job"}, indent=2)
        raise SystemExit(1)
    if not test["passed"]:
        fail("the self-test failed on this host: a primitive did not give its known answer, so nothing was attempted (a negative from a broken reader is not a finding)",
             self_test=test)
    path = args.get("login_data")
    if not isinstance(path, str) or not path or "\x00" in path:
        fail("login_data is required: the profile's Login Data file (an SQLite database)")
    limit = args.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        fail("limit must be a whole number from 1 to %d (the inline page; the whole result is in the file the answer names)" % MAX_LIMIT)
    if args.get("key_file") is not None and (args.get("masterkey") is not None or args.get("masterkey_keys_file") is not None):
        fail("give the profile key (key_file) or the DPAPI material that opens it (masterkey with a password_file, a hash_file or empty_password; or masterkey_keys_file), not both")

    key_report, masterkey_reports, masterkeys, sid, sid_from, secret_kind = {}, [], {}, None, None, None
    try:
        PROGRESS["stage"] = "while the inputs were read"
        try:
            if stat.S_ISLNK(os.lstat(path).st_mode):
                raise Refused("login_data is a symbolic link: name the file it resolves to")
            with open(os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)), "rb") as fh:
                info = os.fstat(fh.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise Refused("login_data is not a regular file")
                header = fh.read(16)
        except OSError as exc:
            raise Refused("login_data could not be opened (%s)" % type(exc).__name__) from None
        if header != SQLITE_MAGIC:
            raise Refused("login_data is not an SQLite database (%d bytes; it does not begin 'SQLite format 3'): nothing was read from it" % info.st_size)
        values = SealedFile(VALUES_NAME)
        SEALED.append(values)
        local_state = None
        if args.get("local_state") is not None:
            try:
                local_state = json.loads(read_regular(args["local_state"], "local_state", LOCAL_STATE_MAX).decode("utf-8"))
            except (ValueError, UnicodeDecodeError, RecursionError):
                raise Refused("local_state is not JSON: it is the profile directory's parent's Local State file (User Data/Local State)") from None
            if not isinstance(local_state, dict):
                raise Refused("local_state is JSON but not an object")
        if args.get("masterkey") is not None:
            files = masterkey_paths(args["masterkey"])
            sid, sid_from = sid_of(args, files)
            secret_kind, secret = user_secret(args)
            PROGRESS["stage"] = "while the master keys were tried"
            masterkey_reports, masterkeys = open_masterkeys(files, sid, secret, out_of_time)
        elif any(args.get(k) not in (None, False) for k in ("password_file", "hash_file", "empty_password", "sid")):
            raise Refused("a password, a hash or a SID was given without masterkey: name the user's master key file (AppData/Roaming/Microsoft/Protect/<SID>/<GUID>) "
                          "or the Protect/<SID> directory")
        if args.get("masterkey_keys_file") is not None:
            for guid, key in read_keys_file(args["masterkey_keys_file"]).items():
                masterkeys.setdefault(guid, key)
        PROGRESS["stage"] = "while the profile key was opened"
        profile_key = profile_key_from(args, local_state, masterkeys, key_report)
    except Refused as exc:
        fail(str(exc), self_test={"passed": True, "checks": len(test["checks"])})
    if profile_key is not None and args.get("key_file") is None:
        values.add({"kind": "profile_key", "source": key_report.get("source"), "key_hex": profile_key.hex()})     # a key this call opened; one it was handed is not written again

    # The database file is opened alone: read-only and immutable, so nothing beside it is replayed or written, and with an authorizer that lets
    # only a read of the logins table through (a view or a trigger of the evidence runs nothing).
    PROGRESS["stage"] = "while the logins were read"
    looked, beside = sidecars(path)
    rows = NoReplacePage("chromium_logins", [os.path.abspath(path), limit], limit)
    counts = {"rows": 0, "password_present": 0, "decrypted": 0, "not_decrypted": 0, "unreadable": 0, "too_long": 0, "cells_over_limit": 0, "rows_with_cell_over_limit": 0}
    schemes = collections.Counter()
    why_counts = collections.Counter()
    declared = None
    stopped = None
    read_error = None
    present = []
    columns = []
    try:
        conn = sqlite3.connect("file:%s?mode=ro&immutable=1" % urllib.parse.quote(os.path.abspath(path)), uri=True)
    except sqlite3.Error as exc:
        fail("login_data could not be opened as an SQLite database (%s)" % type(exc).__name__, self_test={"passed": True, "checks": len(test["checks"])})
    try:
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
        try:
            conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, CELL_MAX)
        except (AttributeError, sqlite3.Error):
            pass
        conn.set_progress_handler(lambda: 1 if out_of_time() else 0, 2000)

        def authorizer(action, arg1, arg2, _db, _source):
            if action == sqlite3.SQLITE_SELECT:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_READ and isinstance(arg1, str) and arg1.lower() in ("logins", "sqlite_master"):
                return sqlite3.SQLITE_OK                                   # (SQLite's names are not case-sensitive: 'Logins' is the logins table)
            if action == sqlite3.SQLITE_PRAGMA and arg1 == "table_info" and arg2 == "logins":
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_FUNCTION and arg2 in ("count", "typeof", "length"):
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        conn.set_authorizer(authorizer)
        try:
            kind = conn.execute("SELECT type FROM sqlite_master WHERE name = 'logins' COLLATE NOCASE").fetchall()
            if [k[0] for k in kind] != ["table"]:
                read_error = "the database has no table named logins (it is not a Chromium Login Data, or its schema is damaged)"
            else:
                # SQLite matches a column's name without regard to case, so this reader does too: the fields are named as the reader names them
                # (COLUMNS), and the table's own spelling is what the statements select.
                columns = [(r[1].lower(), r[1]) for r in conn.execute("PRAGMA table_info(logins)")
                           if isinstance(r[1], str) and r[1].lower() in COLUMNS and '"' not in r[1]]
                present = [name for name, _real in columns]
                if "password_value" not in present or "origin_url" not in present:
                    read_error = "the logins table has no origin_url or no password_value column: not a layout this reader knows"
        except sqlite3.Error as exc:
            read_error = "the schema could not be read (%s)" % type(exc).__name__
        if read_error is None:
            try:
                declared = conn.execute("SELECT count(*) FROM logins").fetchone()[0]
                records = login_records(conn, columns)
                while True:
                    if out_of_time():
                        stopped = "the tool's own clock (%d s) ran out after %d row(s)" % (DEADLINE_SECONDS, counts["rows"])
                        break
                    if counts["rows"] >= MAX_ROWS:
                        stopped = "the bound of %d rows was reached" % MAX_ROWS
                        break
                    field, over = next(records, (None, None))
                    if field is None:
                        break
                    counts["rows"] += 1
                    PROGRESS["rows"] = counts["rows"]
                    stored = field.get("password_value")
                    stored = stored.encode("utf-8", "surrogatepass") if isinstance(stored, str) else stored if isinstance(stored, bytes) else b""
                    scheme = chromium_scheme(stored)
                    schemes[scheme] += 1
                    origin, origin_left = origin_shown(field.get("origin_url"))
                    user, user_left = text_shown(field.get("username_value"))
                    row = {"row": counts["rows"], "rowid": field["rowid"], "id": field.get("id") if isinstance(field.get("id"), int) else None,
                           "origin": origin, "username": user, "password_present": scheme != "empty", "password_value_bytes": len(stored), "scheme": scheme}
                    if over:
                        # A cell of this row is over the limit of one cell: it was not taken into memory. What SQLite says of it without loading it
                        # is here, and every other cell of the row, and every other row, was read as usual.
                        row["cells_not_read"] = {name: {"type": about["type"], "length": about["length"],
                                                        "why": "over the %d bytes this reader takes of one cell: read as its type and length only" % CELL_MAX}
                                                 for name, about in over.items()}
                        counts["cells_over_limit"] += len(over)
                        counts["rows_with_cell_over_limit"] += 1
                        if "password_value" in over:
                            scheme = "not_read"
                            schemes["empty"] -= 1
                            schemes[scheme] += 1
                            row.update(password_present=True, password_value_bytes=over["password_value"]["length"], scheme=scheme)
                    if origin_left:
                        row["origin_left_out"] = origin_left
                    if user_left:
                        row["username_left_out"] = user_left
                    for column, name in (("date_created", "created"), ("date_last_used", "last_used"), ("date_password_modified", "password_modified")):
                        if column in field:
                            raw = field[column]
                            row[name] = webkit_time(raw)
                            row[name + "_raw"] = raw if isinstance(raw, int) and not isinstance(raw, bool) else None
                    if "times_used" in field:
                        row["times_used"] = field["times_used"] if isinstance(field["times_used"], int) else None
                    if "blacklisted_by_user" in field:
                        row["never_save"] = bool(field["blacklisted_by_user"]) if isinstance(field["blacklisted_by_user"], int) else None
                    clear = None
                    why = None
                    if scheme == "empty":
                        row["decrypted"] = None
                    else:
                        counts["password_present"] += 1
                        if scheme == "not_read":
                            why = ("the stored value is %s bytes, over the %d this reader takes of one cell: only its type and length were read, and it was "
                                   "not decrypted" % (over["password_value"]["length"], CELL_MAX))
                            counts["too_long"] += 1
                        elif len(stored) > VALUE_MAX:
                            why = "the stored value is over %d bytes: not decrypted" % VALUE_MAX
                            counts["too_long"] += 1
                        elif scheme in ("v10", "v11"):
                            if len(stored) < V10_MIN:
                                why = ("the stored value is %d bytes: too short to hold a 12-byte nonce and a 16-byte tag after '%s' (%d bytes at the least), so "
                                       "there is nothing to verify" % (len(stored), scheme, V10_MIN))
                            elif profile_key is None:
                                why = "no profile key (profile_key.why_not)"
                            else:
                                clear = chromium_decrypt(stored, profile_key)
                                if clear is None:
                                    why = "the tag did not verify under the profile key: a wrong key for this value, or a changed value"
                        elif scheme == "dpapi":
                            try:
                                blob = parse_dpapi_blob(stored)
                                reason = blob_supported(blob)
                                key = masterkeys.get(blob["masterkey_guid"])
                                if reason:
                                    why = reason
                                elif key is None:
                                    why = "a DPAPI blob under master key %s, and no verified key of that GUID is at hand" % blob["masterkey_guid"]
                                else:
                                    clear = decrypt_dpapi_blob(blob, key)
                                    if clear is None:
                                        why = "the DPAPI blob's signature did not verify under the master key of its GUID"
                            except Malformed:
                                why = "the stored value begins like a DPAPI blob and is malformed"
                        elif scheme == "v20":
                            why = ("a v20 value (app-bound encryption, Chrome 127 and later): its key is under os_crypt.app_bound_encrypted_key and the SYSTEM account's "
                                   "DPAPI, which this reader does not open")
                        else:
                            why = "the stored value is of no scheme this reader knows (not v10, v11, v20 or a DPAPI blob)"
                        row["decrypted"] = clear is not None
                        if clear is not None:
                            counts["decrypted"] += 1
                            out = {"kind": "login", "row": row["row"], "rowid": field["rowid"], "origin_url": field.get("origin_url"), "action_url": field.get("action_url"),
                                   "signon_realm": field.get("signon_realm"), "username": field.get("username_value"), "scheme": scheme}
                            for k, v in list(out.items()):
                                if isinstance(v, bytes):
                                    out[k] = {"hex": v.hex()}
                                elif isinstance(v, float) and not math.isfinite(v):
                                    out[k] = repr(v)                       # a REAL cell of Infinity or NaN is no JSON number: written as its text

                            if over:
                                out["cells_not_read"] = row["cells_not_read"]
                            try:
                                out["password"], out["password_encoding"] = clear.decode("utf-8"), "utf-8"
                            except UnicodeDecodeError:
                                out["password"], out["password_encoding"] = clear.hex(), "hex"
                            values.add(out)
                        else:
                            counts["not_decrypted"] += 1
                            row["why_not"] = why
                            why_counts[("a stored value over %d bytes: read as its type and length only" % CELL_MAX) if scheme == "not_read" else
                                       ("a v10 or v11 value under %d bytes: too short to hold a nonce and a tag" % V10_MIN) if why.startswith("the stored value is") and "too short" in why else
                                       why if scheme != "dpapi" else why.split(" under master key")[0]] += 1
                    rows.add(row)
            except sqlite3.Error as exc:
                if stopped is None and out_of_time():
                    stopped = "the tool's own clock (%d s) ran out after %d row(s)" % (DEADLINE_SECONDS, counts["rows"])
                elif stopped is None:
                    read_error = "the logins table could not be read past row %d (%s)" % (counts["rows"], type(exc).__name__)
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass
    close_sealed()
    page = rows.finish()

    reasons = []
    if read_error:
        reasons.append(read_error)
    if stopped:
        reasons.append(stopped + ": the rows after it were not read")
    if declared is not None and not stopped and not read_error and declared != counts["rows"]:
        reasons.append("the table counts %d row(s) and %d were read" % (declared, counts["rows"]))
    if counts["cells_over_limit"]:
        reasons.append("%d cell(s) in %d row(s) are over the %d bytes this reader takes of one cell and were read as their type and length only (rows[].cells_not_read); "
                       "every other cell and row was read" % (counts["cells_over_limit"], counts["rows_with_cell_over_limit"], CELL_MAX))
    if beside:
        reasons.append("%d file(s) SQLite keeps beside the database are there and not empty (sidecars_beside): they hold changes the database file does not, and this "
                       "reader opens the database file alone" % len(beside))
    if key_report.get("obtained") is False and (schemes["v10"] or schemes["v11"]):
        reasons.append("the profile key was not obtained: %s" % key_report.get("why_not"))
    if masterkey_reports and not any(r.get("verified") for r in masterkey_reports):
        reasons.append("none of the %d master key file(s) verified with %s for this SID (masterkeys[] says what was tried for each)" % (len(masterkey_reports), secret_kind))
    if counts["not_decrypted"]:
        reasons.append("%d of the %d stored password(s) were not decrypted (rows[].why_not; not_decrypted_by_reason counts them)" % (counts["not_decrypted"], counts["password_present"]))
    if any(not r.get("attempted") or r.get("not_tried_for_time") for r in masterkey_reports):
        reasons.append("not every master key file named was tried (masterkeys[].error or unsupported_why)")
    rows_read_whole = not read_error and not stopped and declared == counts["rows"]
    if read_error and not counts["rows"]:
        status = "failed"
    else:
        status = "partial" if reasons else "complete"
    basis = "; ".join(reasons) if reasons else ("every row of the logins table was read (%d): %d hold a password and each was decrypted with its tag or signature verified; "
                                                "%d hold none" % (counts["rows"], counts["password_present"], counts["rows"] - counts["password_present"]))
    answer = {
        "parser": PARSER,
        "status": status,
        "status_basis": basis,
        "self_test": {"passed": True, "checks": len(test["checks"])},
        "verification_note": VERIFIED_NOTE,
        "login_data": path,
        "every_row_read": rows_read_whole,
        "rows_in_table": declared,
        "rows_read": counts["rows"],
        "passwords_present": counts["password_present"],
        "decrypted": counts["decrypted"],
        "not_decrypted": counts["not_decrypted"],
        "not_decrypted_by_reason": dict(why_counts),
        "cells_over_limit": counts["cells_over_limit"],
        "schemes": {k: n for k, n in schemes.items() if n},
        "profile_key": key_report,
        "sid": sid, "sid_from": sid_from, "secret_kind": secret_kind,
        "masterkeys": masterkey_reports,
        "sidecars_looked_for": looked,
        "sidecars_beside": beside,
        "columns_read": present,
        "rows": rows.page,
        "row_count": page["matched"],
        "secret_values": values.said(),
        "contains_secret_values": values.written > 0,
        "note": "A row is a login the browser saved: the origin, the user name and Chromium's own times (microseconds since 1601 UTC, the raw value beside each). "
                "decrypted: true means the tag or the signature verified; the password itself is only in the sealed values file, with the whole URLs. "
                "decrypted: false is an answer about the key at hand, and counts only because the self-test passed. Cite the row and the file, never a password.",
        **page,
    }
    if status == "failed":
        answer["error"] = read_error
    print_answer(answer, indent=2)
    if status == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            main()
        except SystemExit:
            raise
        except Exception as exc:                                  # whatever hostile input does, the answer is JSON, and it quotes nothing that was read
            hold_stop_signals(quietly=True)
            drop_pages()
            close_sealed()
            print_answer({"error": "the tool failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error: nothing it read is an answer",
                          "reason": type(exc).__name__,
                          **({"secret_values": SEALED[0].said(), "contains_secret_values": SEALED[0].written > 0} if SEALED else {})}, indent=2)
            sys.exit(1)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
