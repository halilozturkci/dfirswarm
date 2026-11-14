#!/usr/bin/env python3
"""Apply a recipe (a key rule, a nonce and a cipher, as stream_kpa_check writes it) to every member of an encrypted family.

For each member: the key is taken as the recipe says (a fixed value, or the member's own first or last bytes, XORed with the recipe's
constant), the payload (the file without the recipe's header and trailer bytes) is XORed with the keystream, and the result is written
under $OUT/decrypted as secret output, with one receipt per member: sizes, the sha256 of the member as it was and of what was written,
the type its first bytes show, and any failure. It authenticates NOTHING: a stream cipher has no integrity check, a wrong key also
"decrypts", and the only check made is whether the result starts with the bytes of the type the member's name promises; a member
whose result does not is reported "decrypted, type not confirmed". Budgets: max_files, max_bytes and max_seconds; what a budget or a
stop leaves undone is listed, a file being written when the tool stops is removed, and the files already written stay with their
receipts. It runs only as a job run as secret output (the manifest makes every job of this tool one): outside one it refuses and
writes nothing.
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


import errno
import fnmatch
import hashlib
import re
import stat
from pathlib import Path

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

RULES = [
    "Measure what the encryptor added before hunting a key: compare an encrypted member with a same-name plaintext twin, or the members "
    "with each other (encrypted_survey reports the size overhead, the smallest member and whether the tails are unique per file).",
    "Read the encryption routine to the key's LAST use: where is the per-file key written? A constant-size trailer or header that is "
    "unique per file is where per-file key material is usually kept, often masked by a constant; test it (stream_kpa_check) before hunting memory.",
    "One known (file, key) pair verifies any footer hypothesis: XOR the key with the file's trailer and test the result on every other "
    "member (stream_kpa_check does this by itself when a key from a dump opens one file).",
    "A scan that finds nothing is a negative only after its planted control passed, and only for the shapes it lists.",
]
PAGES = []                        # what a stop removes: objects with a `_tmp` path (the shared STOP block reads this name)


class Refused(Exception):
    """A parameter or an input the tool refuses: the text is the whole message, and it quotes no byte of a key or of a file."""


def fail(message, **extra):
    print_answer({"error": message, "status": "failed",
                  "status_basis": "the tool stopped with an error (see error): it made no finding, and that is not a negative", **extra}, indent=2)
    raise SystemExit(1)


def describe(exc):
    """An error without the path it names: type, errno name and the system's own words."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    words = getattr(exc, "strerror", None) or "no system message"
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", words)


def where_it_failed(exc):
    tb = exc.__traceback__
    line = None
    while tb is not None:
        if tb.tb_frame.f_code.co_filename == __file__:
            line = tb.tb_lineno
        tb = tb.tb_next
    return "line %s of the tool" % line if line else "an unknown line"


def as_given(path, most=1024):
    """A path as the answer prints it: as it was given, whatever its characters (the answer is JSON, which escapes what is not ASCII
    and every control character), cut at `most` characters with the count."""
    return path if len(path) <= most else path[:most] + "...(%d characters)" % len(path)


def printable(text, most=200):
    """A caller's string as the answer repeats it: bounded, and with nothing a terminal or a JSON reader would trip on."""
    text = text if isinstance(text, str) else repr(text)
    text = "".join(ch if " " <= ch < "\x7f" else "?" for ch in text)
    return text if len(text) <= most else text[:most] + "...(%d characters)" % len(text)


def read_args(known):
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=type(exc).__name__)
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args, sorted(printable(k, 60) for k in args if k not in known)


def int_param(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise Refused("%s must be a whole number from %d to %d" % (key, low, high))
    return value


def bool_param(args, key, default=False):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise Refused("%s must be true or false" % key)
    return value


def path_param(value, what):
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
        raise Refused("%s must be a path: a string of 1 to 4096 characters without a NUL" % what)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise Refused("%s is not a path this tool can open: it does not encode as UTF-8" % what)
    return value


def open_regular(path, follow=True):
    """Open a regular file for reading without waiting on a FIFO or a device; (fd, size). follow False refuses a link at the name."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | (0 if follow else getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return fd, st.st_size


def pread_full(fd, length, offset):
    parts = []
    while length > 0:
        block = os.pread(fd, min(length, 1 << 24), offset)
        if not block:
            break
        parts.append(block)
        offset += len(block)
        length -= len(block)
    return b"".join(parts)


def job_place():
    """Where this run writes and how the answer names it: (directory, the name the answer cites for it, in a job, in a secret-output job)."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and out:
        return Path(out), "store/jobs/%s/out" % re.sub(r"[^A-Za-z0-9_.-]", "_", job), True, os.environ.get("SECRET_OUTPUT") == "1"
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    return Path("work") / agent / "tool-output", "work/%s/tool-output" % agent, False, False


def create_new(directory, name, mode=0o600):
    """Create `name` (or name-2, name-3, ...) in the directory, never through a link and never over a file that is there: (fd, name)."""
    directory.mkdir(parents=True, exist_ok=True)
    stem, dot, suffix = name.rpartition(".")
    for n in range(1, 1000):
        candidate = name if n == 1 else "%s-%d%s%s" % (stem or suffix, n, dot, suffix if stem else "")
        try:
            return os.open(str(directory / candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode), candidate
        except FileExistsError:
            continue
    raise OSError(errno.EEXIST, "no free name for a result file")


def answered(main, cleanup=None):
    """main(), with every way it can fail turned into one JSON answer (fail() ends with SystemExit, which the caller turns into the exit code)."""
    try:
        main()
    except SystemExit:
        raise
    except Refused as exc:
        hold_stop_signals(quietly=True)
        if cleanup:
            cleanup()
        fail(str(exc))
    except Exception as exc:  # noqa: BLE001 - never an empty or clean answer for a failure
        hold_stop_signals(quietly=True)
        if cleanup:
            cleanup()
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else "%s at %s" % (type(exc).__name__, where_it_failed(exc))))

# CIPHERS: begin
# The same text is in stream_kpa_check and family_decrypt (tests/pack-ransomware-cipher-vectors.test.ts holds the two copies equal and
# checks them against RFC 8439, the ECRYPT Salsa20 set, RFC 6229 and FIPS-197). Pure Python, standard library only. ChaCha20 and Salsa20
# run many blocks at once: each of the 16 state words is one big integer that holds a 32-bit value per 64-bit lane, one lane per block,
# so an addition, an XOR or a rotation of a word of every block is one integer operation. AES runs its blocks side by side too: SubBytes
# and the two multiplications of MixColumns are bytes.translate over the whole buffer, the rest is integer shifts and XORs. RC4 is a
# byte loop. None of it is constant time and none of it authenticates anything.
CIPHER_NAMES = ("chacha20-ietf", "chacha20-original", "salsa20", "aes-ctr", "rc4", "xor")
_LANES = {}


def _lanes(n):
    made = _LANES.get(n)
    if made is None:
        ones = int.from_bytes(b"\x01\x00\x00\x00\x00\x00\x00\x00" * n, "little")
        made = _LANES[n] = (ones, ones * 0xFFFFFFFF)
        if len(_LANES) > 8:
            _LANES.pop(next(iter(_LANES)))
    return made


def _words(key, constant16, constant32):
    if len(key) == 32:
        text, k = constant32, key
    elif len(key) == 16:
        text, k = constant16, key + key
    else:
        raise ValueError("the key is 16 or 32 bytes")
    return ([int.from_bytes(text[i:i + 4], "little") for i in range(0, 16, 4)],
            [int.from_bytes(k[i:i + 4], "little") for i in range(0, 32, 4)])


def _counters(counter, n, ones):
    """The low and the high 32-bit words of counter, counter + 1, ... as lanes."""
    low = int.from_bytes(b"".join(((counter + i) & 0xFFFFFFFF).to_bytes(8, "little") for i in range(n)), "little")
    if (counter + n - 1) >> 32 == counter >> 32:
        return low, ((counter >> 32) & 0xFFFFFFFF) * ones
    return low, int.from_bytes(b"".join((((counter + i) >> 32) & 0xFFFFFFFF).to_bytes(8, "little") for i in range(n)), "little")


def _serialise(words, start, n, mask):
    out = bytearray(64 * n)
    for w in range(16):
        raw = ((words[w] + start[w]) & mask).to_bytes(8 * n, "little")
        for k in range(4):
            out[4 * w + k::64] = raw[k::8]
    return bytes(out)


def chacha20_blocks(key, nonce, counter, n, layout="ietf"):
    """n keystream blocks (64 bytes each) from block `counter`. layout "ietf": a 12-byte nonce and a 32-bit counter (RFC 8439);
    "original": an 8-byte nonce and a 64-bit counter (Bernstein's)."""
    ones, mask = _lanes(n)
    const, k = _words(key, b"expand 16-byte k", b"expand 32-byte k")
    if layout == "ietf":
        if len(nonce) != 12:
            raise ValueError("the IETF layout takes a 12-byte nonce")
        if counter < 0 or counter + n > 1 << 32:
            raise ValueError("the IETF layout's 32-bit block counter would wrap")
        low, _high = _counters(counter, n, ones)
        tail = [low] + [int.from_bytes(nonce[i:i + 4], "little") * ones for i in (0, 4, 8)]
    elif layout == "original":
        if len(nonce) != 8:
            raise ValueError("the original layout takes an 8-byte nonce")
        if counter < 0 or counter + n > 1 << 64:
            raise ValueError("the 64-bit block counter would wrap")
        low, high = _counters(counter, n, ones)
        tail = [low, high] + [int.from_bytes(nonce[i:i + 4], "little") * ones for i in (0, 4)]
    else:
        raise ValueError("layout is ietf or original")
    start = [c * ones for c in const] + [w * ones for w in k] + tail
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 = start
    for _round in range(10):
        x0 = (x0 + x4) & mask; x12 ^= x0; x12 = ((x12 << 16) | (x12 >> 16)) & mask
        x8 = (x8 + x12) & mask; x4 ^= x8; x4 = ((x4 << 12) | (x4 >> 20)) & mask
        x0 = (x0 + x4) & mask; x12 ^= x0; x12 = ((x12 << 8) | (x12 >> 24)) & mask
        x8 = (x8 + x12) & mask; x4 ^= x8; x4 = ((x4 << 7) | (x4 >> 25)) & mask
        x1 = (x1 + x5) & mask; x13 ^= x1; x13 = ((x13 << 16) | (x13 >> 16)) & mask
        x9 = (x9 + x13) & mask; x5 ^= x9; x5 = ((x5 << 12) | (x5 >> 20)) & mask
        x1 = (x1 + x5) & mask; x13 ^= x1; x13 = ((x13 << 8) | (x13 >> 24)) & mask
        x9 = (x9 + x13) & mask; x5 ^= x9; x5 = ((x5 << 7) | (x5 >> 25)) & mask
        x2 = (x2 + x6) & mask; x14 ^= x2; x14 = ((x14 << 16) | (x14 >> 16)) & mask
        x10 = (x10 + x14) & mask; x6 ^= x10; x6 = ((x6 << 12) | (x6 >> 20)) & mask
        x2 = (x2 + x6) & mask; x14 ^= x2; x14 = ((x14 << 8) | (x14 >> 24)) & mask
        x10 = (x10 + x14) & mask; x6 ^= x10; x6 = ((x6 << 7) | (x6 >> 25)) & mask
        x3 = (x3 + x7) & mask; x15 ^= x3; x15 = ((x15 << 16) | (x15 >> 16)) & mask
        x11 = (x11 + x15) & mask; x7 ^= x11; x7 = ((x7 << 12) | (x7 >> 20)) & mask
        x3 = (x3 + x7) & mask; x15 ^= x3; x15 = ((x15 << 8) | (x15 >> 24)) & mask
        x11 = (x11 + x15) & mask; x7 ^= x11; x7 = ((x7 << 7) | (x7 >> 25)) & mask
        x0 = (x0 + x5) & mask; x15 ^= x0; x15 = ((x15 << 16) | (x15 >> 16)) & mask
        x10 = (x10 + x15) & mask; x5 ^= x10; x5 = ((x5 << 12) | (x5 >> 20)) & mask
        x0 = (x0 + x5) & mask; x15 ^= x0; x15 = ((x15 << 8) | (x15 >> 24)) & mask
        x10 = (x10 + x15) & mask; x5 ^= x10; x5 = ((x5 << 7) | (x5 >> 25)) & mask
        x1 = (x1 + x6) & mask; x12 ^= x1; x12 = ((x12 << 16) | (x12 >> 16)) & mask
        x11 = (x11 + x12) & mask; x6 ^= x11; x6 = ((x6 << 12) | (x6 >> 20)) & mask
        x1 = (x1 + x6) & mask; x12 ^= x1; x12 = ((x12 << 8) | (x12 >> 24)) & mask
        x11 = (x11 + x12) & mask; x6 ^= x11; x6 = ((x6 << 7) | (x6 >> 25)) & mask
        x2 = (x2 + x7) & mask; x13 ^= x2; x13 = ((x13 << 16) | (x13 >> 16)) & mask
        x8 = (x8 + x13) & mask; x7 ^= x8; x7 = ((x7 << 12) | (x7 >> 20)) & mask
        x2 = (x2 + x7) & mask; x13 ^= x2; x13 = ((x13 << 8) | (x13 >> 24)) & mask
        x8 = (x8 + x13) & mask; x7 ^= x8; x7 = ((x7 << 7) | (x7 >> 25)) & mask
        x3 = (x3 + x4) & mask; x14 ^= x3; x14 = ((x14 << 16) | (x14 >> 16)) & mask
        x9 = (x9 + x14) & mask; x4 ^= x9; x4 = ((x4 << 12) | (x4 >> 20)) & mask
        x3 = (x3 + x4) & mask; x14 ^= x3; x14 = ((x14 << 8) | (x14 >> 24)) & mask
        x9 = (x9 + x14) & mask; x4 ^= x9; x4 = ((x4 << 7) | (x4 >> 25)) & mask
    return _serialise((x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15), start, n, mask)


def salsa20_blocks(key, nonce, counter, n):
    """n keystream blocks of Salsa20/20 (an 8-byte nonce, a 64-bit block counter) from block `counter`."""
    ones, mask = _lanes(n)
    const, k = _words(key, b"expand 16-byte k", b"expand 32-byte k")
    if len(nonce) != 8:
        raise ValueError("Salsa20 takes an 8-byte nonce")
    if counter < 0 or counter + n > 1 << 64:
        raise ValueError("the 64-bit block counter would wrap")
    low, high = _counters(counter, n, ones)
    n0, n1 = (int.from_bytes(nonce[i:i + 4], "little") * ones for i in (0, 4))
    start = [const[0] * ones, k[0] * ones, k[1] * ones, k[2] * ones, k[3] * ones, const[1] * ones, n0, n1,
             low, high, const[2] * ones, k[4] * ones, k[5] * ones, k[6] * ones, k[7] * ones, const[3] * ones]
    x = list(start)

    def quarter(a, b, c, d):
        s = (x[a] + x[d]) & mask; x[b] ^= ((s << 7) | (s >> 25)) & mask
        s = (x[b] + x[a]) & mask; x[c] ^= ((s << 9) | (s >> 23)) & mask
        s = (x[c] + x[b]) & mask; x[d] ^= ((s << 13) | (s >> 19)) & mask
        s = (x[d] + x[c]) & mask; x[a] ^= ((s << 18) | (s >> 14)) & mask

    for _round in range(10):
        quarter(0, 4, 8, 12); quarter(5, 9, 13, 1); quarter(10, 14, 2, 6); quarter(15, 3, 7, 11)
        quarter(0, 1, 2, 3); quarter(5, 6, 7, 4); quarter(10, 11, 8, 9); quarter(15, 12, 13, 14)
    return _serialise(x, start, n, mask)


def _aes_tables():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        v = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (v ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    double = [((v << 1) ^ (0x1B if v & 0x80 else 0)) & 0xFF for v in sbox]
    return bytes(sbox), bytes(double), bytes(d ^ v for d, v in zip(double, sbox))


AES_SBOX, _AES_SBOX2, _AES_SBOX3 = _aes_tables()


def aes_expand_key(key):
    """The FIPS-197 key schedule: the round keys of a 16, 24 or 32-byte key, as one byte string (176, 208 or 240 bytes)."""
    nk = len(key) // 4
    if len(key) not in (16, 24, 32):
        raise ValueError("an AES key is 16, 24 or 32 bytes")
    words = [key[i:i + 4] for i in range(0, len(key), 4)]
    rcon = 1
    for i in range(nk, 4 * (nk + 7)):
        t = words[i - 1]
        if i % nk == 0:
            t = bytes((AES_SBOX[t[1]] ^ rcon, AES_SBOX[t[2]], AES_SBOX[t[3]], AES_SBOX[t[0]]))
            rcon = ((rcon << 1) ^ (0x11B if rcon & 0x80 else 0)) & 0xFF
        elif nk > 6 and i % nk == 4:
            t = bytes(AES_SBOX[b] for b in t)
        words.append(bytes(a ^ b for a, b in zip(words[i - nk], t)))
    return b"".join(words)


_AES_MASKS = {}


def aes_encrypt_blocks(schedule, blocks):
    """AES encryption (ECB) of a whole number of 16-byte blocks under an expanded key."""
    size = len(blocks)
    n = size // 16
    if size % 16:
        raise ValueError("a whole number of 16-byte blocks")
    rounds = len(schedule) // 16 - 1
    masks = _AES_MASKS.get(n)
    if masks is None:
        lane = int.from_bytes(b"\x01\x00\x00\x00" * (4 * n), "little")
        masks = _AES_MASKS[n] = (lane * 0x00FFFFFF, lane * 0xFF000000, lane * 0x0000FFFF, lane * 0xFFFF0000, lane * 0x000000FF, lane * 0xFFFFFF00)
        if len(_AES_MASKS) > 8:
            _AES_MASKS.pop(next(iter(_AES_MASKS)))
    low3, high1, low2, high2, low1, high3 = masks
    keys = [int.from_bytes(schedule[16 * r:16 * r + 16] * n, "little") for r in range(rounds + 1)]
    state = (int.from_bytes(blocks, "little") ^ keys[0]).to_bytes(size, "little")
    for r in range(1, rounds + 1):
        moved = bytearray(state)
        for row in (1, 2, 3):
            for col in range(4):
                moved[row + 4 * col::16] = state[row + 4 * ((col + row) % 4)::16]
        moved = bytes(moved)
        a1 = int.from_bytes(moved.translate(AES_SBOX), "little")
        if r == rounds:
            mixed = a1
        else:
            a2 = int.from_bytes(moved.translate(_AES_SBOX2), "little")
            a3 = int.from_bytes(moved.translate(_AES_SBOX3), "little")
            mixed = (a2 ^ ((a3 >> 8) & low3) ^ ((a3 << 24) & high1) ^ ((a1 >> 16) & low2) ^ ((a1 << 16) & high2)
                     ^ ((a1 >> 24) & low1) ^ ((a1 << 8) & high3))
        state = (mixed ^ keys[r]).to_bytes(size, "little")
    return state


def aes_ctr_blocks(schedule, first_block, n):
    """n keystream blocks (16 bytes each) of AES in counter mode: the counter block is a 128-bit big-endian number that starts at
    `first_block` and goes up by one per block (modulo 2**128)."""
    wrap = (1 << 128) - 1
    return aes_encrypt_blocks(schedule, b"".join(((first_block + i) & wrap).to_bytes(16, "big") for i in range(n)))


def rc4_schedule(key):
    if not 1 <= len(key) <= 256:
        raise ValueError("an RC4 key is 1 to 256 bytes")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return [s, 0, 0]


def rc4_stream(state, n):
    """The next n keystream bytes of an RC4 state ([permutation, i, j], changed in place)."""
    s, i, j = state
    out = bytearray(n)
    for at in range(n):
        i = (i + 1) & 0xFF
        a = s[i]
        j = (j + a) & 0xFF
        b = s[j]
        s[i] = b
        s[j] = a
        out[at] = s[(a + b) & 0xFF]
    state[1], state[2] = i, j
    return bytes(out)


def xor_bytes(a, b):
    """a XOR b over the shorter of the two."""
    n = min(len(a), len(b))
    return (int.from_bytes(a[:n], "little") ^ int.from_bytes(b[:n], "little")).to_bytes(n, "little")


class Keystream:
    """One cipher's keystream for one file, in order from its first byte. cipher is one of CIPHER_NAMES; counter is the first block's
    number (ChaCha20, Salsa20) or is added to the counter block the nonce makes (AES-CTR: a 16-byte nonce is the whole first counter
    block, a 12-byte one is followed by a 32-bit big-endian counter, an 8-byte one by a 64-bit one). RC4 and XOR take no nonce."""

    def __init__(self, cipher, key, nonce=b"", counter=0):
        self.cipher, self.key, self.nonce, self.block, self.kept = cipher, key, nonce, counter, b""
        if cipher in ("chacha20-ietf", "chacha20-original"):
            chacha20_blocks(key, nonce, counter, 1, cipher[9:])          # refuses a wrong length now
            self.width = 64
        elif cipher == "salsa20":
            salsa20_blocks(key, nonce, counter, 1)
            self.width = 64
        elif cipher == "aes-ctr":
            self.schedule = aes_expand_key(key)
            if len(nonce) == 16:
                self.block = int.from_bytes(nonce, "big") + counter
            elif len(nonce) == 12:
                self.block = (int.from_bytes(nonce, "big") << 32) + counter
            elif len(nonce) == 8:
                self.block = (int.from_bytes(nonce, "big") << 64) + counter
            else:
                raise ValueError("AES-CTR takes a nonce of 8, 12 or 16 bytes")
            self.width = 16
        elif cipher == "rc4":
            self.state = rc4_schedule(key)
            self.width = 1
        elif cipher == "xor":
            if not key:
                raise ValueError("an XOR key is at least one byte")
            self.width = len(key)
            self.at = 0
        else:
            raise ValueError("cipher is one of %s" % ", ".join(CIPHER_NAMES))

    def take(self, n):
        if self.cipher == "rc4":
            return rc4_stream(self.state, n)
        if self.cipher == "xor":
            k, at = self.key, self.at
            self.at = (at + n) % len(k)
            return (k[at:] + k * (n // len(k) + 1))[:n]
        blocks = -(-(n - len(self.kept)) // self.width)
        if blocks > 0:
            if self.cipher == "salsa20":
                more = salsa20_blocks(self.key, self.nonce, self.block, blocks)
            elif self.cipher == "aes-ctr":
                more = aes_ctr_blocks(self.schedule, self.block, blocks)
            else:
                more = chacha20_blocks(self.key, self.nonce, self.block, blocks, self.cipher[9:])
            self.block += blocks
            self.kept += more
        out, self.kept = self.kept[:n], self.kept[n:]
        return out
# CIPHERS: end

# FAMILY: begin
# The same text is in stream_kpa_check and family_decrypt (tests/pack-ransomware-cipher-vectors.test.ts holds the two copies equal):
# the file types known by their first bytes, how a member's expected type is read from its name, and how the members are listed.
def _riff(kind):
    return [((0, b"RIFF"), (8, kind))]


_ZIP = [((0, b"PK\x03\x04"),)]
_OLE = [((0, bytes.fromhex("d0cf11e0a1b11ae1")),)]
_FTYP = [((4, b"ftyp"),)]
_JPG = [((0, b"\xff\xd8\xff"),)]
_TIF = [((0, b"II*\x00"),), ((0, b"MM\x00*"),)]
# type -> alternatives; an alternative is one or more (offset, bytes) that must all hold. All of it lies in the first 64 bytes.
MAGICS = {
    "png": [((0, b"\x89PNG\r\n\x1a\n"),)], "jpg": _JPG, "jpeg": _JPG, "gif": [((0, b"GIF87a"),), ((0, b"GIF89a"),)],
    "bmp": [((0, b"BM"), (6, bytes(4)))], "tif": _TIF, "tiff": _TIF, "psd": [((0, b"8BPS"),)], "webp": _riff(b"WEBP"),
    "pdf": [((0, b"%PDF-"),)], "rtf": [((0, b"{\\rtf"),)],
    "zip": _ZIP, "docx": _ZIP, "xlsx": _ZIP, "pptx": _ZIP, "odt": _ZIP, "ods": _ZIP, "odp": _ZIP, "jar": _ZIP, "apk": _ZIP, "epub": _ZIP,
    "doc": _OLE, "xls": _OLE, "ppt": _OLE, "msg": _OLE, "msi": _OLE,
    "mp4": _FTYP, "m4a": _FTYP, "m4v": _FTYP, "3gp": _FTYP, "heic": _FTYP, "mov": [((4, b"ftyp"),), ((4, b"moov"),), ((4, b"mdat"),), ((4, b"wide"),), ((4, b"free"),)],
    "avi": _riff(b"AVI "), "wav": _riff(b"WAVE"), "mkv": [((0, bytes.fromhex("1a45dfa3")),)], "webm": [((0, bytes.fromhex("1a45dfa3")),)],
    "flac": [((0, b"fLaC"),)], "ogg": [((0, b"OggS"),)], "wmv": [((0, bytes.fromhex("3026b2758e66cf11")),)], "wma": [((0, bytes.fromhex("3026b2758e66cf11")),)],
    "sqlite": [((0, b"SQLite format 3\x00"),)], "sqlite3": [((0, b"SQLite format 3\x00"),)], "db": [((0, b"SQLite format 3\x00"),)],
    "7z": [((0, b"7z\xbc\xaf\x27\x1c"),)], "rar": [((0, b"Rar!\x1a\x07"),)], "gz": [((0, b"\x1f\x8b\x08"),)], "xz": [((0, b"\xfd7zXZ\x00"),)],
    "bz2": [((0, b"BZh"),)], "exe": [((0, b"MZ"),)], "dll": [((0, b"MZ"),)], "elf": [((0, b"\x7fELF"),)], "class": [((0, bytes.fromhex("cafebabe")),)],
    "lnk": [((0, bytes.fromhex("4c00000001140200")),)], "evtx": [((0, b"ElfFile\x00"),)], "pst": [((0, b"!BDN"),)], "ost": [((0, b"!BDN"),)],
    "pcap": [((0, bytes.fromhex("d4c3b2a1")),), ((0, bytes.fromhex("a1b2c3d4")),)], "vhdx": [((0, b"vhdxfile"),)], "vmdk": [((0, b"KDMV"),)],
}
# The types a decrypted head is named by when its name says nothing, in this order (a container's magic names the container only).
# (The 7-Zip type is written in two pieces here: its name between quotes before a comma reads as a call of that program to
# tests/pack-program-declarations.test.ts, and this tool starts no program.)
DETECT_ORDER = ("png", "jpg", "gif", "pdf", "sqlite", "zip", "doc", "mp4", "mov", "avi", "wav", "webp", "bmp", "tif", "psd", "rtf", "mkv", "flac", "ogg",
                "wmv", "7" "z", "rar", "gz", "xz", "bz2", "elf", "class", "lnk", "evtx", "pst", "pcap", "vhdx", "vmdk", "exe")
DETECT_NAMES = {"zip": "zip container (zip, docx, xlsx, pptx, odt, jar, apk)", "doc": "OLE compound file (doc, xls, ppt, msg, msi)",
                "mp4": "ISO media, ftyp (mp4, m4a, m4v, 3gp, heic, mov)", "mov": "QuickTime atom (mov)", "mkv": "Matroska or WebM", "wmv": "ASF (wmv, wma)",
                "exe": "MZ executable (exe, dll)", "sqlite": "SQLite database", "jpg": "jpeg"}


def crib_holds(head, alternative):
    return all(head[at:at + len(piece)] == piece for at, piece in alternative)


def crib_bytes(alternative):
    return sum(len(piece) for _at, piece in alternative)


def expected_type(name, magics):
    """The type a member's name promises: the last piece of the name, read from the right, that is a known type ("a.png.locked" is a
    png, and so is "a.png"). None when no piece is known."""
    pieces = name.lower().split(".")
    for piece in reversed(pieces[1:]):
        if piece in magics:
            return piece
    return None


def detect_type(head, magics):
    for kind in DETECT_ORDER:
        if any(crib_holds(head, alt) for alt in magics[kind]):
            return DETECT_NAMES.get(kind, kind)
    return None


def carries_suffix(name, suffix):
    """Whether a file name ends in a family's suffix, in any case (".LOCKED" and ".locked" are one suffix) and with something before it."""
    return len(name) > len(suffix) and name.lower().endswith(suffix.lower())


def member_keys(args, paths):
    """How a recipe names each member: its path below `dir`, or, for `files`, below the directory all of them share, with slashes. Two
    members of one name in two directories are two names (a base name alone would be one)."""
    if not paths:
        return []
    if args.get("dir") is not None:
        root = os.path.abspath(args["dir"])
    else:
        root = os.path.commonpath([os.path.dirname(os.path.abspath(path)) for path in paths])
    return [os.path.relpath(os.path.abspath(path), root).replace(os.sep, "/") for path in paths]


def list_members(args, max_files, suffix=None):
    """The files a call names: `files` (paths, the first max_files in the order given), or `dir` with `glob` (a pattern on the file's
    name) and `recursive` (regular files only, no link followed, in the order of their names). With `suffix` and no glob, the files of dir
    whose name carries that suffix (in any case). Returns (paths, how many more there were past max_files, what was skipped). Once
    max_files names are kept, the directories still to list are not listed (counted in directories_not_listed_past_max_files): `more`
    is then a lower bound."""
    files, directory = args.get("files"), args.get("dir")
    if (files is None) == (directory is None):
        raise Refused("give either files (a list of paths) or dir (a directory, with glob and recursive), not both and not neither")
    skipped = {"links": 0, "not_regular": 0, "unreadable_directories": 0, "names_not_utf8": 0}
    if files is not None:
        if not isinstance(files, list) or not files or len(files) > 100000:
            raise Refused("files is a list of 1 to 100000 paths")
        paths = [path_param(f, "an entry of files") for f in files]
        return paths[:max_files], max(0, len(paths) - max_files), skipped
    directory = path_param(directory, "dir")
    pattern = args.get("glob")
    by_suffix = suffix if pattern is None and suffix else None
    pattern = "*" if pattern is None else pattern
    if not isinstance(pattern, str) or not pattern or len(pattern) > 200 or "\x00" in pattern or "/" in pattern:
        raise Refused("glob is a pattern on a file's name (*.locked), 1 to 200 characters, without a slash")
    recursive = bool_param(args, "recursive")
    if not os.path.isdir(directory):
        raise Refused("dir is not a directory")
    # One directory's entries are read one at a time, the clock read every 1024 of them, and what is kept of them is bounded: the files
    # that match, at most twice the room left under max_files (cut to the room, in the order of their names, whenever that is passed;
    # the others are counted in `more`), and the directories still to list, at most 100000 (the others are counted). Once max_files
    # names are kept, listing stops: the directories left are counted, not listed, and `more` is a lower bound.
    found, more = [], 0
    stack = [directory]
    pending_most = 100000                                   # the directories still to list that are kept, at most
    while stack:
        if out_of_time():
            skipped["directories_not_listed_time_limit"] = skipped.get("directories_not_listed_time_limit", 0) + len(stack)
            break
        if len(found) >= max_files:
            skipped["directories_not_listed_past_max_files"] = skipped.get("directories_not_listed_past_max_files", 0) + len(stack)
            break
        here = stack.pop()
        room = max_files - len(found)
        names, below, seen, cut = [], [], 0, False
        try:
            with os.scandir(here) as entries:
                for entry in entries:
                    seen += 1
                    if not seen & 1023 and out_of_time():
                        cut = True
                        break
                    try:
                        entry.name.encode("utf-8")
                    except UnicodeError:
                        skipped["names_not_utf8"] += 1
                        continue
                    try:
                        if entry.is_symlink():
                            skipped["links"] += 1
                        elif entry.is_dir(follow_symlinks=False):
                            if recursive:
                                below.append(entry.name)
                                if len(below) + len(stack) > 2 * pending_most:
                                    below.sort()
                                    keep = max(0, pending_most - len(stack))
                                    skipped["directories_not_listed_bound"] = skipped.get("directories_not_listed_bound", 0) + len(below) - keep
                                    del below[keep:]
                        elif not entry.is_file(follow_symlinks=False):
                            skipped["not_regular"] += 1
                        elif carries_suffix(entry.name, by_suffix) if by_suffix else fnmatch.fnmatchcase(entry.name, pattern):
                            names.append(entry.name)
                            if len(names) > 2 * room + 1024:
                                names.sort()
                                more += len(names) - room
                                del names[room:]
                    except OSError:
                        skipped["not_regular"] += 1
        except OSError:
            skipped["unreadable_directories"] += 1
            continue
        if cut:
            skipped["directories_not_listed_time_limit"] = skipped.get("directories_not_listed_time_limit", 0) + 1 + len(stack)
            break
        names.sort()
        more += max(0, len(names) - room)
        found.extend(os.path.join(here, name) for name in names[:room])
        below.sort()
        if len(below) + len(stack) > pending_most:
            keep = max(0, pending_most - len(stack))
            skipped["directories_not_listed_bound"] = skipped.get("directories_not_listed_bound", 0) + len(below) - keep
            del below[keep:]
        stack.extend(os.path.join(here, name) for name in reversed(below))
    return found, more, skipped
# FAMILY: end

TOOL = "family_decrypt"
VERSION = 6
PARSER = "family_decrypt/2"
DEFAULT_SECONDS, MAX_SECONDS = 1500, 1740
PIECE = 1 << 20
MAX_SLICE = 4096
KNOWN_PARAMS = {"recipe_file", "recipe", "files", "dir", "glob", "recursive", "max_files", "max_bytes", "max_seconds", "limit"}
RECEIPTS = "decrypt-receipts.jsonl"


class Writing:
    """The file being written: a stop removes it (the shared STOP block reads `_tmp` of everything in PAGES)."""

    def __init__(self):
        self._tmp = None


WRITING = Writing()
PAGES.append(WRITING)
PROGRESS = {"members": 0, "decrypted": 0, "receipts": None}


def last_word(signum):
    done = PROGRESS["decrypted"]
    print(json.dumps({"error": "stopped by signal %d before every member was decrypted" % signum, "status": "partial" if done else "failed",
                      "interrupted": True, "signal": signum, "members": PROGRESS["members"], "decrypted_before_the_stop": done,
                      "receipts": PROGRESS["receipts"],
                      "status_basis": "the tool was stopped by signal %d: %d of %d members had been decrypted and each has its receipt; the file being "
                                      "written at the stop was removed, and the other members were not touched. Nothing here is authenticated"
                                      % (signum, done, PROGRESS["members"])}), flush=True)


def hex_field(value, what, lengths=None):
    if not isinstance(value, str) or len(value) > 2 * MAX_SLICE or re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value) is None:
        raise Refused("the recipe's %s is not hexadecimal of 1 to %d bytes" % (what, MAX_SLICE))
    value = bytes.fromhex(value)
    if lengths and len(value) not in lengths:
        raise Refused("the recipe's %s is %d bytes" % (what, len(value)))
    return value


def source_of(spec, what, optional=False):
    """A recipe's key or nonce: ("fixed", bytes) or ("slice", region, length, skip, mask or None); None for an absent nonce."""
    if spec is None and optional:
        return None
    if not isinstance(spec, dict):
        raise Refused("the recipe's %s must be an object: {\"hex\": ...} or {\"slice\": \"head\" or \"tail\", \"length\": ..., \"skip\": ..., \"xor_hex\": ...}" % what)
    if "hex" in spec:
        return ("fixed", hex_field(spec["hex"], "%s.hex" % what))
    region = spec.get("slice")
    if region not in ("head", "tail"):
        raise Refused("the recipe's %s.slice is \"head\" or \"tail\"" % what)
    length, skip = spec.get("length"), spec.get("skip", 0)
    for name, value, low, high in (("length", length, 1, MAX_SLICE), ("skip", skip, 0, 1 << 20)):
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise Refused("the recipe's %s.%s must be a whole number from %d to %d" % (what, name, low, high))
    mask = spec.get("xor_hex")
    if mask is not None:
        mask = hex_field(mask, "%s.xor_hex" % what, (length,))
    return ("slice", region, length, skip, mask)


def value_of(source, fd, size):
    if source is None:
        return b""
    if source[0] == "fixed":
        return source[1]
    _kind, region, length, skip, mask = source
    at = skip if region == "head" else size - skip - length
    if at < 0 or at + length > size:
        return None
    raw = pread_full(fd, length, at)
    if len(raw) != length:
        return None
    return xor_bytes(raw, mask) if mask is not None else raw


def read_recipe(args):
    given, path = args.get("recipe"), args.get("recipe_file")
    if (given is None) == (path is None):
        raise Refused("give either recipe_file (the file stream_kpa_check wrote) or recipe (the same object), not both and not neither")
    if path is not None:
        path = path_param(path, "recipe_file")
        try:
            fd, size = open_regular(path)
            try:
                if size > 16 << 20:
                    raise Refused("recipe_file is larger than 16 MiB: not a recipe")
                text = pread_full(fd, size, 0)
            finally:
                os.close(fd)
            given = json.loads(text)
        except OSError as exc:
            raise Refused("recipe_file could not be read (%s)" % describe(exc))
        except (ValueError, RecursionError):
            raise Refused("recipe_file is not JSON")
    if not isinstance(given, dict) or given.get("recipe") != "stream-family/1":
        raise Refused("the recipe is not a stream-family/1 object (what stream_kpa_check writes as recipe_file)")
    key = source_of(given.get("key"), "key")
    variants = given.get("variants")
    if not isinstance(variants, list) or not 1 <= len(variants) <= 16:
        raise Refused("the recipe's variants is a list of 1 to 16 {cipher, counter, nonce}")
    made = []
    for n, variant in enumerate(variants):
        if not isinstance(variant, dict) or variant.get("cipher") not in CIPHER_NAMES:
            raise Refused("the recipe's variants[%d].cipher is one of %s" % (n, ", ".join(CIPHER_NAMES)))
        counter = variant.get("counter", 0)
        if isinstance(counter, bool) or not isinstance(counter, int) or not 0 <= counter < 1 << 62:
            raise Refused("the recipe's variants[%d].counter is a block number, 0 or more" % n)
        nonce = source_of(variant.get("nonce"), "variants[%d].nonce" % n, optional=True)
        if (nonce is None) != (variant["cipher"] in ("rc4", "xor")):
            raise Refused("the recipe's variants[%d]: %s" % (n, "rc4 and xor take no nonce" if nonce is not None else "this cipher needs a nonce"))
        made.append((variant["cipher"], counter, nonce))
    assignments = given.get("assignments", {})
    if not isinstance(assignments, dict) or not all(isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and 0 <= v < len(made)
                                                    for k, v in assignments.items()):
        raise Refused("the recipe's assignments maps a member's name to the number of one of its variants")
    sizes = []
    for name in ("header_bytes", "trailer_bytes"):
        value = given.get(name, 0)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1 << 30:
            raise Refused("the recipe's %s is a number of bytes, 0 or more" % name)
        sizes.append(value)
    suffix = given.get("member_suffix")
    if suffix is not None and (not isinstance(suffix, str) or not re.fullmatch(r"\.[^/\x00]{1,64}", suffix)):
        raise Refused("the recipe's member_suffix is a file name ending that starts with a dot, or null")
    return key, made, assignments, sizes[0], sizes[1], suffix


def restored_name(name, magics):
    """A member's name without its last extension when a known type stands before it ("a.png.locked" -> "a.png"), made safe as a file name."""
    stem, dot, _last = name.rpartition(".")
    if dot and expected_type(stem, magics):
        name = stem
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".") or "member"
    return name[-120:]


def looks_like_text(head):
    """Whether at least 16 bytes are there and nearly all are printable ASCII, tabs or line ends."""
    return len(head) >= 16 and sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13)) >= 0.95 * len(head)


def keystream_for(variant, key, fd, size):
    cipher, counter, nonce_source = variant
    nonce = value_of(nonce_source, fd, size)
    if nonce is None:
        raise ValueError("the file is too short to hold the nonce the recipe reads from it")
    return Keystream(cipher, key, nonce, counter)


def main():
    install_signal_handlers(last_word)
    # The clock runs from here: the recipe and the directory are read after the deadline is set, and under it.
    started = time.monotonic()
    set_deadline(MAX_SECONDS)
    args, unknown = read_args(KNOWN_PARAMS)
    max_files = int_param(args, "max_files", 1000, 1, 100000)
    max_bytes = int_param(args, "max_bytes", 2 << 30, 1, 64 << 30)
    max_seconds = int_param(args, "max_seconds", DEFAULT_SECONDS, 1, MAX_SECONDS)
    set_deadline(max_seconds - (time.monotonic() - started))
    limit = int_param(args, "limit", 200, 1, 5000)
    # Refused first, before the recipe is read or a directory listed: outside a secret-output job this tool opens nothing.
    directory, shown, in_job, secret = job_place()
    if not (in_job and secret):
        fail("family_decrypt writes decrypted content and is refused outside a job run as secret output: %s. Run it as job_run "
             "tool=family_decrypt (its manifest makes the job secret output). Nothing was read and nothing was written"
             % ("this run is not a job (JOB_ID and OUT are not set), so a file written here would not be sealed" if not in_job else
                "SECRET_OUTPUT is not 1 in this job, so its files would be sealed as ordinary output"), written=False)
    key_source, variants, assignments, header, trailer, suffix = read_recipe(args)
    paths, more, skipped = list_members(args, max_files, suffix)
    names_in_recipe = member_keys(args, paths)
    by_base = {}                    # a base name -> the variants of the recipe's members of that name
    for n, (assigned_name, variant_number) in enumerate(assignments.items()):
        if not n & 4095 and out_of_time():
            raise Refused("the time limit (max_seconds %d) was reached while the recipe's assignments were read (%d of %d): nothing was "
                          "decrypted and nothing was written" % (max_seconds, n, len(assignments)))
        by_base.setdefault(assigned_name.rsplit("/", 1)[-1], []).append(variant_number)
    out_dir = directory / "decrypted"
    if out_dir.is_symlink() or (out_dir.exists() and not out_dir.is_dir()):
        fail("$OUT/decrypted is there and is not a directory of this job (a link or a file): nothing was written", written=False)
    out_dir.mkdir(parents=True, exist_ok=True)
    rfd, receipts_name = create_new(directory, RECEIPTS)
    receipts = os.fdopen(rfd, "w", encoding="ascii")
    PROGRESS["members"], PROGRESS["receipts"] = len(paths), "%s/%s" % (shown, receipts_name)
    magics = MAGICS
    rows = []
    spent = 0
    defaulted = 0
    counts = {"decrypted_type_confirmed": 0, "decrypted_type_not_confirmed": 0, "failed": 0, "not_decrypted_budget": 0, "not_decrypted_time": 0,
              "not_decrypted_not_a_member": 0}
    started = time.monotonic()
    for number, path in enumerate(paths, 1):
        name = os.path.basename(path)
        row = {"member": number, "file": as_given(path), "bytes": None, "payload_bytes": None, "cipher": None, "counter": None,
               "sha256_ciphertext": None, "output": None, "detected_type": None, "expected_type": expected_type(name, magics), "verdict": None}
        rows.append(row)
        if out_of_time():
            row["verdict"], row["failure"] = "not decrypted", "the time limit (max_seconds %d) was reached before this member" % max_seconds
            counts["not_decrypted_time"] += 1
            continue
        if suffix and not carries_suffix(name, suffix):
            # A file that does not carry the family's suffix is not a member (a ransom note, a plaintext twin): it is not "decrypted".
            row["verdict"], row["failure"] = "not decrypted", ("not a member: its name does not end in the recipe's member_suffix (compared in any "
                                                               "case). A recipe whose member_suffix is null takes every file named")
            counts["not_decrypted_not_a_member"] += 1
            continue
        fd = None
        out_fd = None
        try:
            try:
                fd, size = open_regular(path, follow=False)
            except (OSError, ValueError) as exc:
                raise ValueError("the file could not be opened (%s)" % (describe(exc) if isinstance(exc, OSError) else "not a usable path"))
            row["bytes"] = size
            payload = size - header - trailer
            if payload < 0:
                raise ValueError("the file is smaller than the recipe's header and trailer (%d + %d bytes)" % (header, trailer))
            row["payload_bytes"] = payload
            if spent + payload > max_bytes:
                row["verdict"], row["failure"] = "not decrypted", "max_bytes (%d) would be passed: %d bytes were decrypted before this member" % (max_bytes, spent)
                counts["not_decrypted_budget"] += 1
                continue
            key = value_of(key_source, fd, size)
            if not key:
                raise ValueError("the file is too short to hold the key the recipe reads from it")
            head = pread_full(fd, min(64, payload), header)
            wanted = magics.get(row["expected_type"]) if row["expected_type"] else None
            chosen, how = assignments.get(names_in_recipe[number - 1]), "the recipe's assignment for this member"
            if chosen is None and len(set(by_base.get(name, ()))) == 1:
                # Listed from another directory than the recipe was made from (or an older recipe, keyed by base name): the name decides
                # only when every member of that name in the recipe has the same variant.
                chosen, how = by_base[name][0], "the recipe's assignment for this name (every member of that name in the recipe has this variant)"
            if chosen is None:
                chosen, how = 0, "the recipe's only variant" if len(variants) == 1 else None
                if len(variants) > 1:
                    heads = []
                    for variant in variants:
                        try:
                            heads.append(xor_bytes(head, keystream_for(variant, key, fd, size).take(len(head))))
                        except ValueError:
                            heads.append(b"")
                    for test, said in ((lambda p: bool(wanted) and any(crib_holds(p, alt) for alt in wanted), "the variant whose result starts with the bytes of the type in the name"),
                                       (lambda p: detect_type(p, magics) is not None, "the variant whose result starts with the bytes of a known type"),
                                       (looks_like_text, "the variant whose result starts as text")):
                        fits = [n for n, plain in enumerate(heads) if plain and test(plain)]
                        if len(fits) == 1:
                            chosen, how = fits[0], said
                            break
                    if how is None:
                        defaulted += 1
                        how = ("a default: the recipe's first variant. The recipe has %d variants, this name is in none of its assignments, and "
                               "no variant's result showed a known type or text: the output may be noise" % len(variants))
            variant = variants[chosen]
            row["cipher"], row["counter"], row["variant_chosen_by"] = variant[0], variant[1], how
            stream = keystream_for(variant, key, fd, size)
            out_name = "%04d_%s" % (number, restored_name(name, magics))
            out_fd, out_name = create_new(out_dir, out_name)
            WRITING._tmp = str(out_dir / out_name)
            both = hashlib.sha256(), hashlib.sha256()
            timed_out = not _hash_range(fd, 0, header, both[0])
            at, first = header, None
            end = header + payload
            while at < end and not timed_out:
                block = pread_full(fd, min(PIECE, end - at), at)
                if not block:
                    raise ValueError("the file ended at byte %d, before its size" % at)
                plain = xor_bytes(block, stream.take(len(block)))
                if first is None:
                    first = plain[:64]
                _write_all(out_fd, plain)
                both[0].update(block)
                both[1].update(plain)
                at += len(block)
                if at < end and out_of_time():
                    timed_out = True
                    break
            if not timed_out and not _hash_range(fd, end, trailer, both[0]):
                timed_out = True
            if timed_out:
                os.close(out_fd)
                out_fd = None
                os.unlink(WRITING._tmp)
                WRITING._tmp = None
                row["verdict"], row["failure"] = "not decrypted", ("the time limit (max_seconds %d) was reached %d bytes into this member; its "
                                                                   "partial output was removed" % (max_seconds, at - header))
                counts["not_decrypted_time"] += 1
                continue
            os.fsync(out_fd)
            os.close(out_fd)
            out_fd = None
            WRITING._tmp = None
            spent += payload
            first = first or b""
            row["sha256_ciphertext"] = both[0].hexdigest()
            row["output"] = "%s/decrypted/%s" % (shown, out_name)
            row["detected_type"] = detect_type(first, magics) or ("text (its first bytes are printable)" if looks_like_text(first) else None)
            confirmed = bool(wanted) and any(crib_holds(first, alt) for alt in wanted)
            row["verdict"] = "decrypted, type confirmed" if confirmed else "decrypted, type not confirmed"
            if not confirmed:
                row["why_not_confirmed"] = ("the name promises no known type, so there is nothing to compare the result with" if not wanted else
                                            "the result does not start with the bytes of a %s: the recipe may not hold for this member (another "
                                            "key rule, cipher or counter, or a member that was not encrypted from its first byte)" % row["expected_type"])
            counts["decrypted_type_confirmed" if confirmed else "decrypted_type_not_confirmed"] += 1
            receipts.write(json.dumps({**row, "sha256_plaintext": both[1].hexdigest(), "parser": PARSER, "authenticated": False}) + "\n")
            receipts.flush()
            PROGRESS["decrypted"] += 1
        except (ValueError, OSError) as exc:
            row["verdict"] = "failed"
            row["failure"] = str(exc) if isinstance(exc, ValueError) and not isinstance(exc, UnicodeError) else describe(exc) if isinstance(exc, OSError) else type(exc).__name__
            counts["failed"] += 1
            if out_fd is not None:
                os.close(out_fd)
            if WRITING._tmp:
                try:
                    os.unlink(WRITING._tmp)
                except OSError:
                    pass
                WRITING._tmp = None
            receipts.write(json.dumps({**row, "parser": PARSER, "authenticated": False}) + "\n")
            receipts.flush()
        finally:
            if fd is not None:
                os.close(fd)
    receipts.flush()
    os.fsync(receipts.fileno())
    receipts.close()
    elapsed = time.monotonic() - started
    done = counts["decrypted_type_confirmed"] + counts["decrypted_type_not_confirmed"]
    promised_unconfirmed = sum(1 for r in rows if r["verdict"] == "decrypted, type not confirmed" and r["expected_type"])
    reasons = []
    if more:
        reasons.append("%s%d more files matched and were not decrypted: max_files is %d" % ("at least " if skipped.get("directories_not_listed_past_max_files") else "", more, max_files))
    if counts["failed"]:
        reasons.append("%d members failed (see their rows)" % counts["failed"])
    if counts["not_decrypted_budget"]:
        reasons.append("%d members were not decrypted: max_bytes (%d)" % (counts["not_decrypted_budget"], max_bytes))
    if counts["not_decrypted_time"]:
        reasons.append("%d members were not decrypted: the time limit (max_seconds %d)" % (counts["not_decrypted_time"], max_seconds))
    if counts["not_decrypted_not_a_member"]:
        reasons.append("%d files named are not members and were not decrypted: their names do not end in the recipe's member_suffix"
                       % counts["not_decrypted_not_a_member"])
    if promised_unconfirmed:
        reasons.append("%d members were decrypted and do not start with the bytes of the type their name promises: for them the recipe is not "
                       "confirmed, and what was written may be noise" % promised_unconfirmed)
    if defaulted:
        reasons.append("%d members were decrypted with a variant chosen by default (the recipe has several, and nothing told them apart for these "
                       "members): their output may be noise" % defaulted)
    if any(skipped.values()):
        reasons.append("in the directory: %s" % ", ".join("%d %s" % (n, what.replace("_", " ")) for what, n in skipped.items() if n))
    if not rows:
        reasons.append("no file matched: nothing was decrypted")
    status = "partial" if reasons else "complete"
    if not done:                                     # nothing decrypted, a directory with no member included: failed, as the manifest says
        status = "failed"
    basis = ("; ".join(reasons) if reasons else
             "all %d members named were decrypted with the recipe and written, each with a receipt; %d start with the bytes of the type their "
             "name promises and %d promise no known type. Nothing is authenticated: a stream cipher has no integrity check"
             % (len(rows), counts["decrypted_type_confirmed"], counts["decrypted_type_not_confirmed"]))
    print_answer({
        "tool": TOOL, "parser": PARSER, "version": VERSION, "status": status, "complete": status == "complete", "status_basis": basis,
        "partial_reasons": reasons,
        "members": {"named": len(rows), "decrypted": done, **counts},
        "authenticated": False,
        "authentication": "none: a stream cipher gives no integrity. `type confirmed` means only that the first bytes are those of the type "
                          "in the member's name; open a file with its own reader before relying on it",
        "recipe": {"header_bytes": header, "trailer_bytes": trailer, "member_suffix": suffix,
                   "variants": [{"cipher": c, "counter": k} for c, k, _n in variants],
                   "key": "a fixed key" if key_source[0] == "fixed" else "the %s %d bytes of each member%s%s" % (
                       "first" if key_source[1] == "head" else "last", key_source[2], " after skipping %d" % key_source[3] if key_source[3] else "",
                       " XOR a constant" if key_source[4] is not None else "")},
        "bytes_decrypted": spent, "seconds": round(elapsed, 2), "megabytes_per_second": round(spent / elapsed / 1e6, 2) if elapsed > 0.5 else None,
        "output_dir": "%s/decrypted" % shown, "receipts": "%s/%s" % (shown, receipts_name),
        "receipts_format": "JSON Lines, one row per member that was decrypted or failed: this row and sha256_plaintext (the digest of the "
                           "decrypted file is kept in the receipts, not in this answer)",
        "contains_secret_values": done > 0,
        "files": rows[:limit], "truncated": len(rows) > limit, **({"files_not_listed": len(rows) - limit} if len(rows) > limit else {}),
        "rules": RULES, **({"unrecognised_parameters": unknown} if unknown else {}),
    }, indent=2)


def _hash_range(fd, at, length, digest):
    """`length` bytes of a file from `at` into a digest, a piece at a time (a header or a trailer may be as large as 1 GiB), the clock read
    between pieces. False when the time limit was reached first."""
    end = at + length
    while at < end:
        if out_of_time():
            return False
        block = pread_full(fd, min(PIECE, end - at), at)
        if not block:
            raise ValueError("the file ended at byte %d, before its size" % at)
        digest.update(block)
        at += len(block)
    return True


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def cleanup():
    if WRITING._tmp:
        try:
            os.unlink(WRITING._tmp)
        except OSError:
            pass


if __name__ == "__main__":
    exit_code = 0
    try:
        answered(main, cleanup)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
