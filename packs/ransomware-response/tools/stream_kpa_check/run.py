#!/usr/bin/env python3
"""Check key and nonce hypotheses against a family of encrypted files by their expected first bytes, and say exactly what was tried.

Inputs: the members (paths, or a directory with a pattern), the first bytes each type should have (a built-in table by the type in
the member's name, a same-name plaintext twin beside the member when there is one, and types the caller adds), and SOURCES for the key
and the nonce: a literal, a slice of a file, the values file of cipher_state_scan, or a slice of each member itself (its first or last
N bytes, optionally XORed with a constant: a per-file key kept masked in a trailer is the common design). Every source combination is
tried on every member with each cipher asked for (ChaCha20 in both layouts, Salsa20, AES-CTR, RC4, repeating XOR) at each counter
(0 and 1 unless told otherwise); only the first 64 bytes of a member are decrypted, in memory.

Output: one verdict per member (which combination gives its expected first bytes), the length of the crib and the number of false
positives to expect from that many trials, and, when one key rule explains the members, a recipe for family_decrypt. When a key that
is not a slice (a key from a dump) opens a member, the tool forms the footer hypothesis by itself: that key XOR the member's own first
or last bytes is tried as a mask on every other member. No plaintext and no key byte is printed: a source is named by its place in the
call and a finding by its id, and the recipe (which holds key material) is written only under $OUT in a job run as secret output.
A negative lists the ciphers, counters, layouts and sources tried: it is never "no key exists".
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


import array
import errno
import fnmatch
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

TOOL = "stream_kpa_check"
VERSION = 7
PARSER = "stream_kpa_check/6"
DEFAULT_SECONDS, MAX_SECONDS = 480, 540
HEAD = 64                         # bytes of a member that are ever decrypted here
MAX_SLICE = 4096
MAX_SKIP = 64                     # how far from the end (or the start) the footer hypothesis looks for a key
MAX_DERIVED_KEY = 256             # the longest key the footer hypothesis is made from (what is kept of each member is bounded by it)
# What a call's inputs may make the tool hold, each bound stated in the manifest. Every one of them is counted as it is reached, and the
# clock is read inside every loop that reads an input or makes a hypothesis.
MAX_CANDIDATES_BYTES = 64 << 20   # a candidates file larger than this is refused unread
MAX_CANDIDATE_ROWS = 20000        # lines of one candidates file (four times the 5000 rows cipher_state_scan writes); more is refused
MAX_ROW_BYTES = 1 << 16           # a longer line is not a row of a values file: counted as not usable, never parsed
MAX_LAYOUTS = 8                   # nonces taken from one row's layouts (cipher_state_scan writes two at most)
MAX_VALUES = 40000                # distinct keys, and distinct nonces, the sources of one call may yield; more is refused
MAX_KEY_TAKEN = 256               # the longest key a cipher takes (rc4, xor): a longer key of a candidates file is counted, not kept
NONCE_TAKEN = (8, 12, 16)         # the nonce lengths a cipher takes: a nonce of a candidates file of another length is counted, not kept
MAX_MATCHES_KEPT = 64             # matching combinations kept per member and per rule; the others are counted
MAX_PLACES = 65536                # places of the footer hypothesis listed; the others are counted, and the answer is partial
MAX_RECIPE_VARIANTS = 16          # the most variants family_decrypt reads from a recipe
MAX_SHOWN = 6                     # matches a member's row lists; the others are counted (matches_not_listed)
# The footer hypothesis's memory budget (invariant I2 of its block in main()): every structure of it that grows with rules x members,
# pairs x places or hits is counted in bytes as it grows, by the costs below, and it stops (partial, stopped_by max_memory) before the
# count would pass HYPOTHESIS_MEMORY. The costs were measured with tracemalloc on CPython and rounded up, so the count errs high.
HYPOTHESIS_MEMORY = 512 << 20
COST_MEMBER = 1600                # once per member with a crib: its row's matches and count, its entry in a place's members, in the hits of
                                  # the place being tried and of the best rule, and its derived-trial and not-kept counts
COST_HIT = 260                    # a kept match of pass 2: its tuple, its slot, and a list and a dict entry of its own (the worst case)
COST_HIT_MORE = 100               # a further kept match in the same list
COST_TRYING = (2 * (COST_HIT + (MAX_MATCHES_KEPT - 1) * COST_HIT_MORE)    # once per member with a crib, before any place is listed: the
               + MAX_MATCHES_KEPT * 72)                                   # hits of the place being tried and of the best derived rule (at
                                                                          # most MAX_MATCHES_KEPT each) and the variants of a place's members
COST_PAIR = 300                   # a pair: its tuple and slot, its sort key while the pairs are sorted, where its group starts
COST_GROUP = 800                  # a group: its object, its members (one) and its variants (one)
COST_GROUP_ENTRY = 140            # each further member or variant a group carries
COST_PLACE = 512                  # a place, plus the bytes of its mask: its list, its list of groups, its entry in the index of places
COST_RULE = 4096                  # what a place holds once it is a rule (counted when the place is listed): its count, record, label and
                                  # source, and its JSON in the answer
COST_LINK = 16                    # each further group a place carries
KNOWN_PARAMS = {"files", "dir", "glob", "recursive", "max_files", "magics", "ciphers", "key_sources", "nonce_sources", "counters",
                "header_bytes", "trailer_bytes", "derive", "max_trials", "max_seconds", "limit"}
KEY_LENGTHS = {"chacha20-ietf": (16, 32), "chacha20-original": (16, 32), "salsa20": (16, 32), "aes-ctr": (16, 24, 32)}
NONCE_LENGTHS = {"chacha20-ietf": (12,), "chacha20-original": (8,), "salsa20": (8,), "aes-ctr": (8, 12, 16)}
NOT_TRIED = [
    "ciphers not asked for or not built in: AES in CBC, ECB, CFB, OFB, GCM or XTS mode, XChaCha20, ChaCha or Salsa with 8 or 12 rounds, "
    "HC-128, Sosemanuk, Rabbit, RC4 with dropped bytes, anything home-made",
    "counters other than the ones in tried.counters, and an AES-CTR counter block built another way (little-endian, nonce after the counter)",
    "a key that is not one of the sources as given: derived by a KDF or a hash, wrapped by RSA or a curve, or a slice of another length or place",
    "members encrypted from an offset other than header_bytes, or in parts (an intermittent layout whose first block is skipped)",
]


class Fixed:
    """A value that is the same for every member."""

    def __init__(self, ident, label, value):
        self.ident, self.label, self.value = ident, label, value

    def of(self, _member):
        return self.value


class Sliced:
    """A value read from each member: its first or last `length` bytes after `skip`, XORed with `mask` when one is given."""

    def __init__(self, ident, label, region, length, skip, mask):
        self.ident, self.label, self.region, self.length, self.skip, self.mask = ident, label, region, length, skip, mask

    def of(self, member):
        at = self.skip if self.region == "head" else member.size - self.skip - self.length
        if at < 0 or at + self.length > member.size:
            return None
        raw = pread_full(member.fd, self.length, at)
        if len(raw) != self.length:
            return None
        return xor_bytes(raw, self.mask) if self.mask is not None else raw


class Member:
    def __init__(self, path, key):
        self.path, self.name, self.key = path, os.path.basename(path), key      # key: how a recipe names the member (member_keys)
        self.fd, self.size = None, 0
        self.first, self.last = b"", b""                                          # its first and last bytes, kept for the footer hypothesis
        # What the member's own slices gave, by source ident. A fixed value (a literal, a file, a candidates file) is not copied onto every
        # member: `keys` and `nonces` are made from the call's sources when they are asked for, one member at a time, so that what is kept
        # per member is its slices, never a list as long as a values file (nor the trials, which are made as they are run).
        self.sliced = {}
        self.call = Call((), (), ())                                              # the call's key and nonce sources, shared by every member
        self.counts = {}                                                          # cipher -> the trials planned on this member

    def _values(self, specs, slices, fixed):
        if not slices:
            return fixed                                  # the call's own list, shared: nothing is copied for a member
        return [(s.ident, v) for s in specs for v in [s.value if isinstance(s, Fixed) else self.sliced.get(s.ident)] if v]

    @property
    def keys(self):
        return self._values(self.call.keys, self.call.key_slices, self.call.fixed_keys)

    @property
    def nonces(self):
        return self._values(self.call.nonces, self.call.nonce_slices, self.call.fixed_nonces)


def key_taken(length, ciphers):
    """Whether one of the ciphers takes a key of this length."""
    return any(1 <= length <= 256 if c in ("rc4", "xor") else length in KEY_LENGTHS[c] for c in ciphers)


def nonce_taken(length, ciphers):
    """Whether one of the ciphers takes a nonce of this length (rc4 and xor take none)."""
    return any(length in NONCE_LENGTHS.get(c, ()) for c in ciphers)


class Call:
    """The sources of a call, sorted once for every member: the slices of each role that a cipher asked for can take (a slice of another
    length is never read: what is kept per member is at most 32 keys of 256 bytes and 32 nonces of 16 bytes), the fixed values of each
    role as (ident, bytes) in the order of the call, and for each cipher the nonce sources whose length it takes (so that no member's loop
    runs over a values file's worth of nonces that no cipher can use)."""

    def __init__(self, keys, nonces, ciphers):
        self.keys, self.nonces = tuple(keys), tuple(nonces)
        self.key_slices = [s for s in self.keys if isinstance(s, Sliced) and key_taken(s.length, ciphers)]
        self.nonce_slices = [s for s in self.nonces if isinstance(s, Sliced) and nonce_taken(s.length, ciphers)]
        self.unused_slices = [s for s in self.keys + self.nonces
                              if isinstance(s, Sliced) and s not in self.key_slices and s not in self.nonce_slices]
        self.fixed_keys = [(s.ident, s.value) for s in self.keys if isinstance(s, Fixed)]
        self.fixed_nonces = [(s.ident, s.value) for s in self.nonces if isinstance(s, Fixed)]
        self.nonces_for = {cipher: [s for s in self.nonces if (len(s.value) if isinstance(s, Fixed) else s.length) in NONCE_LENGTHS[cipher]]
                           for cipher in ciphers if cipher in NONCE_LENGTHS}


class Budget:
    """The footer hypothesis's memory, in bytes counted by the costs of what it adds (I2). take() refuses a cost that would pass the
    budget (the listing then stops); add() is for what is bounded by construction (pass 2's kept matches and the pairs made of them, the
    per-member parts and what trying the places holds: MAX_MATCHES_KEPT a member and max_files members at most, about 280 MB at 5000)
    and never refuses. Nothing is given back: peak is what was counted at most."""
    __slots__ = ("most", "held", "peak")

    def __init__(self, most):
        self.most, self.held, self.peak = most, 0, 0

    def add(self, cost):
        self.held += cost
        if self.held > self.peak:
            self.peak = self.held

    def take(self, cost):
        if self.held + cost > self.most:
            return False
        self.add(cost)
        return True


def window_slice(member, region, skip, length, header):
    """`length` bytes of a member `skip` bytes from one end, from the bytes kept of it: a place the footer hypothesis reads. None when
    the place is not in the file, runs into the payload's start (a tail) or out of the header the call gave (a head)."""
    if region == "head":
        if skip + length > min(header, len(member.first)):
            return None
        return member.first[skip:skip + length]
    at = len(member.last) - skip - length
    if at < 0 or member.size - skip - length < header:
        return None
    return member.last[at:at + length]


def variants_for(ciphers, key_length, member, counters):
    """Every (cipher, nonce ident, nonce, counter) a key of this length can take with a member's nonces: what combinations() gives for
    one key. The nonces are read from the call's sources as they are needed, never copied into a list per member."""
    for cipher in ciphers:
        if cipher in ("rc4", "xor"):
            if 1 <= key_length <= 256:
                yield cipher, None, b"", 0
            continue
        if key_length not in KEY_LENGTHS[cipher]:
            continue
        limit = (1 << 32) - 1 if cipher == "chacha20-ietf" else (1 << 62)
        for spec in member.call.nonces_for.get(cipher, ()):
            nonce = spec.value if isinstance(spec, Fixed) else member.sliced.get(spec.ident)
            if nonce and len(nonce) in NONCE_LENGTHS[cipher]:
                for counter in counters:
                    if counter <= limit:
                        yield cipher, spec.ident, nonce, counter


def hex_value(text, what, most=MAX_SLICE):
    if not isinstance(text, str) or not text or len(text) > 2 * most or len(text) % 2 or re.fullmatch(r"[0-9a-fA-F]+", text) is None:
        raise Refused("%s must be hexadecimal: an even number of digits, 1 to %d bytes (the value is not repeated here)" % (what, most))
    return bytes.fromhex(text)


def bytes_of(spec, what):
    """The bytes of a {"hex": ...} or {"file": ..., "offset": ..., "length": ...} source, and how the answer names it."""
    if "hex" in spec:
        value = hex_value(spec["hex"], "%s.hex" % what)
        return value, "a literal of %d bytes" % len(value)
    path = path_param(spec.get("file"), "%s.file" % what)
    offset = int_param(spec, "offset", 0, 0, 1 << 62)
    length = int_param(spec, "length", None, 1, MAX_SLICE)
    if length is None:
        raise Refused("%s needs length: how many bytes of the file are the value (1 to %d)" % (what, MAX_SLICE))
    try:
        fd, _size = open_regular(path)
        try:
            value = pread_full(fd, length, offset)
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        raise Refused("%s.file could not be read (%s)" % (what, describe(exc) if isinstance(exc, OSError) else "not a usable path"))
    if len(value) != length:
        raise Refused("%s.file holds %d bytes at offset %d, not the %d asked for" % (what, len(value), offset, length))
    return value, "%d bytes at offset %d of a file" % (length, offset)


def read_candidates(path, what, take, files_read, index):
    """Read a values file one line at a time and hand each row (a JSON object) to take(row number, row), which returns how many of its
    values were not usable. Nothing of the file is kept here: a line is parsed and dropped, a line longer than MAX_ROW_BYTES is counted
    as not usable without being parsed, and the clock is read for every 64 KiB read and every 1024 rows. A file the call named already
    in this role ((st_dev, st_ino) in files_read) is not read again. Returns (rows, rows not usable, the index of the source that read
    the file first, or None). It holds a block of 64 KiB, the line being read and one parsed row at a time."""
    path = path_param(path, "%s.candidates" % what)
    try:
        fd, size = open_regular(path)
    except (OSError, ValueError) as exc:
        raise Refused("%s.candidates could not be read (%s)" % (what, describe(exc) if isinstance(exc, OSError) else "not a usable path"))
    try:
        st = os.fstat(fd)
        same = files_read.get((st.st_dev, st.st_ino))
        if same is not None:
            return same[1], same[2], same[0]
        if size > MAX_CANDIDATES_BYTES:
            raise Refused("%s.candidates is larger than %d MiB: not a values file of cipher_state_scan. Nothing was tried" % (what, MAX_CANDIDATES_BYTES >> 20))
        count = {"lines": 0, "rows": 0, "bad": 0}         # lines that are not empty; rows: those that are JSON objects

        def line_of(line):
            if not line.strip():
                return
            count["lines"] += 1
            if count["lines"] > MAX_CANDIDATE_ROWS:
                raise Refused("%s.candidates holds more than %d lines (the values file of cipher_state_scan holds 5000 rows at most): not one, and "
                              "it is not read further. Nothing was tried" % (what, MAX_CANDIDATE_ROWS))
            if not count["lines"] & 1023 and out_of_time():
                raise Refused("the time limit (max_seconds) was reached while %s.candidates was read, %d lines in: nothing was tried. Raise "
                              "max_seconds or name a smaller values file" % (what, count["lines"]))
            if len(line) > MAX_ROW_BYTES:
                count["bad"] += 1
                return
            try:
                row = json.loads(line)
            except (ValueError, RecursionError):
                row = None
            if not isinstance(row, dict):
                count["bad"] += 1
                return
            count["rows"] += 1
            count["bad"] += take(count["rows"], row)

        at, carry, skipping = 0, b"", False
        while at < size:
            if out_of_time():
                raise Refused("the time limit (max_seconds) was reached while %s.candidates was read, %d bytes of %d in: nothing was tried. "
                              "Raise max_seconds or name a smaller values file" % (what, at, size))
            block = os.pread(fd, min(1 << 16, size - at), at)    # 64 KiB at a time: a block of empty lines splits into a list that size
            if not block:
                break
            at += len(block)
            if skipping:                                       # the rest of a line that is too long to be a row
                cut = block.find(b"\n")
                if cut < 0:
                    continue
                block, skipping = block[cut + 1:], False
            lines = (carry + block).split(b"\n")
            carry = lines.pop()
            if len(carry) > MAX_ROW_BYTES:
                carry, skipping = b"", True
                line_of(b"x" * (MAX_ROW_BYTES + 1))            # counted as a row that is not usable
            for line in lines:
                line_of(line)
        if carry and not skipping:
            line_of(carry)
    finally:
        os.close(fd)
    files_read[(st.st_dev, st.st_ino)] = (index, count["rows"], count["bad"])
    return count["rows"], count["bad"], None


def sources(specs, what, role):
    """The sources of a role ("key" or "nonce") as objects, and how the answer describes each (never a byte of a value)."""
    if specs is None:
        return [], []
    if not isinstance(specs, list) or len(specs) > 32:
        raise Refused("%s is a list of at most 32 sources" % what)
    made, said = [], []
    seen = {}
    files_read = {}                 # (st_dev, st_ino) of a candidates file read in this role -> (index of the source, rows, rows not usable)
    for index, spec in enumerate(specs):
        if out_of_time():
            raise Refused("the time limit (max_seconds) was reached while %s were read, at %s[%d]: nothing was tried" % (what, what, index))
        here = "%s[%d]" % (what, index)
        if not isinstance(spec, dict):
            raise Refused("%s must be an object: {\"hex\": ...}, {\"file\": ..., \"offset\": ..., \"length\": ...}, {\"candidates\": ...} or "
                          "{\"slice\": \"head\" or \"tail\", \"length\": ..., \"skip\": ..., \"xor\": {a hex or file source}}" % here)
        kinds = [k for k in ("hex", "file", "candidates", "slice") if k in spec]
        if len(kinds) != 1:
            raise Refused("%s must hold exactly one of hex, file, candidates and slice" % here)
        kind = kinds[0]
        if kind == "slice":
            region = spec["slice"]
            if region not in ("head", "tail"):
                raise Refused("%s.slice is \"head\" or \"tail\"" % here)
            length = int_param(spec, "length", None, 1, MAX_SLICE)
            if length is None:
                raise Refused("%s needs length: how many bytes of each file are the value" % here)
            skip = int_param(spec, "skip", 0, 0, 1 << 20)
            mask, mask_said = None, None
            if spec.get("xor") is not None:
                if not isinstance(spec["xor"], dict) or ("hex" in spec["xor"]) == ("file" in spec["xor"]):
                    raise Refused("%s.xor is a {\"hex\": ...} or a {\"file\": ..., \"offset\": ..., \"length\": ...} source" % here)
                mask, mask_said = bytes_of(spec["xor"], "%s.xor" % here)
                if len(mask) != length:
                    raise Refused("%s.xor is %d bytes and the slice is %d: they must be the same length" % (here, len(mask), length))
            label = "%s: the %s %d bytes of each file%s%s" % (here, "first" if region == "head" else "last", length,
                                                             " after skipping %d" % skip if skip else "", " XOR %s" % mask_said if mask is not None else "")
            made.append(Sliced("%s%d" % (role[0].upper(), index), label, region, length, skip, mask))
            said.append({"index": index, "kind": "slice", "region": region, "length": length, "skip": skip, "xor": mask_said})
        elif kind == "candidates":
            tally = {"distinct": 0, "no_cipher_takes": 0}

            def take(number, row, here=here, tally=tally):
                """The values of one row for this role, kept when they are new; returns how many were not usable. A row with no value
                of this role costs nothing more (its finding id is not even made printable)."""
                texts = []
                if role == "key":
                    if isinstance(row.get("key_hex"), str):
                        texts.append(("key", row["key_hex"]))
                bad, about = 0, None
                if role != "key" and isinstance(row.get("layouts"), dict):
                    # The first MAX_LAYOUTS layouts of a row give a nonce; each one past them is counted as not usable.
                    bad += max(0, len(row["layouts"]) - MAX_LAYOUTS)
                    for n, (name, layout) in enumerate(row["layouts"].items()):
                        if n >= MAX_LAYOUTS:
                            break
                        if isinstance(layout, dict):
                            texts.append(("%s nonce" % printable(str(name), 16), layout.get("nonce_hex")))
                for name, text in texts:
                    if (not isinstance(text, str) or not text or len(text) > 2 * MAX_SLICE
                            or re.fullmatch(r"(?:[0-9a-fA-F]{2})+", text) is None):
                        bad += 1
                        continue
                    value = bytes.fromhex(text)
                    if (len(value) > MAX_KEY_TAKEN) if role == "key" else (len(value) not in NONCE_TAKEN):
                        tally["no_cipher_takes"] += 1
                        continue
                    if value in seen:
                        continue
                    if len(seen) >= MAX_VALUES:
                        raise Refused("%s yield more than %d distinct %ss (%s, row %d): more than one call can try. Nothing was tried: name "
                                      "fewer candidates files, or split them over calls" % (what, MAX_VALUES, role, here, number))
                    seen[value] = True
                    if about is None:
                        about = "%s (%s at offset %s)" % (printable(str(row.get("finding_id", "row %d" % number)), 24), printable(str(row.get("kind", "?")), 32),
                                                          row.get("offset") if isinstance(row.get("offset"), int) else "?")
                    made.append(Fixed("%s%d#%d" % (role[0].upper(), index, len(made)), "%s: %s of %s, %d bytes" % (here, name, about, len(value)), value))
                    tally["distinct"] += 1
                return bad

            rows, bad, first = read_candidates(spec["candidates"], here, take, files_read, index)
            entry = {"index": index, "kind": "candidates", "rows": rows, "rows_not_usable": bad, "distinct_%ss" % role: tally["distinct"]}
            if first is not None:
                entry["same_file_as"] = "%s[%d]" % (what, first)
            if tally["no_cipher_takes"]:
                entry["%ss_of_a_length_no_cipher_takes" % role] = tally["no_cipher_takes"]
            said.append(entry)
        else:
            value, how = bytes_of(spec, here)
            if value not in seen:
                if len(seen) >= MAX_VALUES:
                    raise Refused("%s yield more than %d distinct %ss: more than one call can try. Nothing was tried" % (what, MAX_VALUES, role))
                seen[value] = True
                made.append(Fixed("%s%d" % (role[0].upper(), index), "%s: %s" % (here, how), value))
            said.append({"index": index, "kind": kind, "bytes": len(value)})
    return made, said


def caller_magics(given):
    magics = dict(MAGICS)
    added = []
    if given is None:
        return magics, added
    if not isinstance(given, dict) or len(given) > 64:
        raise Refused("magics maps an extension to the hex of its first bytes, or to {\"hex\": ..., \"offset\": ...}; at most 64 entries")
    for ext, spec in given.items():
        if not isinstance(ext, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,16}", ext) is None:
            raise Refused("a key of magics is an extension: 1 to 16 letters, digits, dashes or underscores")
        offset = 0
        if isinstance(spec, dict):
            offset = int_param(spec, "offset", 0, 0, HEAD - 1)
            spec = spec.get("hex")
        piece = hex_value(spec, "magics.%s" % ext, HEAD)
        if offset + len(piece) > HEAD:
            raise Refused("magics.%s reaches past the first %d bytes of a file" % (ext, HEAD))
        magics[ext.lower()] = [((offset, piece),)]
        added.append({"extension": ext.lower(), "offset": offset, "bytes": len(piece)})
    return magics, added


BLOCKS = {}


def first_bytes(cipher, key, nonce, counter, keep=True):
    """The first 64 keystream bytes of a combination (kept: a fixed key and nonce are asked for again for every member; a key made from
    a member's own bytes is asked for once, and is not kept)."""
    made = BLOCKS.get((cipher, key, nonce, counter)) if keep else None
    if made is not None:
        return made
    if cipher == "aes-ctr":
        made = Keystream(cipher, key, nonce, counter).take(HEAD)
    elif cipher == "rc4":
        made = rc4_stream(rc4_schedule(key), HEAD)
    elif cipher == "xor":
        made = (key * (HEAD // len(key) + 1))[:HEAD]
    elif cipher == "salsa20":
        made = salsa20_blocks(key, nonce, counter, 1)
    else:
        made = chacha20_blocks(key, nonce, counter, 1, cipher[9:])
    if keep and len(BLOCKS) < 200000:
        BLOCKS[(cipher, key, nonce, counter)] = made
    return made


def combinations(cipher, keys, nonces, counters):
    """Every (key, nonce, counter) a cipher can take from the values at hand, made one at a time as they are tried (a list of them would
    be the product of the sources' sizes, in memory); keys and nonces are (ident, bytes)."""
    if cipher in ("rc4", "xor"):
        for k in keys:
            if 1 <= len(k[1]) <= 256:
                yield k, (None, b""), 0
        return
    usable = [k for k in keys if len(k[1]) in KEY_LENGTHS[cipher]]
    fitting = [n for n in nonces if len(n[1]) in NONCE_LENGTHS[cipher]]
    limit = (1 << 32) - 1 if cipher == "chacha20-ietf" else (1 << 62)
    steps = [c for c in counters if c <= limit]
    for k in usable:
        for n in fitting:
            for c in steps:
                yield k, n, c


def lengths_of(values, more=()):
    """{length: how many values have it}, of byte strings `values` and of the lengths in `more`."""
    tally = {}
    for n in [len(v) for v in values] + list(more):
        tally[n] = tally.get(n, 0) + 1
    return tally


def count_trials(ciphers, key_lengths, nonce_lengths, counters):
    """How many trials combinations() makes with each cipher, from the lengths of the keys and nonces alone (each {length: how many
    values have it}): the same count, made by arithmetic, before any member is opened and without a trial in memory."""
    counts = {}
    for cipher in ciphers:
        if cipher in ("rc4", "xor"):
            counts[cipher] = sum(k for n, k in key_lengths.items() if 1 <= n <= 256)
            continue
        limit = (1 << 32) - 1 if cipher == "chacha20-ietf" else (1 << 62)
        counts[cipher] = (sum(k for n, k in key_lengths.items() if n in KEY_LENGTHS[cipher])
                          * sum(k for n, k in nonce_lengths.items() if n in NONCE_LENGTHS[cipher]) * sum(1 for c in counters if c <= limit))
    return counts


def chance(alternatives):
    return min(1.0, sum(2.0 ** (-8 * crib_bytes(alt)) for alt in alternatives))


PROGRESS = {"members": 0, "checked": 0, "trials": 0}


def read_member(member, row, magics, header, trailer, call, ciphers, counters, window, fixed_lengths):
    """Everything the check needs of one open member, read now so that the file can be closed: its first bytes, its crib (the type in its
    name, a plaintext twin beside it), the keys and nonces its slices give, how many trials are planned on it (counted, not listed: the
    trials are made in pass 2 as they are run), and its first and last `window` bytes for the footer hypothesis. `fixed_lengths` is
    {length: how many} of the values the call's fixed sources give (keys, nonces), the same for every member. A verdict that needs no
    trial is written to the row."""
    path = member.path
    row["bytes"] = member.size
    raw = pread_full(member.fd, HEAD, 0)
    kind = expected_type(member.name, magics)
    row["expected_type"] = kind
    alternatives = list(magics[kind]) if kind else []
    own = member.name.lower().rsplit(".", 1)
    if kind and any(crib_holds(raw, alt) for alt in alternatives):
        row["verdict"] = "head_is_plaintext"
        row["note"] = ("the file as it is starts with the first bytes of its type: " +
                       ("it is not an encrypted member" if len(own) == 2 and own[1] == kind else
                        "its head is not encrypted (a part-encrypted member, or one that was never encrypted)"))
        return
    twin = None
    if len(own) == 2 and own[0]:
        twin_path = path[: len(path) - len(member.name)] + member.name[: len(own[0])]
        try:
            tfd, _tsize = open_regular(twin_path, follow=False)
            try:
                twin = pread_full(tfd, HEAD, 0)
            finally:
                os.close(tfd)
        except (OSError, ValueError):
            twin = None
    payload = member.size - header - trailer
    if payload < 2:
        row["verdict"] = "too_small"
        row["note"] = "the file has %d bytes after header_bytes and trailer_bytes are taken off" % max(payload, 0)
        return
    member.cipher_head = pread_full(member.fd, min(HEAD, payload), header)
    if twin is not None and len(twin) >= 8:
        piece = twin[: min(len(twin), len(member.cipher_head))]
        alternatives = [((0, piece),)] + alternatives
        row["twin"] = "a same-name file without the last extension is beside it: its first %d bytes are a crib too" % len(piece)
    alternatives = [alt for alt in alternatives if max(at + len(piece) for at, piece in alt) <= len(member.cipher_head)]
    if not alternatives:
        row["verdict"] = "no_crib"
        row["note"] = ("no known type in the name and no plaintext twin: nothing to compare a decryption with. Give its first bytes "
                       "in magics, or it stays unchecked" if not kind else "the payload is shorter than the type's first bytes")
        return
    member.alternatives = alternatives
    row["crib_bytes"] = min(crib_bytes(alt) for alt in alternatives)
    member.call = call
    member.sliced = {s.ident: s.of(member) for s in call.key_slices + call.nonce_slices}
    fixed_keys, fixed_nonces = fixed_lengths

    def plus_slices(fixed, slices):
        tally = dict(fixed)
        for spec in slices:
            value = member.sliced.get(spec.ident)
            if value:
                tally[len(value)] = tally.get(len(value), 0) + 1
        return tally

    member.counts = count_trials(ciphers, plus_slices(fixed_keys, call.key_slices), plus_slices(fixed_nonces, call.nonce_slices), counters)
    row["trials"] = sum(member.counts.values())
    if window:
        member.first = pread_full(member.fd, min(window, header, member.size), 0)
        keep = min(window, member.size)
        member.last = pread_full(member.fd, keep, member.size - keep)


class RecipePage:
    """The recipe file of this call while it is being written, and once written until the answer is printed: a stop removes it (the shared
    STOP block reads `_tmp` of everything in PAGES), so that an answer that says no recipe was written leaves none behind."""

    def __init__(self):
        self._tmp = None


RECIPE = RecipePage()
PAGES.append(RECIPE)


def write_recipe(directory, text):
    """Write the recipe under a temporary name, then give it its name (stream-recipe.json, or -2, -3 ... when one is there: nothing is
    replaced). The name is given by a hard link, which fails when the name is taken; a file system that takes no hard link gets no recipe
    (a rename there would replace a file that appeared at the name in between), and the answer says why. The stop signals are held for
    the few steps it takes, and a stop that came then is answered once they are let go: by then RECIPE._tmp names the file, and the stop
    removes it. A kill that no handler sees leaves a .part file, never a cut stream-recipe.json."""
    try:
        old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        old = None
    try:
        fd, part = create_new(directory, ".stream-recipe.json.part")
        RECIPE._tmp = str(directory / part)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        for n in range(1, 1000):
            name = "stream-recipe.json" if n == 1 else "stream-recipe-%d.json" % n
            try:
                os.link(RECIPE._tmp, str(directory / name))
            except FileExistsError:
                continue
            except OSError as exc:
                if os.path.lexists(str(directory / name)):
                    continue
                # No hard link here: a rename would replace a file that appeared at the name in between, so none is made.
                raise OSError(exc.errno, "the output directory takes no hard link, and the recipe is given its name only by one "
                                         "(a rename could replace a file): %s" % (exc.strerror or "no system message"))
            os.unlink(RECIPE._tmp)
            RECIPE._tmp = str(directory / name)
            return name
        raise OSError(errno.EEXIST, "no free name for the recipe file")
    except BaseException:
        if RECIPE._tmp is not None:
            try:
                os.unlink(RECIPE._tmp)
            except OSError:
                pass
            RECIPE._tmp = None
        raise
    finally:
        if old is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, old)


RESULT = RecipePage()               # the result file that holds the whole lists when the answer shows `limit` of them
PAGES.append(RESULT)


def write_result(directory, document):
    """Write the whole lists of an answer that shows `limit` of them to stream-kpa-check.json (or -2, -3 ...: nothing is replaced), with
    the stop signals held while the file is made and named in RESULT._tmp, so that a stop removes it. It holds no key, nonce or mask
    byte and no plaintext: what the answer holds, whole."""
    try:
        old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        old = None
    try:
        fd, name = create_new(directory, "stream-kpa-check.json")
        RESULT._tmp = str(directory / name)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            json.dump(document, fh, indent=1)                # written as it is encoded: the text is never held whole
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        return name
    except BaseException:
        if RESULT._tmp is not None:
            try:
                os.unlink(RESULT._tmp)
            except OSError:
                pass
            RESULT._tmp = None
        raise
    finally:
        if old is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, old)


def forget_recipe():
    """answered()'s cleanup: an answer that is an error does not leave the recipe (or the result file) it did not name."""
    for page in (RECIPE, RESULT):
        if page._tmp is not None:
            try:
                os.unlink(page._tmp)
            except OSError:
                pass
            page._tmp = None


def last_word(signum):
    print(json.dumps({"error": "stopped by signal %d before every member was checked" % signum, "status": "failed", "interrupted": True, "signal": signum,
                      "members_checked_so_far": PROGRESS["checked"], "members": PROGRESS["members"], "trials_so_far": PROGRESS["trials"],
                      "status_basis": "the tool was stopped by signal %d: no verdict is given, no recipe was written, and what it had tried by "
                                      "then is no negative" % signum}), flush=True)


def main():
    install_signal_handlers(last_word)
    # The clock runs from here: every input (the sources' files included) is read after the deadline is set, and under it.
    started = time.monotonic()
    set_deadline(MAX_SECONDS)
    args, unknown = read_args(KNOWN_PARAMS)
    max_files = int_param(args, "max_files", 200, 1, 5000)
    max_trials = int_param(args, "max_trials", 500000, 1, 5000000)
    max_seconds = int_param(args, "max_seconds", DEFAULT_SECONDS, 1, MAX_SECONDS)
    set_deadline(max_seconds - (time.monotonic() - started))
    limit = int_param(args, "limit", 200, 1, 5000)
    derive = bool_param(args, "derive", True)
    header_given = int_param(args, "header_bytes", None, 0, 1 << 30)
    trailer_given = int_param(args, "trailer_bytes", None, 0, 1 << 30)
    ciphers = args.get("ciphers")
    if ciphers is None:
        ciphers = list(CIPHER_NAMES)
    elif not isinstance(ciphers, list) or not ciphers or not all(isinstance(c, str) and c in CIPHER_NAMES for c in ciphers):
        raise Refused("ciphers is a list of one or more of: %s" % ", ".join(CIPHER_NAMES))
    else:
        ciphers = [c for c in CIPHER_NAMES if c in ciphers]
    counters = args.get("counters")
    if counters is None:
        counters = [0, 1]
    elif (not isinstance(counters, list) or not 1 <= len(counters) <= 8
          or not all(isinstance(c, int) and not isinstance(c, bool) and 0 <= c < 1 << 62 for c in counters)):
        raise Refused("counters is a list of 1 to 8 block numbers, each 0 or more (default [0, 1])")
    else:
        counters = sorted(set(counters))
    magics, added = caller_magics(args.get("magics"))
    key_sources, keys_said = sources(args.get("key_sources"), "key_sources", "key")
    nonce_sources, nonces_said = sources(args.get("nonce_sources"), "nonce_sources", "nonce")
    if not key_sources and keys_said:
        # Sources were given and none yields a key: say what each held, not that the parameter is missing.
        held = "; ".join("key_sources[%d] is a candidates file of %d rows, %d of them not usable (not JSON objects, or a value that is not "
                         "hexadecimal), and %d distinct keys (rows with key_hex: a state or an AES schedule; a permutation or a table has none)"
                         % (said["index"], said["rows"], said["rows_not_usable"], said["distinct_keys"]) for said in keys_said if said["kind"] == "candidates")
        raise Refused("key_sources yields no key: %s. Nothing was tried, and that says nothing about any key: scan another dump, or give a key "
                      "source of another kind (a literal, a slice of a file, a slice of each member)" % held)
    if not key_sources:
        raise Refused("key_sources is required: at least one source that yields a key. A literal ({\"hex\": ...}), a slice of a file ({\"file\": ..., "
                      "\"offset\": ..., \"length\": ...}), the values file of cipher_state_scan ({\"candidates\": ...}) or a slice of each member "
                      "({\"slice\": \"tail\", \"length\": 32, \"xor\": {...}}). Nothing was tried")
    paths, more, skipped = list_members(args, max_files)
    labels = {s.ident: s.label for s in key_sources + nonce_sources}

    def extent(region):
        return max([s.skip + s.length for s in key_sources + nonce_sources if isinstance(s, Sliced) and s.region == region] or [0])

    header = header_given if header_given is not None else extent("head")
    trailer = trailer_given if trailer_given is not None else extent("tail")
    tried = {
        "ciphers": ciphers, "counters": counters,
        "layouts": "chacha20-ietf: 12-byte nonce, 32-bit counter; chacha20-original: 8-byte nonce, 64-bit counter; salsa20: 8-byte nonce, 64-bit "
                   "counter, 20 rounds; aes-ctr: a 16-byte nonce is the first counter block, a 12-byte one is followed by a 32-bit big-endian "
                   "counter, an 8-byte one by a 64-bit one; rc4 and xor take the key alone, from the first byte",
        "key_sources": keys_said, "nonce_sources": nonces_said, "magics_added": added,
        "header_bytes": header, "trailer_bytes": trailer,
        "payload": "a member's ciphertext is taken to start at header_bytes; only its first %d bytes are decrypted" % HEAD,
    }

    # Before any member is opened: the trials one member can take, counted from the lengths of what the sources give (every slice taken to
    # be in the file). A call whose sources alone pass max_trials on ONE member is refused here, with the count; nothing is listed in
    # memory, however large a values file is.
    call_keys, call_nonces = tuple(key_sources), tuple(nonce_sources)
    call = Call(call_keys, call_nonces, ciphers)
    nonce_by_ident = {s.ident: s for s in call_nonces}
    fixed_lengths = (lengths_of(s.value for s in call_keys if isinstance(s, Fixed)), lengths_of(s.value for s in call_nonces if isinstance(s, Fixed)))
    most_per_member = count_trials(ciphers, lengths_of((s.value for s in call_keys if isinstance(s, Fixed)), [s.length for s in call_keys if isinstance(s, Sliced)]),
                                   lengths_of((s.value for s in call_nonces if isinstance(s, Fixed)), [s.length for s in call_nonces if isinstance(s, Sliced)]),
                                   counters)
    if sum(most_per_member.values()) > max_trials:
        raise Refused("%d trials would be made on each member that has a crib (%s; every cipher, key, nonce and counter of the call) and %d "
                      "members are named, and max_trials is %d: narrow ciphers, counters or the sources, or raise max_trials (at most 5000000). "
                      "Nothing was opened and nothing was tried"
                      % (sum(most_per_member.values()), ", ".join("%s %d" % (c, n) for c, n in most_per_member.items() if n), len(paths), max_trials))

    # Pass 1: open every member, read what a verdict and the footer hypothesis need, close it, and count the trials before any is made.
    fixed_sources = [s for s in key_sources if isinstance(s, Fixed)]
    window = MAX_SKIP + max([len(s.value) for s in fixed_sources if len(s.value) <= MAX_DERIVED_KEY] or [0]) if derive and fixed_sources else 0
    members, rows = [], []
    unread_members = 0
    for path, name_in_recipe in zip(paths, member_keys(args, paths)):
        member = Member(path, name_in_recipe)
        row = {"file": as_given(path), "bytes": None, "expected_type": None, "crib_bytes": None, "trials": 0,
               "expected_false_positives": None, "verdict": None, "matches": []}
        rows.append(row)
        members.append(member)
        if out_of_time():
            row["verdict"], row["note"] = "not_tried", "the time limit was reached before this member was read"
            unread_members += 1
            continue
        try:
            member.fd, member.size = open_regular(path, follow=False)
        except (OSError, ValueError) as exc:
            row["verdict"], row["error"] = "read_failed", describe(exc) if isinstance(exc, OSError) else "not a usable path"
            continue
        try:
            read_member(member, row, magics, header, trailer, call, ciphers, counters, window, fixed_lengths)
        except OSError as exc:
            row["verdict"], row["error"] = "read_failed", describe(exc)
        finally:
            os.close(member.fd)                              # one member open at a time: a family of thousands needs one descriptor
            member.fd = None
    PROGRESS["members"] = len(members)
    planned = sum(row["trials"] for row in rows)
    if planned > max_trials:
        raise Refused("%d trials would be made (%d members with a crib, and every cipher, key, nonce and counter on each) and max_trials is %d: "
                      "narrow ciphers, counters or the sources, or raise max_trials (at most 5000000). Nothing was tried"
                      % (planned, sum(1 for r in rows if r["trials"]), max_trials))
    trials_by_cipher = {cipher: sum(m.counts.get(cipher, 0) for m in members) for cipher in ciphers}

    # Pass 2: the trials.
    budget = Budget(HYPOTHESIS_MEMORY)   # I2: pass 2's kept matches are counted in it too (bounded: MAX_MATCHES_KEPT a member)
    matched = {}                    # key ident -> {member index: [(cipher, nonce ident, counter)]}
    opened_by_fixed = []            # (member index, key bytes, key ident): a key that is not a slice opened this member
    opened_pairs = set()            # (member index, key ident) of opened_by_fixed
    fixed_keys = {s.ident for s in fixed_sources}
    not_tried_members = unread_members
    no_trial_members = 0
    total_trials = 0
    for index, (member, row) in enumerate(zip(members, rows)):
        if row["verdict"] is not None:
            continue
        if not row["trials"]:
            # No trial is no negative: the member has a crib, and no source gave a key (and a nonce) that a cipher asked for takes.
            row["verdict"] = "not_tried"
            row["note"] = ("no trial could be made on this member: no source yields a key, and for a cipher that needs one a nonce, of a "
                           "length one of the ciphers asked for takes (or a slice reaches past this file). See tried.trials_by_cipher")
            no_trial_members += 1
            continue
        if out_of_time():
            row["verdict"] = "not_tried"
            row["note"] = "the time limit was reached before this member"
            not_tried_members += 1
            continue
        head = member.cipher_head
        made, hits, cut, extra_hits = 0, [], False, 0
        keys, nonces = member.keys, member.nonces                 # this member's values, for as long as its trials run
        for cipher in ciphers:
            for (key_id, key), (nonce_id, nonce), counter in combinations(cipher, keys, nonces, counters):
                made += 1
                if not made & 255 and out_of_time():
                    cut = True
                    break
                plain = xor_bytes(head, first_bytes(cipher, key, nonce, counter))
                if any(crib_holds(plain, alt) for alt in member.alternatives):
                    if len(hits) < MAX_MATCHES_KEPT:
                        hits.append((key_id, key, cipher, nonce_id, counter))
                    else:
                        extra_hits += 1                   # a crib this short matches by chance: counted, not kept
            if cut:
                break
        if cut:
            # A member whose trials the clock cut has no verdict: a match found so far is not kept as one, a miss is not a negative.
            total_trials += made
            row["verdict"] = "not_tried"
            row["note"] = "the time limit was reached %d trials into this member's %d: it has no verdict" % (made, row["trials"])
            row["trials"] = made
            not_tried_members += 1
            continue
        if extra_hits:
            row["matches_not_kept"] = extra_hits              # counted, not kept: the answer is partial (the reason is made from the rows)
        for key_id, key, cipher, nonce_id, counter in hits:      # at most MAX_MATCHES_KEPT
            matched.setdefault(key_id, {}).setdefault(index, []).append((cipher, nonce_id, counter))
            budget.add(COST_HIT)
            if key_id in fixed_keys and (index, key_id) not in opened_pairs:
                opened_pairs.add((index, key_id))
                opened_by_fixed.append((index, key, key_id))
        total_trials += row["trials"]
        PROGRESS["checked"] += 1
        PROGRESS["trials"] = total_trials

    with_crib = [i for i, row in enumerate(rows) if row["verdict"] is None]
    crib_set = set(with_crib)

    # THE FOOTER HYPOTHESIS: a key that is not a slice opened a member, so that key XOR the member's own last (or, inside header_bytes,
    # first) bytes may be a constant mask; every place (an end and a skip) of every such pair is one hypothesis, tried on the other
    # members. It is reviewed as one unit, and holds two invariants before anything else:
    #   I1 (when it is complete). The hypothesis is complete only if every place numbered before the chosen rule's (5, 11) is SETTLED
    #      (tried with every variant on every other member that has a crib), or a slice of the call read from the files explained
    #      every member before it started (then it is not made). Any bound (max_trials, the clock, MAX_PLACES, the memory budget of
    #      I2) that stops it before that sets stopped_by and makes the answer partial, whichever pass it stopped and whatever rule was
    #      found before; places_not_tried_once_one_rule_explained_every_member counts only the places after the chosen rule's. `ended`
    #      below is computed from `settled` itself, never from the passes' control flow.
    #  I2 (what it holds). One memory budget, HYPOTHESIS_MEMORY bytes, over every structure that grows with rules x members, pairs x
    #      places or hits: pass 2's kept matches, the pairs, the groups (their members and variants), the places and the groups each
    #      carries, the hits of the place being tried, the derived rules (a count each, and their records), the best derived rule's
    #      hits, and per member its row's first MAX_SHOWN matches and a count. Each is counted (Budget, by the COST_ constants) as it
    #      grows: pass 2's matches, the per-member parts and the pairs are bounded by MAX_MATCHES_KEPT x max_files and are counted
    #      first; what trying the places holds at most (the hits of one place and of the best rule, MAX_MATCHES_KEPT a member each) is
    #      counted before any place is listed (COST_TRYING); each group, each place (with what it holds if it becomes a rule) and each
    #      group a place carries is counted as it is listed. So only the listing can reach the budget: before the count would pass it,
    #      the listing stops (stopped_by max_memory, partial unless a rule ends the hypothesis by I1), the places not listed are counted
    #      in places_not_listed, and every place listed is still tried. What a rule opens is never held per rule: a rule keeps a
    #      count, each member keeps what its row prints, and only the best derived rule (by 11, kept as the rules are made) keeps its
    #      matches, for the recipe.
    # Below is every selection, tie-break, cap and shortcut it (and the choice of the best rule after it) makes. Each holds two rules:
    # (a) nothing depends on the members' names or the order they were listed in, only on their bytes, the type their name promises
    # and the order of the call's sources: every order below is a TOTAL order over what the hypothesis reads, or what comes after it
    # reads the tied elements as a set, never as "the first one"; (b) a cap or a shortcut that leaves a hypothesis untried while a
    # member is left unexplained makes the answer partial, with a reason, and the no_match rows say that they do not cover it.
    #   1. Matches kept (pass 2, above). Per member, the first MAX_MATCHES_KEPT hits in the order of the trials: cipher (in the order of
    #      CIPHER_NAMES), then key and nonce in the order of the call's sources, then counter (ascending). That order is the call's, the
    #      same for every member, and the hits of one member never depend on another. The others are counted (the row's
    #      matches_not_kept) and the answer is partial, with a reason that says the pairs, the rule and the recipe were made from the
    #      kept hits.
    #   2. Pairs. Every (key that is not a slice, member it opened) among the kept hits is a pair: no other selection. A key that opened
    #      several members is paired with each of them, since the crib cannot tell which opening was by chance. A key longer than
    #      MAX_DERIVED_KEY is no pair (counted); no cipher takes such a key, so it never opens a member, and if one did, the answer would
    #      be partial while no rule explains every member.
    #   3. Groups, and their order. A pair's key is: the longest crib first, then the key's place among the call's sources, then the
    #      member's size, its first ciphertext bytes, its last and first bytes kept, its cribs; never its name or its place in the
    #      listing. Pairs equal in that key are ONE GROUP: they hold one key and the same kept bytes, so they give the same masks at the
    #      same places. What can still differ between them (the variant that opened each member, a nonce slice outside the kept bytes,
    #      the name) is carried by the group as sets: its members (each with the hits pass 2 gave it) and the union of the variants that
    #      opened them, sorted (cipher in the order of CIPHER_NAMES, nonce source by its place in the call, counter). Two groups differ
    #      in their keys, so the order of the groups is total; the order of the pairs inside a group is never read.
    #   4. Places. For each group in that order, the tail at skips 0 to MAX_SKIP, then the head at skips 0 to MAX_SKIP inside
    #      header_bytes. They are counted by arithmetic and listed one at a time with the clock and the budget (I2) read; at
    #      MAX_PLACES, the clock or the budget the listing stops and the rest are counted in places_not_listed (a group's places once,
    #      however many pairs it holds). Places not listed come after every place listed, so after any rule (I1).
    #   5. Merging. The same mask at the same end and skip is listed once, where the first group in the order of (3) gives it, and every
    #      later group that gives it while the list is not full adds its members and variants to it (unions, as in 3). No (end, skip,
    #      mask) is listed twice, so the order of the list, the place numbers, is total, and a place carries every pair that gave it.
    #   6. First pass. Every place, in order, with the sorted union of the variants that opened its own members, on EVERY other member
    #      that has a crib, whether a rule explains it already or not: what a rule explains never depends on the rules made before it.
    #      The place's own members are not tried: the mask gives each the key that opened it, and pass 2 tried that key with every
    #      variant. A place that opens a member, or that two members or more gave, is then tried with every other variant on every
    #      member it did not open (it is then settled), and is a rule (derived_rules) with every member it opens, its own ones included.
    #   7. Second pass. Every place not yet settled, in the same order, with every variant on every other member that has a crib.
    #   8. The end (I1). Once a rule read from the files (a slice of the call or a derived rule) opens every member that has a crib, no
    #      place can explain more, and only an EARLIER place (a smaller number in 5) can tie and be preferred (11): the first pass stops,
    #      the second goes on over the places before it alone, and the places after it are counted
    #      (places_not_tried_once_one_rule_explained_every_member). The hypothesis has ended, and may be complete, only when every place
    #      before that rule's is settled; a bound that stops the second pass before then leaves it partial (stopped_by), though a rule
    #      explains every member: an earlier place could have tied and been the recipe's. The hypothesis is not made at all when a
    #      slice of the call explains every member before it starts (a source of the call comes before every derived rule in 11). A
    #      fixed key that opens every member does not end it: in a small family it may have opened all but one by chance, and a rule
    #      read from the files that ties with it is preferred (11), so every place is tried (or the answer is partial).
    #   9. Bounds. max_trials, the clock, MAX_PLACES and the memory budget (I2, which stops the listing only) are the only others. A
    #      place (each of its two steps) is begun only when the trials it takes, counted before any is made, fit in what max_trials
    #      leaves: under max_trials a place is tried whole or not at all, so the trials a member gets never depend on the order the
    #      members are tried in. The clock can cut a place halfway; a place cut in either step is no rule (its hits, those of its first
    #      step included, are dropped; its trials are counted), and is not settled. When a bound stops the hypothesis before it has
    #      ended (I1), the answer is partial.
    #  10. Matches kept per derived rule. Per member, MAX_MATCHES_KEPT in the order of the variants (the sorted union of 6 first, then
    #      the call's order of 1); the others are counted in the row's matches_not_kept when the place becomes a rule, and the answer
    #      is partial.
    #  11. The best rule (after the hypothesis): the most members explained; then a rule read from the files (a slice of the call or a
    #      derived rule) over a fixed key; then the smallest position: a source of the call by its place in the call, a derived rule
    #      after all of them by its place's number in 5. Every source and every place has its own position, so this is total, and the
    #      best derived rule is kept by it as the rules are made (a rule made later with a smaller number replaces a tie). The derived
    #      rules are numbered and listed in that order too, never in the order they were made, and from_file (a label only: what a
    #      rule explains does not depend on it) is the place's own member of the first group with the smallest path below the call's
    #      directory, also_from_files counting the others.
    #  12. The recipe's variants: by how many members use each, then cipher, counter and nonce source (distinct variants differ in one
    #      of them: total); a member with several takes the best ranked; the assignments are written in the order of the members'
    #      paths below the call's directory, not of their listing.
    #  13. A member's row: its first MAX_SHOWN matches in the order of 11 (the call's sources, then the derived rules by number), each
    #      rule's in the order it kept them (1, 10), and the count of all of them; kept per member as the rules are made (I2).
    derived = []
    work = {"trials": 0, "left": max_trials - total_trials, "cut": None}
    position = {s.ident: n for n, s in enumerate(key_sources)}     # a source's place in the call (the derived rules follow, by place)
    nonce_rank = {s.ident: n for n, s in enumerate(call_nonces)}
    cipher_rank = {c: n for n, c in enumerate(CIPHER_NAMES)}
    budget.add(COST_MEMBER * len(with_crib))                        # bounded by max_files

    def variant_rank(variant):
        cipher, nonce_id, counter = variant
        return (cipher_rank[cipher], -1 if nonce_id is None else nonce_rank[nonce_id], counter)

    shown, found = {}, {}           # (13) member index -> its first MAX_SHOWN matches (position, n, key ident, cipher, nonce ident, counter); and their count

    def note_matches(index, at, key_id, combos):
        found[index] = found.get(index, 0) + len(combos)
        have = shown.get(index)
        if have is None:
            have = shown[index] = []
        elif len(have) >= MAX_SHOWN and have[-1][0] < at:
            return                                       # every one it holds comes before these (a rule's matches share its position)
        have.extend((at, n, key_id) + combo for n, combo in enumerate(combos[:MAX_SHOWN]))
        have.sort(key=lambda entry: (entry[0], entry[1]))
        del have[MAX_SHOWN:]

    for key_id in matched:                                       # the call's sources (bounded: MAX_MATCHES_KEPT a member)
        for index, combos in matched[key_id].items():
            note_matches(index, position[key_id], key_id, combos)

    derivation = {"made": derive, "pairs": 0, "pair_groups": 0, "places": 0, "places_not_listed": 0, "places_tried_on_every_member": 0,
                  "places_not_tried_once_one_rule_explained_every_member": 0, "trials": 0, "stopped_by": None,
                  "memory_budget_bytes": HYPOTHESIS_MEMORY, "memory_counted_at_most_bytes": 0}
    # A slice of the call read from the files explains every member (8): the hypothesis is not made. A fixed key that does is no end.
    sliced_full = bool(with_crib) and any(len(per) == len(with_crib) for k, per in matched.items() if k not in fixed_keys)
    pairs = []
    too_long = 0
    for index, key, key_id in opened_by_fixed:
        if len(key) > MAX_DERIVED_KEY:
            too_long += 1
        elif index in crib_set:
            pairs.append((index, key, key_id))
    budget.add(COST_PAIR * len(pairs))                              # at most one a kept match of pass 2

    def pair_order(pair):
        member = members[pair[0]]
        return (-rows[pair[0]]["crib_bytes"], position[pair[2]], member.size, member.cipher_head, member.last, member.first, member.alternatives)

    class Group:
        """Pairs equal in pair_order (3): one key, one member's worth of kept bytes, and as sets the members it opened (member index ->
        key ident) and the variants that opened them. Made only for a group whose places are listed, once the budget took it (I2)."""
        __slots__ = ("index", "key", "key_id", "own", "variants")

        def __init__(self, tied):
            self.index, self.key, self.key_id = tied[0]                 # any one of them: every place reads the same bytes from each
            self.own = {index: key_id for index, _key, key_id in tied}
            self.variants = {variant for index, _key, key_id in tied for variant in matched[key_id][index]}

    def group_cost(tied):
        """What a Group of these pairs holds, counted before it is made (its variants at most the hits that opened its members)."""
        return COST_GROUP + COST_GROUP_ENTRY * max(0, len(tied) - 1 + sum(len(matched[key_id][index]) for index, _key, key_id in tied) - 1)

    def place_count(pair, region):
        """How many skips of one end window_slice() gives for a pair (and so for its group), by arithmetic (the places are made one at a
        time below)."""
        member, length = members[pair[0]], len(pair[1])
        if region == "tail":
            most = min(len(member.last) - length, member.size - length - header)
        else:
            most = min(header, len(member.first)) - length
        return max(0, min(MAX_SKIP, most) + 1)

    # A place is [region, skip, mask, groups]: the groups that gave it, the first one first (5).
    todo = []                       # every hypothesis listed, the same mask at the same place once
    places_not_listed = 0           # places past MAX_PLACES, the clock or the budget, counted per group before equal masks are merged
    listing_cut = None              # what stopped the listing (4): max_places or max_memory (the clock stops everything: work["cut"])
    if derive and len(with_crib) > 1 and not sliced_full:
        # The pairs in the order of their keys; a group is a run of equal keys, kept as where it starts in the sorted list (the order of
        # the pairs inside a run is never read). The clock is read every 4096 pairs: past it, every pair left is a group of its own, and
        # the listing below stops at once.
        budget.add(COST_TRYING * len(with_crib))                    # what trying the places holds, at most (I2): it never stops there
        pairs.sort(key=pair_order)
        starts, previous = array.array("q"), None              # 8 bytes a group: 320,000 pairs at most
        for n, pair in enumerate(pairs):
            if not n & 4095 and out_of_time():
                starts.extend(range(n, len(pairs)))
                break
            order_key = pair_order(pair)
            if not n or order_key != previous:
                starts.append(n)
            previous = order_key
        previous = None
        starts.append(len(pairs))
        listed = {}                 # (region, skip, mask) -> its place in todo
        listing = True
        for number in range(len(starts) - 1):
            if listing and not number & 255 and out_of_time():
                listing = False
                work["cut"] = "max_seconds"
            group = None
            for region in ("tail", "head"):
                count = place_count(pairs[starts[number]], region)
                if listing and len(todo) >= MAX_PLACES:
                    listing, listing_cut = False, "max_places"
                if not listing:
                    places_not_listed += count
                    continue
                if group is None and count:
                    tied = pairs[starts[number]:starts[number + 1]]
                    if not budget.take(group_cost(tied)):
                        listing, listing_cut = False, "max_memory"
                        places_not_listed += count
                        continue
                    group = Group(tied)
                for skip in range(count):
                    if len(todo) >= MAX_PLACES:
                        listing, listing_cut = False, "max_places"
                    else:
                        mask = xor_bytes(window_slice(members[group.index], region, skip, len(group.key), header), group.key)
                        at = listed.get((region, skip, mask))
                        if not budget.take(COST_PLACE + COST_RULE + len(mask) if at is None else COST_LINK):
                            listing, listing_cut = False, "max_memory"
                    if not listing:
                        places_not_listed += count - skip
                        break
                    if at is None:
                        listed[(region, skip, mask)] = len(todo)
                        todo.append([region, skip, mask, [group]])
                    else:
                        todo[at][3].append(group)
        listed = None
        derivation["pairs"], derivation["pair_groups"] = len(pairs), len(starts) - 1
        starts = None
        derivation["places"], derivation["places_not_listed"] = len(todo), places_not_listed
    extra = {}                      # member index -> the derived trials made on it
    derived_not_kept = {}           # member index -> derived matches past MAX_MATCHES_KEPT for one rule, counted (10)

    def own_of(place):
        """The members that gave a place (member index -> the key ident that opened it), and the sorted union of their variants (3, 5)."""
        own, variants = {}, set()
        for group in place[3]:
            own.update(group.own)
            variants |= group.variants
        return own, sorted(variants, key=variant_rank)

    def spend(other):
        """One more derived trial on a member, if the clock allows it (max_trials was counted before the step began, 9)."""
        if work["cut"]:
            return False
        if work["trials"] >= work["left"]:
            work["cut"] = "max_trials"
            return False
        if not work["trials"] & 255 and out_of_time():
            work["cut"] = "max_seconds"
            return False
        work["trials"] += 1
        extra[other] = extra.get(other, 0) + 1
        return True

    def try_place(place, own, others, variants_of, bound, done=()):
        """The mask of a place on each of `others` but its own members, with the variants variants_of(member) gives, but for those in
        `done` (what the first pass tried on every one of them already). The trials it takes are counted first, without a trial (not
        counted when `bound`, the most variants a member can take, times the members fits), and the step is not begun when they do not
        fit in what max_trials leaves (9). Returns (the hits, at most MAX_MATCHES_KEPT a member, and the count of the others per
        member), or None when a bound stopped it (then nothing of it is kept). The clock is read for every member, whether a trial is
        made on it or not. What it keeps was counted in the budget before any place was listed (COST_TRYING: I2)."""
        region, skip, mask = place[0], place[1], place[2]
        room = work["left"] - work["trials"]
        need = 0
        # `bound` is at least the variants a member can take: when every member taking that many fits, the count is not needed.
        for other in (others if len(others) * bound > room else ()):
            if out_of_time():
                work["cut"] = work["cut"] or "max_seconds"
                return None
            if other in own or window_slice(members[other], region, skip, len(mask), header) is None:
                continue
            for cipher, nonce_id, _nonce, counter in variants_of(members[other]):
                if (cipher, nonce_id, counter) not in done:
                    need += 1
                    if need > room:
                        work["cut"] = work["cut"] or "max_trials"
                        return None
                    if not need & 4095 and out_of_time():
                        work["cut"] = work["cut"] or "max_seconds"
                        return None
        hits, over = {}, {}
        for other in others:
            if out_of_time():
                work["cut"] = work["cut"] or "max_seconds"
                return None
            if other in own:
                continue
            target = members[other]
            at = window_slice(target, region, skip, len(mask), header)
            if at is None:
                continue                                         # the file is too short to hold a key at this place
            value = xor_bytes(at, mask)
            for cipher, nonce_id, nonce, counter in variants_of(target):
                if (cipher, nonce_id, counter) in done:
                    continue
                if not spend(other):
                    return None
                plain = xor_bytes(target.cipher_head, first_bytes(cipher, value, nonce, counter, keep=False))
                if any(crib_holds(plain, alt) for alt in target.alternatives):
                    found_here = hits.setdefault(other, [])
                    if len(found_here) < MAX_MATCHES_KEPT:
                        found_here.append((cipher, nonce_id, counter))
                    else:
                        over[other] = over.get(other, 0) + 1
        return hits, over

    def every_variant(length):
        return lambda target: variants_for(ciphers, length, target, counters)

    def variant_bound(length):
        """The most variants variants_for() gives a member for a key of this length (a nonce slice a member lacks gives fewer)."""
        most = 0
        for cipher in ciphers:
            if cipher in ("rc4", "xor"):
                most += 1 <= length <= 256
            elif length in KEY_LENGTHS[cipher]:
                limit = (1 << 32) - 1 if cipher == "chacha20-ietf" else (1 << 62)
                most += len(call.nonces_for.get(cipher, ())) * sum(1 for c in counters if c <= limit)
        return most

    rule_count = {}                 # place number -> how many members its rule opens (a count: I2)
    rule_own = {}                   # place number -> how many members gave its place
    best_derived = {"number": None, "count": 0, "hits": None}   # the best derived rule by 11, with its matches (the recipe's)

    def make_rule(number, own, hits, over):
        """A place that opened a member is a rule, with every member it opens (its own ones included: each with what pass 2 gave it).
        Returns whether it explains every member that has a crib. What it holds was counted when its place was listed (I2)."""
        for index, key_id in own.items():
            hits[index] = matched[key_id][index]
        for other, n in over.items():
            derived_not_kept[other] = derived_not_kept.get(other, 0) + n
        count = rule_count[number] = len(hits)
        rule_own[number] = len(own)
        at, ident = len(call_keys) + number, "D%d" % number
        for index, combos in hits.items():
            note_matches(index, at, ident, combos)
        if count > best_derived["count"] or (count == best_derived["count"] and number < best_derived["number"]):
            best_derived.update(number=number, count=count, hits=hits)     # the one it replaces is let go
        return count == len(with_crib)

    def as_opened_by(variants):
        def as_opened(target):
            # The nonce of each variant is looked up by its source, not by a list of every nonce the member has (a values file's worth).
            made = []
            for cipher, nonce_id, counter in variants:
                if not nonce_id:
                    made.append((cipher, nonce_id, b"", counter))
                    continue
                source = nonce_by_ident.get(nonce_id)
                value = source.value if isinstance(source, Fixed) else target.sliced.get(nonce_id) if source is not None else None
                if value:
                    made.append((cipher, nonce_id, value, counter))
            return made
        return as_opened

    screened = set()                # (6) places tried with what opened their own members, on every other member that has a crib
    settled = set()                 # (6, 7) places tried with every variant, on every other member that has a crib
    first_full = None               # (8) the number of the earliest place whose rule explains every member
    for number, place in enumerate(todo):
        if work["cut"] or sliced_full or first_full is not None:
            break
        own, own_variants = own_of(place)
        step = try_place(place, own, with_crib, as_opened_by(own_variants), len(own_variants))
        if step is None:
            break
        screened.add(number)
        hits, over = step
        if hits or len(own) > 1:
            # A place that opens a member, or that several members gave (each opened by the key the mask gives it), explains two members
            # or more. Every other variant on the members the place did not open (a member may use another counter or cipher).
            rest = try_place(place, own, [i for i in with_crib if i not in hits], every_variant(len(place[2])), variant_bound(len(place[2])),
                             set(own_variants))
            if rest is None:
                break                                    # cut halfway: no rule, not settled (9)
            for other, found_here in rest[0].items():
                hits.setdefault(other, []).extend(found_here)
            for other, n in rest[1].items():
                over[other] = over.get(other, 0) + n
            settled.add(number)
            if make_rule(number, own, hits, over):
                first_full = number
    for number, place in enumerate(todo):
        if work["cut"] or sliced_full or (first_full is not None and number >= first_full):
            break
        if number in settled:
            continue
        own, own_variants = own_of(place)
        step = try_place(place, own, with_crib, every_variant(len(place[2])), variant_bound(len(place[2])),
                         set(own_variants) if number in screened else ())
        if step is None:
            break                                        # cut halfway: no rule, not settled (9)
        settled.add(number)
        hits, over = step
        if (hits or len(own) > 1) and make_rule(number, own, hits, over):
            first_full = number
    # I1: ended (and so possibly complete) only when every place before the chosen rule's is settled, read from `settled` itself.
    ended = sliced_full or (first_full is not None and all(n in settled for n in range(first_full)))
    cause = work["cut"] or (listing_cut or "max_places" if places_not_listed else None)
    derivation_cut = bool(todo or places_not_listed) and not ended and cause is not None
    # The derived rules, numbered and listed by the number of their place (11), never by the pass or the moment that made them.
    for number in sorted(rule_count):
        region, skip, mask, place_groups = todo[number]
        length = len(mask)
        lead = min(place_groups[0].own, key=lambda i: members[i].key)
        source = Sliced("D%d" % number, "", region, length, skip, mask)
        source.label = "derived_rules[%d]: the %s %d bytes of each file%s XOR a %d-byte constant" % (
            len(derived), "first" if region == "head" else "last", length, " after skipping %d" % skip if skip else "", length)
        labels[source.ident] = source.label
        position[source.ident] = len(call_keys) + number
        key_sources.append(source)
        derived.append({"rule": source.label, "from_file": as_given(members[lead].path), "from_key": labels[place_groups[0].own[lead]],
                        **({"also_from_files": rule_own[number] - 1} if rule_own[number] > 1 else {}),
                        "constant": "the key that opened from_file XOR that file's own bytes at the same place. It is not here: when this "
                                    "rule is the recipe's, the recipe file holds it (key.xor_hex) and says whether it is all zero",
                        "region": region, "skip": skip, "length": length, "explains": rule_count[number], "of": len(with_crib)})
    derived_trials = work["trials"]
    total_trials += derived_trials
    derivation.update({"trials": derived_trials, "places_tried_on_every_member": len(settled), "stopped_by": cause if derivation_cut else None,
                       "places_not_tried_once_one_rule_explained_every_member":
                           sum(1 for n in range(first_full + 1, len(todo)) if n not in settled) + places_not_listed
                           if ended and first_full is not None else 0,
                       "memory_counted_at_most_bytes": budget.peak,
                       "keys_longer_than_%d_bytes_not_used" % MAX_DERIVED_KEY: too_long,
                       "plan": "for each key that is not a slice and each member it opened: that key XOR the member's own last bytes (and, inside "
                               "header_bytes, first bytes) at every skip from 0 to %d is one constant mask; each is tried on every other member "
                               "that has a crib, first with every cipher, nonce source and counter that opened a member the place was made "
                               "from, then with every cipher, nonce and counter in `tried`. The pairs and places are taken in an order of "
                               "their bytes (the longest crib first), never of the members' names: pairs equal in those bytes are one group "
                               "(pair_groups), and a place made by several pairs carries all of them. A place is tried whole or not at all "
                               "under max_trials. It ends when every place was tried so, or when one rule explains every member and every "
                               "place before it was tried so (else a bound that stopped it makes the answer partial); at most %d places are "
                               "listed (places_not_listed counts the others, per group, before equal masks are merged), and what it holds is "
                               "counted against a budget of %d MiB (memory_budget_bytes), which stops it before it is passed"
                               % (MAX_SKIP, MAX_PLACES, HYPOTHESIS_MEMORY >> 20)})
    if not derive:
        derivation = {"made": False}

    # Verdicts (13), and the rule that explains the most members (11).
    expected_total = 0.0
    for index in with_crib:
        row, member = rows[index], members[index]
        row["trials"] += extra.get(index, 0)
        if derived_not_kept.get(index):
            row["matches_not_kept"] = row.get("matches_not_kept", 0) + derived_not_kept[index]
        row["expected_false_positives"] = float("%.3g" % (row["trials"] * chance(member.alternatives)))
        expected_total += row["trials"] * chance(member.alternatives)
        count = found.get(index, 0)
        row["verdict"] = "match" if count else "no_match"
        if not count and derivation_cut:
            row["note"] = ("no source of the call opened it, and the footer hypothesis was stopped by %s before every place was tried on it: "
                           "this no_match covers the trials made, not the hypothesis" % cause)
        row["matches"] = [{"cipher": cipher, "counter": counter, "key": labels[key_id], "nonce": labels.get(nonce_id)}
                          for _at, _n, key_id, cipher, nonce_id, counter in shown.get(index, ())]
        if count > MAX_SHOWN:
            row["matches_not_listed"] = count - MAX_SHOWN
        if row["crib_bytes"] <= 4:
            row["crib_note"] = ("a %d-byte crib: one wrong trial in %d passes by chance, so %d trials are expected to give %s false positives on this "
                                "file. A longer crib (a plaintext twin, a magic of more bytes) or the same rule holding on other members is what "
                                "makes a match mean something" % (row["crib_bytes"], round(1 / chance(member.alternatives)), row["trials"], row["expected_false_positives"]))
    shown = found = None
    # The best rule (11): the most members, then a rule read from the files over a fixed key, then the earliest source. The derived
    # rules are counted, and the best of them (by the same order) kept its matches.
    explains = {key_id: len(per) for key_id, per in matched.items()}
    explains.update(("D%d" % number, count) for number, count in rule_count.items())
    rule_count = rule_own = None
    best = max(explains, key=lambda k: (explains[k], k not in fixed_keys, -position[k]), default=None)
    if best is not None and best not in matched:
        assert best == "D%d" % best_derived["number"]
        best_hits = best_derived["hits"]
    else:
        best_hits = matched.get(best)
    explained = explains[best] if best else 0
    if explained >= 2:
        # A member the best rule was tried on and did not open: its crib may not hold (a file whose content is not what its name
        # promises shows none), and that is no evidence against the rule. The row says so instead of leaving a bare no_match.
        for index in with_crib:
            row = rows[index]
            if row["verdict"] == "no_match" and "note" not in row:
                row["note"] = ("the best key rule (%s) opens %d other members and does not give this member's crib: either its content is "
                               "not the type its name says (then it has no crib, and this is no evidence against the rule) or it follows "
                               "another rule. family_decrypt with the recipe decrypts it and says whether the type is confirmed"
                               % (labels[best], explained))
    recipe_said, recipe_file, recipe_why = None, None, None
    source_of = {s.ident: s for s in key_sources + nonce_sources}
    if best and with_crib:
        tally = {}
        for index, combos in best_hits.items():
            for combo in combos:
                tally[combo] = tally.get(combo, 0) + 1
        order = sorted(tally, key=lambda combo: (-tally[combo], combo[0], combo[2], str(combo[1])))
        rank = {combo: n for n, combo in enumerate(order)}
        assignments, ambiguous = {}, 0
        for index, combos in sorted(best_hits.items(), key=lambda item: members[item[0]].key):   # by path, not by listing (12)
            assignments[members[index].key] = min(rank[combo] for combo in combos)
            ambiguous += len(combos) > 1

        def as_source(source):
            if source is None:
                return None
            if isinstance(source, Fixed):
                return {"hex": source.value.hex()}
            return {"slice": source.region, "length": source.length, "skip": source.skip, "xor_hex": source.mask.hex() if source.mask is not None else None}

        key_source = source_of[best]
        need_tail = max([s.skip + s.length for s in [key_source] + [source_of[n] for _c, n, _k in order if n] if isinstance(s, Sliced) and s.region == "tail"] or [0])
        recipe_trailer = trailer_given if trailer_given is not None else max(trailer, need_tail)
        # The extension the explained members share, compared in any case and kept as most of them write it.
        spelled = {}
        for i in best_hits:
            ending = os.path.splitext(members[i].name)[1]
            spelled[ending] = spelled.get(ending, 0) + 1
        suffix = max(sorted(spelled), key=spelled.get) if len({e.lower() for e in spelled}) == 1 else ""
        recipe = {
            "recipe": "stream-family/1", "made_by": PARSER,
            "key": as_source(key_source),
            "variants": [{"cipher": cipher, "counter": counter, "nonce": as_source(source_of.get(nonce_id))} for cipher, nonce_id, counter in order],
            "key_mask_all_zero": isinstance(key_source, Sliced) and key_source.mask is not None and not any(key_source.mask),
            "assignments": assignments,
            "assignments_by": "the member's path below the directory of the call (dir, or the directory the files share), with slashes",
            "header_bytes": header, "trailer_bytes": recipe_trailer,
            "member_suffix": suffix if len(suffix) > 1 and suffix[1:].lower() not in magics else None,
            "verified": {"members_explained": explained, "members_with_a_crib": len(with_crib), "expected_false_positives": float("%.3g" % expected_total)},
        }
        recipe_said = {
            "key": labels[best],
            "variants": [{"cipher": cipher, "counter": counter, "nonce": labels.get(nonce_id), "members": tally[(cipher, nonce_id, counter)]}
                         for cipher, nonce_id, counter in order[:MAX_RECIPE_VARIANTS]],
            **({"variants_not_listed": len(order) - MAX_RECIPE_VARIANTS} if len(order) > MAX_RECIPE_VARIANTS else {}),
            "header_bytes": header, "trailer_bytes": recipe_trailer,
            "trailer_basis": "given in the call" if trailer_given is not None else
                             ("at least the bytes the key and nonce slices take from the end; a longer trailer leaves its other bytes at the end of each "
                              "decrypted file. encrypted_survey's overhead against a plaintext twin is the measure" if recipe_trailer else "none assumed"),
            "member_suffix": recipe["member_suffix"],
            "explains": "%d of the %d members that have a crib" % (explained, len(with_crib)),
            **({"members_with_more_than_one_matching_variant": ambiguous} if ambiguous else {}),
        }
        directory, shown, in_job, secret = job_place()
        if explained < 2 and explained < len(with_crib):
            recipe_why = ("not written: the best rule explains %d of %d members, which is one known (file, key) pair, not a rule for the family. "
                          "Use it: see rules" % (explained, len(with_crib)))
        elif len(order) > MAX_RECIPE_VARIANTS:
            recipe_why = ("not written: the best rule matched with %d combinations of cipher, nonce and counter, and family_decrypt reads at most "
                          "%d. A rule that needs that many is a crib too short to tell them apart: narrow ciphers, counters or nonce_sources"
                          % (len(order), MAX_RECIPE_VARIANTS))
        elif not (in_job and secret):
            recipe_why = ("not written: the recipe holds key material and this run is not a job run as secret output. Run it as job_run "
                          "tool=stream_kpa_check (the manifest makes the job secret output)")
        else:
            try:
                name = write_recipe(directory, json.dumps(recipe, indent=1) + "\n")
                recipe_file = "%s/%s" % (shown, name)
            except OSError as exc:
                recipe_why = "not written: the recipe file could not be created (%s)" % describe(exc)
    counts = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    reasons = []
    if more:
        reasons.append("%s%d more files matched and were not checked: max_files is %d" % ("at least " if skipped.get("directories_not_listed_past_max_files") else "", more, max_files))
    if not_tried_members:
        reasons.append("the time limit (max_seconds %d) was reached: %d members were not tried" % (max_seconds, not_tried_members))
    if no_trial_members:
        reasons.append("%d members that have a crib had no trial at all: no source yields a key (and, where a cipher needs one, a nonce) of a "
                       "length a cipher asked for takes. That is not a negative for them" % no_trial_members)
    not_tried = list(NOT_TRIED)
    idle = [cipher for cipher in ciphers if not trials_by_cipher[cipher]]
    if idle and (with_crib or no_trial_members):
        not_tried.append("asked for and not tried, on any member: %s. No trial was made with %s: the sources yield no key of a length it takes, "
                         "or no nonce of a length it takes (see tried.layouts and tried.trials_by_cipher)" % (", ".join(idle), "it" if len(idle) == 1 else "them"))
    not_kept = {"members": sum(1 for row in rows if row.get("matches_not_kept")), "matches": sum(row.get("matches_not_kept", 0) for row in rows)}
    if not_kept["matches"]:
        reasons.append("%d matching combinations were counted and not kept: more than %d matched on %d members (or for one derived rule on one "
                       "member), which a crib this short gives by chance. The key rule, the footer hypothesis and the recipe were made from "
                       "the kept ones; give a longer crib (magics, a plaintext twin) or fewer sources" % (not_kept["matches"], MAX_MATCHES_KEPT, not_kept["members"]))
    if derivation_cut:
        unlisted = (" %d more places (past the first %d listed, counted before equal masks are merged) were not listed or tried."
                    % (places_not_listed, len(todo)) if places_not_listed else "")
        earlier = (" A rule explains every member, and %d places before its place were not tried with every cipher, nonce and counter: "
                   "one of them could have explained as many and been preferred, so the rule is not settled as the family's."
                   % sum(1 for n in range(first_full) if n not in settled) if first_full is not None else "")
        if cause == "max_places":
            said = ("the footer hypothesis has more places (a key that opened a member XOR that member's own bytes, at one end and one skip) than "
                    "the %d it lists: the %d listed were tried on every member that has a crib, with every cipher, nonce and counter, and%s "
                    "A no_match of this answer does not cover them" % (MAX_PLACES, len(todo), unlisted))
        else:
            bound = {"max_trials": "max_trials (%d) was reached" % max_trials,
                     "max_seconds": "the time limit (max_seconds %d) was reached" % max_seconds,
                     "max_memory": "the footer hypothesis's memory budget (%d MiB, counted as it grew: its pairs, groups, places, rules and kept "
                                   "matches) would have been passed" % (HYPOTHESIS_MEMORY >> 20)}[cause]
            said = ("%s while the footer hypothesis was being tried: %d of its %d places listed (a key that opened a member XOR that member's own "
                    "bytes, at one end and one skip) were tried on every member that has a crib, with every cipher, nonce and counter; the "
                    "others were not, so a no_match of this answer does not cover them.%s%s" % (bound, len(settled), len(todo), unlisted, earlier))
        reasons.append(said)
        narrow = ("narrow it" if cause == "max_memory" else "raise max_trials (at most 5000000) or max_seconds, or narrow it")
        not_tried.append("the footer hypothesis, in part: %s. To finish it, %s: give the key that opened a member as the only key source, with "
                         "the one nonce and cipher it matched" % (said, narrow))
    if too_long and derive:
        not_tried.append("the footer hypothesis from a key of more than %d bytes: %d such keys opened a member and no mask was derived from them" % (MAX_DERIVED_KEY, too_long))
        if not ended:
            reasons.append("the footer hypothesis was not made from %d keys of more than %d bytes that opened a member, and no rule explains "
                           "every member" % (too_long, MAX_DERIVED_KEY))
    for spec in call.unused_slices:
        not_tried.append("%s: a slice of %d bytes, a length that no cipher asked for takes as a %s; it was not read"
                         % (spec.label.split(":")[0], spec.length, "key" if spec in call_keys else "nonce"))
    if counts.get("read_failed"):
        reasons.append("%d files could not be read" % counts["read_failed"])
    if any(skipped.values()):
        reasons.append("in the directory: %s" % ", ".join("%d %s" % (n, what.replace("_", " ")) for what, n in skipped.items() if n))
    if not rows:
        reasons.append("no file matched: nothing was checked")
    if not with_crib and (no_trial_members or not_tried_members):
        outcome = "nothing_tried"
        finding = ("no member has a verdict: on %d members that have a crib no trial could be made (the sources yield no key, or no nonce, of a "
                   "length a cipher asked for takes), and %d members were left by the time limit (their trials were cut, or they were not "
                   "reached). That says nothing about any key" % (no_trial_members, not_tried_members))
    elif not with_crib:
        outcome = "nothing_to_check"
        finding = ("no member has a crib (a known type in its name, a plaintext twin or a magic given in the call): nothing was tried, and that "
                   "says nothing about any key")
    elif explained == len(with_crib):
        outcome = "one_rule_explains_every_member"
        finding = "one key rule gives the expected first bytes on all %d members that have a crib: see recipe" % explained
    elif explained:
        outcome = "some_members_explained"
        finding = ("the best key rule gives the expected first bytes on %d of %d members that have a crib. A key that opens ONE member is a known "
                   "(file, key) pair: compare it with that file's first and last bytes (derive does this for a constant XOR mask up to %d "
                   "bytes from either end; tried.derivation says how far it got); the rule for the others is not shown yet" % (explained, len(with_crib), MAX_SKIP))
    else:
        outcome = "no_combination_matched"
        finding = ("none of the %d trials gave the expected first bytes on any of the %d members that have a crib. That is a negative for the "
                   "ciphers, counters, layouts and sources in `tried` only: it does not say that no key exists or that the files cannot be "
                   "decrypted. See not_tried" % (total_trials, len(with_crib)))
    # The lists the answer shows `limit` of (the member rows, the derived rules): when either is cut, both are kept whole in the result file.
    derived_said = derived
    result_file, result_why = None, None
    if len(rows) > limit or len(derived_said) > limit:
        directory, shown, _in_job, _secret = job_place()
        try:
            name = write_result(directory, {"tool": TOOL, "parser": PARSER, "version": VERSION, "files": rows, "derived_rules": derived_said})
            result_file = "%s/%s" % (shown, name)
        except OSError as exc:
            result_why = "not written: the result file could not be created (%s)" % describe(exc)
            reasons.append("the answer shows %d of its member rows and derived rules, and the result file that would hold them whole could "
                           "not be written (%s)" % (limit, describe(exc)))
    status = "partial" if reasons else "complete"
    basis = ("; ".join(reasons) if reasons else
             "every member named was opened and, where it has a crib, every combination in `tried` was run on its first %d bytes (%d trials in "
             "all); `complete` says the check ran whole, `outcome` says what it found" % (HEAD, total_trials))
    print_answer({
        "tool": TOOL, "parser": PARSER, "version": VERSION, "status": status, "complete": status == "complete", "status_basis": basis,
        "partial_reasons": reasons, "outcome": outcome, "finding": finding,
        "members": {"named": len(rows), "with_a_crib": len(with_crib), "by_verdict": dict(sorted(counts.items()))},
        "trials": total_trials, "expected_false_positives_in_all": float("%.3g" % expected_total),
        "false_positive_basis": "per member: trials times the chance that random bytes show its crib (2 to the power of minus 8 times the crib's "
                                "length, summed over the alternatives of its type)",
        "tried": {**tried, "trials_by_cipher": trials_by_cipher, "derivation": derivation},
        "not_tried": not_tried,
        "derived_rules": derived_said[:limit], **({"derived_rules_not_listed": len(derived_said) - limit} if len(derived_said) > limit else {}),
        "recipe": recipe_said, "recipe_file": recipe_file, **({"recipe_file_why": recipe_why} if recipe_why else {}),
        "contains_secret_values": bool(recipe_file),
        "next": ("family_decrypt with {\"recipe_file\": \"%s\"} and the same dir or files" % recipe_file) if recipe_file else None,
        "files": rows[:limit], "truncated": len(rows) > limit or len(derived_said) > limit,
        **({"files_not_listed": len(rows) - limit} if len(rows) > limit else {}),
        **({"result_file": result_file} if result_file else {}), **({"result_file_why": result_why} if result_why else {}),
        "reading": "A match is the expected first bytes under one combination, on a crib of the length shown: it is not an integrity check, "
                   "and a stream cipher has none. No plaintext byte and no key, nonce or mask byte is in this answer, nor whether a mask is "
                   "all zero; the recipe file holds key material.",
        "rules": RULES, **({"unrecognised_parameters": unknown} if unknown else {}),
    }, indent=2)


if __name__ == "__main__":
    exit_code = 0
    try:
        answered(main, forget_recipe)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
