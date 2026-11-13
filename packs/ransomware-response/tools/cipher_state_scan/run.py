#!/usr/bin/env python3
"""Scan a file (a process dump, a memory image, any binary) for the shapes a cipher leaves in memory, and say what was looked for.

What it finds, each hit a CANDIDATE with its offset until it is checked against a file (stream_kpa_check):

  * ChaCha and Salsa20 states: the constant "expand 32-byte k" (or "expand 16-byte k") as the four constant words of a 64-byte state,
    contiguous (ChaCha) or at words 0, 5, 10 and 15 (Salsa20), with the key, the block counter and the nonce decoded in both ChaCha
    layouts (the original one, a 64-bit counter and an 8-byte nonce; the IETF one, a 32-bit counter and a 12-byte nonce);
  * AES key schedules: 176, 208 or 240 bytes that are the FIPS-197 expansion of their own first 16, 24 or 32 bytes (the encryption
    schedule, words as stored or byte-swapped);
  * 256-byte permutations (the shape of an RC4 state kept as bytes, and of any substitution table);
  * well-known constant tables as markers of which algorithms a program carries (AES S-boxes and Te0, SHA-256 and SHA-512 round
    constants, the SHA-256 initial values, the MD5 sine table, the MD5/SHA-1 initial state, the CRC-32 table, the Blowfish P-array).

The file is read once, in 16 MiB pieces that overlap by 4096 bytes; nothing is searched byte by byte in Python (constants with
bytes.find, the AES and the permutation shapes with whole-buffer integer arithmetic and one regular expression). Before the file is
read a control is run: every shape is planted in random bytes and must be found at its planted offset, so that "no hit" is a negative
for the shapes listed, and only for them. Keys and nonces are key material: the answer carries counts, kinds and offsets, and the
decoded values go only to a values file under $OUT in a job run as secret output (the manifest makes every job of this tool one).
A stop signal ends it with one JSON answer (status failed, interrupted); its own clock (max_seconds) ends it with a partial answer that
says how far it read.
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
import hashlib
import math
import re
import stat
import struct
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

TOOL = "cipher_state_scan"
VERSION = 2
PARSER = "cipher_state_scan/2"
CHUNK = 16 << 20
OVERLAP = 4096
MAX_HITS = 20000                  # hits kept (each is a few hundred bytes of JSON); past it they are counted and the answer is partial
MAX_VALUES = 5000                 # rows of the values file
RC4_DISTANCES = 10                # a permutation has no two equal bytes at these distances: the filter before the exact check
DEFAULT_SECONDS, MAX_SECONDS = 780, 840
KNOWN_PARAMS = {"file", "offset", "look_for", "limit", "max_seconds", "self_test"}
SHAPES = ("chacha-salsa", "aes-schedule", "rc4", "tables")
SIGMA, TAU = b"expand 32-byte k", b"expand 16-byte k"
CONTAINERS = (
    (0, b"\x1f\x8b\x08", "gzip"), (0, b"PK\x03\x04", "zip"), (0, b"7z\xbc\xaf\x27\x1c", "7-Zip"), (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"\x28\xb5\x2f\xfd", "zstd"), (0, b"BZh", "bzip2"), (0, b"\x04\x22\x4d\x18", "lz4"), (0, b"ADSEGMENTEDFILE", "AD1 (zlib-compressed items)"),
    (0, b"EVF\x09\x0d\x0a\xff\x00", "EnCase E01 (compressed chunks)"), (0, b"EVF2\x0d\x0a\x81\x00", "EnCase Ex01 (compressed chunks)"),
    (0, b"Rar!\x1a\x07", "RAR"), (0, b"hibr", "a Windows hibernation file (compressed pages)"), (0, b"HIBR", "a Windows hibernation file (compressed pages)"),
)


# The tables below are computed, not typed in: the AES S-box from the field inverse and the affine map, the SHA-2 constants from the
# roots of the primes, the MD5 table from the sine, the CRC table from its polynomial.
def _aes_sbox():
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
    return bytes(sbox)


AES_SBOX = _aes_sbox()


def aes_expand_key(key):
    """The FIPS-197 key schedule of a 16, 24 or 32-byte key, as one byte string (176, 208 or 240 bytes)."""
    nk = len(key) // 4
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


def first_word_fits(region, key_bytes, swapped):
    """Whether word Nk of a region is w[0] XOR SubWord(RotWord(w[Nk-1])) XOR 01000000, the first step of the FIPS-197 expansion."""
    first, last, made = region[:4], region[key_bytes - 4:key_bytes], region[key_bytes:key_bytes + 4]
    if swapped:
        first, last, made = first[::-1], last[::-1], made[::-1]
    return (made[0] == first[0] ^ AES_SBOX[last[1]] ^ 1 and made[1] == first[1] ^ AES_SBOX[last[2]]
            and made[2] == first[2] ^ AES_SBOX[last[3]] and made[3] == first[3] ^ AES_SBOX[last[0]])


def _root(n, k):
    """The integer k-th root of n (floor)."""
    x = 1 << -(-n.bit_length() // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            return x
        x = y


def _tables():
    primes = [p for p in range(2, 410) if all(p % d for d in range(2, int(p ** 0.5) + 1))][:80]
    k256 = [_root(p << 96, 3) & 0xFFFFFFFF for p in primes[:64]]
    h256 = [_root(p << 64, 2) & 0xFFFFFFFF for p in primes[:8]]
    k512 = [_root(p << 192, 3) & 0xFFFFFFFFFFFFFFFF for p in primes]
    md5 = [int(abs(math.sin(i + 1)) * 4294967296) & 0xFFFFFFFF for i in range(64)]
    crc = []
    for i in range(256):
        c = i
        for _bit in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        crc.append(c)
    inverse = bytearray(256)
    for i, v in enumerate(AES_SBOX):
        inverse[v] = i
    double = [((v << 1) ^ (0x1B if v & 0x80 else 0)) & 0xFF for v in AES_SBOX]
    te0 = [(d << 24) | (v << 16) | (v << 8) | (d ^ v) for d, v in zip(double, AES_SBOX)]
    blowfish = [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0]
    return [
        ("AES S-box", AES_SBOX), ("AES inverse S-box", bytes(inverse)),
        ("AES Te0 table, little-endian words", struct.pack("<256I", *te0)), ("AES Te0 table, big-endian words", struct.pack(">256I", *te0)),
        ("SHA-256 round constants, little-endian words", struct.pack("<64I", *k256)), ("SHA-256 round constants, big-endian words", struct.pack(">64I", *k256)),
        ("SHA-256 initial hash values, little-endian words", struct.pack("<8I", *h256)), ("SHA-256 initial hash values, big-endian words", struct.pack(">8I", *h256)),
        ("SHA-512 round constants, little-endian words", struct.pack("<80Q", *k512)), ("SHA-512 round constants, big-endian words", struct.pack(">80Q", *k512)),
        ("MD5 sine table, little-endian words", struct.pack("<64I", *md5)),
        ("MD5 / SHA-1 initial state, little-endian words", bytes.fromhex("0123456789abcdeffedcba9876543210")),
        ("CRC-32 table, little-endian words", struct.pack("<256I", *crc)),
        ("Blowfish P-array (its first six words), little-endian words", struct.pack("<6I", *blowfish)),
        ("Blowfish P-array (its first six words), big-endian words", struct.pack(">6I", *blowfish)),
    ]


TABLES = _tables()
AES_SHAPES = (
    # key bytes, schedule bytes, the two shifts of the XOR relation w[i] = w[i-1] ^ w[i-Nk], and what that relation leaves in the buffer
    (16, 176, 12, 16, re.compile(b"\x00" * 12 + b"(?:(?!\x00\x00\x00\x00)....\x00{12}){9}", re.S)),
    (24, 208, 20, 24, re.compile(b"\x00" * 20 + b"(?:(?!\x00\x00\x00\x00)....\x00{20}){6}", re.S)),
    (32, 240, 28, 32, re.compile(b"\x00" * 12 + b"(?:(?!\x00\x00\x00\x00)....\x00{12}){12}", re.S)),
)
LOOKED_FOR = {
    "chacha-salsa": [
        "ChaCha state: the 16 bytes 'expand 32-byte k' (or 'expand 16-byte k') followed by 48 more bytes, decoded as key (32 bytes, or 16 "
        "twice), then counter and nonce in both layouts: original (64-bit counter, 8-byte nonce) and IETF (32-bit counter, 12-byte nonce)",
        "Salsa20 state: the same constant as four words at bytes 0, 20, 40 and 60 of 64, decoded as key, 8-byte nonce and 64-bit counter",
    ],
    "aes-schedule": [
        "AES encryption key schedule for a 128, 192 or 256-bit key: 176, 208 or 240 bytes that equal the FIPS-197 expansion of their own "
        "first 16, 24 or 32 bytes, with the words as stored or byte-swapped",
    ],
    "rc4": ["a 256-byte permutation of 0..255 (an RC4 state kept as a byte array has this shape; so has any substitution table)"],
    "tables": ["constant tables, whole or a prefix of 16 bytes or more: " + "; ".join(name for name, _table in TABLES)],
}
NOT_LOOKED_FOR = [
    "a state or a key with no constant beside it (a raw 32-byte key on a stack or a heap is not found: random bytes have no shape)",
    "ChaCha or Salsa20 constants stored as big-endian words, or built in registers and never stored",
    "AES decryption schedules (the equivalent inverse cipher), bit-sliced or AES-NI-only key forms that are not the FIPS-197 words, a "
    "schedule only part of which is in the file, and a schedule in which the key expansion's own step gives a zero word (SubWord(RotWord(w)) "
    "equal to the round constant, or for AES-256 SubWord(w) of all zero bytes: about one random key in 2^29). Zero bytes in or around a "
    "schedule do not hide it: the schedule of the all-zero key is found, and so is one that ends or begins with zero bytes among zero pages",
    "an RC4 state kept as 32-bit integers (OpenSSL's RC4_KEY), and the i and j of a byte state",
    "any cipher not listed (HC-128, Sosemanuk, Rabbit, XTEA, RSA or elliptic-curve private keys), and anything inside compressed, "
    "encrypted or paged-out content: the bytes are read as they are in the file",
]


def chacha_state(buf, at):
    """What a 64-byte ChaCha state at `at` decodes to: (the row of the answer, the row of the values file)."""
    state = buf[at:at + 64]
    short = state[:16] == TAU
    key = state[16:32] if short else state[16:48]
    distinct = len(set(key))
    shown = {
        "kind": "chacha-state", "matched": "expand %d-byte k, contiguous" % (16 if short else 32), "bytes": 64, "key_bytes": len(key),
        "key_distinct_byte_values": distinct,
        "key_shape": ("looks random" if distinct >= (12 if short else 20) else
                      "low variety (zeros, text or code): more likely the bare constant in a binary than a keyed state"),
        "counter_32bit": int.from_bytes(state[48:52], "little"),
    }
    if short:
        shown["key_halves_equal"] = state[16:32] == state[32:48]
    # Whether the four bytes after the 32-bit counter are zero says four bytes of the IETF nonce when it is true: it goes with the values.
    values = {"key_hex": key.hex(), "bytes_52_to_56_zero": state[52:56] == bytes(4),
              "layouts": {"ietf": {"counter": int.from_bytes(state[48:52], "little"), "nonce_hex": state[52:64].hex()},
                          "original": {"counter": int.from_bytes(state[48:56], "little"), "nonce_hex": state[56:64].hex()}}}
    return shown, values


def salsa_state(buf, at):
    state = buf[at:at + 64]
    short = state[20:24] == b"nd 1"
    key = state[4:20] if short else state[4:20] + state[44:60]
    distinct = len(set(key))
    shown = {
        "kind": "salsa20-state", "matched": "expand %d-byte k, at words 0, 5, 10 and 15" % (16 if short else 32), "bytes": 64,
        "key_bytes": len(key), "key_distinct_byte_values": distinct,
        "key_shape": "looks random" if distinct >= (12 if short else 20) else "low variety (zeros, text or code)",
        "counter_32bit": int.from_bytes(state[32:36], "little"), "counter_high_word_zero": state[36:40] == bytes(4),
    }
    if short:
        shown["key_halves_equal"] = state[4:20] == state[44:60]
    values = {"key_hex": key.hex(), "layouts": {"salsa20": {"counter": int.from_bytes(state[32:40], "little"), "nonce_hex": state[24:32].hex()}}}
    return shown, values


def find_all(buf, needle, end):
    at = buf.find(needle)
    while 0 <= at < end:
        yield at
        at = buf.find(needle, at + 1)


def scan_buffer(buf, own, shapes, emit, counts):
    """Every hit that starts in buf[:own] (the rest of buf is the overlap a shape may run into). emit(offset in buf, shown, values)."""
    if "chacha-salsa" in shapes:
        for needle in (SIGMA, TAU):
            for at in find_all(buf, needle, own):
                if at + 64 <= len(buf):
                    emit(at, *chacha_state(buf, at))
                else:
                    emit(at, {"kind": "chacha-constant", "matched": needle.decode("ascii"), "bytes": 16,
                              "note": "the file ends less than 64 bytes after it: no state is decoded"}, None)
        for at in find_all(buf, b"expa", own):
            piece = buf[at:at + 64]
            if len(piece) == 64 and piece[60:64] == b"te k" and (piece[20:24], piece[40:44]) in ((b"nd 3", b"2-by"), (b"nd 1", b"6-by")):
                emit(at, *salsa_state(buf, at))
    if "tables" in shapes:
        for name, table in TABLES:
            for at in find_all(buf, table[:16], own):
                piece = buf[at:at + len(table)]
                same = len(table) if piece == table else next(i for i in range(len(piece) + 1) if i == len(piece) or piece[i] != table[i])
                emit(at, {"kind": "constant-table", "matched": name, "bytes": same, "table_bytes": len(table), "whole": same == len(table)}, None)
    if not ("aes-schedule" in shapes or "rc4" in shapes) or len(buf) < 176:
        return
    size = len(buf)
    number = int.from_bytes(quiet_zero_runs(buf), "little")
    if "aes-schedule" in shapes:
        for key_bytes, length, near, far, pattern in AES_SHAPES:
            relation = (number ^ (number >> (8 * near)) ^ (number >> (8 * far))).to_bytes(size, "little")
            # Every place the pattern holds, the overlapping ones too: among zero bytes the relation of a schedule's first words also holds
            # a few bytes early, and a search that went on after the end of that early match would step over the schedule itself.
            match = pattern.search(relation)
            while match is not None:
                at = match.start() - 4
                match = pattern.search(relation, at + 5)
                if not 0 <= at < own or at + length > size:
                    continue
                region = buf[at:at + length]
                order = None
                # The first word the expansion makes is checked before the whole schedule is: data that only repeats the relation
                # (a table of words 16 bytes apart) is then refused in a few operations per place, not by a whole key expansion.
                if first_word_fits(region, key_bytes, False) and aes_expand_key(region[:key_bytes]) == region:
                    order = "as FIPS-197 writes them"
                elif first_word_fits(region, key_bytes, True):
                    swapped = b"".join(region[i:i + 4][::-1] for i in range(0, length, 4))
                    if aes_expand_key(swapped[:key_bytes]) == swapped:
                        order, region = "byte-swapped words (a 32-bit big-endian load on a little-endian machine)", swapped
                if order is None:
                    counts["aes_like_not_a_schedule"] += 1
                    continue
                emit(at, {"kind": "aes-%d-key-schedule" % (8 * key_bytes), "matched": "FIPS-197 key expansion, %d bytes" % length, "bytes": length,
                          "key_bytes": key_bytes, "word_order": order}, {"key_hex": region[:key_bytes].hex()})
    if "rc4" in shapes:
        ones = RC4_ONES.get(size)
        if ones is None:
            RC4_ONES.clear()
            ones = RC4_ONES[size] = int.from_bytes(b"\x01" * size, "little")
        low7 = ones * 0x7F
        equal = 0
        for distance in range(1, RC4_DISTANCES + 1):
            x = number ^ (number >> (8 * distance))
            equal |= ~(((x & low7) + low7) | x)                                    # the top bit of each byte that is zero in x
        marks = (equal & (ones * 0x80)).to_bytes(size, "little")
        run = bytes(256 - RC4_DISTANCES)
        at = marks.find(run)
        misses = 0
        while 0 <= at < own:
            piece = buf[at:at + 256]
            if len(piece) == 256 and len(set(piece)) == 256:
                if piece == RAMPS[piece[0]:piece[0] + 256]:
                    counts["identity_tables"] += 1                                # 00 01 02 ... in any rotation: a ramp, not a keyed state
                    at = marks.find(run, at + 256)
                    continue
                # The window one byte on is a permutation too whenever the byte after this one equals its first byte: where the
                # permutation starts is then not decided by its shape, and every such offset is said with the hit.
                slide = 0
                while slide < 255 and at + 256 + slide < size and buf[at + 256 + slide] == buf[at + slide]:
                    slide += 1
                if any(buf[at + k:at + k + 256] in (TABLES[0][1], TABLES[1][1]) for k in range(slide + 1)):
                    counts["aes_sbox_permutations"] += 1                          # the AES S-box or its inverse: a table, named under "tables"
                else:
                    emit(at, {"kind": "rc4-permutation", "matched": "a permutation of 0..255", "bytes": 256,
                              "also_a_permutation_at_the_next_offsets": slide,
                              "note": "an RC4 state kept as bytes has this shape, and so has any substitution table; the key is not "
                                      "recoverable from a state, and the two indices i and j are not located"},
                         {"permutation_hex": piece.hex(), "also_a_permutation_at_the_next_offsets": slide, "bytes_after_hex": buf[at + 256:at + 256 + slide].hex()})
                at = marks.find(run, at + 256 + slide)
            else:
                misses += 1
                if misses > RC4_MISSES:
                    counts["permutation_search_cut_pieces"] += 1                  # data with no near repeats and no permutation: bounded work
                    break
                at = marks.find(run, at + 1)


RC4_ONES = {}
RAMPS = bytes(range(256)) * 2
ZERO_KEEP = 64                    # zero bytes left as they are at each end of a long zero run (a schedule holds 50 in a row at most)


def quiet_zero_runs(buf):
    """A copy of the bytes for the two whole-buffer searches, with the INSIDE of long zero runs made non-zero: over a zero page every XOR
    relation holds and no two bytes differ, and the pattern search would crawl over it. Only bytes that lie in a run of 256 or more zero
    bytes and at least ZERO_KEEP bytes from each of its ends are changed. A key schedule cannot hold such a byte: its words satisfy
    w[i] = w[i-Nk] ^ f(w[i-1]) and f of a zero word is not zero where a round begins, so it has at most 11 zero words in a row (44 bytes,
    and up to 3 zero bytes of the word on each side: 50). A zero run that begins in a schedule's last word or ends in its first is
    therefore left as it is for at least the bytes the schedule has in it; a permutation holds one zero byte. Every candidate is
    checked against the file's own bytes, never against this copy."""
    for block in (4096, 256):
        buf = buf.replace(bytes(block), bytes(ZERO_KEEP) + b"\xa5" * (block - 2 * ZERO_KEEP) + bytes(ZERO_KEEP))
    return buf
RC4_MISSES = 200000               # near-permutations checked and refused per piece before the search of that piece is given up


def scan(read_at, size, shapes, chunk, emit, counts, progress, start=0):
    """Read [0, size) in pieces of `chunk` bytes plus the overlap and scan each; returns the offset reading stopped at."""
    at = start
    while at < size:
        buf = read_at(at, min(chunk + OVERLAP, size - at))
        if not buf:
            break
        own = min(chunk, len(buf))
        scan_buffer(buf, own, shapes, lambda rel, shown, values, base=at: emit(base + rel, shown, values), counts)
        at += own
        progress["bytes_scanned"] = at
        if len(buf) < min(chunk + OVERLAP, size - (at - own)) or out_of_time():
            break
    return at


def control(shapes):
    """Plant every shape in random bytes and find it again with the code that reads the file. The pieces are small (64 KiB), so that
    plants sit at a piece's edge and in its overlap too."""
    chunk = 1 << 16
    data = bytearray(os.urandom(8 * chunk + 999))
    planted = []

    def plant(at, blob, kind, shape):
        data[at:at + len(blob)] = blob
        if shape in shapes:
            planted.append((at, kind))

    key = os.urandom(32)
    plant(1000, SIGMA + key + (7).to_bytes(4, "little") + os.urandom(12), "chacha-state", "chacha-salsa")
    plant(chunk - 20, SIGMA + os.urandom(48), "chacha-state", "chacha-salsa")                                 # across the edge of a piece
    plant(chunk + 3000, TAU + key[:16] + key[:16] + os.urandom(16), "chacha-state", "chacha-salsa")
    salsa = b"expa" + key[:16] + b"nd 3" + os.urandom(16) + b"2-by" + key[16:] + b"te k"
    plant(2 * chunk + 1000, salsa, "salsa20-state", "chacha-salsa")
    for n, where in ((16, 3 * chunk - 100), (24, 3 * chunk + 5001), (32, 4 * chunk - 239)):
        plant(where, aes_expand_key(os.urandom(n)), "aes-%d-key-schedule" % (8 * n), "aes-schedule")
    swapped = aes_expand_key(os.urandom(32))
    plant(4 * chunk + 2000, b"".join(swapped[i:i + 4][::-1] for i in range(0, 240, 4)), "aes-256-key-schedule", "aes-schedule")
    # Zero bytes around a schedule (the unused words of a key structure, a zeroed page) must not hide it. Planted: a schedule whose LAST
    # byte is zero with zero bytes after it and before it, for 128 and 256-bit keys, as stored and byte-swapped; one whose FIRST bytes
    # are zero after zero bytes; the schedule of the all-zero key between zero pages; and a 192-bit one between zero bytes.
    at = 5 * chunk + 2000
    if "aes-schedule" in shapes:
        def ending_in_zero(n, last):
            for _try in range(20000):
                made = aes_expand_key(os.urandom(n))
                if made[last] == 0:
                    return made
            raise Refused("the control could not draw an AES key whose schedule ends in a zero byte")

        def swap(made):
            return b"".join(made[i:i + 4][::-1] for i in range(0, len(made), 4))

        leading = aes_expand_key(bytes(3) + os.urandom(13))
        for blob, bits in ((ending_in_zero(16, -1), 128), (ending_in_zero(32, -1), 256), (swap(ending_in_zero(16, -4)), 128),
                           (swap(ending_in_zero(32, -4)), 256), (leading, 128), (swap(aes_expand_key(os.urandom(15) + bytes(1) + os.urandom(16))), 256),
                           (aes_expand_key(bytes(16)), 128), (aes_expand_key(bytes(32)), 256), (aes_expand_key(os.urandom(24)), 192)):
            for before, after in ((700, 700), (15, 15), (16, 4500)):
                data[at:at + before] = bytes(before)
                plant(at + before, blob, "aes-%d-key-schedule" % bits, "aes-schedule")
                data[at + before + len(blob):at + before + len(blob) + after] = bytes(after)
                at += before + len(blob) + after + 64
    perm = list(range(256))
    for i in range(255, 0, -1):
        j = int.from_bytes(os.urandom(2), "little") % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    plant(2 * chunk - 128, bytes(perm), "rc4-permutation", "rc4")
    plant(4 * chunk + 9000, TABLES[4][1], "constant-table", "tables")
    plant(5 * chunk + 100, TABLES[0][1], "constant-table", "tables")
    data = bytes(data)
    found = set()
    counts = {"aes_like_not_a_schedule": 0, "identity_tables": 0, "aes_sbox_permutations": 0, "permutation_search_cut_pieces": 0}

    def note(at, shown, _values):
        # A permutation whose neighbours make the window before or after it one too is found at any of those offsets.
        for k in range(shown.get("also_a_permutation_at_the_next_offsets", 0) + 1):
            found.add((at + k, shown["kind"]))

    scan(lambda at, n: data[at:at + n], len(data), shapes, chunk, note, counts, {})
    missed = [{"offset": at, "kind": kind} for at, kind in planted if (at, kind) not in found]
    return {"planted": len(planted), "found_at_planted_offset": len(planted) - len(missed), "passed": not missed, "missed": missed,
            "how": "each shape asked for is planted in %d random bytes (at the edge of a piece, in its overlap and inside it; AES schedules also "
                   "with a last or a first byte of zero among zero bytes, as stored and byte-swapped, and the schedule of the all-zero key "
                   "between zero pages) and searched with the code and the piece logic that read the file" % len(data)}


class Values:
    """The decoded keys and nonces, written only in a job run as secret output, to one file under $OUT (JSON Lines, mode 0600)."""

    NAME = "cipher-state-candidates.jsonl"

    def __init__(self):
        self.directory, shown, in_job, secret = job_place()
        self.written, self.dropped, self._fh, self.shown = 0, 0, None, None
        self.why = None
        if not in_job:
            self.why = ("not written: this run is not a job, and a file here would not be a sealed secret output. Run it as job_run "
                        "tool=cipher_state_scan (the manifest makes the job secret output); the hits and their offsets are still listed")
        elif not secret:
            self.why = ("not written: this job was not run as secret output (SECRET_OUTPUT is not 1), so its files would be sealed as "
                        "ordinary output. Run it as job_run tool=cipher_state_scan, or give a command job secret_output: true")
        else:
            try:
                fd, name = create_new(self.directory, self.NAME)
            except OSError as exc:
                self.why = "not written: the values file could not be created (%s)" % describe(exc)
                return
            self._fh = os.fdopen(fd, "w", encoding="ascii")
            self.shown = "%s/%s" % (shown, name)

    def add(self, row):
        if self._fh is None:
            return
        if self.written >= MAX_VALUES:
            self.dropped += 1
            return
        self._fh.write(json.dumps(row) + "\n")           # one row, one write: a stop cannot leave half a row
        self._fh.flush()
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self, candidates):
        return {"key_or_state_candidates": candidates, "written": self.written, "values_file": self.shown,
                "contains_secret_values": self.written > 0,
                **({"not_written": self.dropped, "cap": MAX_VALUES} if self.dropped else {}),
                **({"why": self.why} if self.why else {}),
                "format": "JSON Lines, mode 0600: finding_id, file, offset, kind, key_hex (or permutation_hex), and for a state `layouts`, "
                          "each with its counter and nonce_hex. Give the file to stream_kpa_check as {\"candidates\": \"<values_file>\"} in "
                          "key_sources and nonce_sources" if self.shown else None}


PROGRESS = {"bytes_scanned": 0}


def last_word(signum):
    print(json.dumps({"error": "stopped by signal %d before the scan was complete" % signum, "status": "failed", "interrupted": True,
                      "signal": signum, "offset_reached_so_far": PROGRESS.get("bytes_scanned", 0),
                      "status_basis": "the tool was stopped by signal %d: the file was not read to its end, so this is no negative; the hits "
                                      "it had found are not listed (a values file, if one was begun, holds the rows written by then)" % signum}),
          flush=True)


def write_hits(hits, key):
    directory, shown, _in_job, _secret = job_place()
    directory = directory / "tool-output"
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise OSError(errno.ENOTDIR, "tool-output is there and is not a directory of this run (a link or a file): nothing was written through it")
    name = "cipher_state_scan-hits-%s.jsonl" % hashlib.sha256(json.dumps(key, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    fd, name = create_new(directory, name, 0o644)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        for hit in hits:
            fh.write(json.dumps(hit) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return "%s/tool-output/%s" % (shown, name)


def main():
    install_signal_handlers(last_word)
    args, unknown = read_args(KNOWN_PARAMS)
    self_test = bool_param(args, "self_test")
    limit = int_param(args, "limit", 100, 1, MAX_HITS)
    max_seconds = int_param(args, "max_seconds", DEFAULT_SECONDS, 1, MAX_SECONDS)
    look_for = args.get("look_for")
    if look_for is None:
        shapes = list(SHAPES)
    elif isinstance(look_for, list) and look_for and all(isinstance(x, str) and x in SHAPES for x in look_for):
        shapes = [s for s in SHAPES if s in look_for]
    else:
        raise Refused("look_for is a list of one or more of: %s" % ", ".join(SHAPES))
    looked_for = [line for shape in shapes for line in LOOKED_FOR[shape]]
    set_deadline(max_seconds)
    common = {"tool": TOOL, "parser": PARSER, "version": VERSION, "looked_for": looked_for,
              "not_looked_for": NOT_LOOKED_FOR + ["the shapes left out by look_for: %s" % ", ".join(s for s in SHAPES if s not in shapes)] * (len(shapes) < len(SHAPES))}
    check = control(shapes)
    if self_test:
        print_answer({**common, "self_test": check, "status": "complete" if check["passed"] else "failed",
                      "status_basis": ("the planted control passed: %d of %d planted shapes were found at their planted offsets. No evidence was read"
                                       % (check["found_at_planted_offset"], check["planted"])) if check["passed"] else
                                      "the planted control FAILED (see self_test.missed): this build of the scanner misses shapes it claims to find, "
                                      "and no negative from it may be used",
                      "rules": RULES, **({"unrecognised_parameters": unknown} if unknown else {})}, indent=2)
        if not check["passed"]:
            raise SystemExit(1)
        return
    if not check["passed"]:
        fail("the planted control failed: the scanner did not find shapes it had planted itself, so the file was not read and no negative "
             "may be drawn", control=check, **common)
    path = path_param(args.get("file"), "file")
    try:
        fd, size = open_regular(path)
    except (OSError, ValueError) as exc:
        fail("the file could not be opened: %s" % (describe(exc) if isinstance(exc, OSError) else "not a usable path"), file=as_given(path), **common)
    start = int_param(args, "offset", 0, 0, 1 << 62)
    if start > size:
        os.close(fd)
        raise Refused("offset (%d) is past the end of the file (%d bytes)" % (start, size))
    head = pread_full(fd, 16, 0)
    container = next((name for at, magic, name in CONTAINERS if head[at:at + len(magic)] == magic), None)
    values = Values()
    hits, counts, kinds = [], {"aes_like_not_a_schedule": 0, "identity_tables": 0, "aes_sbox_permutations": 0, "permutation_search_cut_pieces": 0}, {}
    over = [0]
    candidates = [0]
    shown_path = as_given(path)

    def emit(offset, shown, secret):
        kinds[shown["kind"]] = kinds.get(shown["kind"], 0) + 1
        if len(hits) >= MAX_HITS:
            over[0] += 1
            return
        finding = "F%06d" % (len(hits) + 1)
        row = {"finding_id": finding, "offset": offset, **shown, "candidate": True}
        if secret is not None:
            candidates[0] += 1
            row["values"] = "in the values file" if values.shown else "not written"
            values.add({"finding_id": finding, "file": path, "offset": offset, "kind": shown["kind"], **secret})
        hits.append(row)

    reached = scan(lambda at, n: pread_full(fd, n, at), size, shapes, CHUNK, emit, counts, PROGRESS, start)
    os.close(fd)
    values.close()
    reasons = []
    if start:
        reasons.append("the scan began at offset %d (the offset parameter): the bytes before it were not read in this call" % start)
    if reached < size:
        reasons.append(("the time limit (max_seconds %d) was reached" % max_seconds if out_of_time() else "the file ended early or a read came back short")
                       + ": bytes %d to %d of %d were scanned, and nothing from offset %d on was looked at (run again with offset %d to go on)"
                       % (start, reached, size, reached, reached))
    if over[0]:
        reasons.append("%d hits past the first %d are counted in counts and not listed" % (over[0], MAX_HITS))
    if values.dropped:
        reasons.append("%d key or state candidates past the first %d are not in the values file" % (values.dropped, MAX_VALUES))
    if candidates[0] and not values.shown:
        reasons.append("%d key or state candidates were found and their values were not written (%s)" % (candidates[0], values.why))
    if counts["permutation_search_cut_pieces"]:
        reasons.append("the search for 256-byte permutations was given up in %d of the 16 MiB pieces: each held more than %d runs of bytes with no "
                       "near repeat that were not permutations, and the rest of such a piece was not searched for that shape (the other shapes were)"
                       % (counts["permutation_search_cut_pieces"], RC4_MISSES))
    if container:
        reasons.append("the file begins like %s: its content was not decompressed, so a state inside it could not match; scan the extracted "
                       "or decompressed content" % container)
    if size == 0:
        reasons.append("the file is empty")
    hits_file = None
    if len(hits) > limit:
        try:
            hits_file = write_hits(hits, [os.path.realpath(path), shapes])
        except OSError as exc:
            reasons.append("the list of all hits could not be written (%s): only the first %d are shown" % (describe(exc), limit))
    status = "partial" if reasons else "complete"
    if reasons:
        basis = "; ".join(reasons)
    elif hits:
        basis = ("the whole file (%d bytes) was read and the planted control passed; every hit is a candidate at an offset until a file "
                 "decrypts with it (stream_kpa_check)" % size)
    else:
        basis = ("the whole file (%d bytes) was read, none of the shapes in looked_for was found, and the planted control passed (%d of %d "
                 "planted shapes found): this is a negative for those shapes in these bytes only. It does not say that no key exists: "
                 "see not_looked_for" % (size, check["found_at_planted_offset"], check["planted"]))
    print_answer({
        **common, "file": shown_path, "bytes": size, "scanned_from": start, "scanned_to": reached, "bytes_scanned": reached - start, "status": status, "complete": status == "complete",
        "status_basis": basis, "partial_reasons": reasons, "control": check,
        "counts": {"hits": len(hits) + over[0], "by_kind": dict(sorted(kinds.items())), **counts},
        "hits": hits[:limit], "truncated": len(hits) > limit or bool(over[0]), **({"all_hits": hits_file, "all_hits_format": "JSON Lines"} if hits_file else {}),
        "candidates": values.summary(candidates[0]),
        "reading": "A hit is a shape at an offset, not a key that works. A ChaCha constant with low-variety bytes after it is the constant "
                   "in the program's data; one with random-looking bytes after it is a state candidate. Check candidates against the "
                   "encrypted files with stream_kpa_check; a key that opens one file and its trailer give the per-file rule.",
        "rules": RULES, **({"unrecognised_parameters": unknown} if unknown else {}),
    }, indent=2)


if __name__ == "__main__":
    exit_code = 0
    try:
        answered(main)
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
