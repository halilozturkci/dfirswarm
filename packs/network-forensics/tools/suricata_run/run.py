#!/usr/bin/env python3
"""Run local Suricata rules offline over a capture, and say exactly what ran.

What is recorded, so that the run can be repeated and its coverage judged:

  * The engine: `suricata --build-info`, kept whole in out_dir, and its version line.
  * The configuration. By default the tool writes suricata.yaml into out_dir (an explicit file: eve-log with its
    types listed by name and `tls: extended: yes`, the TLS fingerprint settings by key under app-layer) and records
    its path and SHA-256; nothing is addressed by list position. Everything the file does not set is the engine's
    own default, not your distribution's suricata.yaml: pass `config` (a local file, never one from inputs/) to use
    a configuration of your own. Whether a build accepts the keys written here is decided by the engine, not
    assumed: the configuration is tested with `suricata -T` BEFORE the run, and when that fails nothing is run and
    the diagnostic is returned whole. The file also sets the variables rules are written against (HOME_NET from the
    `home_net` argument or the private ranges, and the other address and port groups under their usual names): a rule
    naming a variable the file does not define does not load. Those values are this tool's assumptions and are said in
    the answer; a rule using another variable needs `config`. A `config` or a `rules` file from inputs/ is refused:
    both can name scripts and files the engine reads, and would be code the evidence supplied.
  * The rules: path, SHA-256, size and the number of rule lines in the file (a count of lines, not of rules the
    engine loaded). The numbers Suricata itself prints about loading rules ("N rules successfully loaded, M rules
    failed") are read from its own output when they are there: a rule that failed to load, or none loaded from a file
    that has rule lines, fails the run, and when the engine printed nothing of the kind rule_load.known is false and
    nothing here shows that a rule loaded.
  * The checksum mode (-k) and the command.

TLS fingerprints are three different facts and are kept apart: ja3_enabled and ja4_enabled are what the written
configuration asks for (not read from a configuration you supply); tls_events is the TLS events the engine logged (an
event from a stream picked up after its ClientHello cannot carry one); tls_with_ja3 and tls_with_ja4 are the events
that do, and other_events_with_a_fingerprint counts those found in events of another type. An event with no
fingerprint is not evidence that the build lacks the feature, and a build may ignore a key it does not know. No
default and no version fact about Suricata is stated here: read the version the evidence was run with.

EVE is read line by line. A line that is not JSON, or is JSON but not an object, is counted with its line number
(the line itself stays in eve.json), and an object with no event_type is counted and located the same way, and each
makes the run not ok. eve.json is the whole result.

The engine runs in this tool's own process group, not a session of its own: the harness ends a tool by killing its
group, and an engine outside it would go on writing into the output directory. SIGTERM, SIGINT and SIGHUP kill it and
what it started, and timeout_seconds is held under the manifest's limit (at most 1000).

SENSITIVE OUTPUT. EVE can carry URLs, host names, SNI, DNS names, file names and payload excerpts. The directory is
private (mode 0700, every file 0600, including what Suricata writes) and the answer says to run the tool as a job
with secret_output: true. Inline alerts carry addresses, ports and the rule's signature only.
"""
import collections
import errno
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path

TOOL = {"name": "suricata_run", "version": 5}
PARSER = "suricata_run/5"
TEST_SECONDS = 120
MAX_TIMEOUT = 1000            # the manifest's limit is 1200: --build-info (30 s) and the configuration test (120 s) come first
DEFAULT_HOME_NET = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
PREFLIGHT_SECONDS = 30
MAX_LINE = 16 << 20
MAX_JSON_DEPTH = 64           # an EVE line nested deeper than this is located and not parsed: the same answer on every Python, which differs on how deep json.loads goes
MAX_SIGNATURES = 10_000
LOADED = re.compile(r"(\d+) rules? successfully loaded, (\d+) rules? failed")

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
_PREFIXED = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                       r"|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}"
                       r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"
                       r"|(?i:basic|bearer)\s+[A-Za-z0-9+/=._~-]{8,}")
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
# A text longer than this is withheld whole, by its length, and not examined: the examination is linear, but a text of
# millions of characters is not one a name or a URL is, and the answer says how long it was.
TEXT_LIMIT = 2097152


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
    spans = [m.span() for m in _PREFIXED.finditer(text)]
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


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def fail(message, **extra):
    print(json.dumps({"error": scrub(message), "tool": TOOL, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself,
    or anything under inputs/ is refused, and in a job so is anything outside $OUT, the one place a job writes.

    A string check is not enough: `work/../inputs/x`, an absolute path and a symlink that points out all name a
    place the tool must not write. Resolving first and comparing directories is what holds, and the read-only
    inputs are the one place Suricata's logs must never appear: a later integrity check would report the evidence
    as modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    if in_job():
        job_out = Path(os.environ["OUT"]).resolve()
        if dest != job_out and job_out not in dest.parents:
            fail("in a job %s is a directory under $OUT, the one place a job writes" % what, **{what: str(out), "out": str(job_out)})
    return str(dest.relative_to(root))


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
# walk has no bound but the number of processes. Two cases leave the tree running: a ps that needs more than PS_WAIT
# seconds, and a sandbox that denies both libproc and ps (macOS).
try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now

def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    return subprocess.Popen(argv, **kwargs)


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
    found, seen, stack = [], {pid}, [pid]
    while stack:
        for child in kids.get(stack.pop(), []):
            if child not in seen:
                seen.add(child)
                found.append(child)
                stack.append(child)
    return found


def descendants(pid):
    """Every process below `pid` (never one beside it): from /proc where there is one, else from libproc, else from ps
    (given PS_WAIT seconds). libproc is believed when it lists a child; an empty answer is believed only when libproc has
    just listed this tool's own child `pid` (a library that answers nothing for a live child is not working, as in a
    sandbox that denies it), and otherwise ps is asked."""
    kids = {}
    try:
        if os.path.isdir("/proc/self"):
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        kids.setdefault(int(fields[1]), []).append(int(entry))
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
                return found
            if first is not None and pid in (_children_libproc(os.getpid()) or []):
                return []
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=PS_WAIT).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    return _below(kids, pid)


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it. A program already waited for is not touched: its pid is free to
    be another process's, and the walk below it would be that process's children."""
    if proc.poll() is not None:
        return
    victims = descendants(proc.pid)
    try:
        proc.kill()
    except OSError:
        pass
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def _on_signal(signum, _frame):
    for proc in list(ACTIVE):
        kill_tree(proc)
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
        out, err = proc.communicate(timeout=max(1.0, seconds))
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        out, err = proc.communicate()
        return None, out, err, True
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


def json_depth(text):
    """The deepest nesting of brackets in a JSON text, counted without recursion and without parsing."""
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def note_problem(handle, out_dir, line, why):
    """Append one EVE line that was not read as an event to eve-problems.jsonl (created on the first); returns the handle."""
    if handle is None:
        fd = os.open(os.path.join(out_dir, "eve-problems.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        handle = os.fdopen(fd, "w", encoding="utf-8")
    handle.write(json.dumps({"line": line, "why": why}) + "\n")
    return handle


def shown_address(value):
    """An address field of an event: an IP address as it is, anything else through the block."""
    if value is None or isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    text = str(value)
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        return scrub(text)


def shown_number(value):
    """A port, an id, a count: a number as it is; text that is digits as it is; anything else through the block."""
    if value is None or isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    text = str(value)
    return text if re.fullmatch(r"-?\d{1,20}", text) else scrub(text)


def shown_text(value):
    if value is None or isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    return scrub(str(value))


def shown_time(value):
    """An EVE timestamp (ISO 8601 with an offset) as it is; anything else through the block."""
    text = value if isinstance(value, str) else None
    if text is not None and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})", text):
        return text
    return shown_text(value)


PROGRESS = {"stage": "arguments", "out_dir": None}


def last_word(signum):
    """What a stopped run says on stdout: partial, which stage it was in, and what is on disk."""
    out_dir = PROGRESS.get("out_dir")
    try:
        files = sorted(os.listdir(out_dir)) if out_dir else []
    except OSError:
        files = []
    print(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "ok": False,
                      "status_basis": "the tool was stopped by signal %d while it was %s; the engine, if it was running, was killed with what it had started, and eve.json is only as far as it got" % (signum, PROGRESS["stage"]),
                      "interrupted_by_signal": signum, "stage": PROGRESS["stage"], "out_dir": out_dir, "files_on_disk": files}), flush=True)


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rule_load_counts(*paths):
    """What Suricata itself printed about loading rules, or None when it printed nothing of the kind."""
    found = None
    for path in paths:
        try:
            with open(path, "rb") as fh:
                for raw in fh:
                    m = LOADED.search(raw.decode("utf-8", "replace"))
                    if m:
                        found = {"loaded": int(m.group(1)), "failed": int(m.group(2)), "from": os.path.basename(path)}
        except OSError:
            continue
    return found


VARS = (
    "vars:\n"
    "  address-groups:\n"
    "    HOME_NET: %s\n"
    "    EXTERNAL_NET: \"!$HOME_NET\"\n"
    "    HTTP_SERVERS: \"$HOME_NET\"\n"
    "    SMTP_SERVERS: \"$HOME_NET\"\n"
    "    SQL_SERVERS: \"$HOME_NET\"\n"
    "    DNS_SERVERS: \"$HOME_NET\"\n"
    "    TELNET_SERVERS: \"$HOME_NET\"\n"
    "    AIM_SERVERS: \"$EXTERNAL_NET\"\n"
    "    DC_SERVERS: \"$HOME_NET\"\n"
    "    DNP3_SERVER: \"$HOME_NET\"\n"
    "    DNP3_CLIENT: \"$HOME_NET\"\n"
    "    MODBUS_CLIENT: \"$HOME_NET\"\n"
    "    MODBUS_SERVER: \"$HOME_NET\"\n"
    "    ENIP_CLIENT: \"$HOME_NET\"\n"
    "    ENIP_SERVER: \"$HOME_NET\"\n"
    "  port-groups:\n"
    "    HTTP_PORTS: \"80\"\n"
    "    SHELLCODE_PORTS: \"!80\"\n"
    "    ORACLE_PORTS: 1521\n"
    "    SSH_PORTS: 22\n"
    "    DNP3_PORTS: 20000\n"
    "    MODBUS_PORTS: 502\n"
    "    FILE_DATA_PORTS: \"[$HTTP_PORTS,110,143]\"\n"
    "    FTP_PORTS: 21\n"
    "    GENEVE_PORTS: 6081\n"
    "    VXLAN_PORTS: 4789\n"
    "    TEREDO_PORTS: 3544\n"
)


def configuration(out_dir, home_net):
    """The explicit configuration the tool writes: every setting by key, none by position. The variables rules are written
    against (HOME_NET and the other groups) are set here, because a rule that names a variable the file does not define
    does not load; the values are this tool's assumptions, stated in the answer, not a copy of any distribution's file."""
    return (
        "%YAML 1.1\n---\n"
        "# Written by suricata_run (network-forensics pack). Settings not named here are the engine's own defaults.\n"
        "default-log-dir: " + json.dumps(os.path.abspath(out_dir)) + "\n"
        + VARS % json.dumps("[" + ",".join(home_net) + "]") +
        "outputs:\n"
        "  - eve-log:\n"
        "      enabled: yes\n"
        "      filetype: regular\n"
        "      filename: eve.json\n"
        "      types:\n"
        "        - alert\n"
        "        - anomaly\n"
        "        - dns\n"
        "        - http\n"
        "        - tls:\n"
        "            extended: yes\n"
        "        - files\n"
        "        - flow\n"
        "app-layer:\n"
        "  protocols:\n"
        "    tls:\n"
        "      enabled: yes\n"
        "      ja3-fingerprints: yes\n"
        "      ja4-fingerprints: yes\n"
    )


def main():
    STATE["last_word"] = last_word
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path, rules, out_dir = args.get("path"), args.get("rules"), args.get("out_dir")
    for label, value in (("path", path), ("rules", rules)):
        if not isinstance(value, str) or not os.path.isfile(value):
            fail("%s must name a readable file" % label, **{label: value if isinstance(value, str) else None})
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: an empty directory under work/ (in a job, under $OUT)")
    out_dir = resolve_output(out_dir, "out_dir")
    PROGRESS["out_dir"] = out_dir
    try:
        if os.path.exists(out_dir) and os.listdir(out_dir):
            fail("out_dir already holds files", out_dir=out_dir)
    except OSError as exc:
        fail("out_dir cannot be listed (%s)" % describe(exc), out_dir=out_dir)
    limit = args.get("return_alerts", 100)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        fail("return_alerts must be a non-negative integer")
    timeout = args.get("timeout_seconds", 900)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 10 <= timeout <= MAX_TIMEOUT:
        fail("timeout_seconds must be an integer from 10 to %d: kept under the 1200-second limit, after the build information and the "
             "configuration test, so that this tool stops Suricata itself and the limit never has to" % MAX_TIMEOUT)
    home_net = args.get("home_net", DEFAULT_HOME_NET)
    if (not isinstance(home_net, list) or not home_net or len(home_net) > 64 or any(not isinstance(n, str) for n in home_net)):
        fail("home_net must be a non-empty list of addresses or networks, such as [\"10.0.0.0/8\"]")
    for position, n in enumerate(home_net):
        try:
            ipaddress.ip_network(n, strict=False)
        except ValueError:
            # The caller has the entry; it is named by position and length, not echoed (and so not cut).
            fail("home_net names something that is not an address or a network", home_net_index=position, home_net_entry_length=len(n))
    checksum_mode = str(args.get("checksum_mode") or "none").lower()
    if checksum_mode not in ("none", "all"):
        fail("checksum_mode must be none or all", checksum_mode=checksum_mode)
    config_arg = args.get("config")
    if config_arg is not None:
        if not isinstance(config_arg, str) or not os.path.isfile(config_arg):
            fail("config must name a readable file", config=config_arg if isinstance(config_arg, str) else None)
        resolved = Path(config_arg).resolve()
        inputs = Path.cwd().resolve() / "inputs"
        if resolved == inputs or inputs in resolved.parents:
            fail("a configuration from inputs/ is refused: a configuration can load scripts and rule files, and this one would be code the evidence supplied", config=config_arg)
    rules_resolved = Path(rules).resolve()
    evidence = Path.cwd().resolve() / "inputs"
    if rules_resolved == evidence or evidence in rules_resolved.parents:
        fail("a rules file from inputs/ is refused: a rule can name Lua scripts and dataset files the engine reads and writes, and this one "
             "would be code the evidence supplied; copy the rules you mean to apply out of the evidence, read them, and say so", rules=rules)
    binary = shutil.which("suricata")
    if not binary:
        fail("suricata is not on PATH")

    os.umask(0o077)
    try:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        os.chmod(out_dir, 0o700)
    except OSError as exc:
        fail("the output directory could not be created (%s)" % describe(exc), out_dir=out_dir)

    PROGRESS["stage"] = "reading the build information"
    build_code, build_out, build_err, _ = preflight([binary, "--build-info"], PREFLIGHT_SECONDS)
    build_path = os.path.join(out_dir, "suricata-build-info.txt")
    try:
        fd = os.open(build_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(build_out + (b"\n--- stderr ---\n" + build_err if build_err else b""))
    except OSError as exc:
        fail("the build information could not be written (%s)" % describe(exc), out_dir=out_dir)
    version_line = None
    for line in build_out.decode("utf-8", "replace").splitlines():
        if re.search(r"(?i)\bversion\b", line):
            version_line = line.strip()
            break

    generated = config_arg is None
    config_path = os.path.join(out_dir, "suricata.yaml") if generated else config_arg
    if generated:
        try:
            fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(configuration(out_dir, home_net))
        except OSError as exc:
            fail("the configuration could not be written (%s)" % describe(exc), out_dir=out_dir)
    try:
        config_sha, rules_sha = file_sha256(config_path), file_sha256(rules)
        with open(rules, "rb") as fh:
            rule_lines = sum(1 for raw in fh if raw.strip() and not raw.lstrip().startswith(b"#"))
        rules_bytes = os.path.getsize(rules)
    except OSError as exc:
        fail("a configuration or rules file could not be read (%s)" % describe(exc))

    common = ["-c", os.path.abspath(config_path), "-S", os.path.abspath(rules), "-l", os.path.abspath(out_dir), "-k", checksum_mode, "-v"]
    test_argv = [binary, "-T"] + common
    test_out, test_err = os.path.join(out_dir, "suricata-test.stdout"), os.path.join(out_dir, "suricata-test.stderr")
    PROGRESS["stage"] = "testing the configuration"
    test_code, test_timed_out = run_to_files(test_argv, test_out, test_err, TEST_SECONDS)
    if test_code != 0:
        fail("the configuration test (suricata -T) %s, so nothing was run" % ("did not finish in time" if test_timed_out else "failed with exit code %s" % test_code),
             exit_code=test_code, command=test_argv, config=config_path, config_sha256=config_sha, config_generated=generated,
             suricata_version=version_line, build_info=build_path, stdout=test_out, stderr=test_err,
             note="The configuration is tested before any capture is read. Read the diagnostic; if the written configuration does not suit the "
                  "installed build, pass config with a file of your own.")

    argv = [binary, "-r", os.path.abspath(path)] + common
    stdout_path, stderr_path = os.path.join(out_dir, "suricata.stdout"), os.path.join(out_dir, "suricata.stderr")
    PROGRESS["stage"] = "running Suricata"
    code, timed_out = run_to_files(argv, stdout_path, stderr_path, timeout)
    for name in os.listdir(out_dir):
        full = os.path.join(out_dir, name)
        try:
            if not os.path.islink(full):
                os.chmod(full, 0o700 if os.path.isdir(full) else 0o600)
        except OSError:
            pass
    if timed_out:
        fail("suricata did not finish in time and was killed with everything it had started", after_seconds=timeout, command=argv,
             partial_output=out_dir, stdout=stdout_path, stderr=stderr_path)
    eve = os.path.join(out_dir, "eve.json")
    if not os.path.isfile(eve):
        fail("suricata wrote no eve.json", exit_code=code, command=argv, stdout=stdout_path, stderr=stderr_path, out_dir=out_dir)

    PROGRESS["stage"] = "reading eve.json"
    event_types, signatures = collections.Counter(), collections.Counter()
    alerts, bad_lines, not_objects, no_type, too_long = [], [], 0, 0, []
    problem_total = 0
    problems_file = None                 # every EVE line that was not read as an event, whole, in a file of its own
    invalid = 0
    tls_events = tls_ja3 = tls_ja4 = 0
    other_with_fingerprint = 0
    signature_overflow = 0
    lines = 0
    with open(eve, "rb") as fh:
        while True:
            raw = fh.readline(MAX_LINE + 1)
            if not raw:
                break
            lines += 1
            if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
                while True:
                    more = fh.readline(MAX_LINE)
                    if not more or more.endswith(b"\n"):
                        break
                if len(too_long) < 10:
                    too_long.append(lines)
                problem_total += 1
                problems_file = note_problem(problems_file, out_dir, lines, "longer than %d bytes: located, not read" % MAX_LINE)
                continue
            if not raw.strip():
                continue
            text = raw.decode("utf-8", "surrogateescape")
            try:
                if text.count("[") + text.count("{") > MAX_JSON_DEPTH and json_depth(text) > MAX_JSON_DEPTH:
                    raise RecursionError("nested deeper than %d levels" % MAX_JSON_DEPTH)
                event = json.loads(text)
            except (ValueError, RecursionError) as exc:
                invalid += 1
                why = "nested deeper than %d levels: located, not parsed" % MAX_JSON_DEPTH if isinstance(exc, RecursionError) else "not valid JSON"
                if len(bad_lines) < 10:
                    bad_lines.append({"line": lines, "why": why})
                problem_total += 1
                problems_file = note_problem(problems_file, out_dir, lines, why)
                continue
            if not isinstance(event, dict):
                not_objects += 1
                if len(bad_lines) < 10:
                    bad_lines.append({"line": lines, "why": "valid JSON that is not an object"})
                problem_total += 1
                problems_file = note_problem(problems_file, out_dir, lines, "valid JSON that is not an object")
                continue
            kind = event.get("event_type")
            if not isinstance(kind, str) or not kind:
                no_type += 1
                kind = "no_event_type"
                if len(bad_lines) < 10:
                    bad_lines.append({"line": lines, "why": "an object with no event_type"})
                problem_total += 1
                problems_file = note_problem(problems_file, out_dir, lines, "an object with no event_type")
            event_types[scrub(kind)] += 1
            if kind == "alert":
                alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
                label = scrub(str(alert.get("signature") or alert.get("signature_id") or "unknown"))
                if label in signatures or len(signatures) < MAX_SIGNATURES:
                    signatures[label] += 1
                else:
                    signature_overflow += 1
                if len(alerts) < limit:
                    alerts.append({"line": lines, "timestamp": shown_time(event.get("timestamp")), "flow_id": shown_number(event.get("flow_id")),
                                   "src_ip": shown_address(event.get("src_ip")), "src_port": shown_number(event.get("src_port")),
                                   "dest_ip": shown_address(event.get("dest_ip")), "dest_port": shown_number(event.get("dest_port")),
                                   "proto": shown_text(event.get("proto")), "signature_id": shown_number(alert.get("signature_id")),
                                   "signature": shown_text(alert.get("signature"))})
            elif kind == "tls":
                tls = event.get("tls") if isinstance(event.get("tls"), dict) else {}
                tls_events += 1
                tls_ja3 += int(bool(tls.get("ja3")))
                tls_ja4 += int(bool(tls.get("ja4")))
            if kind != "tls" and isinstance(event.get("tls"), dict) and (event["tls"].get("ja3") or event["tls"].get("ja4")):
                other_with_fingerprint += 1

    if problems_file is not None:
        problems_file.close()
    loads = {"configuration_test": rule_load_counts(test_out, test_err), "run": rule_load_counts(stdout_path, stderr_path)}
    load_failed = any(v and v["failed"] for v in loads.values())
    problems = []
    if code != 0:
        problems.append("suricata exited with code %s" % code)
    if version_line is None:
        problems.append("`suricata --build-info` %s, so the version of the engine that ran is not recorded" % ("exited %s" % build_code if build_code is not None else "did not run"))
    if load_failed:
        problems.append("Suricata reported rules that failed to load")
    known = [v for v in loads.values() if v]
    if known and rule_lines and not any(v["loaded"] for v in known):
        problems.append("Suricata reported 0 rules loaded though the rules file has %d rule lines: an empty detection run is not a run with no alerts" % rule_lines)
    if invalid or not_objects or too_long or no_type:
        problems.append("%d EVE lines were not read as events" % (invalid + not_objects + len(too_long) + no_type))
    ok = not problems
    basis = ("the engine exited 0, its configuration test passed, every rule loaded and every EVE line was read as an event" if ok else
             "; ".join(problems[:6]) + (" (and %d more, all in problems)" % (len(problems) - 6) if len(problems) > 6 else "") + ": eve.json is whole in out_dir")
    print(json.dumps({
        "tool": TOOL, "parser": PARSER,
        "status": "complete" if ok else "partial", "status_basis": basis,
        "path": path, "out_dir": out_dir, "eve_json": eve,
        "suricata_version": version_line, "build_info": build_path, "build_info_exit_code": build_code,
        "command": argv,
        "configuration": {"path": config_path, "sha256": config_sha, "generated_by_this_tool": generated,
                          "tested_with": "suricata -T", "test_exit_code": test_code, "test_stdout": test_out, "test_stderr": test_err,
                          "note": ("written by this tool: only the keys it names are set, the rest are the engine's own defaults" if generated else
                                   "supplied by the caller and not read by this tool"),
                          "vars": ({"HOME_NET": home_net, "note": "HOME_NET is the home_net argument, or the private ranges when it was not given; the other address "
                                    "groups and the port groups are set to the usual names rulesets use. They are this tool's assumptions, not read from your "
                                    "environment: a rule that uses another variable does not load, and then config is the way"} if generated else None)},
        "rules": {"path": rules, "sha256": rules_sha, "bytes": rules_bytes, "rule_lines": rule_lines,
                  "rule_lines_note": "lines that are neither empty nor comments; not the number of rules the engine loaded"},
        "rule_load": {**loads, "known": bool(known), "note": "read from Suricata's own output when it printed the numbers, and None when it did not: None is not a count "
                                                             "of zero, and with known false nothing here shows that any rule loaded: read suricata.stderr"},
        "checksum_mode": checksum_mode,
        "exit_code": code,
        "event_types": dict(event_types),
        "events": sum(event_types.values()),
        "alert_count": event_types.get("alert", 0), "alerts_returned": len(alerts), "alerts_omitted": event_types.get("alert", 0) - len(alerts),
        "alerts": alerts, "signatures": dict(signatures), "signatures_over_cap": signature_overflow,
        "tls_fingerprints": {
            "ja3_enabled": "yes (asked of the engine in the written configuration)" if generated else "not read: the configuration is the caller's",
            "ja4_enabled": "yes (asked of the engine in the written configuration)" if generated else "not read: the configuration is the caller's",
            "tls_events": tls_events, "tls_with_ja3": tls_ja3, "tls_with_ja4": tls_ja4,
            "other_events_with_a_fingerprint": other_with_fingerprint,
            "note": "enabled is what the configuration asks for, tls_events is the TLS events the engine logged (an event from a stream picked up after its "
                    "ClientHello cannot carry a fingerprint, so it is not a count of those that could), the next two are what was produced in them, and "
                    "other_events_with_a_fingerprint counts fingerprints found in events of another type (an alert, QUIC). An event with none does not show "
                    "the build lacks the feature, and a build may ignore a key it does not know.",
        },
        "tls_with_ja3": tls_ja3, "tls_with_ja4": tls_ja4,
        "eve_lines": lines, "invalid_eve_lines": invalid, "eve_lines_not_objects": not_objects, "events_without_event_type": no_type,
        "eve_lines_over_limit": too_long, "eve_line_problems": bad_lines,
        "eve_problem_lines_total": problem_total, "eve_problems_file": "eve-problems.jsonl" if problem_total else None,
        "eve_problems_note": "eve_line_problems and eve_lines_over_limit show the first ten; every one is in eve_problems_file with its line number",
        "stdout": stdout_path, "stderr": stderr_path,
        "problems": problems,
        "ok": ok,
        "withheld": dict(COUNTS),
        "out_dir_contains_secret_values": True,
        "out_dir_note": ("EVE can carry URLs, host names, SNI, DNS names, file names and payload excerpts. The directory is private (mode 0700, files "
                         "0600). Run this tool as a job with secret_output: true so the job output is sealed. Inline alerts carry addresses, ports "
                         "and the rule's signature only."),
        "note": ("Inline alerts are bounded and eve.json is the whole result; it, the configuration, the build information and Suricata's complete "
                 "stdout and stderr are named above. An alert is a rule match on the traffic as the engine reassembled it, not a finding: the rules are "
                 "the caller's, and no ruleset ships with this pack. Checksum validation defaults to none because capture offload commonly leaves "
                 "invalid TCP checksums; use all to test integrity. JA3 and JA4 are pivots, not unique identities of a program."),
    }, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
