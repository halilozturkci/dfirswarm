#!/usr/bin/env python3
"""Run capa and FLOSS over one PE or ELF file, if they are installed, and say exactly what each of them said.

Two programs, each started in this recipe's own process group with its output going straight to a file of the recipe's
directory: `capa -j` (capability rule matches) and `floss -j` (recovered strings). The programs are not shipped by the pack
(it declares them as optional), and this recipe does not assume either is present:

    complete      every engine ran, exited 0 and wrote JSON of the shape this recipe reads
    partial       at least one engine produced a usable result and something is missing: an engine that is not installed, that failed,
                  that was stopped at its time limit, or whose JSON had no rules mapping (coverage.json says which and why)
    unsupported   the file is not a PE or an ELF
    failed        no engine produced a usable result

The recipe judges an engine by its exit status and the shape of its output, never by the output file being non-empty. It records each
program's argv and what `--version` printed, copies no string and no matched feature into coverage.json, index.tsv or matches.tsv (the
whole output files hold them, and they can hold credentials), and does not know or claim which release has which capability: a
program that rejects an argument fails visibly, with its stderr kept. Nothing here executes the sample; capa and FLOSS analyse it, and
FLOSS emulates parts of its code inside its own process, which is the program's behaviour and not this recipe's.
"""
import errno
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import unicodedata

# BEGIN SHARED WITHHOLDING
# The same text is in pcap_extract, zeek_run, suricata_run and network_log_summary, so that the four tools withhold
# the same strings; tests/pack-network-withholding.test.ts holds the copies equal. An identifier-shaped string is
# withheld wherever the tool would print one: a name, a path component, a URL, a message that quotes either.
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


def token_spans(text):
    spans = [m.span() for m in _PREFIXED.finditer(text)]
    for m in _RUN.finditer(text):
        if _token_run(m.group()):
            spans.append(m.span())
    # A base64 token holds `/`: pieces too short to be one alone (an AWS-style secret has two) are caught as a whole.
    for m in _SLASHED.finditer(text):
        run = m.group()
        if "/" in run and sum(1 for p in run.split("/") if _randomish(p)) >= 3 and re.search(r"[0-9+]", run):
            spans.append(m.span())
    # A flagged piece takes the random-looking pieces next to it across a `/`: the head of a token is not printed.
    grown = []
    for start, end in spans:
        while start > 1 and text[start - 1] == "/":
            m = re.search(r"[A-Za-z0-9_+%-]+$", text[:start - 1])
            if not m or not _randomish(m.group()):
                break
            start = m.start()
        while end < len(text) - 1 and text[end] == "/":
            m = re.match(r"[A-Za-z0-9_+%-]+={0,2}", text[end + 1:])
            if not m or not _randomish(m.group()):
                break
            end = end + 1 + m.end()
        grown.append((start, end))
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


# BEGIN SHARED LINEAR SPANS
# The same text is in doc_structure, pe_directories and the capa-floss recipe (tests/pack-re-process.test.ts holds the copies
# equal). The shared block's token_spans grows each flagged span across `/` by searching the whole text before it again for
# every piece it takes, which costs about the cube of the text's length: a name of 13 KB of `/`-joined tokens took 44 s. The
# block is not edited (its copies are held equal to the network pack's), so this tool binds the same function, computed in
# linear time: the same spans for every text, which tests/pack-re-canary-harness.test.ts holds against the block's own
# token_spans on generated text. Making the block itself linear, for every tool that carries it, is a follow-up.
_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+%-")
_shared_token_spans = token_spans


def _linear_token_spans(text):
    spans = [m.span() for m in _PREFIXED.finditer(text)]
    for m in _RUN.finditer(text):
        if _token_run(m.group()):
            spans.append(m.span())
    for m in _SLASHED.finditer(text):
        run = m.group()
        if "/" in run and sum(1 for p in run.split("/") if _randomish(p)) >= 3 and re.search(r"[0-9+]", run):
            spans.append(m.span())
    if not spans:
        return []
    n = len(text)
    run_start, run_end = [0] * n, [0] * n
    i = 0
    while i < n:
        if text[i] in _NAME_CHARS:
            j = i
            while j < n and text[j] in _NAME_CHARS:
                j += 1
            for k in range(i, j):
                run_start[k], run_end[k] = i, j
            i = j
        else:
            i += 1
    left, right = {}, {}

    def piece_left(start):
        # what re.search(r"[A-Za-z0-9_+%-]+$", text[:start - 1]) finds: `$` also matches before a final line break
        last = start - 2
        if text[last] in _NAME_CHARS:
            return run_start[last], last + 1
        if text[last] == "\n" and last >= 1 and text[last - 1] in _NAME_CHARS:
            return run_start[last - 1], last
        return None

    def grow_left(start):
        path = []
        while True:
            if start in left:
                start = left[start]
                break
            if not (start > 1 and text[start - 1] == "/"):
                break
            found = piece_left(start)
            if found is None or not _randomish(text[found[0]:found[1]]):
                break
            path.append(start)
            start = found[0]
        for p in path:
            left[p] = start
        return start

    def grow_right(end):
        path = []
        while True:
            if end in right:
                end = right[end]
                break
            if not (end < n - 1 and text[end] == "/") or text[end + 1] not in _NAME_CHARS:
                break
            stop = run_end[end + 1]
            pads = 0
            while pads < 2 and stop + pads < n and text[stop + pads] == "=":
                pads += 1
            if not _randomish(text[end + 1:stop + pads]):
                break
            path.append(end)
            end = stop + pads
        for p in path:
            right[p] = end
        return end

    grown = sorted((grow_left(start), grow_right(end)) for start, end in spans)
    merged = []
    for start, end in grown:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


token_spans = _linear_token_spans
# END SHARED LINEAR SPANS


# BEGIN SHARED PROCESS
# The same text is in pcap_extract, zeek_run, suricata_run and the network-capture recipe; tests/pack-network-process.test.ts
# holds the copies equal. A program an engine tool runs is started in THIS tool's process group, never in a session of
# its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid,
# SIGKILL)), and an engine in a group of its own goes on writing into the output directory after the tool is gone. On
# Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it started by
# walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word.
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


def descendants(pid):
    """Every process below `pid`, from /proc where there is one, else from ps."""
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
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    found, stack = [], [pid]
    while stack:
        for child in kids.get(stack.pop(), []):
            found.append(child)
            stack.append(child)
    return found


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it."""
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


# -- new code of the capa-floss recipe --

HERE = os.path.dirname(os.path.abspath(__file__))


# BEGIN SHARED ONE WAY OUT
# The same text is in doc_structure, pe_directories and the capa-floss recipe (tests/pack-re-process.test.ts holds the copies equal).
# Two steps stand between a string out of a file and any byte the tool writes. shown_path is the sanitiser: it withholds every shape
# below, by shape only: what is printed is what no rule here recognises, and a secret of another shape (a plain password, a token
# family the rules do not name, a token split across two fields) is printed. It reads the WHOLE text for what only the whole shows (a
# user-info whose `//` or host a split would remove, a `Basic`/`Bearer` credential, base64 joined by `/`), then each `/` component (a
# path is not one token), and a copy of the text without the characters that can split a token unseen (NUL, other control characters
# and their \xNN escapes, zero-width, soft hyphen, bidi and combining marks; NFKD folds full-width forms): a text whose copy holds a
# token is withheld whole. final_check is the backstop: every key and every value of what the tool is about to print or write is
# tested again with the same rules, and one that the sanitiser would still change (a string that did not pass through it, or a number
# long enough to be a key) is replaced by its length, counted, and the answer is partial. A field the backstop withholds is a fault of
# the tool, never of the file: the count says how many.
_CLEAN = set()                      # strings known to hold nothing to withhold: tested once (a table repeats its keys and kinds)
_CLEAN_CHARS = [0]                  # their total length, bounded
_CACHE_ALL = [False]                # True while a string is sanitised that the tool keeps for its answer: its settled result is remembered whatever its size
# A mailto: address has no user-info (RFC 6068: an address is local-part@domain), so the shared block keeps `mailto:name:secret@host`
# as an address; a ':' in the local part is a name:password pair placed there, and what follows the ':' (to the last `@` within
# MAILTO_SPAN characters, no `?`, space, `<` or `>` before it) is withheld here. It is found with one pass over the `mailto:name:`
# heads and a search for `@` inside a fixed window after each, so that a million `mailto:a:` cost a million small steps and not their
# square: a password of more than MAILTO_SPAN characters in a mailto: address is not withheld by this rule (the shared rules for a
# token-shaped run still read it).
MAILTO_HEAD = re.compile(r"mailto:[^:@?/\s]*:", re.I)
MAILTO_STOP = re.compile(r"[?\s<>]")
MAILTO_SPAN = 512


def mailto_userinfo(text):
    out, last = [], 0
    for m in MAILTO_HEAD.finditer(text):
        if m.start() < last:
            continue
        begin = m.end()
        window = min(len(text), begin + MAILTO_SPAN + 1)
        at = text.rfind("@", begin, window)
        if at >= 0:
            stop = MAILTO_STOP.search(text, begin, at)
            if stop:
                at = text.rfind("@", begin, stop.start())
        if at < 0:
            continue
        out.append(text[last:begin])
        out.append(_withheld("userinfo", at - begin, "urls"))
        last = at
    if not out:
        return text
    out.append(text[last:])
    return "".join(out)


# `name:secret@` wherever it stands, with or without a host after the `@` (a name cut at a declared length ends right there): the
# shared block's bare rule wants a host, and its URL rule wants the `//` a path split removes. A password may hold `@`: the user-info
# runs to the last `@` before the host, as a URL's does (RFC 3986 3.2.1). A format string (`user:%s@%s`) is kept.
CUT_USERINFO = re.compile(r"(?<![\w.%+-])(?!mailto:)[\w.%+-]{1,64}:[^\s/:<>]{1,128}(?=@)", re.I)
# A URL's user-info whose password holds `/`, `?` or `#` (files hold them raw, though RFC 3986 3.2.1 asks for percent-encoding): the
# first `@` of such a string follows a `/`, `?` or `#`, which no authority holds, so the password is read to the last `@` of the same
# whitespace-delimited token. A port (`host:8080/path@x`) is not one: only digits and then `/`, `?`, `#` or the end after the `:`. The
# `///` (a file URL: `file:///C:/Dir/icon@2x.png`) is not one. The bare form (`name:pass/word@host`, no `//`) is not read: a path with an `@` in it (`C:/Dir/icon@2x.png`) is not user-info.
SLASH_USERINFO = re.compile(r"(?:(?<=[^/]//)|(?<=^//))[\w.%+-]{1,64}:(?!\d{1,5}(?:[/?#]|$))(?=[^\s@/?#]{0,256}[/?#][^\s@]{0,256}@)(?:[^\s@]|@(?=[^\s@]*@)){1,512}(?=@)")


def slash_userinfo(text):
    """text with the user-info of a URL whose password holds `/`, `?` or `#` withheld (shown_path reads it too; a URL's query is split
    off before the sanitiser sees it, so this is also run first on a target)."""
    if "//" not in text or "@" not in text:
        return text
    return SLASH_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), "urls"), text)


def plain_userinfo(text):
    """text with the user-info of a URL whose password holds `/`, `?` or `#` replaced by a plain name of the same length, which
    redact_url (it splits a URL at the first `?` and `#` and its authority at the first `/`) then withholds as user-info."""
    if "//" not in text or "@" not in text:
        return text
    return SLASH_USERINFO.sub(lambda m: "x" * len(m.group()), text)
# The value of a secret-named key (`Password=...;`, `password: ...`, `Pwd='...'`, `"AccountKey": "..."`, `"token": "..."`): after `=`, or
# after `:` for the password and key names (`token:`, `secret:` and `credentials:` are common in prose, so their `:` form counts only
# when the key itself is quoted, as in JSON), quoted (to its closing quote; an opening quote nothing closes is dropped and the rest is
# the value) or not (to `;`, a space or the end: a `,` `&` `<` `>` stays in the value, as a password may hold them). The short names
# (`pw`, `pass`, `auth`) only where no letter or digit precedes them, so that `bypass:` or `OAuth=` inside a word is not one. A value
# made only of `%` conversions is a format. A password that holds `;` or a space, or a quote of the other kind, is withheld up to it.
# The text can show a quote in three ways: as is, with up to four backslashes before it (JSON inside a JSON string, and the backslashes doubled again
# when the text is printed), and as an entity (`&quot;`, `&apos;`, `&#34;`, `&#39;`, `&#x22;`, `&#x27;`); a gap between a name and its `=` or `:`
# is a space, a tab, or a tab as it is written (`\t`, `\x09`). The same rule reads `<add key="Password" value="...">` (a name, its quote, then `value=`),
# and ELEMENT_SECRET reads `<Password>...</Password>` and its escaped form (`&lt;Password&gt;...&lt;/Password&gt;`).
_KV_ENTITY = r"&(?:quot|apos|#0{0,6}3[49]|#x2[27]);"
_KV_QUOTE = r"(?:\\{0,4}[\"']|" + _KV_ENTITY + r")"
_KV_GAP = r"(?:[ \t]|\\{1,2}(?:x09|t))*"
_KV_NAMES = (r"pass[_-]?word|pass[_-]?wd|pass[_-]?phrase|pwd|pswd|psw|secret[_-]?key|private[_-]?key|secret|client[_-]?secret|token|api[_-]?key"
             r"|access[_-]?key|account[_-]?key|shared[_-]?access[_-]?key|credentials?|(?<![A-Za-z0-9])(?:pw|pass|auth|sig)")
_KV_PASSWORD_NAMES = (r"pass[_-]?word|pass[_-]?wd|pass[_-]?phrase|pwd|pswd|psw|secret[_-]?key|private[_-]?key|client[_-]?secret|api[_-]?key|access[_-]?key|account[_-]?key"
                      r"|shared[_-]?access[_-]?key|(?<![A-Za-z0-9])(?:pw|pass)")
KEYVALUE_SECRET = re.compile(r"((?:(?:" + _KV_NAMES + r")" + _KV_QUOTE + r"?" + _KV_GAP + r"="
                             r"|(?:" + _KV_NAMES + r")" + _KV_QUOTE + r"[ \t]+value[ \t]*="
                             r"|(?:" + _KV_PASSWORD_NAMES + r")" + _KV_QUOTE + r"?" + _KV_GAP + r":"
                             r"|" + _KV_QUOTE + r"(?:token|secret|credentials?|auth|sig)" + _KV_QUOTE + _KV_GAP + r":)" + _KV_GAP + r")"
                             r"(?:(" + _KV_QUOTE + r")(?!<withheld )((?:(?!" + _KV_ENTITY + r")[^\"'\r\n]){1,512})(?=[\"']|" + _KV_ENTITY + r")"
                             r"|" + _KV_QUOTE + r"?(?!" + _KV_QUOTE + r"|\\{1,2}(?:x09|t))(?!<[a-z -]{0,40}withheld \d)([^;\s\"']{1,512}))", re.I)
# The letters any name of the rule above has in it. A text without them is not read by the rule, which would otherwise try every name at every
# position of it: the test is a few times cheaper than the rule on a text of any other kind.
KEYVALUE_HINT = re.compile(r"pw|pass|psw|secret|private|token|key|cred|auth|sig", re.I)
# The name of an element (or of a `name="..."` attribute) that holds a secret. Its text is withheld to the next `<` (or `&lt;`), the end of the
# line or the end of the text: nothing has to follow it, a `>` or `&gt;` inside the text does not end it and its length is not bounded, so that
# a value that is not closed, that holds `>` or that is longer than any window is withheld to its end and not printed whole. A text that begins
# with white space is read only when it is closed (`<token> x` in prose is no value; a padded `<Password> pw </Password>` is). The element
# may carry a namespace prefix (`<wsse:Password>`), and the setting forms are `<setting name="Password"><value>...`, and the element whose
# `name` or `key` attribute names the secret (`<property name="password">...`, `<entry key="password">...`).
_EL_NAMES = (r"pass[_-]?word|pass[_-]?wd|pass[_-]?phrase|pwd|pswd|secret[_-]?key|private[_-]?key|client[_-]?secret|api[_-]?key|access[_-]?key"
             r"|account[_-]?key|shared[_-]?access[_-]?key|token|secret")
# attributes of the open tag (`<Password Type="x">`, also with `&quot;`): `name=value` pairs, so that prose such as `<secret key>` is no element
_EL_ATTRS = (r"(?:[ \t]+[\w:.-]{1,64}[ \t]*=[ \t]*(?:\"[^\"<>\r\n]{0,128}\"|'[^'<>\r\n]{0,128}'|&quot;(?:(?!&quot;)[^<>\r\n]){0,128}&quot;"
             r"|[^\s\"'<>&]{1,128}))*")
# the text of an element: any character but `<` and a line break (`&lt;` ends it too); a value that begins with a `<` that is no tag (not a name and an
# end, a closing tag, a comment or an instruction) is a value that begins with one
_EL_REST = r"[^<&\r\n]*(?:&(?!lt;)[^<&\r\n]*)*"
_EL_TEXT = r"(?:[^<&\r\n]|&(?!lt;))" + _EL_REST
_EL_LEAD = r"(?:<|&lt;)(?!/?[A-Za-z][\w:.-]*(?:[ \t][^<>\r\n]{0,256})?/?(?:>|&gt;)|[!?/])"
# White space, `*`, `${NAME}`, `%NAME%` and `%s` in front of a value that begins with a `<` that is no tag are part of that value, not the text before it
# (`<Password>*****<8r$...` is a password after a mask, withheld whole). Each unit begins with a character of its own, so the run has one reading.
_EL_PREFIX = r"(?:[ \t*]|\$\{[A-Za-z_][A-Za-z0-9_]{0,31}\}|%(?:[A-Za-z_][A-Za-z0-9_]{0,31}%?|@))*"
ELEMENT_SECRET = re.compile(r"((?:(?:<|&lt;)(?:[A-Za-z_][\w.-]{0,31}:)?(?:" + _EL_NAMES + r")" + _EL_ATTRS + r"(?<!/)(?:>|&gt;)"
                            r"|<setting[ \t]+name[ \t]*=[ \t]*[\"'](?:" + _EL_NAMES + r")[\"']" + _EL_ATTRS + r"(?<!/)>(?:\s|\\[nrt]){0,256}<value>"
                            r"|<(?:property|entry)[ \t]+(?:name|key)[ \t]*=[ \t]*[\"'](?:" + _EL_NAMES + r")[\"']" + _EL_ATTRS + r"(?<!/)>))"
                            r"((?:" + _EL_PREFIX + _EL_LEAD + _EL_REST + r"|(?=\S)(?:" + _EL_LEAD + _EL_REST + r"|" + _EL_TEXT + r")|" + _EL_TEXT + r"(?=<|&lt;)))", re.I)
FORMAT_ONLY = re.compile(r"(?:%[-+ #0-9.*]*[A-Za-z@])+")
# What is no secret in a secret-named key's place: a format (above), a run of `*` (a mask), `${NAME}` and `%NAME%` (a variable a file names). Only
# those two rules use it; a user-info keeps FORMAT_ONLY. The other rules still read what is kept.
PLACEHOLDER_ONLY = re.compile(r"(?:%[-+ #0-9.*]*[A-Za-z@])+|\*+|\$\{[A-Za-z_][A-Za-z0-9_]{0,31}\}|%[A-Za-z_][A-Za-z0-9_]{0,31}%")


def _ends_element(m):
    """True when the part the rule read is all of the element's text: a closing tag, a line break or the end of the text follows it. A mask
    or a variable followed by more text (`*<8r<...`) is the head of a value and not the whole of one."""
    rest = m.string[m.end():m.end() + 5].lower()
    return rest == "" or rest[0] in "\r\n" or rest.startswith("</") or rest.startswith("&lt;/")


# The head of a token whose own prefix says what it is, too short for the shared block's patterns (a name cut by a declared length, a
# string read from the middle of a field): the prefix and four characters more are a piece of a token. An AWS key id's head, in capitals, is one
# wherever it stands (`XAKIA...` is a key id with a letter in front: its capitals and digits are no word). The GitHub, Slack and `sk-`
# prefixes are also the ends of words (`highs_lows`, `Risk-Assessment`, `Task-Scheduler`), so a short head of those counts only
# where no letter or digit precedes it, and twenty characters after the prefix count anywhere. `sk-` needs a capital or a digit in its
# first twelve characters, as a random key has, and twelve characters, or four where the string or a path component ends (a name cut
# by a declared length ends there). The GitHub and Slack prefixes are matched in any case: a resource compiler upper-cases a string
# resource name, and `XOXB-<digits>-...` keeps the digits. A JWT's head takes the `.`-joined segments after it (a JWT glued to another
# token loses its own head to that token's match, and its signature would be left).
TOKEN_HEAD = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{4,}"
                        r"|(?<![A-Za-z0-9])(?i:gh[pousr]_)[A-Za-z0-9]{4,}|(?i:gh[pousr]_)[A-Za-z0-9]{20,}"
                        r"|(?i:github_pat_)[A-Za-z0-9_]{4,}|(?i:xox[abeprs]-)[A-Za-z0-9-]{4,}"
                        r"|(?<![A-Za-z0-9])sk-(?=[A-Za-z0-9_-]{0,11}[0-9A-Z])(?:[A-Za-z0-9_-]{12,}|[A-Za-z0-9_-]{4,11}(?=$|[/\\]))"
                        r"|sk-(?=[A-Za-z0-9_-]{0,11}[0-9A-Z])[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]+){0,2}")
# The body of a PEM block after its header (RFC 7468), up to the next '-' (its END line): withheld whole whatever its letters look like,
# as the dashes of a header glued to it join the two into one run that no shape rule of the shared block reads as a token.
PEM_BODY = re.compile(r"(-----BEGIN [^\r\n-]{1,64}-----)(?!<withheld)([^-]{8,})")
GLUED = re.compile(r"(?:%s)[A-Za-z0-9_+%%-]*" % _PREFIXED.pattern)
JWT_TAIL = re.compile(r"(?<![A-Za-z0-9_+/-])eyJ[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]+){1,2}")
LONG_NUMBER = 10 ** 31              # a number of 32 digits or more is printed as its size: the same digits as a string are withheld (32 hex)
# Base64 joined by `/` (the AWS secret access key shape; a 16-, 20- or 32-byte value encoded): the pieces between two `/` are often too
# short to look like a token alone (the shared block's `/` rule wants three random-looking pieces), so whole pieces are read together.
# Random base64 changes character class (capital, small letter, digit) at about 0.64 of its characters; words, CamelCase names,
# versions and dated folders at 0.15 to 0.3. Every window of two or more whole pieces, 16 to 64 characters with its `/`, that holds a
# digit and no piece that is a plain word (`Outlook`, `Temp`, `FinalDraftV2`, `scan0042`: a random folder name next to a word is a
# cache directory, not a key), and that changes class at SLASH_DENSITY of its characters or more, is withheld; so is padded base64
# across `/` (below). A drive letter, a UNC host and a file name's extension are never in a window (a `.` or `:` ends the run). This
# is a shape rule with a measured residue, which the changelog states in numbers. The shared block's own `/` rule (three random-looking
# pieces) is kept, counting no plain word: the published example key, whose `EXAMPLEKEY` tail is not random, is caught by it.
SLASH_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
SLASH_DENSITY = 0.45
PLAIN_PIECE = re.compile(r"[A-Z]?[a-z]{3,}|(?=.{8})(?:[A-Z][a-z]{3,}){2,}(?:[A-Z]?[0-9]{1,4})?|(?=.{8})[A-Z]?[a-z]{3,}[0-9]{1,4}")


_CLASS_RUNS = re.compile(r"[A-Z]+|[a-z]+|[0-9]+")           # a piece's runs of one character class (`+` is not counted)


def _char_class(ch):
    return 0 if "A" <= ch <= "Z" else 1 if "a" <= ch <= "z" else 2 if "0" <= ch <= "9" else 3


def _slash_spans(text):
    spans = []
    # the shared block's `/` rule (three random-looking pieces, 30 characters, a digit), read as three such pieces in a row, none a plain word
    for m in _SLASHED.finditer(text):
        if "/" not in m.group():
            continue
        group, at = [], m.start()
        for piece in m.group().split("/") + [""]:
            if piece and _randomish(piece) and not PLAIN_PIECE.fullmatch(piece.rstrip("=")):
                group.append((at, at + len(piece)))
            else:
                if len(group) >= 3 and group[-1][1] - group[0][0] >= 30 and re.search(r"[0-9+]", text[group[0][0]:group[-1][1]]):
                    spans.append((group[0][0], group[-1][1]))
                group = []
            at += len(piece) + 1
    for m in SLASH_RUN.finditer(text):
        run = m.group()
        if "/" not in run.strip("/"):
            continue
        # each piece is read once: its start and end, whether it can be in a window (not a plain word; an empty piece, as `//` makes, and
        # `==` alone can be inside one, though no window begins or ends with either), the class of its first
        # and last counted character, its class changes, its counted characters and whether one is a digit (`+` and `=` not counted)
        pieces, at = [], m.start()
        for piece in run.split("/"):
            core = piece.rstrip("=")
            runs = _CLASS_RUNS.findall(core.replace("+", "")) if "+" in core else _CLASS_RUNS.findall(core)
            counted = sum(len(r) for r in runs)
            pieces.append((at, at + len(piece), bool(PLAIN_PIECE.fullmatch(core)), _char_class(runs[0][0]) if runs else None,
                           _char_class(runs[-1][0]) if runs else None, max(0, len(runs) - 1), counted, any(r[0].isdigit() for r in runs), len(core)))
            at += len(piece) + 1
        n = len(pieces)
        if run.endswith("="):
            # padded base64 (RFC 4648 section 4): the longest window of whole pieces that ends the run, holds a `/` and no plain word,
            # and is a multiple of four characters long, as an encoding with its padding is: the shared block's own `==` rule, across `/`
            clear = [False] * (n + 1)
            clear[n] = True
            for i in range(n - 1, -1, -1):
                clear[i] = clear[i + 1] and not pieces[i][2]
            for i in range(n - 1):
                length = m.end() - pieces[i][0]
                if clear[i] and pieces[i][8] and 16 <= length <= 64 and length % 4 == 0:
                    spans.append((pieces[i][0], m.end()))
                    break
        # prefix sums, so that a window costs a few additions: class changes inside pieces, at the `/` between two pieces (the last
        # counted character of the one before and the first of the next), counted characters, digits, and pieces a window cannot hold
        inner_sum, join_sum, char_sum, digit_sum, block_sum = [0], [0], [0], [0], [0]
        join, next_counted, last = [0] * n, [n] * (n + 1), None
        for k, (start, end, blocked, first, tail, inner, count, digit, core_len) in enumerate(pieces):
            join[k] = 1 if last is not None and first is not None and first != last else 0
            last = tail if tail is not None else last
            inner_sum.append(inner_sum[-1] + inner)
            join_sum.append(join_sum[-1] + join[k])
            char_sum.append(char_sum[-1] + count)
            digit_sum.append(digit_sum[-1] + (1 if digit else 0))
            block_sum.append(block_sum[-1] + (1 if blocked else 0))
        for k in range(n - 1, -1, -1):
            next_counted[k] = k if pieces[k][6] else next_counted[k + 1]
        far = 0
        for i in range(n):
            if pieces[i][2] or pieces[i][8] < 3:
                continue
            # the last piece a window from i can reach: within 64 characters and before a piece a window cannot hold
            far = max(far, i)
            while far + 1 < n and pieces[far + 1][1] - pieces[i][0] <= 64 and not pieces[far + 1][2]:
                far += 1
            while far > i and pieces[far][1] - pieces[i][0] > 64:
                far -= 1
            if far == i or digit_sum[far + 1] == digit_sum[i]:
                continue
            f = next_counted[i]
            # the longest window from i that is withheld: one span per start. A window neither begins nor ends with a piece of one or two
            # characters (a file name `s` after a withheld folder is not taken into it; such a piece of a key, left out, is two at most)
            for j in range(far, i, -1):
                end = pieces[j][1]
                if end - pieces[i][0] < 16:
                    break
                chars = char_sum[j + 1] - char_sum[i]
                if pieces[j][8] < 3 or chars < 14 or digit_sum[j + 1] == digit_sum[i]:
                    continue
                changes = inner_sum[j + 1] - inner_sum[i] + join_sum[j + 1] - join_sum[i + 1] - (join[f] if i < f <= j else 0)
                if changes >= SLASH_DENSITY * (chars - 1):
                    spans.append((pieces[i][0], end))
                    break
    spans.sort()
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


# What can split a token without being seen: control characters (NUL between the bytes of UTF-16 read as 8-bit text), their \xNN and
# \uNNNN escapes as cell() writes them, and the format and combining characters (zero-width, soft hyphen, bidi, variation selectors).
_HIDDEN_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
_MAYBE_HIDDEN = re.compile(r"[^\x20-\x7e]|\\[xu][0-9a-fA-F]{2}")
# every space but U+0020 (no-break, en, ideographic and the like), which NFKD would make plain spaces that end a user-info; and the
# characters that print as nothing without being a format or combining mark: the line and paragraph separators, the braille blank, the
# Hangul fillers (U+115F, U+1160, U+3164, U+FFA0)
_NO_BREAK = {c: None for c in (0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029,
                               0x202F, 0x205F, 0x2800, 0x3000, 0x115F, 0x1160, 0x3164, 0xFFA0)}
_NON_ASCII_RUN = re.compile(r"[^\x00-\x7f]+")


def _redecoded(text, encoding):
    """text with each run of non-ASCII characters that is the UTF-8 of something, read by a tool as 8-bit text (Latin-1, CP437) and
    shown as the three or two characters it came to, put back to what the bytes mean (the three bytes of a zero-width space read as
    Latin-1 are three visible characters, and a token split by them is split unseen). None when no run is."""
    changed = [False]

    def back(m):
        try:
            fixed = m.group().encode(encoding).decode("utf-8")
        except UnicodeError:
            return m.group()
        changed[0] = True
        return fixed
    out = _NON_ASCII_RUN.sub(back, text)
    return out if changed[0] else None


def unhidden(text):
    """The text without what can split a token unseen (a copy that is tested, never printed)."""
    if not _MAYBE_HIDDEN.search(text):
        return text
    text = _HIDDEN_ESCAPE.sub("", text).translate(_NO_BREAK)
    # NFKD, so that a mark a composition would fold into its letter (L and U+0301 compose to U+0139) is a mark that is dropped
    text = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in text if not (unicodedata.category(ch) in ("Cc", "Cf", "Mn", "Me", "Cs")))


def hidden_copies(text):
    """The copies of the text a token may be split in unseen: without the hidden characters, and the same after the UTF-8 that was
    read as Latin-1 or CP437 is put back."""
    if not _MAYBE_HIDDEN.search(text):
        return ()
    copies = [unhidden(text)]
    for encoding in ("latin-1", "cp437"):
        back = _redecoded(text, encoding)
        if back is not None:
            copies.append(unhidden(back))
    return copies


def _whole_withheld(m, kind="names"):
    return _withheld("token-shaped text", len(m.group()), kind)


def _shown_pass(out):
    if "-----BEGIN " in out:
        out = PEM_BODY.sub(lambda m: m.group(1) + _withheld("", len(m.group(2)), "text"), out)
    if ":" in out:
        out = mailto_userinfo(out)
    if "@" in out:
        # first: a rule that withheld a piece of a password with a `:` in it would leave the marker, which breaks the token this one reads
        out = slash_userinfo(out)
    if ("=" in out or ":" in out) and KEYVALUE_HINT.search(out):
        # the value of a secret-named key before the bare user-info rule, for the same reason (the marker of that rule holds spaces)
        out = KEYVALUE_SECRET.sub(lambda m: m.group(0) if PLACEHOLDER_ONLY.fullmatch(m.group(3) or m.group(4)) else
                                  m.group(1) + (m.group(2) or "") + _withheld("", len(m.group(3) or m.group(4)), "text"), out)
    if ">" in out or "&gt;" in out:
        out = ELEMENT_SECRET.sub(lambda m: m.group() if PLACEHOLDER_ONLY.fullmatch(m.group(2).strip(" \t")) and _ends_element(m) else m.group(1) + _withheld("", len(m.group(2)), "text"), out)
    if "@" in out:
        out = CUT_USERINFO.sub(lambda m: m.group() if FORMAT_ONLY.fullmatch(m.group().partition(":")[2]) else _withheld("userinfo", len(m.group()), "urls"), out)
    # a prefixed token takes the rest of the run of name characters it ends inside (a token glued to it, whose own prefix it took), and
    # a JWT's payload and signature after a `.` are one token even when its head was glued to another and taken with it
    if "/" in out:
        # what only the whole text shows, found in the same text and withheld together (one rule's match never hides another's): base64
        # joined by `/`, a prefixed token (a JWT, `Basic`/`Bearer` holding `/`) with the run it ends inside, a user-info whose `//` or
        # host a split would remove; then each component alone
        found = [(s, e, "token-shaped text") for s, e in _slash_spans(out)]
        found += [(m.start(), m.end(), "token-shaped text") for rule in (GLUED, JWT_TAIL) for m in rule.finditer(out)]
        found += [(m.start(), m.end(), "userinfo") for rule in (_USERINFO, _BARE_USERINFO) for m in rule.finditer(out)]
        if found:
            found.sort()
            merged = []
            for s, e, what in found:
                if merged and s < merged[-1][1]:
                    ps, pe, pw = merged[-1]
                    merged[-1] = (ps, max(pe, e), "token-shaped text" if "token" in pw + what else pw)
                else:
                    merged.append((s, e, what))
            parts, last = [], 0
            for s, e, what in merged:
                parts.append(out[last:s])
                parts.append(_withheld(what, e - s, "urls" if what == "userinfo" else "names"))
                last = e
            parts.append(out[last:])
            out = "".join(parts)
        out = "/".join(scrub(part, "names") for part in out.split("/"))
    else:
        if "eyJ" in out:
            out = JWT_TAIL.sub(_whole_withheld, out)
        out = scrub(GLUED.sub(_whole_withheld, out), "names")
    return _grow(TOKEN_HEAD.sub(_whole_withheld, out))


_MARK_END = re.compile(r"<token-shaped text withheld (\d+) characters>$")
_MARK_START = re.compile(r"<token-shaped text withheld (\d+) characters>")
_PIECE = re.compile(r"[A-Za-z0-9_+%-]+={0,2}")
_PIECE_END = re.compile(r"[A-Za-z0-9_+%-]+={0,2}$")


def _grow(out):
    """A withheld token takes the random-looking pieces joined to it by `/` (the shared block's growth across `/`, which the component
    pass does not see): a piece of a key next to a piece withheld alone is not left printed."""
    if "/" not in out or "withheld" not in out:
        return out
    # the run of name characters a part begins or ends with is the piece taken, as the shared block's growth takes it (`\\srv\<piece>/`)
    res = []
    for part in out.split("/"):
        m = _MARK_END.search(res[-1]) if res else None
        piece = _PIECE.match(part) if m else None
        if piece and _randomish(piece.group()):
            res[-1] = res[-1][:m.start()] + _withheld("token-shaped text", int(m.group(1)) + 1 + piece.end(), "names") + part[piece.end():]
        else:
            res.append(part)
    out = []
    for part in reversed(res):
        m = _MARK_START.match(out[-1]) if out else None
        piece = _PIECE_END.search(part) if m else None
        if piece and _randomish(piece.group()):
            out[-1] = part[:piece.start()] + _withheld("token-shaped text", int(m.group(1)) + 1 + len(piece.group()), "names") + out[-1][m.end():]
        else:
            out.append(part)
    return "/".join(reversed(out))


_ONE_CLEAN = set()                  # pieces of text between escapes known to pass _shown_one unchanged


def _shown_one(text):
    if text in _ONE_CLEAN:
        return text, 1
    out = _shown_pass(text)
    passes = 1
    while out != text and passes < 4:
        text, out = out, _shown_pass(out)
        passes += 1
    if passes == 1 and len(out) <= 256 and len(_ONE_CLEAN) < 200000:
        _ONE_CLEAN.add(out)
    return out, passes


# The escapes cell() writes (\xNN and \uNNNN) end a piece of text: `\x06DataSpaces` is a control character and a word, and the `x06` of
# its escape is not a part of the word (whose digit would make it read as random). What an escape splits is tested joined by unhidden.
# A backslash of the file is written doubled and is a character of its piece, not an end of it (a password holding one is read whole);
# it is found as a pair only so that the `\x06` written for a file's own backslash and `x06` is not taken for an escape.
_ESCAPE = re.compile(r"\\\\|(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})")


def _shown(text):
    if "\\" not in text:
        return _shown_one(text)
    parts, passes, start = [], 1, 0
    for m in _ESCAPE.finditer(text):
        if m.group(1) is not None:
            parts.append(text[start:m.start()])
            parts.append(m.group(1))
            start = m.end()
    parts.append(text[start:])
    for k in range(0, len(parts), 2):
        parts[k], n = _shown_one(parts[k])
        passes = max(passes, n)
    return "".join(parts), passes


def shown_path(text):
    """A string as it may be printed: user-info, a secret-named value, a token-shaped run of the whole text and of each `/` component,
    every token head, withheld; and the whole text withheld when its copy without hidden characters (unhidden) holds any of these.
    A pass that withheld something is run again on its own result (a marker it wrote can leave a new edge in front of a user-info), up
    to four times, so that the result is a fixed point: shown_path of it is itself, which is what final_check tests."""
    if not isinstance(text, str):
        return text
    if text in _CLEAN:
        return text
    for bare in hidden_copies(text):
        if bare != text and _shown(bare)[0] != bare:
            return _withheld("token-shaped text", len(text), "names")
    out, passes = _shown(text)
    for bare in hidden_copies(out):
        if bare != out and _shown(bare)[0] != bare:
            return _withheld("token-shaped text", len(text), "names")
    # A result that settled (the last pass changed nothing, and the hidden-character copies above held nothing more) is known to be a
    # fixed point: the backstop and the next write of the same string do not read it again, so that a file of thousands of hostile names
    # costs the sanitiser one pass over each and not three. (Four passes may not have settled: that result is read again.)
    if passes < 4 and (_CACHE_ALL[0] or (len(out) <= 65536 and len(_CLEAN) < 200000 and _CLEAN_CHARS[0] + len(out) <= (1 << 25))):
        _CLEAN.add(out)
        _CLEAN_CHARS[0] += len(out)
    return out


def shown_number(value):
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) >= LONG_NUMBER:
        return "<a number of %d bits, withheld>" % value.bit_length()
    return value


FINAL = {"fields": 0}


def _final_withheld(what):
    FINAL["fields"] += 1
    return "<withheld by the final check: %s>" % what


def final_check(value, safe=None, key=""):
    """The backstop. `value` is what is about to be written (after the sanitiser); `safe(key, text)` names the strings the tool made
    itself and registered (a file's path, a class id). Every other string, key or value, is withheld whole when shown_path would still
    change it; a number of 32 digits or more and any value of a type JSON does not carry are withheld too. Returns the value to write."""
    if isinstance(value, str):
        if (safe is not None and safe(key, value)) or shown_path(value) == value:
            return value
        return _final_withheld("%d characters" % len(value))
    if isinstance(value, bool) or value is None or isinstance(value, float):
        return value
    if isinstance(value, int):
        return value if abs(value) < LONG_NUMBER else _final_withheld("a number of %d bits" % value.bit_length())
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            name = k if isinstance(k, str) else str(k)
            if shown_path(name) != name:
                name = _final_withheld("a key of %d characters" % len(name))
            base, n = name, 1
            while name in out:
                n += 1
                name = "%s #%d" % (base, n)
            out[name] = final_check(v, safe, k if isinstance(k, str) else "")
        return out
    if isinstance(value, (list, tuple)):
        return [final_check(v, safe) for v in value]
    return _final_withheld("a value of type %s" % type(value).__name__)
# END SHARED ONE WAY OUT


BUDGET_SECONDS = 3500                     # recipe.json gives this recipe 3600
GRACE_SECONDS = 10                        # a program that outlives its own clock by this much is ended
VERSION_SECONDS = 20
MAX_JSON = 32 << 20                       # an engine's JSON read here: parsed JSON takes up to about twenty-five times its size, so a larger file is kept whole and not read
TSV_ROWS = 1_000_000
EARLIER = re.compile(r"^(capa|floss|coverage)(-\d+)?\.(json|stderr)$|^(matches|index)(-\d+)?\.tsv$")
FLOSS_KINDS = ("static_strings", "stack_strings", "tight_strings", "decoded_strings")
# The engines are programs the pack declares and does not ship; this recipe runs them if they are on PATH and says what they said.
ENGINES = [
    {"id": "capa", "program": "capa", "argv": ["-j"], "seconds": 1500,
     "what": "capability rule matches over features the program extracts from the file; each match is a hypothesis about what code could do"},
    {"id": "floss", "program": "floss", "argv": ["-j"], "seconds": 1900,
     "what": "strings recovered by analysis and emulation, in the program's own modes; recovered strings are derived, not literals at a file offset"},
]
NOT_COVERED = "execution of the sample, reachability or intent of any matched capability, strings or capabilities the engines do not recover, any engine that is not installed"


def describe(exc):
    return "%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or str(exc))


def target_of(arg):
    text = open(arg, encoding="utf-8").read() if os.path.isfile(arg) else arg
    target = json.loads(text)
    if not isinstance(target, dict):
        raise ValueError("the target is not a JSON object")
    paths = target.get("paths")
    if not isinstance(paths, list) or not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def detect(path):
    """(format or None, why): a PE with its signature where the DOS header points, or an ELF with a class, a byte order and a whole header."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(64)
            if head[:2] == b"MZ":
                if len(head) < 0x40:
                    return None, "MZ header is too short to name a PE signature"
                fh.seek(int.from_bytes(head[0x3C:0x40], "little"))
                if fh.read(4) == b"PE\x00\x00":
                    return "PE", "DOS header points to a PE signature"
                return None, "MZ header does not point to a PE signature"
            if head[:4] == b"\x7fELF":
                if len(head) < 6 or head[4] not in (1, 2) or head[5] not in (1, 2):
                    return None, "ELF signature with an unusable class or byte order"
                need = 64 if head[4] == 2 else 52
                if size < need:
                    return None, "ELF signature, and the file is shorter than its header (%d bytes)" % need
                return "ELF", "ELF signature and a whole ELF header"
    except OSError as exc:
        return None, "unreadable: %s" % (exc.strerror or exc)
    return None, "no PE or ELF signature (the engines are run on those; Mach-O and raw shellcode are not offered)"


def new_name(out_dir, stem, ext, mode=0o644):
    """A name in `out_dir` that nothing has: `stem.ext`, or `stem-2.ext`, ... The file is created at once, exclusively, so that a result an
    earlier run left in this directory is never opened for writing, let alone replaced."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for n in range(1, 1000):
        name = "%s%s" % (stem if n == 1 else "%s-%d" % (stem, n), ext)
        try:
            os.close(os.open(os.path.join(out_dir, name), flags, mode))
        except FileExistsError:
            continue
        return name
    raise OSError(errno.EEXIST, "a thousand files of this name already exist in %s" % out_dir)


def version_of(exe, out_dir, seconds=VERSION_SECONDS):
    """(exit code, stdout head, stderr head, timed out) of `exe --version`: its output goes to two files of the recipe's directory and
    is read back 4 KiB at a time, so a program that never stops printing fills a file, not this process's memory."""
    import tempfile
    paths = []
    try:
        for kind in ("out", "err"):
            fd, name = tempfile.mkstemp(prefix=".version-", suffix="." + kind, dir=out_dir)
            os.close(fd)
            paths.append(name)
        rc, timed = run_to_files([exe, "--version"], paths[0], paths[1], seconds)
        heads = []
        for name in paths:
            with open(name, "rb") as fh:
                heads.append(fh.read(4096))
        return rc, heads[0], heads[1], timed
    except OSError as exc:
        return None, b"", describe(exc).encode("utf-8", "replace"), False
    finally:
        for name in paths:
            try:
                os.unlink(name)
            except OSError:
                pass


def shown_text(text, keep):
    """A string an engine printed, withheld whole and then cut to `keep` characters: a cut before the withholding could leave the head of
    a token too short to be recognised as one."""
    return shown_path(cell(text))[:keep]


def shown_key(key):
    return shown_path(cell(str(key)))


def shown_cell(value):
    """One cell of matches.tsv: through the sanitiser, then the backstop."""
    return final_check(shown_path(cell(str(value))))


def first_line(raw):
    for line in raw.decode("utf-8", "replace").splitlines():
        if line.strip():
            return shown_text(line.strip(), 200)
    return None


def read_json(path):
    try:
        if os.path.getsize(path) > MAX_JSON:
            return None, "the output is larger than %d bytes: kept whole, not read here" % MAX_JSON
        with open(path, encoding="utf-8") as fh:
            value = json.load(fh)
    except (OSError, ValueError, RecursionError) as exc:
        return None, "not JSON (%s)" % type(exc).__name__
    return (value, None) if isinstance(value, dict) else (None, "JSON, but not an object")


def judge(engine, rc, timed_out, doc, why):
    """(status, reason, details) from what the program said. Never from the output file being non-empty."""
    if timed_out:
        return "failed", "%s was stopped at its time limit; what it had written is kept" % engine["program"], {}
    if rc is None:
        return "failed", "%s could not be started" % engine["program"], {}
    if rc != 0:
        return "failed", "%s exited with status %d; its stderr is kept" % (engine["program"], rc), {}
    if doc is None and why and why.startswith("the output is larger"):
        return "partial", "%s exited 0; %s, so nothing of it is summarised here" % (engine["program"], why), {}
    if doc is None:
        return "failed", "%s exited 0 and its output is not a readable JSON object: %s" % (engine["program"], why), {}
    if engine["id"] == "capa":
        rules = doc.get("rules")
        if not isinstance(rules, dict):
            return "partial", "capa's JSON has no `rules` mapping, so no match was listed; the whole output is kept", {"keys": sorted(shown_key(k) for k in doc)[:20]}
        meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
        details = {"rules_matched": len(rules), "meta_keys": sorted(shown_key(k) for k in meta)[:20]}
        for key in ("version",):
            if isinstance(meta.get(key), str):
                details["reported_version"] = shown_text(meta[key], 60)
        # Which rule set matched is part of the result: capa names it (meta.analysis.rules, the rule paths it loaded).
        analysis = meta.get("analysis") if isinstance(meta.get("analysis"), dict) else {}
        rule_sets = analysis.get("rules")
        if isinstance(rule_sets, list):
            details["rule_sets"] = [shown_path(cell(str(r))) for r in rule_sets[:20]]
            if len(rule_sets) > 20:
                details["rule_sets_total"] = len(rule_sets)
        else:
            details["rule_sets"] = None
            details["rule_sets_note"] = "capa's JSON does not name the rule set it loaded (meta.analysis.rules)"
        return "complete", "capa exited 0 and wrote a JSON object with a rules mapping", details
    strings = doc.get("strings")
    details = {"keys": sorted(shown_key(k) for k in doc)[:20]}
    analysis = doc.get("analysis") if isinstance(doc.get("analysis"), dict) else {}
    flags = {shown_key(k): v for k, v in analysis.items() if str(k).startswith("enable_") and isinstance(v, bool)}
    if flags:
        details["analysis_enabled"] = dict(sorted(flags.items()))
    if not isinstance(strings, dict):
        return "partial", "floss's JSON has no `strings` mapping, so no string kind was counted; the whole output is kept", details
    details["string_kinds"] = {shown_key(k): (len(v) if isinstance(v, list) else None) for k, v in list(strings.items())[:20]}
    known = [k for k in FLOSS_KINDS if isinstance(strings.get(k), list)]
    if not known:
        return "partial", "floss's `strings` mapping holds none of the string kinds this recipe reads (%s) as a list; the whole output is kept" % ", ".join(FLOSS_KINDS), details
    # A kind whose analysis floss's own flags say was off (analysis.enable_<kind> false, as for a .NET file) was not run: its empty list
    # is not "none found", and only the kinds that ran are counted as read.
    off = [k for k in FLOSS_KINDS if analysis.get("enable_" + k) is False]
    ran = [k for k in known if k not in off]
    if off:
        details["kinds_not_run"] = off
        return "partial", ("floss exited 0 and its analysis flags say %s %s not run (analysis.enable_* false): an empty list of %s is not 'none found'; "
                           "the kinds that ran: %s" % (", ".join(off), "was" if len(off) == 1 else "were", "that kind" if len(off) == 1 else "those kinds",
                                                         ", ".join(ran) or "none")), details
    return "complete", "floss exited 0 and wrote a JSON object whose `strings` mapping holds %s" % ", ".join(known), details


def write_matches(doc, path):
    """matches.tsv from capa's `rules` mapping: rule name, namespace, ATT&CK ids, match count. No matched feature or string is copied."""
    rows = 0
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("rule\tnamespace\tattack_ids\tmatches\n")
        for name, rule in doc["rules"].items():
            if rows >= TSV_ROWS:
                return rows, True
            meta = rule.get("meta") if isinstance(rule, dict) and isinstance(rule.get("meta"), dict) else {}
            attack = meta.get("attack") if isinstance(meta.get("attack"), list) else []
            ids = [str(a.get("id")) for a in attack if isinstance(a, dict) and a.get("id")]
            matches = rule.get("matches") if isinstance(rule, dict) else None
            fh.write("%s\t%s\t%s\t%s\n" % (shown_cell(name), shown_cell(meta.get("namespace", "")), ",".join(shown_cell(i) for i in ids),
                                           len(matches) if isinstance(matches, (list, dict)) else ""))
            rows += 1
    return rows, False


def assemble(state):
    out_dir = state["out_dir"]
    engines = state["engines"]
    errors = list(state["errors"])
    notes, limits = [], []
    for e in engines.values():
        if e["status"] in ("failed", "unavailable"):
            errors.append("%s %s: %s" % (e["id"], e["status"], e["reason"]))
        elif e["status"] == "partial":
            notes.append("%s partial: %s" % (e["id"], e["reason"]))
        if e.get("timed_out"):
            limits.append("%s was stopped at its time limit (%d s)" % (e["id"], e["seconds"]))
    statuses = [e["status"] for e in engines.values()]
    usable = [s for s in statuses if s in ("complete", "partial")]
    if statuses and all(s == "complete" for s in statuses) and not state["errors"]:
        status = "complete"
    elif usable:
        status = "partial"
    else:
        status = "failed"
    coverage = {
        "recipe": "capa-floss",
        "target": state["shown"],
        "format": state["fmt"],
        "status": status,
        "covered": "what each engine that is installed wrote about the file, as the engine said it (see engines); a match is a hypothesis, a recovered string is derived",
        "not_covered": NOT_COVERED,
        "engines": {k: {kk: vv for kk, vv in v.items() if kk not in ("seconds",)} for k, v in engines.items()},
        "limits_hit": limits,
        "warnings": notes,
        "errors": errors,
        "sensitive_outputs": [e["file"] for e in engines.values() if e.get("file")],
        "sensitive_note": "capa's explanations and floss's recovered strings can hold credentials: read them by rule, offset and length. coverage.json, index.tsv and matches.tsv copy no string and no matched feature",
    }
    lines = []
    for e in engines.values():
        for key, what in (("file", "%s output, whole, exactly as the program wrote it (status %s)" % (e["id"], e["status"])), ("stderr_file", "what %s said on stderr" % e["id"])):
            name = e.get(key)
            if name and os.path.isfile(os.path.join(out_dir, name)) and os.path.getsize(os.path.join(out_dir, name)):
                lines.append("%s\t%s" % (name, what))
    if state.get("matches") and os.path.isfile(os.path.join(out_dir, state["matches"])):
        lines.append("%s\tcapa rules that matched: name, namespace, ATT&CK ids, match count (no feature or string)" % state["matches"])
    # This run's own receipt is this run's: it is named as such and never as a file an earlier run left.
    lines.append("%s\tthis run's receipt: the status of each engine, what was and was not covered, and the files of this run" % state["coverage_name"])
    lines.append("%s\tthis run's index of its files (this file)" % state["index_name"])
    listed = {l.split("\t", 1)[0] for l in lines}
    try:
        present = sorted(os.listdir(out_dir))
    except OSError:
        present = []
    for name in present:
        if name in listed or not EARLIER.match(name) or not os.path.isfile(os.path.join(out_dir, name)) or os.path.getsize(os.path.join(out_dir, name)) == 0:
            continue
        lines.append("%s\tleft by an earlier run in this directory; kept, and not part of this result" % name)
    coverage["outputs"] = {k: v for k, v in {"matches": state.get("matches"), **{e["id"]: e.get("file") for e in engines.values()}}.items() if v}
    return status, coverage, lines


def receipt_names(out_dir):
    """coverage.json and index.tsv, or, when an earlier run left either in this directory, new names for this run's: the earlier run's
    receipt describes the files it wrote, which are still there, and is never replaced."""
    if not any(os.path.lexists(os.path.join(out_dir, n)) for n in ("coverage.json", "index.tsv")):
        return "coverage.json", "index.tsv"
    return new_name(out_dir, "coverage", ".json"), new_name(out_dir, "index", ".tsv")


def write_receipt(out_dir, name, text):
    """`text` into this run's own receipt file, whole or not at all: a temporary file beside it, then a rename over it."""
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix=".receipt-", suffix=".tmp", dir=out_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(out_dir, name))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_results(state):
    """The receipt and the index, each through the backstop (final_check) as the last step: a field it withholds here or in matches.tsv
    is counted in the receipt, named in its errors, and makes a complete result partial (a fault of this recipe, never of the file)."""
    status, coverage, lines = assemble(state)
    out_dir = state["out_dir"]
    # this pass's count, with what the backstop withheld in matches.tsv (written once): the receipt is rewritten after every engine
    FINAL["fields"] = state.get("matches_withheld", 0)
    lines = ["\t".join(final_check(part) for part in l.split("\t")) for l in lines]
    coverage = final_check(coverage)
    if FINAL["fields"]:
        coverage["withheld_by_final_check"] = FINAL["fields"]
        coverage["errors"].append("the final check withheld %d field(s) the sanitiser had let through: each is given by its length; a fault of this recipe, not of the file" % FINAL["fields"])
        if coverage["status"] == "complete":
            coverage["status"] = status = "partial"
    write_receipt(out_dir, state["coverage_name"], json.dumps(coverage, indent=2) + "\n")
    write_receipt(out_dir, state["index_name"], "".join(l + "\n" for l in lines))
    return status


def run(path, out_dir, fmt, budget):
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    started = time.monotonic()
    sample = os.path.abspath(path)
    state = {"out_dir": out_dir, "fmt": fmt, "shown": shown_path(path), "errors": [], "engines": {}, "matches": None}
    state["coverage_name"], state["index_name"] = receipt_names(out_dir)

    def last_word(signum):
        state["errors"].append("the recipe was stopped by signal %d; the program that was running was ended" % signum)
        try:
            write_results(state)
        except OSError:
            pass

    STATE["last_word"] = last_word
    install_signal_handlers()
    become_subreaper()
    for engine in ENGINES:
        state["engines"][engine["id"]] = {"id": engine["id"], "program": engine["program"], "status": "failed", "reason": "%s has not run" % engine["program"],
                                          "argv": [engine["program"]] + engine["argv"] + ["<sample>"], "seconds": engine["seconds"], "file": None, "stderr_file": None,
                                          "what": engine["what"]}

    def unfinished():
        state["errors"].append("the recipe was started and has not finished")
        write_results(state)
        state["errors"].pop()

    unfinished()
    try:
        run_engines(state, sample, budget, started, unfinished)
    except Exception as exc:  # noqa: BLE001 - the receipt says what stopped the recipe, never "started and has not finished"
        state["errors"].append("the recipe stopped on an unexpected error (%s): the engines' statuses are as far as it got" % scrub(describe(exc), "text"))
    sweep_orphans()
    final = write_results(state)
    print(json.dumps({"ok": final == "complete", "status": final, "format": fmt, "coverage": state["coverage_name"], "index": state["index_name"]}))
    return 0 if final in ("complete", "partial") else 2


def run_engines(state, sample, budget, started, unfinished):
    out_dir = state["out_dir"]
    for engine in ENGINES:
        e = state["engines"][engine["id"]]
        exe = shutil.which(engine["program"])
        if exe is None:
            e.update({"status": "unavailable", "reason": "%s is not on PATH in this image (the pack declares it as optional)" % engine["program"], "installed": False})
            unfinished()
            continue
        e["installed"] = True
        rc, out, err, timed = version_of(exe, out_dir, max(1, min(VERSION_SECONDS, int(budget - (time.monotonic() - started)))))
        sweep_orphans()
        e["version_command"] = {"argv": [engine["program"], "--version"], "exit_code": rc, "first_line": first_line(out) or first_line(err), "timed_out": timed,
                                "note": "what the program printed, not a statement of what this recipe knows about that release"}
        left = budget - (time.monotonic() - started)
        seconds = max(1, min(engine["seconds"], int(left)))
        if left < 1:
            e.update({"status": "failed", "reason": "the recipe's time budget was spent before %s could start" % engine["program"], "timed_out": True})
            unfinished()
            continue
        # what an engine wrote is raw (strings out of the sample, as FLOSS recovers them): mode 0600, as the tools' own raw files are
        e["file"] = new_name(out_dir, engine["id"], ".json", 0o600)
        e["stderr_file"] = new_name(out_dir, engine["id"], ".stderr", 0o600)
        e["seconds"] = seconds
        try:
            rc, timed_out = run_to_files([exe] + engine["argv"] + [sample], os.path.join(out_dir, e["file"]), os.path.join(out_dir, e["stderr_file"]), seconds)
        except OSError as exc:
            # A program on PATH that cannot be executed (not a program, a missing interpreter, no permission: ENOEXEC, ENOENT, EACCES)
            # is a named failure of that engine; the recipe goes on and its receipt says so.
            e.update({"status": "failed", "reason": "%s could not be started: %s" % (engine["program"], scrub(describe(exc), "text")), "exit_code": None, "timed_out": False,
                      "start_error": errno.errorcode.get(exc.errno, "") if exc.errno else type(exc).__name__})
            if drop_if_empty(os.path.join(out_dir, e["stderr_file"])):
                e["stderr_file"] = None
            if drop_if_empty(os.path.join(out_dir, e["file"])):
                e["file"] = None
            unfinished()
            continue
        e["exit_code"], e["timed_out"] = rc, timed_out
        orphans = sweep_orphans()
        doc, why = read_json(os.path.join(out_dir, e["file"]))
        status, reason, details = judge(engine, rc, timed_out, doc, why)
        if orphans:
            e["orphans_ended"] = orphans
            if status == "complete":
                status, reason = "partial", "%s exited 0 and left %d process(es) of its own running, which were ended: what they wrote after it exited is not in its output" % (engine["program"], orphans)
        e.update({"status": status, "reason": reason, "bytes": os.path.getsize(os.path.join(out_dir, e["file"])), **details})
        if engine["id"] == "capa" and status == "complete" and isinstance(doc.get("rules"), dict):
            state["matches"] = new_name(out_dir, "matches", ".tsv")
            before = FINAL["fields"]
            rows, capped = write_matches(doc, os.path.join(out_dir, state["matches"]))
            state["matches_withheld"] = state.get("matches_withheld", 0) + FINAL["fields"] - before
            e["matches_listed"] = rows
            if capped:
                e["status"], e["reason"] = "partial", "capa matched more than %d rules: matches.tsv lists the first %d; capa.json holds them all" % (TSV_ROWS, TSV_ROWS)
        if drop_if_empty(os.path.join(out_dir, e["stderr_file"])):
            e["stderr_file"] = None
        unfinished()


SUBREAPER = [False]


def become_subreaper():
    """On Linux, ask the kernel to make this process the parent of any process an engine leaves behind (PR_SET_CHILD_SUBREAPER = 36), so that
    one that called setsid or double-forked and outlived its parent can still be found and ended. macOS has no such call: there an orphan
    of an engine that exited by itself is not found (the tree is walked, and killed, only while its parent is alive)."""
    if sys.platform.startswith("linux") and ctypes is not None:
        try:
            SUBREAPER[0] = ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
        except Exception:  # noqa: BLE001
            SUBREAPER[0] = False


def sweep_orphans():
    """End every process still below this one (an engine has exited, so none should be) and reap what can be reaped; how many were ended."""
    if not SUBREAPER[0]:
        return 0
    ended = 0
    for _ in range(4):
        victims = descendants(os.getpid())
        if not victims:
            break
        for pid in victims:
            try:
                os.kill(pid, signal.SIGKILL)
                ended += 1
            except OSError:
                pass
        for pid in victims:
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
    return ended


def drop_if_empty(path):
    try:
        if os.path.isfile(path) and os.path.getsize(path) == 0:
            os.unlink(path)
            return True
    except OSError:
        pass
    return False


def main(argv):
    if len(argv) < 2 or argv[1] not in ("detect", "run"):
        print(json.dumps({"ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR [--seconds N]"}))
        return 2
    args = dict(zip(argv[2::2], argv[3::2]))
    if "--target" not in args:
        print(json.dumps({"ok": False, "error": "--target is required"}))
        return 2
    try:
        _target, path = target_of(args["--target"])
    except (OSError, ValueError, RecursionError) as exc:
        print(json.dumps({"ok": False, "error": scrub(str(exc) if not isinstance(exc, RecursionError) else "the target is nested too deeply")}))
        return 2
    if not os.path.isfile(path):
        print(json.dumps({"ok": False, "error": "the target is not a readable file"}))
        return 2
    fmt, why = detect(path)
    if argv[1] == "detect":
        print(json.dumps({"applies": fmt is not None, "format": fmt, "why": why}))
        return 0 if fmt else 1
    if "--out" not in args:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    if fmt is None:
        os.makedirs(args["--out"], mode=0o700, exist_ok=True)
        name, index = receipt_names(args["--out"])
        if index != "index.tsv":
            os.unlink(os.path.join(args["--out"], index))
        write_receipt(args["--out"], name, json.dumps({"recipe": "capa-floss", "status": "unsupported", "why": why, "limits_hit": [], "errors": []}, indent=2))
        print(json.dumps({"ok": False, "status": "unsupported", "why": why, "coverage": name}))
        return 2
    budget = BUDGET_SECONDS
    if "--seconds" in args:
        try:
            budget = int(args["--seconds"])
        except ValueError:
            budget = 0
        if not 1 <= budget <= BUDGET_SECONDS:
            print(json.dumps({"ok": False, "error": "--seconds is a whole number from 1 to %d" % BUDGET_SECONDS}))
            return 2
    try:
        return run(path, args["--out"], fmt, budget)
    except OSError as exc:
        # an --out that cannot be made or written (a hand run; the harness gives a writable $OUT): said as JSON, never a traceback
        print(json.dumps({"ok": False, "status": "failed", "error": "the output directory cannot be written: %s" % scrub(describe(exc), "text")}))
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
