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
import json
import os
import signal
import sys

TOOL = {"name": "suricata_run", "version": 12}
PARSER = "suricata_run/5"


def _before_start(signum, _frame):
    """A stop that arrives while the rest of this file is still loading (the other imports, the compile of what follows): the first signal
    counts, nothing was read, started or written, and the one answer says so. main() installs the tool's own handlers and replaces this one.
    What no script can answer is a stop that arrives before the interpreter has run these first lines (its own start-up)."""
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    try:
        sys.stdout.write(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "ok": False, "stage": "starting",
                                     "status_basis": "stopped by signal %d before any work: nothing was read, started or written" % signum,
                                     "interrupted_by_signal": signum}) + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        pass
    os._exit(128 + signum)


for _signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(_signum, _before_start)   # replaced by main() once the module is loaded


import stat
import array
import collections
import contextlib
import errno
import hashlib
import ipaddress
import re
import shutil
import subprocess
import time
from pathlib import Path

TEST_SECONDS = 120
MAX_TIMEOUT = 1000            # the manifest's limit is 1200: --build-info (30 s) and the configuration test (120 s) come first
MANIFEST_SECONDS = 1200       # the manifest's limit: the tool's own clock for reading eve.json ends READ_MARGIN seconds before it, counted from the start
READ_MARGIN = 30              # kept for building and printing the answer after the last line was read
CLOCK_BYTES = 1 << 20         # the reading clock is also looked at after this many bytes of EVE
DEFAULT_HOME_NET = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
PREFLIGHT_SECONDS = 30
MAX_LINE = 16 << 20
MAX_JSON_DEPTH = 64           # an EVE line nested deeper than this is located and not parsed: the same answer on every Python, which differs on how deep json.loads goes
MAX_SIGNATURES = 10_000
LOADED = re.compile(r"(\d+) rules? successfully loaded, (\d+) rules? failed")

# BEGIN SHARED WITHHOLDING
# The same text is in every tool that withholds identifier-shaped strings and credentials (the network, base, encrypted-containers,
# memory, virtualization, ransomware and reverse-engineering packs, and the three tools of the cloud pack), so that they withhold the
# same strings; the tests that hold the copies equal are tests/shared-blocks-census.test.ts (how many carry it),
# tests/pack-re-delta10.test.ts (every copy equal, found by the marker), tests/pack-network-withholding.test.ts,
# tests/pack-base-shared.test.ts, tests/pack-virtualization-shared.test.ts, tests/pack-re-process.test.ts and
# tests/pack-cloud-shared.test.ts. An identifier-shaped string is withheld wherever the tool would print one: a name, a path
# component, a URL, a message that quotes either; and a credential (a value given to a password, a token, a cookie, a pair, a
# switch) by the name it is given under. A carrier may set two names above this block: WITHHOLD_LIMIT, the length past which a text is
# withheld whole (65536 when it sets none), and WITHHOLD_TICK, a hook that long scans call and that may raise to end them at the
# carrier's deadline (none when it sets none). Nothing else in the block is a carrier's to change.
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
TEXT_LIMIT = globals().get("WITHHOLD_LIMIT", 65536)


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


# ---- credentials: a value is withheld by the name it is given under and by the text around it ----------------------------------
# The rules above find strings that are shaped like an identifier. These find a secret that has no shape, because of what it is
# assigned to (`password=`, a `Name`/`Value` pair, a `-Password` switch, `curl -u user:pass`, `mysql -pSECRET`), and the common
# token families, private key blocks and hashes of an account database. A name decides whether a value is a secret, a value
# decides nothing. Every rule runs in time linear in the text (a bounded stretch after each anchor, no nested repeat), and a
# carrier whose texts are long (a cloud log: a megabyte) sets WITHHOLD_TICK to a hook that ends the work at its deadline.
_CRED_CHECKSUM_NAME = re.compile(r"(?i)checksum|digest|sha[0-9]|md5|etag|crc[0-9]")
_CRED_REDACTED = re.compile(r"^\W*(?:hidden_due_to_security_reasons|redacted|masked|removed|\*+|x{3,}|\[\])\W*$", re.I)
_CRED_NOT_A_VALUE = frozenset(("true", "false", "null", "none", "nil", "undefined", "required", "optional", "enabled", "disabled"))
_CRED_EXACT = {
    "password", "newpassword", "oldpassword", "currentpassword", "passwd", "pwd", "passphrase", "passcode", "pin", "otp",
    "pass", "dbpass", "userpass", "adminpass", "rootpass", "plaintext",
    "secret", "clientsecret", "secretkey", "secretaccesskey", "awssecretaccesskey", "awssecretkey", "secretstring",
    "secretbinary", "secrettext", "secretvalue", "accesskeysecret",
    "sessiontoken", "securitytoken", "accesstoken", "refreshtoken", "idtoken", "bearertoken", "authtoken", "token",
    "tokencode", "mfacode", "verificationcode", "authorizationcode",
    "authorization", "proxyauthorization", "cookie", "setcookie", "apikey", "privatekey", "privatekeypem",
    "sharedaccesskey", "sharedaccesssignature", "accountkey", "primarykey", "secondarykey", "keyvalue", "masterkey",
    "storagekey", "subscriptionkey", "ocpapimsubscriptionkey",
    "connectionstring", "credential", "credentials", "assertion", "samlresponse", "mfasecret",
    "sastoken", "sassignature", "signature", "sig",
    "passwordhash", "nthash", "ntlmhash", "lmhash",
}
_CRED_SUFFIX = ("password", "passwd", "passphrase", "secret", "apikey", "privatekey", "sessiontoken", "securitytoken",
                "accesstoken", "refreshtoken", "clientsecret", "token", "secrettext", "secretkey", "secretaccesskey",
                "primarykey", "secondarykey", "accountkey", "sharedaccesskey", "subscriptionkey", "passwordhash",
                "ntlmhash", "nthash", "passcode", "signature", "cookie")
# a position or an idempotency key under a name that ends in `token`
_CRED_NOT_SECRET = ("nexttoken", "pagetoken", "continuationtoken", "paginationtoken", "nextpagetoken", "pagingtoken",
                    "startingtoken", "nextmarkertoken", "clienttoken", "clientrequesttoken", "idempotencytoken",
                    "nextforwardtoken", "nextbackwardtoken", "requesttoken")
_CRED_CONTAINERS = ("credential", "credentials")
_CRED_NAME_CACHE = {}
_CRED_NAME_KEYS = ("Name", "name", "Key", "key")
_CRED_VALUE_KEYS = ("Value", "NewValue", "OldValue", "value", "newValue", "oldValue")


def is_container_name(name):
    """`credentials` names a group of fields (an access key id, an expiry, a token): each is judged by its own name."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower()) in _CRED_CONTAINERS


def name_is_sensitive(name):
    """Does a field or a parameter of this name hold a secret? (`Password`, `client_secret`, `x-api-key`; not `nextToken`.)"""
    hit = _CRED_NAME_CACHE.get(name)
    if hit is None:
        flat = re.sub(r"[^a-z0-9]", "", str(name).lower())
        hit = flat in _CRED_EXACT or (len(flat) > 6 and flat.endswith(_CRED_SUFFIX) and not flat.endswith(_CRED_NOT_SECRET))
        if len(_CRED_NAME_CACHE) < 20000:
            _CRED_NAME_CACHE[name] = hit
    return hit


_CRED_B64 = "A-Za-z0-9+/_-"
_CRED_B64_RUN = re.compile(r"(?<![%s])[%s]{128,}={0,2}(?![%s])" % (_CRED_B64, _CRED_B64, _CRED_B64))
_CRED_B64_EDGE = "(?<![A-Za-z0-9+/=_-])"
_CRED_B64_END = "(?![A-Za-z0-9+/=_-])"
# The names an assignment is recognised by. A long compound name may carry any prefix (dbPassword=, apiToken=, adminSecret:);
# a short one needs the edge of a word (sig= is not design=).
_CRED_STRONG = (r"password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|"
                r"security[_-]?token|auth[_-]?token|bearer[_-]?token|account[_-]?key|shared[_-]?access[_-]?key|primary[_-]?key|"
                r"secondary[_-]?key|private[_-]?key|subscription[_-]?key|sas[_-]?token|password[_-]?hash|nt[_-]?hash|ntlm[_-]?hash|"
                r"lm[_-]?hash|client[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?key|secret[_-]?text|secret[_-]?value|token|signature|plaintext")
_CRED_SHORT = r"(?<![A-Za-z0-9])(?:pwd|pass|sig|pin|otp|sas)"
_CRED_SEP = r"""(?:\\*["']|["'])?\s*(?:[:=]|%3[dD]|%3[aA])\s*"""
# a short name is a name only as `pwd=value` or `pass:value`: "pass: 3 attempts" is prose
_CRED_SEPS = r"""(?:\\*["']|["'])?(?:\s*(?:=|%3[dD])\s*|:(?=\S))"""
_CRED_NAME = r"(?:(?:%s)%s|%s%s)" % (_CRED_STRONG, _CRED_SEP, _CRED_SHORT, _CRED_SEPS)
_CRED_ARN_TAIL = re.compile(r"arn:[A-Za-z0-9-]+:[A-Za-z0-9-]+:[A-Za-z0-9-]*:[0-9]*:$")
_CRED_PAIR_WHY = "a value paired with a credential name"
_CRED_RULES = [
    # anchored at the start of a run and possessive, so that a megabyte of `eyJ` is read once, not once per `eyJ`
    ("a JSON Web Token", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}+\.[A-Za-z0-9_-]{2,}+(?:\.[A-Za-z0-9_-]*+)?"), 0),
    ("a JSON Web Encryption token", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}+(?:\.[A-Za-z0-9_-]*+){4}"), 0),
    ("a password in a URL", re.compile(r"(?i)(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]{1,20}://[^\s:/@\"'<>\\]{0,256}:([^\s/\"'<>\\]{1,1024})@(?=[^\s/@\"'<>]{1,255})"), 1),
    ("an Azure Functions key", re.compile(r"""(?i)(?:x-functions-key["']?\s*[:=]\s*(?:\\*["'])?|[?&;]code=)([A-Za-z0-9_/+=-]{16,512})"""), 1),
    ("a private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[\s\S]*)"), 0),
    ("a base64 block of key lines", re.compile(r"(?:[A-Za-z0-9+/]{60,80}={0,2}\r?\n){2,}[A-Za-z0-9+/]{2,80}={0,2}"), 0),
    ("an authorization header value", re.compile(
        r"""(?i)authorization["']?\s*[:=]\s*(?:\\*["'])?(?:(?:bearer|basic|digest|negotiate|ntlm|token)\s+)?([^\s"'&,;\\]{1,4096})"""), 1),
    ("a cookie header value", re.compile(r"""(?i)cookie["']?\s*[:=]\s*(?:\\*["'])?([^\r\n"'\\]{1,4096})"""), 1),
    ("a scheme and its credential", re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{3,4096})|\b(?:negotiate|ntlm|digest)\s+([A-Za-z0-9._~+/=-]{24,4096})"), -2),
    ("a value assigned to a credential name (quoted)", re.compile(
        r"""(?i)%s\\*(["'])(.{1,4096}?)(?=\\*\1)""" % _CRED_NAME), 2),
    ("a value assigned to a credential name", re.compile(
        r"""(?i)%s((?:(?!%%26)[^\s"'&<>\\]){1,4096})""" % _CRED_NAME), 1),
    ("a value given to a credential switch", re.compile(
        r"""(?i)(?<![A-Za-z0-9_])-(?:password|pass|pwd|passphrase|secret|clientsecret|apikey|accesstoken|token)\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    ("a secret given to ConvertTo-SecureString", re.compile(
        r"""(?i)ConvertTo-SecureString\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    # `mysql -u<user> -p<password>`: with `-p` glued to its value, and only as an option of a MySQL or MariaDB client (`ssh -p 22`,
    # `nc -p 80` and `mysql -p` alone, which asks for the password, name a port or nothing). The options are read up to the next
    # command of the kind, so that a text of many of them is read once, not once for each
    ("a password given to a MySQL client", re.compile(
        r"""(?i:(?<![\w.-])(?:mysql|mysqldump|mysqladmin|mysqlcheck|mysqlimport|mysqlshow|mariadb|mariadb-dump|mariadb-admin)(?:\.exe)?(?=\s))(?:(?!(?i:mysql|mariadb)\b)[^\n]){0,512}?(?<=\s)-p(?=\S)(?:"([^"\n]{1,256})"|'([^'\n]{1,256})'|([^\s"']{1,256}))"""), -3),
    # `curl -u user:password`: the part after the colon, and only when there is one (`curl -u user` asks for it)
    ("a password given to curl", re.compile(
        r"""(?i:(?<![\w.-])curl(?:\.exe)?(?=\s))(?:(?!(?i:curl)\b)[^\n]){0,512}?(?<=\s)(?:-u|-U|--user|--proxy-user)(?:\s+|=)(?:"[^":\n]*:([^"\n]{1,256})"|'[^':\n]*:([^'\n]{1,256})'|[^\s:"']*:([^\s"']{1,256}))"""), -3),
    ("a hash pair of an account database", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}:([0-9a-fA-F]{32})(?![0-9a-fA-F])"), 1),
    ("a bcrypt hash", re.compile(r"(?<![A-Za-z0-9$])\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}(?![./A-Za-z0-9])"), 0),
    ("a token of a known family", re.compile(
        r"(?:GOCSPX-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])|"
        r"ya29\.[0-9A-Za-z_-]{20,}|1//0[0-9A-Za-z_-]{30,}|(?:IQoJb3JpZ2lu|FQoGZXIvYXdz|FwoGZXIvYXdz)[A-Za-z0-9+/=]{40,}|"
        r"[A-Za-z0-9_.~-]{3}[0-9]Q~[A-Za-z0-9_.~-]{30,}|[01]\.A[A-Za-z0-9_-]{50,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,})"), 0),
]
_CRED_GROUPS = {-1: (1, 2, 3), -2: (1, 2), -3: (1, 2, 3)}
# A random-looking run of an exact length that keys have: 32, 40 (an AWS secret access key), 43 + "=" and 86 + "==" (a base64 key).
_CRED_SHAPES = [
    ("a key-length base64 string", re.compile(_CRED_B64_EDGE + r"(?:[A-Za-z0-9+/]{32}|[A-Za-z0-9+/]{40}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)" + _CRED_B64_END), True),
]
# A Name/Value pair written as JSON text inside a string (an AuditData in a column of another name, a parameter list in a cell): the
# structure rule (clean_value) cannot see it, so the text rule reads the head of the pair, and the name decides as it does there. The
# value is read by hand, not by an expression: a string up to its first quote (the backslashes before the quote are not part of it), a
# number, a flat array of up to 4,096 characters, or a literal; and the next value of the same pair (`OldValue`, then `NewValue`).
_CRED_PAIR_HEAD = re.compile(r"""(?i)\b(?:name|key)\\*"\s*:\s*\\*"([^"\\]{1,64})\\*"\s*,\s*\\*"(?:new|old)?value\\*"\s*:\s*""")
_CRED_NEXT_VALUE = re.compile(r"""(?i)\s*,\s*\\*"(?:new|old)?value\\*"\s*:\s*""")
_CRED_QUOTE = re.compile(r'\\*"')
_CRED_BARE = re.compile(r"-?[0-9][0-9.eE+-]{0,39}|\[[^\[\]]{0,4096}\]|(?:null|true|false)\b")
# What a text must hold for any rule to match it: a literal one of them looks for, or a run long enough for a shape. A text with none of
# these is judged clean without running the rules (most names, addresses and ids).
_CRED_QUICK = re.compile(r"eyJ|-----BEGIN|\n|authorization|cookie|bearer|basic|digest|negotiate|ntlm|pass|pwd|secret|token|key|signature|sig|"
                         r"plaintext|hash|pin|otp|sas|securestring|gh[pousr]_|github_pat_|xox|AIza|ya29\.|1//0|IQoJb|FQoG|FwoG|Q~|[01]\.A|[sr]k_|"
                         r"://|gocspx|functions|code=|credential|assertion|mfacode|saml|mysql|mariadb|curl|\$2|"
                         r"[A-Za-z0-9+/]{32}|[A-Za-z0-9+/_-]{128}", re.I)
_CRED_CLEAN = set()               # short texts already judged to hold nothing (names, addresses and ids repeat)
_CRED_GATE = 4096                 # a text longer than this is scanned with the carrier's hook in view, rule by rule
# The carrier's hook for long scans: called with the work done so far (1 per stretch found, 4096 between rules over a long text); it may
# raise to end the scan at the carrier's deadline. Most carriers set none and the calls do nothing.
_tick = globals().get("WITHHOLD_TICK") or (lambda units=1: None)


def _cred_json_value(text, at):
    """(start, end, after) of the JSON value whose text starts at `at`: `end` is where what is withheld ends, `after` where the next
    token of the pair begins. None when no value starts there."""
    q = _CRED_QUOTE.match(text, at)
    if q:
        start = q.end()
        close = text.find('"', start)
        if close < 0:
            return start, len(text), len(text)      # a value that is cut off: the rest of the text is the value
        return start, start + len(text[start:close].rstrip("\\")), close + 1
    m = _CRED_BARE.match(text, at)
    if m is None:
        return None
    if m.group()[0] in "nft":
        return at, at, m.end()                     # null, true and false are not secrets
    return m.start(), m.end(), m.end()


def _cred_pair_spans(text, spans):
    for head in _CRED_PAIR_HEAD.finditer(text):
        if not name_is_sensitive(head.group(1)):
            continue
        at = head.end()
        for _ in range(3):
            got = _cred_json_value(text, at)
            if got is None:
                break
            start, end, after = got
            if end > start:
                value = text[start:end]
                if not (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{"))):
                    spans.append((start, end, _CRED_PAIR_WHY))
            more = _CRED_NEXT_VALUE.match(text, after)
            if more is None:
                break
            at = more.end()


def _cred_random_like(run):
    """A run that looks like random base64 and not like a path, a name or a hash: mixed case and digits in the proportions
    random text has (a long path is mostly lower case with few capitals; a hex digest has no case to mix)."""
    n = len(run)
    upper = sum(1 for ch in run if "A" <= ch <= "Z")
    lower = sum(1 for ch in run if "a" <= ch <= "z")
    digit = sum(1 for ch in run if "0" <= ch <= "9")
    return upper * 100 >= 15 * n and lower * 100 >= 15 * n and digit * 100 >= 5 * n


def _cred_name_before(text, at):
    """The letters and digits of the name an assigned value follows (`nextToken=` gives `nexttoken`)."""
    return re.sub(r"[^a-z0-9]", "", text[max(0, at - 64):at].lower())


def _cred_spans(text, shapes):
    spans = []
    big = len(text) > _CRED_GATE
    if "value" in text.lower():
        _cred_pair_spans(text, spans)
    for why, rx, group in _CRED_RULES:
        if big:
            _tick(4096)
        for m in rx.finditer(text):
            if big:
                _tick(1)
            if "assigned to a credential name" in why:
                if _CRED_ARN_TAIL.search(text[max(0, m.start() - 120):m.start()]):
                    continue                              # arn:aws:secretsmanager:...:secret:NAME is a name, not a value
                if _cred_name_before(text, m.start(m.lastindex or 0)).endswith(_CRED_NOT_SECRET):
                    continue                              # nextToken=, pageToken=, clientToken=: a position or an idempotency key
            for g in _CRED_GROUPS.get(group, (group,)):
                if g and m.group(g) is None:
                    continue
                start, end = m.span(g)
                value = text[start:end]
                if g and (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{"))):
                    continue
                if why == "a scheme and its credential" and g == 1 and not (re.search(r"[0-9+/=_.~-]", value) or len(value) >= 16):
                    continue                              # "basic authentication" is prose, "Basic dXNlcjpwYXNz" is not
                if g == 1 and group == -1 and len(m.groups()) >= 2 and m.group(1) in ("'", '"'):
                    continue                              # group 1 of the switch rules is the quote
                spans.append((start, end, why))
    if big:
        _tick(4096)
    for m in _CRED_B64_RUN.finditer(text):
        if _cred_random_like(m.group(0)):
            spans.append((m.start(), m.end(), "a long unbroken base64-like run"))
    if shapes:
        for why, rx, check in _CRED_SHAPES:
            for m in rx.finditer(text):
                if not check or _cred_random_like(m.group(0)):
                    spans.append((m.start(), m.end(), why))
    spans.sort()
    merged = []
    for s in spans:
        if merged and s[0] < merged[-1][1]:
            if s[1] > merged[-1][1]:
                merged[-1] = (merged[-1][0], s[1], merged[-1][2])
            continue
        merged.append(s)
    return merged


def credential_spans(text, shapes=True):
    """(start, end, why) of each stretch of `text` that is a credential by the name it is given under or by its text, in order and
    not overlapping. `shapes` False leaves out the rules that recognise a key by its length alone (a value that is named a checksum or
    a digest is not scanned for them). This is not `token_spans`: an identifier (a GUID, a hex digest, an access key id, an ARN) is
    not a credential here, and a tool that prints identifiers on purpose asks only for these."""
    if len(text) > TEXT_LIMIT:
        return [(0, len(text), "text longer than %d characters" % TEXT_LIMIT)]
    if shapes and text in _CRED_CLEAN:
        return []
    spans = _cred_spans(text, shapes) if _CRED_QUICK.search(text) else []
    if shapes and not spans and len(text) <= 256 and len(_CRED_CLEAN) < 100000:
        _CRED_CLEAN.add(text)
    return spans


def clean_value(value, leaf, note, key=None, pointer="", depth=0, shapes=True, max_depth=200):
    """The structure rule: `value` (what a JSON document decoded to) with every credential in it replaced. A string goes to
    `leaf(text, pointer, shapes)`, which returns what is printed for it. A field whose name says it holds a secret (or a `Value` whose
    `Name` does), at any depth, is not read at all: `note(pointer, why, original)` returns what is printed for it (a number under such
    a name is withheld too: 0 and 1 are not nothing). A key goes through `key(text)` when one is given. A value nested deeper than
    `max_depth` is replaced the same way."""
    if isinstance(value, str):
        return leaf(value, pointer, shapes)
    _tick(1)
    if depth > max_depth and isinstance(value, (dict, list)):
        return note(pointer, "nested deeper than %d levels" % max_depth, value)
    if isinstance(value, dict):
        named = None
        for k in _CRED_NAME_KEYS:
            if isinstance(value.get(k), str):
                named = value[k]
                break
        pair_secret = named is not None and name_is_sensitive(named)
        out = {}
        for k, v in value.items():
            ks = str(k)
            point = "%s/%s" % (pointer, ks.replace("~", "~0").replace("/", "~1"))
            safe_key = key(ks) if key is not None else ks
            if safe_key in out:
                safe_key = "%s#%d" % (safe_key, len(out))
            sensitive = name_is_sensitive(ks) or (pair_secret and ks in _CRED_VALUE_KEYS)
            if sensitive and is_container_name(ks) and isinstance(v, (dict, list)):
                sensitive = False
            if sensitive and not (v is None or isinstance(v, bool) or v == "") and not (isinstance(v, str) and (_CRED_REDACTED.match(v) or v.lower() in _CRED_NOT_A_VALUE)):
                out[safe_key] = note(point, "credential-named field", v)
            else:
                out[safe_key] = clean_value(v, leaf, note, key, point, depth + 1, shapes and not _CRED_CHECKSUM_NAME.search(ks), max_depth)
        return out
    if isinstance(value, list):
        return [clean_value(v, leaf, note, key, "%s/%d" % (pointer, i), depth + 1, shapes, max_depth) for i, v in enumerate(value)]
    return value


def _credentials_withheld(text, kind):
    """`text` with each credential in it withheld. It runs after the rules above, on text that may hold their markers: a stretch that
    begins at a marker is theirs already."""
    if not _CRED_QUICK.search(text):
        return text
    out, last = [], 0
    for start, end, why in credential_spans(text):
        if text.startswith("<", start):
            continue
        out.append(text[last:start])
        out.append(_withheld(why, end - start, kind))
        last = end
    if not out:
        return text
    out.append(text[last:])
    return "".join(out)


def scrub(text, kind="text"):
    """The text with every token-shaped run, every user-info and every credential withheld."""
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
    return _credentials_withheld("".join(out), kind)


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


def holds_files(directory):
    """Whether `directory` holds anything: one entry is looked at, never the whole listing (a caller's directory can hold millions of names)."""
    with os.scandir(directory) as entries:
        return next(entries, None) is not None


def open_regular(path, follow=True):
    """A file opened for reading that is never waited on: the open does not block (a name that became a pipe since it was checked would otherwise wait
    for a writer), the type is read from the descriptor, and anything but a regular file is refused. follow=False also refuses a symbolic link (for a
    name the capture or the engine produced). The file object it returns reads in the ordinary, blocking way."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | (0 if follow else getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        os.set_blocking(fd, True)
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def fail(message, **extra):
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})     # one document: a stop that arrives while this is written waits, and the tool leaves with it
    STATE["last_word"] = None
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
STOP_LISTED = 200       # names the answer to a stop lists
STOP_COUNTED = 100_000  # entries it counts before it says "more than"


def last_word(signum):
    """What a stopped run says on stdout: partial, which stage it was in, and what is on disk."""
    out_dir = PROGRESS.get("out_dir")
    files, total = [], 0
    try:
        with os.scandir(out_dir) if out_dir else contextlib.nullcontext([]) as entries:
            for entry in entries:
                total += 1
                if len(files) < STOP_LISTED:
                    files.append(entry.name)
                elif total > STOP_COUNTED:
                    break
    except OSError:
        pass
    files.sort()
    print(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "ok": False,
                      "status_basis": "the tool was stopped by signal %d while it was %s; the engine, if it was running, was killed with what it had started, and eve.json is only as far as it got" % (signum, PROGRESS["stage"]),
                      "interrupted_by_signal": signum, "stage": PROGRESS["stage"], "out_dir": out_dir, "files_on_disk": files,
                      "files_on_disk_total": total if total <= STOP_COUNTED else None,
                      "files_on_disk_note": "the first %d names are listed (the directory holds more than %d when the total is null); the whole directory is on disk" % (STOP_LISTED, STOP_COUNTED) if total > STOP_LISTED else None}), flush=True)


def file_sha256(path):
    h = hashlib.sha256()
    with open_regular(path) as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def count_rule_lines(fh):
    """The lines that are neither empty nor comments, read in pieces of at most 1 MiB so that one hostile line is never held whole: a line longer
    than a piece is counted once, by its first piece."""
    count, at_start = 0, True
    while True:
        raw = fh.readline(1 << 20)
        if not raw:
            return count
        if at_start and raw.strip() and not raw.lstrip().startswith(b"#"):
            count += 1
        at_start = raw.endswith(b"\n")


def rule_load_counts(*paths):
    """What Suricata itself printed about loading rules, or None when it printed nothing of the kind."""
    found = None
    for path in paths:
        try:
            with open_regular(path, follow=False) as fh:
                for raw in fh:
                    m = LOADED.search(raw.decode("utf-8", "replace"))
                    if m:
                        found = {"loaded": int(m.group(1)), "failed": int(m.group(2)), "from": os.path.basename(path)}
        except OSError:
            continue
    return found


# --- dry_run: the engine receipt without a capture ---------------------------------------------------------------------------------

DRY_LINE = 1 << 20          # a rule (its continuation lines included) longer than this is located and not read
DRY_SIDS = 2_000_000        # active sids kept for the ranges: 16 MB as an array, the sorted copy is the larger cost
DRY_SHOWN = 100             # sid ranges and rev values answered inline; every range is in sid-ranges.txt
DRY_FAILURES = 10           # load failures answered inline; every line of the engine's output is in its files
DRY_FAILURE_CHARS = 300
DRY_LINE_NUMBERS = 10
DRY_FAILURE_READ = 1 << 16  # the part of one line of the engine's output that is read
RULE_ACTION = re.compile(rb"(alert|pass|drop|reject|rejectsrc|rejectdst|rejectboth|config)[ \t]")
RULE_SID = re.compile(rb"[;( \t]sid[ \t]*:[ \t]*(\d{1,18})[ \t]*;")
RULE_SID_KEY = re.compile(rb"[;( \t]sid[ \t]*:")
RULE_REV = re.compile(rb"[;( \t]rev[ \t]*:[ \t]*(\d{1,18})[ \t]*;")
LOADED_FULL = re.compile(r"(\d+) rules? successfully loaded, (\d+) rules? failed(?:, (\d+) rules? skipped)?")
FAILURE_LINE = re.compile(r"<Error>|ERRCODE|\bfailed\b|\berror\b", re.I)
AT_LINE = re.compile(r"\bat line (\d{1,12})\b")
DUMP_CONFIG = re.compile(rb"--dump-config\b")


class RangesFile:
    """Every sid range, one `low-high` line each, in a private file of its own. A write that is refused is a fact about the disk: the file is
    removed (it would hold fewer ranges than the answer counts) and the answer says the ranges beyond the inline ones are not on disk."""

    def __init__(self, path):
        self.path, self.fh, self.written, self.problem = path, None, 0, None

    def add(self, low, high):
        if self.problem:
            return
        try:
            if self.fh is None:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                self.fh = os.fdopen(fd, "w", encoding="ascii")
            self.fh.write("%d-%d\n" % (low, high))
            self.written += 1
        except OSError as exc:
            self.fail(exc)

    def fail(self, exc):
        self.problem = describe(exc)
        try:
            if self.fh is not None:
                self.fh.close()
        except OSError:
            pass
        self.fh = None
        try:
            os.unlink(self.path)
        except OSError:
            pass
        self.written = 0

    def close(self):
        if self.fh is not None and not self.problem:
            try:
                self.fh.close()
            except OSError as exc:
                self.fail(exc)
            self.fh = None


def analyse_rules(path, out_dir, deadline):
    """One bounded pass over a rules file, read as text and not as the engine parses it: the number of rules per action (commented-out rules apart,
    each with its own count), the sid ranges and the rev values. A rule is a line that starts with an action word, with its continuation lines
    (a trailing backslash) joined; a commented-out rule is a line that starts with # and then an action word and has a sid. The sid and rev are the first
    `sid:N;` and `rev:N;` in the text. A line longer than DRY_LINE is located and not read; the clock is looked at after every 1,024 lines and every
    1 MiB; the sids kept are at most DRY_SIDS. Nothing here is quadratic: each byte is looked at a constant number of times."""
    s = {"lines_read": 0, "rules_active": 0, "rules_disabled": 0, "active_by_action": collections.Counter(), "disabled_by_action": collections.Counter(),
         "active_lines_that_are_not_rules": 0, "active_without_sid": 0, "active_sid_unreadable": 0, "active_without_rev": 0, "active_rev_unreadable": 0,
         "disabled_without_sid": 0, "disabled_sid_min": None, "disabled_sid_max": None, "rev_values": collections.Counter(), "rev_values_over_cap": 0,
         "over_limit_lines": [], "over_limit_total": 0, "sids_not_kept": 0, "cut": None}
    sids = array.array("Q")

    def active(text):
        m = RULE_ACTION.match(text)
        if not m:
            s["active_lines_that_are_not_rules"] += 1
            return
        s["rules_active"] += 1
        s["active_by_action"][m.group(1).decode("ascii")] += 1
        m = RULE_SID.search(text)
        if m:
            if len(sids) < DRY_SIDS:
                sids.append(int(m.group(1)))
            else:
                s["sids_not_kept"] += 1
        elif RULE_SID_KEY.search(text):
            s["active_sid_unreadable"] += 1
        else:
            s["active_without_sid"] += 1
        m = RULE_REV.search(text)
        if m:
            value = int(m.group(1))
            if value in s["rev_values"] or len(s["rev_values"]) < DRY_SHOWN:
                s["rev_values"][value] += 1
            else:
                s["rev_values_over_cap"] += 1
        elif re.search(rb"[;( \t]rev[ \t]*:", text):
            s["active_rev_unreadable"] += 1
        else:
            s["active_without_rev"] += 1

    def disabled(text):
        body = text.lstrip(b"#").lstrip()
        m = RULE_ACTION.match(body)
        if not m or not RULE_SID_KEY.search(body):
            return                      # prose after a #, not a rule
        s["rules_disabled"] += 1
        s["disabled_by_action"][m.group(1).decode("ascii")] += 1
        m = RULE_SID.search(body)
        if not m:
            s["disabled_without_sid"] += 1
            return
        value = int(m.group(1))
        s["disabled_sid_min"] = value if s["disabled_sid_min"] is None else min(s["disabled_sid_min"], value)
        s["disabled_sid_max"] = value if s["disabled_sid_max"] is None else max(s["disabled_sid_max"], value)

    def over(line):
        s["over_limit_total"] += 1
        if len(s["over_limit_lines"]) < DRY_LINE_NUMBERS:
            s["over_limit_lines"].append(line)

    pieces, piece_bytes, piece_line, piece_over = None, 0, 0, False
    since_clock = 0
    with open_regular(path) as fh:
        while True:
            raw = fh.readline(DRY_LINE + 1)
            if not raw:
                break
            since_clock += len(raw)
            if since_clock >= CLOCK_BYTES or s["lines_read"] & 1023 == 0:
                since_clock = 0
                if time.monotonic() > deadline:
                    s["cut"] = {"lines_read": s["lines_read"], "stopped_at_byte": fh.tell() - len(raw)}
                    break
            s["lines_read"] += 1
            line = s["lines_read"]
            if len(raw) > DRY_LINE and not raw.endswith(b"\n"):
                while True:
                    more = fh.readline(DRY_LINE)
                    if not more or more.endswith(b"\n"):
                        break
                    if time.monotonic() > deadline:
                        s["cut"] = {"lines_read": line - 1, "stopped_at_byte": fh.tell()}
                        break
                if s["cut"]:
                    s["lines_read"] -= 1
                    break
                over(piece_line if pieces is not None or piece_over else line)
                pieces, piece_bytes, piece_over = None, 0, False
                continue
            text = raw.strip()
            if pieces is None and not piece_over:
                if not text:
                    continue
                if text.startswith(b"#"):
                    disabled(text)
                    continue
                piece_line, pieces, piece_bytes = line, [], 0
            continues = text.endswith(b"\\")
            body = text[:-1] if continues else text
            piece_bytes += len(body)
            if not piece_over:
                if piece_bytes > DRY_LINE:
                    piece_over, pieces = True, None
                else:
                    pieces.append(body)
            if continues:
                continue
            if piece_over:
                over(piece_line)
            else:
                active(b" ".join(pieces))
            pieces, piece_bytes, piece_over = None, 0, False
        if s["cut"] is None and (pieces is not None or piece_over):
            if piece_over:
                over(piece_line)
            else:
                active(b" ".join(pieces))

    sids_sorted = sorted(sids)
    ranges_file = RangesFile(os.path.join(out_dir, "sid-ranges.txt"))
    inline, ranges = [], {"total": 0}

    def emit(lo, hi):
        ranges["total"] += 1
        if len(inline) < DRY_SHOWN:
            inline.append([lo, hi])
            return
        if ranges["total"] == DRY_SHOWN + 1:
            for a, b in inline:
                ranges_file.add(a, b)
        ranges_file.add(lo, hi)

    distinct = duplicates = 0
    low = high = None
    for value in sids_sorted:
        if high is not None and value == high:
            duplicates += 1
            continue
        distinct += 1
        if high is not None and value == high + 1:
            high = value
            continue
        if low is not None:
            emit(low, high)
        low = high = value
    if low is not None:
        emit(low, high)
    total = ranges["total"]
    ranges_file.close()
    ranges_in_file = ranges_file.written if total > DRY_SHOWN and not ranges_file.problem else None
    problems = []
    if s["cut"]:
        problems.append("the tool's own clock ran out while the rules file was read: the counts are those of the first %d lines" % s["cut"]["lines_read"])
    if s["over_limit_total"]:
        problems.append("%d rule(s) longer than %d bytes were located by line number and not read: they are in no count here" % (s["over_limit_total"], DRY_LINE))
    if s["sids_not_kept"]:
        problems.append("%d sid(s) beyond the first %d were not kept: the ranges and the duplicate count cover the first %d" % (s["sids_not_kept"], DRY_SIDS, DRY_SIDS))
    if ranges_file.problem:
        problems.append("the file of all sid ranges could not be written (%s): the first %d ranges are answered inline and the rest are not on disk" % (ranges_file.problem, DRY_SHOWN))
    return {
        "whole": not problems,
        "problems": problems,
        "lines_read": s["lines_read"],
        "cut_by_its_clock": s["cut"],
        "rules_active": s["rules_active"],
        "active_by_action": dict(s["active_by_action"]),
        "active_lines_that_are_not_rules": s["active_lines_that_are_not_rules"],
        "rules_disabled": s["rules_disabled"],
        "disabled_by_action": dict(s["disabled_by_action"]),
        "disabled_sid_min": s["disabled_sid_min"], "disabled_sid_max": s["disabled_sid_max"], "disabled_without_sid": s["disabled_without_sid"],
        "sid": {"count": len(sids_sorted), "distinct": distinct, "duplicates": duplicates,
                "min": sids_sorted[0] if sids_sorted else None, "max": sids_sorted[-1] if sids_sorted else None,
                "ranges_total": total, "ranges": inline, "ranges_shown": len(inline), "ranges_file": "sid-ranges.txt" if ranges_in_file else None,
                "ranges_in_file": ranges_in_file, "not_kept": s["sids_not_kept"],
                "without_sid": s["active_without_sid"], "unreadable": s["active_sid_unreadable"]},
        "rev": {"values": {str(k): v for k, v in sorted(s["rev_values"].items())}, "values_over_cap": s["rev_values_over_cap"],
                "without_rev": s["active_without_rev"], "unreadable": s["active_rev_unreadable"]},
        "over_limit_lines": s["over_limit_lines"], "over_limit_total": s["over_limit_total"],
        "note": ("read as text, not as the engine parses it: a rule is a line that starts with an action word (continuation lines joined), a commented-out rule "
                 "is a # line with an action word and a sid, and sid and rev are the first sid:N; and rev:N; in the text. What the engine loaded is rule_load."),
    }


def rule_load_detail(*paths):
    """The numbers Suricata printed about loading rules (loaded, failed and, where the build prints it, skipped), or None."""
    found = None
    for path in paths:
        try:
            with open_regular(path, follow=False) as fh:
                while True:
                    raw = fh.readline(DRY_FAILURE_READ)
                    if not raw:
                        break
                    m = LOADED_FULL.search(raw.decode("utf-8", "replace"))
                    if m:
                        found = {"loaded": int(m.group(1)), "failed": int(m.group(2)), "skipped": int(m.group(3)) if m.group(3) is not None else None,
                                 "from": os.path.basename(path)}
        except OSError:
            continue
    return found


def withheld_cut(text, name):
    """A line of the engine's output as the answer shows it: the whole line goes through the block first, and only then is it cut, so that a cut never
    leaves a piece of a secret too short for the block to recognise."""
    shown = scrub(text)
    return shown[:DRY_FAILURE_CHARS] + (" ...(%d more characters in %s)" % (len(shown) - DRY_FAILURE_CHARS, name) if len(shown) > DRY_FAILURE_CHARS else "")


def first_failures(paths, deadline):
    """(the first DRY_FAILURES lines the engine printed about a failure, how many there were, whether the clock cut the reading). Each line is
    read to DRY_FAILURE_READ bytes, cut for the answer to DRY_FAILURE_CHARS characters (the whole line is in the file) and passed through the block."""
    shown, total, cut = [], 0, False
    for path in paths:
        try:
            with open_regular(path, follow=False) as fh:
                n = 0
                while True:
                    raw = fh.readline(DRY_FAILURE_READ)
                    if not raw:
                        break
                    n += 1
                    if n & 1023 == 0 and time.monotonic() > deadline:
                        cut = True
                        break
                    text = raw.decode("utf-8", "replace")
                    if FAILURE_LINE.search(text) and not LOADED_FULL.search(text):
                        total += 1
                        if len(shown) < DRY_FAILURES:
                            text = text.strip()
                            at = AT_LINE.search(text)
                            shown.append({"from": os.path.basename(path), "line": n, "rules_line": int(at.group(1)) if at else None,
                                          "text": withheld_cut(text, os.path.basename(path))})
        except OSError:
            continue
        if cut:
            break
    return shown, total, cut


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


def answer_out(text):
    """Print the final answer as one unit a stop signal cannot cut or follow: signals are held while it is written and there is no last
    word to add to it, so a signal that arrives during or after it ends the tool (exit 128 plus the signal) with this one document."""
    held = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    signal.pthread_sigmask(signal.SIG_BLOCK, held)
    try:
        STATE["last_word"] = None
        print(text, flush=True)
    finally:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, held)


EVE_TYPES = ["alert", "anomaly", "dns", "http", "tls", "files", "flow"]      # the types configuration() writes, by name


def write_new(path, data):
    """A file of this run's own, new, private and whole; the problem as a sentence (None when written) when the write is refused."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return None
    except OSError as exc:
        try:
            os.unlink(path)
        except OSError:
            pass
        return describe(exc)


def dry_run_receipt(c):
    """dry_run: the engine receipt without a capture. Nothing here opens a capture, listens on a port or writes outside out_dir. Five parts: the
    identities of the rules and the configuration, the effective configuration (the -T test, the dump of the configuration where the build has the
    command), the rule-load status, the log outputs and what is not covered. complete says that every part the build can give was given and the
    engine's own test and load numbers show a configuration that loads every rule; a command the build lacks is named, not failed."""
    started, out_dir, binary = c["started"], c["out_dir"], c["binary"]
    deadline = min(started + c["timeout"], started + MANIFEST_SECONDS - READ_MARGIN)
    try:     # SURICATA_RUN_DRY_SECONDS (seconds from here) exists for the tests, as SURICATA_RUN_READ_SECONDS does for the reading of eve.json
        deadline = time.monotonic() + float(os.environ["SURICATA_RUN_DRY_SECONDS"])
    except (KeyError, ValueError):
        pass
    problems = []

    def remaining():
        return deadline - time.monotonic()

    PROGRESS["stage"] = "reading the rules file"
    analysis = None
    try:
        analysis = analyse_rules(c["rules"], out_dir, deadline)
    except OSError as exc:
        problems.append("the rules file could not be read for the counts (%s)" % describe(exc))
    if analysis is not None:
        problems.extend(analysis["problems"])

    PROGRESS["stage"] = "reading the engine's help"
    help_code, help_out, help_err, help_timed = preflight([binary, "--help"], max(1.0, min(PREFLIGHT_SECONDS, remaining())))
    help_path = os.path.join(out_dir, "suricata-help.txt")
    help_problem = write_new(help_path, help_out + (b"\n--- stderr ---\n" + help_err if help_err else b""))
    if help_problem:
        problems.append("the engine's help could not be kept in a file (%s)" % help_problem)
    help_known = help_code is not None and not help_timed
    has_dump = bool(DUMP_CONFIG.search(help_out + help_err)) if help_known else None

    dump = {"available": has_dump, "command": None, "exit_code": None, "timed_out": False, "file": None, "bytes": None, "sha256": None, "stderr": None}
    if has_dump is None:
        dump["reason"] = "`suricata --help` %s, so whether this build has --dump-config is not known" % ("did not finish" if help_timed else "did not run")
        problems.append(dump["reason"])
    elif not has_dump:
        dump["reason"] = ("this build's help (suricata-help.txt) does not list --dump-config: the effective configuration is not dumped; "
                          "the configuration test and the file's digest are what is recorded")
    elif remaining() < 1:
        dump["reason"] = "the tool's own clock ran out before the dump"
        problems.append(dump["reason"])
    else:
        PROGRESS["stage"] = "dumping the configuration"
        dump_out, dump_err = os.path.join(out_dir, "suricata-dump-config.txt"), os.path.join(out_dir, "suricata-dump-config.stderr")
        argv = [binary, "--dump-config", "-c", os.path.abspath(c["config_path"])]
        dump["command"] = argv
        try:
            code, timed = run_to_files(argv, dump_out, dump_err, min(TEST_SECONDS, max(1.0, remaining())))
            dump.update(exit_code=code, timed_out=timed, file=dump_out, stderr=dump_err)
            if code != 0:
                problems.append("`suricata --dump-config` %s" % ("did not finish in time" if timed else "exited %s" % code))
            else:
                dump["bytes"], dump["sha256"] = os.path.getsize(dump_out), file_sha256(dump_out)
        except OSError as exc:
            problems.append("`suricata --dump-config` could not be run or read (%s)" % describe(exc))

    loads = rule_load_detail(c["test_out"], c["test_err"])
    failures, failure_total, failures_cut = first_failures([c["test_err"], c["test_out"]], deadline)
    if failures_cut:
        problems.append("the tool's own clock ran out while the engine's output was searched for load failures: the list and its count are those of the lines read")
    if c["test_code"] != 0:
        problems.append("the configuration test (suricata -T) %s" % ("did not finish in time" if c["test_timed_out"] else "failed with exit code %s" % c["test_code"]))
    if loads and loads["failed"]:
        problems.append("Suricata reported %d rule(s) that failed to load" % loads["failed"])
    if loads and c["rule_lines"] and not loads["loaded"]:
        problems.append("Suricata reported 0 rules loaded though the rules file has %d rule lines" % c["rule_lines"])
    if loads and loads["skipped"]:
        problems.append("Suricata reported %d rule(s) skipped (%d loaded): a skipped rule is not loaded" % (loads["skipped"], loads["loaded"]))
    if loads and analysis is not None and loads["loaded"] and not loads["failed"] and not loads["skipped"] and loads["loaded"] != analysis["rules_active"]:
        problems.append("Suricata loaded %d rule(s) but the rules file has %d active rule(s) read as text: the numbers differ, so not every rule is shown to have loaded"
                        % (loads["loaded"], analysis["rules_active"]))
    if loads is None and c["test_code"] == 0:
        problems.append("the engine printed no rule-load numbers, so nothing here shows that any rule loaded (rule_load.known is false)")
    if c["version_line"] is None:
        problems.append("`suricata --build-info` %s, so the version of the engine is not recorded" % ("exited %s" % c["build_code"] if c["build_code"] is not None else "did not run"))

    for name in os.listdir(out_dir):
        full = os.path.join(out_dir, name)
        try:
            if not os.path.islink(full):
                os.chmod(full, 0o700 if os.path.isdir(full) else 0o600)
        except OSError:
            pass
    ok = not problems
    generated = c["generated"]
    basis = ("the engine's configuration test passed, every rule loaded, the rules file was read whole%s, and no capture was read" %
             ("" if has_dump else " (this build has no --dump-config: named in effective_configuration.dump_config)") if ok else
             "; ".join(problems[:6]) + (" (and %d more, all in problems)" % (len(problems) - 6) if len(problems) > 6 else "") + ": no capture was read")
    answer_out(json.dumps({
        "tool": TOOL, "parser": PARSER, "dry_run": True,
        "status": "complete" if ok else "partial", "status_basis": basis,
        "out_dir": out_dir,
        "identities": {
            "rules": {"path": c["rules"], "sha256": c["rules_sha"], "bytes": c["rules_bytes"], "rule_lines": c["rule_lines"],
                      "rule_lines_note": "lines that are neither empty nor comments; not the number of rules the engine loaded", "analysis": analysis},
            "configuration": {"path": c["config_path"], "sha256": c["config_sha"], "generated_by_this_tool": generated,
                              "note": ("written by this tool: only the keys it names are set, the rest are the engine's own defaults" if generated else
                                       "supplied by the caller and not read by this tool")},
            "engine": {"suricata_version": c["version_line"], "build_info": c["build_path"], "build_info_exit_code": c["build_code"]},
        },
        "effective_configuration": {
            "test": {"command": c["test_argv"], "exit_code": c["test_code"], "timed_out": c["test_timed_out"], "stdout": c["test_out"], "stderr": c["test_err"]},
            "dump_config": dump,
            "help": help_path if not help_problem else None,
            "checksum_mode": c["checksum_mode"],
            "vars": ({"HOME_NET": c["home_net"], "note": "HOME_NET is the home_net argument, or the private ranges when it was not given; the other address groups and "
                      "the port groups are set to the usual names rulesets use: this tool's assumptions, not read from your environment"} if generated else None),
        },
        "rule_load": {"configuration_test": loads, "known": loads is not None,
                      "disabled_in_file": analysis["rules_disabled"] if analysis else None,
                      "first_failures": failures, "failure_lines_total": failure_total,
                      "failures_note": "lines of the engine's own output that name an error or a failure, the first %d, each cut to %d characters and passed through the block; "
                                       "every line is in the test files named under effective_configuration.test" % (DRY_FAILURES, DRY_FAILURE_CHARS),
                      "note": "loaded, failed and skipped are read from Suricata's own output when it printed them (None is not zero); disabled is the commented-out rules "
                              "counted in the rules file, which the engine does not see"},
        "log_outputs": ({"source": "the configuration this tool wrote", "log_directory": out_dir,
                         "files": [{"name": "eve.json", "kind": "eve-log", "filetype": "regular", "types": EVE_TYPES, "tls_extended": True}],
                         "note": "the engine's console output goes to suricata.stdout and suricata.stderr of a run; any other file the engine writes under the log directory is "
                                 "decided by that build's defaults, and a run lists it"} if generated else
                        {"source": "the caller's configuration", "files": None,
                         "note": "not read by this tool: the outputs it sets are in the dump of the effective configuration when the build has one, and a run lists the files it wrote"}),
        "not_covered": [
            "No ruleset ships with the pack and none is fetched: the rules are the file you gave.",
            "There is no automatic download and no suricata-update; this mode downloads nothing.",
            "No capture was read: nothing here says what the rules would match, or that any rule fires.",
            "The counts per action, the sid ranges and the rev values are read from the text of the rules file; what the engine loaded is rule_load.",
            "Whether this build produces JA3 or JA4 fingerprints is not shown by a dry run.",
        ],
        "problems": problems,
        "ok": ok,
        "withheld": dict(COUNTS),
        "out_dir_contains_secret_values": True,
        "out_dir_note": ("The directory holds the engine's build information, help, test output and the configuration, which can quote rule text. It is private (mode 0700, "
                         "files 0600). Run this tool as a job with secret_output: true so the job output is sealed."),
    }, indent=2))
    return 0


def main():
    started = time.monotonic()
    STATE["last_word"] = last_word
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    dry_run = args.get("dry_run", False)
    if not isinstance(dry_run, bool):
        fail("dry_run must be true or false")
    path, rules, out_dir = args.get("path"), args.get("rules"), args.get("out_dir")
    if dry_run and path is not None:
        fail("path is not taken with dry_run: a dry run reads no capture (it gives the engine receipt of the rules and the configuration); leave path out, or leave dry_run out to run a capture")
    for label, value in (("path", path), ("rules", rules)):
        if label == "path" and dry_run:
            continue
        if not isinstance(value, str) or not os.path.isfile(value):
            fail("%s must name a readable file" % label, **{label: value if isinstance(value, str) else None})
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: an empty directory under work/ (in a job, under $OUT)")
    out_dir = resolve_output(out_dir, "out_dir")
    PROGRESS["out_dir"] = out_dir
    try:
        if os.path.exists(out_dir) and holds_files(out_dir):
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
        with open_regular(rules) as fh:
            rule_lines = count_rule_lines(fh)
        rules_bytes = os.path.getsize(rules)
    except OSError as exc:
        fail("a configuration or rules file could not be read (%s)" % describe(exc))

    common = ["-c", os.path.abspath(config_path), "-S", os.path.abspath(rules), "-l", os.path.abspath(out_dir), "-k", checksum_mode, "-v"]
    test_argv = [binary, "-T"] + common
    test_out, test_err = os.path.join(out_dir, "suricata-test.stdout"), os.path.join(out_dir, "suricata-test.stderr")
    PROGRESS["stage"] = "testing the configuration"
    test_code, test_timed_out = run_to_files(test_argv, test_out, test_err, TEST_SECONDS)
    if dry_run:
        return dry_run_receipt(dict(
            started=started, timeout=timeout, binary=binary, out_dir=out_dir, version_line=version_line, build_path=build_path, build_code=build_code,
            config_path=config_path, config_sha=config_sha, generated=generated, home_net=home_net, checksum_mode=checksum_mode, rules=rules,
            rules_sha=rules_sha, rules_bytes=rules_bytes, rule_lines=rule_lines, test_argv=test_argv, test_code=test_code, test_timed_out=test_timed_out,
            test_out=test_out, test_err=test_err))
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
    # Reading eve.json has its own end: the manifest's limit less READ_MARGIN, counted from the start of the tool, so the build information, the
    # configuration test and the engine's own time are already out of it. SURICATA_RUN_READ_SECONDS (seconds from here) exists for the tests.
    try:
        read_seconds = float(os.environ.get("SURICATA_RUN_READ_SECONDS", ""))
    except ValueError:
        read_seconds = None
    read_deadline = (time.monotonic() + read_seconds) if read_seconds is not None else started + MANIFEST_SECONDS - READ_MARGIN
    read_cut = None
    since_clock = 0
    event_types, signatures = collections.Counter(), collections.Counter()
    alerts, bad_lines, not_objects, no_type, too_long = [], [], 0, 0, []
    problem_total = 0
    problems_file = None                 # every EVE line that was not read as an event, whole, in a file of its own
    invalid = 0
    tls_events = tls_ja3 = tls_ja4 = 0
    other_with_fingerprint = 0
    signature_overflow = 0
    lines = 0
    try:
        eve_fh = open_regular(eve, follow=False)
    except OSError as exc:
        fail("eve.json is not a regular file that can be read (%s)" % describe(exc), exit_code=code, stdout=stdout_path, stderr=stderr_path, out_dir=out_dir)
    with eve_fh as fh:
        while True:
            raw = fh.readline(MAX_LINE + 1)
            if not raw:
                break
            since_clock += len(raw)
            if since_clock >= CLOCK_BYTES or lines & 1023 == 0:
                since_clock = 0
                if time.monotonic() > read_deadline:
                    read_cut = {"lines_read": lines, "stopped_at_byte": fh.tell() - len(raw)}
                    break
            lines += 1
            if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
                while True:
                    more = fh.readline(MAX_LINE)
                    if not more or more.endswith(b"\n"):
                        break
                    if time.monotonic() > read_deadline:
                        read_cut = {"lines_read": lines - 1, "stopped_at_byte": fh.tell()}
                        break
                if read_cut:
                    lines -= 1        # the line being skipped was not finished: it is not a line read
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
    if read_cut:
        problems.append("eve.json was read only to line %d (stopped at byte %d): the tool's own clock for reading it ran out; the file is whole in out_dir, "
                        "and the events, alerts and counts here are those of the lines read" % (read_cut["lines_read"], read_cut["stopped_at_byte"]))
    ok = not problems
    basis = ("the engine exited 0, its configuration test passed, every rule loaded and every EVE line was read as an event" if ok else
             "; ".join(problems[:6]) + (" (and %d more, all in problems)" % (len(problems) - 6) if len(problems) > 6 else "") + ": eve.json is whole in out_dir")
    answer_out(json.dumps({
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
        "eve_read_to_the_end": read_cut is None, "eve_reading_cut_by_its_clock": read_cut,
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
