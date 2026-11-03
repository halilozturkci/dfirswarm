#!/usr/bin/env python3
"""List the registry hives of a Windows memory image, and read selected non-secret keys and values from one, through Volatility 3, offline.

This is opt-in and narrow. It runs two plugins of the installed Volatility, `windows.registry.hivelist` and `windows.registry.printkey`
(the names are taken from what `vol --offline --help` lists, never assumed), and puts what they print into records:

    mode hivelist   one record per hive Volatility found: its offset, the path the hive names itself by, whether the path is a
                    credential-class hive (SAM, SECURITY). Coverage says how many hives were found and how many had a readable name.
    mode printkey   needs `offset`, the offset of a hive in that list, and reads one key (`key`, the root by default), recursively when
                    `recurse` is true: one record per subkey and per value, each with the hive offset, the key, the name, the type, the
                    last write time, the plugin and the Volatility version.

Every record carries `hive_offset`, `plugin` and `volatility`. The answer carries `coverage`: hives found, hives with a name, hives read,
and whether the engine's log says pages were missing; the status is `partial` when pages were missing, when a hive had no readable name,
when a limit or the clock ended the read, or when a line was too long to read. Records are paged: `limit` of them in the answer and the
whole set in a file the answer names, which is written as the same judged records the answer shows.

WHAT IS NOT PRINTED. Key names and values are free text from the capture and go through the shared SHOWN rules (a part that looks like a
secret is replaced; withholding is by shape, so a plain password or a name under 16 characters is printed). On top of that:

  - SAM and SECURITY hives, and keys under SAM, SECURITY, Policy\\Secrets or SAM\\Domains, are refused (printkey) unless `write_values` is
    true in a job run as secret output; the refusal is made before the key is read and before anything is written. The inventory
    (hivelist) names those hives and their offsets, which is not a secret;
  - the value of a record whose key path or value name carries a credential word (password, secret, token, hash, ntlm, lsa, dpapi,
    masterkey, bootkey, vault and others; by name, not by content) is withheld, whole, with its length. It is written, unjudged, to
    $OUT/mem_registry only when `write_values` is true in a job run as secret output (mode 0600, in a directory with mode 0700, created
    exclusively, never over an earlier file); the answer carries a count and the file's name, never a value, a fragment or a digest;
  - a value of a binary or unknown type is not printed: its type and length are.
`write_values` is declared secret output in the manifest, so the harness seals such a job as sensitive, and the tool checks SECRET_OUTPUT=1
and refuses as JSON otherwise, before it looks at the image.

Offline: every Volatility call carries `--offline`, the tool fetches nothing, and a caller's text reaches Volatility only as an image path,
a symbol directory, an offset and a key, each in a form an option cannot be mistaken for. Volatility keeps its own cache where it keeps it.

THE CLOCK. `max_seconds` (default 420, at most 540, inside the manifest's 600) bounds the call; each program is given what is left less a
reserve, and one not finished at its time, or past its output cap, is ended with what it started (the process tree, in this tool's own
process group; never a session of its own). Records are counted as they stream: `max_records` ends the read, and the answer says where
and why. SIGTERM, SIGINT and SIGHUP end the programs and answer once: status failed, interrupted true, what had been counted, exit 128 plus
the signal; a hidden temporary file is removed or named. A signal that arrives while the answer is written is held until it is out.
"""
import json
import os
import signal
import sys

PARSER = "mem_registry/1"


def _before_start(signum, _frame):
    """A stop that arrives while the rest of the module is still loading: nothing was started or written yet, and the one answer says so."""
    sys.stdout.write(json.dumps({
        "error": "stopped by signal %d before the registry read started" % signum, "status": "failed", "interrupted": True,
        "status_basis": "the tool was stopped by signal %d before it started a program or wrote anything; nothing is a finding, and the call "
                        "can be repeated as it was" % signum,
        "signal": signum, "parser": PARSER}) + "\n")
    sys.stdout.flush()
    os._exit(128 + signum)


for _signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(_signum, _before_start)   # replaced once the module is loaded

import errno  # noqa: E402  (after the early handler, so a stop during these imports is answered too)
import hashlib  # noqa: E402
import re  # noqa: E402
import selectors  # noqa: E402
import shutil  # noqa: E402
import stat  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

MODES = ("hivelist", "printkey")
DEFAULT_SECONDS, MAX_SECONDS, MIN_SECONDS = 420.0, 540.0, 10.0
RESERVE = 8.0              # seconds of the clock kept back for the end: ending a program, placing the files, the answer
HELP_SECONDS = 90.0        # the most `vol --help` is given (it imports every plugin)
HIVELIST_SECONDS = 150.0   # the most hivelist is given
HELP_CAP = 16 << 20        # bytes of `vol --help` read; past it the program is ended
HIVELIST_CAP = 64 << 20    # bytes of hivelist output read
ROWS_CAP = 1 << 30         # bytes of printkey output read; past it the program is ended and the answer is partial
ERR_SCAN_CAP = 64 << 20    # bytes of an engine's log read
ERR_KEEP = 8192            # bytes of the start of a log kept to quote its first lines
MAX_STDIN = 1 << 20
MAX_TEXT = 4096            # the longest string a parameter may be
MAX_HIVES = 10000
MAX_LINE = 1 << 20         # a row longer than this is counted and skipped
DEFAULT_RECORDS, MAX_RECORDS = 100000, 2000000
DEFAULT_LIMIT, MAX_LIMIT = 100, 1000
NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.]{0,127}")
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
        r"""(?i:(?<![\w.-])(?:mysql|mysqldump|mysqladmin|mysqlcheck|mysqlimport|mysqlshow|mariadb|mariadb-dump|mariadb-admin)(?:\.exe)?(?=\s))(?:(?!(?i:mysql|mariadb)\b)[^\n]){0,512}?(?<=\s)-p(?=[^\s`,;)])(?:"([^"\n]{1,256})"|'([^'\n]{1,256})'|([^\s"']{1,256}))"""), -3),
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
# a format directive (`%s`, `%d`), a template field (`{0}`, `{name}`) or a `%VAR%` is where a value goes, not a value
_CRED_PLACEHOLDER = re.compile(r"%[-+ #0-9.]*[sdiuxXfeEgGcr](?![A-Za-z0-9])|\{\w*\}|%\w+%$|\.{2,}|\u2026")
_CRED_BARE = re.compile(r"-?[0-9][0-9.eE+-]{0,39}|\[[^\[\]]{0,4096}\]|(?:null|true|false)\b")
# What a text must hold for a rule to match it: a literal (lower case) of which one must be in the text, checked before the rule runs, so
# that a text with none of them (most names, addresses and ids) costs a few substring tests and no expression. An assignment rule also
# needs a separator in the text. Each is a necessary condition of its rule.
_CRED_ASSIGN = ("pass", "pwd", "secret", "key", "token", "signature", "plaintext", "sig", "pin", "otp", "sas", "hash")
_CRED_NEEDLES = {
    "a JSON Web Token": ("eyj",), "a JSON Web Encryption token": ("eyj",), "a password in a URL": ("://",),
    "an Azure Functions key": ("x-functions-key", "code="), "a private key block": ("-----begin",), "a base64 block of key lines": ("\n",),
    "an authorization header value": ("authorization",), "a cookie header value": ("cookie",),
    "a scheme and its credential": ("bearer", "basic", "negotiate", "ntlm", "digest"),
    "a value assigned to a credential name (quoted)": _CRED_ASSIGN, "a value assigned to a credential name": _CRED_ASSIGN,
    "a value given to a credential switch": ("password", "pass", "pwd", "secret", "apikey", "accesstoken", "token"),
    "a secret given to ConvertTo-SecureString": ("securestring",), "a password given to a MySQL client": ("mysql", "mariadb"),
    "a password given to curl": ("curl",), "a hash pair of an account database": (":",), "a bcrypt hash": ("$2",),
    "a token of a known family": ("gocspx-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-",
                                  "aiza", "ya29.", "1//0", "iqojb3", "fqogzx", "fwogzx", "q~", "0.a", "1.a", "sk_", "rk_"),
}
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
                if not (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{")) or _CRED_PLACEHOLDER.match(value)):
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


def _cred_spans(text, shapes, skip=()):
    spans = []
    big = len(text) > _CRED_GATE
    low = text.lower()
    sep = "=" in text or ":" in text or "%3" in low
    if "value" in low:
        _cred_pair_spans(text, spans)
    for why, rx, group in _CRED_RULES:
        if why in skip:
            continue
        need = _CRED_NEEDLES[why]
        if need is _CRED_ASSIGN and not sep:
            continue
        for n in need:
            if n in low:
                break
        else:
            continue
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
                if g and (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{")) or _CRED_PLACEHOLDER.match(value)):
                    continue
                if why == "a scheme and its credential" and g == 1 and not (re.search(r"[0-9+/=_.~-]", value) or len(value) >= 16):
                    continue                              # "basic authentication" is prose, "Basic dXNlcjpwYXNz" is not
                if g == 1 and group == -1 and len(m.groups()) >= 2 and m.group(1) in ("'", '"'):
                    continue                              # group 1 of the switch rules is the quote
                spans.append((start, end, why))
    if big:
        _tick(4096)
    for m in (_CRED_B64_RUN.finditer(text) if len(text) >= 128 and "a long unbroken base64-like run" not in skip else ()):
        if _cred_random_like(m.group(0)):
            spans.append((m.start(), m.end(), "a long unbroken base64-like run"))
    if shapes and len(text) >= 32 and "a key-length base64 string" not in skip:
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


def credential_spans(text, shapes=True, skip=()):
    """(start, end, why) of each stretch of `text` that is a credential by the name it is given under or by its text, in order and
    not overlapping. `shapes` False leaves out the rules that recognise a key by its length alone (a value that is named a checksum or
    a digest is not scanned for them). This is not `token_spans`: an identifier (a GUID, a hex digest, an access key id, an ARN) is
    not a credential here, and a tool that prints identifiers on purpose asks only for these."""
    if len(text) > TEXT_LIMIT:
        return [(0, len(text), "text longer than %d characters" % TEXT_LIMIT)]
    if shapes and not skip and text in _CRED_CLEAN:
        return []
    spans = _cred_spans(text, shapes, skip)
    if shapes and not skip and not spans and len(text) <= 256 and len(_CRED_CLEAN) < 100000:
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


# what the rules of the block above already withhold whole, with their own markers: the first pass leaves these to them
_CRED_OLD_COVERS = frozenset(("a JSON Web Token", "a password in a URL", "an authorization header value", "a scheme and its credential",
                              "a long unbroken base64-like run", "a key-length base64 string"))


def _credentials_withheld(text, kind, skip=()):
    """`text` with each credential in it withheld. It runs after the rules above, on text that may hold their markers: a stretch that
    begins at a marker is theirs already."""
    out, last = [], 0
    for start, end, why in credential_spans(text, True, skip):
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
    text = _credentials_withheld(text, kind, _CRED_OLD_COVERS)     # first: the rules above cut a secret into pieces that no rule for a whole one can match
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
# BEGIN SHARED SHOWN
# MEMORY SHOWN v1: the same text is in mem_fs and mem_profile (tests/pack-memory-shared.test.ts holds the copies equal), and it
# reads the shared WITHHOLDING block above it. A string read from the capture (a name MemProcFS lists, a line the engine prints, a
# release string in a header) is not printed as it is: it goes through shown(text, kind), and the answer and the paged file go
# through sealed(), so that nothing reaches stdout or a file that is not sealed output without having been judged. Three layers,
# the hybrid design: an allow-list per kind, the shared deny-list, and an independent backstop with its own rules.
#
# LAYER 1, an allow-list per kind of field. "release" (a kernel release) and "build" (a Windows build string) are shown only when
# they fit the grammar of a version: digits, dots and the tags of a closed list (_RELEASE_WORD, _BUILD_WORD), at most 6 groups and 16
# digits after the version, nothing else, so a secret placed where a version should be, or glued to one, is not printed. "name" (a file, directory, process or key name; "path" is the same for a virtual path, judged as a whole and
# then component by component) is shown when it has no invisible character, no component over 128 characters, and no chain of 16
# or more letters and digits that looks random (it flips between letters and digits, or between capitals and lower case, as words
# do not). A GUID, a SID, a 16-digit hexadecimal address and 0x numbers are typed ids and are plain. "text" (one line of an
# engine's output) has no character grammar, only layers 2 and 3.
# LAYER 2, the deny-list of the shared block (token_spans: vendor prefixes, long token-like runs, user-info) plus the value after
# a secret's name (password=, token:, api key ...), read on the string with typed ids masked. A span is replaced; the rest stays.
# LAYER 3, the backstop, written apart from the two above and applied to what layers 1 and 2 would print: a PEM marker, a named
# secret, a vendor prefix in any case, user-info, 19 or more digits, 32 or more hexadecimal digits, a run of 20 or more characters
# that changes class (lower, upper, digit, other) as random text does; read on a copy with invisible characters taken out and NFKC
# applied, and on the original: 12 characters of anything it calls secret in the original that are still in the shown string mean
# a piece was left between two cuts. A string it finds suspect is replaced whole by <withheld N characters: why>, counted, and the
# answer says so.
# NOT RECOGNISED, by design: a plain password or passphrase, a pronounceable secret, anything under 16 characters in a name,
# a secret in an encoding this block does not read. Withholding is by shape. Measured on planted canaries (1,000 per cell; a name
# alone, then inside `proc_<k>.exe`, `<k>.dll` and `1234-<k>`), the share of keys printed whole: base64 and base62 keys 0 to 0.6 per
# cent alone and up to 3 per cent in a process-name context (24 base62 characters 2.9, 20 bytes of base64 1.2); in an engine line
# (kind text, used for the first lines of a failure, which has no allow-list) base64 keys of 16 to 32 bytes 0 to 18 per cent, base62
# keys of 20 to 32 characters 10 to 61, a 24-character base36 key 48 to 65, a base64 key holding `/` 37 to 40. The prefixes of the vendors in _PREFIX2 and _PREFIX_RULES are read at 0 in 3,400 plants per shape. Printed at
# 100 per cent, because they are made of pieces under 16 characters or of words: UUID-shaped and 16-digit hexadecimal secrets (typed
# ids are plain), tokens split by `.` or `:` into pieces under 16 characters, word passwords and passphrases, 14-character policy
# passwords. Printed at tens of per cent: base32 seeds (43 to 46), licence keys of 5 groups of 5 (18 to 20), a bcrypt hash's
# 12-character fragments (28 to 31), a vendor key whose prefix is in no list (`rk_live_` was 3 to 18 before it was added).
import collections
import unicodedata

LMIN = 16
MAX_ONE = 4096
MAX_COMPONENT = 128
BOUNDARY = {"shown": 0, "withheld_spans": 0, "withheld_whole": 0, "backstop_replaced": 0, "swept": 0}
BACKSTOP_WHY = collections.Counter()


class Shown(str):
    """A string read from the capture that has been judged: sealed() does not judge it again."""


_TYPED = re.compile(r"\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?"
                    r"|S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}"
                    r"|(?<![0-9A-Za-z])0x[0-9A-Fa-f]{1,16}(?![0-9A-Za-z])"
                    r"|(?<![0-9A-Za-z])[0-9A-Fa-f]{16}(?![0-9A-Za-z])"
                    r"|(?<=[A-Za-z0-9]_)[0-9a-z]{13}(?![0-9A-Za-z])")        # the publisher id at the end of an app package family name
_PREFIX2 = re.compile(r"(?i)glpat-[0-9a-z_-]{16,}|(?:sk|rk|pk)_(?:live|test)_[0-9a-z]{16,}|whsec_[0-9a-z_+/=-]{16,}|sg\.[0-9a-z_-]{16,}|aiza[0-9a-z_-]{30,}|npm_[0-9a-z]{30,}|dop_v1_[0-9a-f]{32,}|ya29\.[0-9a-z_-]{20,}")
_PIECE = re.compile(r"[A-Za-z0-9+_=-]{16,}")
_PLAIN_SHORT = re.compile(r"[A-Za-z0-9 ._()+-]{1,15}")
_NAMED = re.compile(r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)"
                    r"[A-Za-z0-9_]{0,12}[ \t]{0,3}[=:](?![=:/\\])[ \t]{0,3}['\"]?([^\s'\"<>&;,]{3,128})")
# the same rule for a string the tool wrote itself (documentation-like text such as "secret_output: true" must pass): the value is 6 or more characters with a digit or a symbol in it
_NAMED_TEXT = re.compile(r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)"
                         r"[A-Za-z0-9_]{0,12}[ \t]{0,3}[=:][ \t]{0,3}['\"]?(?=[^\s'\"<>&;,]{0,127}[0-9!#$%^*+@~])[^\s'\"<>&;,]{6,128}")
_USER_INFO = re.compile(r"[^\s/@:<>]{1,64}:[^\s/<>]{1,128}@[\w\[]")        # the backstop's own form: the password may hold an @
_UINFO_SPAN = re.compile(r"(?<![\w.%+-])[\w.%+-]{1,64}:[^\s/<>]{1,128}(?=@[\w\[])")   # layer 2's: up to the last @ before a host
_BS_PEM = re.compile(r"-----BEGIN")
_BS_PREFIX = re.compile(r"(?i)(?:akia|asia)[0-9a-z]{16}|gh[pousr]_[0-9a-z]{16}|github_pat_[0-9a-z_]{16}|xox[abeprs]-[0-9a-z-]{8}"
                        r"|glpat-[0-9a-z_-]{16}|(?:sk|rk|pk)_(?:live|test)_[0-9a-z]{16}|whsec_[0-9a-z_+/=-]{16}|sk-[0-9a-z_-]{16}|aiza[0-9a-z_-]{20}|npm_[0-9a-z]{20}"
                        r"|eyj[0-9a-z_-]{8,}\.[0-9a-z_-]{8,}\.|sg\.[0-9a-z_-]{16}|(?:basic|bearer)[ \t]{1,3}[0-9a-z+/=._~-]{16}")
_BS_DIGITS = re.compile(r"[0-9]{19,}")
_BS_HEX = re.compile(r"[0-9A-Fa-f]{32,}")
_BS_RUN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
# The version grammars are closed lists, not shapes: a release is the version, then at most six groups, each a number of up to five digits or one
# word of the list below (a distribution's or a kernel flavour's own tag, with up to three digits after it); a Windows build string is the build, the
# platform, and a branch made of at most four words of the list below and a date. A word that is not in the list, or a seventh group, or more than 16
# digits in all, is not a version, and the string is withheld whole (a release with an unusual tag is withheld too: the count is in boundary).
_RELEASE_WORD = (r"(?:generic|lowlatency|aws|azure|gcp|gke|oem|cloud|kvm|virtual|raspi|rpi|lts|zen|hardened|realtime|rt|rc|amd64|arm64|armhf|"
                 r"i[3-6]86|x86_64|aarch64|ppc64le|s390x|el|fc|ubuntu|debian|deb|bpo|pve|default|arch|mainline|android|linuxkit|coreos|edge|std|"
                 r"smp|preempt|uek|lp|oracle|ibm|nvidia|tegra|stable|gentoo|xanmod|liquorix|v7l?|v8|k3s|dirty)")
_RELEASE = re.compile(r"[0-9]{1,2}\.[0-9]{1,3}(?:\.[0-9]{1,3})?((?:[-+~._](?:[0-9]{1,5}|" + _RELEASE_WORD + r"[0-9]{0,3}(?:_[0-9]{1,3})?)){0,6})\+?")
_BUILD_WORD = (r"(?:win7sp1|win7|win8|winmain|winblue|vibranium|th[12]|rs|rs[0-9]{1,2}|[0-9]{2}h[12]|vb|ni|co|ge|fe|zn|mn|sv|lh|r[0-9]{1,2}|release|"
               r"prerelease|rtm|gdr|ldr|svc|sec|escrow|inmarket|flt|prod|dev|beta|lab|sp[0-9]|rc|oem|st|uup|rel|main|win|vista|server|ltsc)[0-9]{0,2}")
_BUILD = re.compile(r"[0-9]{3,6}\.[0-9]{1,5}\.(?:x86|amd64|arm64|armnt)(?:fre|chk)(?:\.(?:" + _BUILD_WORD + r"(?:_" + _BUILD_WORD + r"){0,3})?(?:\.[0-9]{0,6}(?:-[0-9]{0,4})?)?)?")


def _norm(text):
    """NFKC with the invisible characters (format, control, combining) taken out: what the rules read besides the string itself."""
    if text.isascii() and text.isprintable():
        return text
    folded = unicodedata.normalize("NFKC", text)
    return "".join(c for c in folded if unicodedata.category(c) not in ("Cf", "Cc", "Mn", "Me"))


def _hidden(text):
    """Whether the text holds an invisible or unassigned character (a byte that was not UTF-8, written as a lone surrogate escape, is not one)."""
    if text.isascii() and text.isprintable():
        return False
    for c in text:
        cat = unicodedata.category(c)
        if cat in ("Cf", "Cc", "Co", "Cn") or (cat == "Cs" and not 0xDC80 <= ord(c) <= 0xDCFF):
            return True
    return False


def _escaped(text):
    """A byte that was not UTF-8 (a lone surrogate escape) written as \\xNN, so that no writer raises on it."""
    if text.isascii():
        return text
    return "".join("\\x%02x" % (ord(c) - 0xDC00) if 0xDC80 <= ord(c) <= 0xDCFF else c for c in text)


def _mask(text):
    return _TYPED.sub(lambda m: "x" * len(m.group()), text)


_SEGMENT = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


def _random_piece(piece):
    """A run of 16 or more characters that is not shaped like words. Words, CamelCase names and dates break into segments (a word, a capital
    and its lower-case letters, a number) of 3 or more characters on average; random base62 and base64 break into segments of about 2. A
    base64 padding (== at the end, or a + inside a run of letters and digits) is not in a word either."""
    alnum = "".join(c for c in piece if c.isalnum())
    if len(alnum) < LMIN - 2 or alnum.isdigit():
        return False
    if piece.endswith("==") or (len(alnum) >= LMIN and "+" in piece.strip("+") and not piece.isalpha()):
        return True
    return len(alnum) >= LMIN and len(alnum) <= 3.0 * len(_SEGMENT.findall(alnum))


def _spans(text, kind):
    """The spans of a string that layers 1 and 2 withhold, as (start, end, what), merged."""
    masked = _mask(text)
    if kind == "text":
        found = [(s, e, "token-shaped text") for s, e in token_spans(masked)]
    else:
        # a name is judged by the allow-list below; of the shared deny-list only the vendor prefixes apply to it
        found = [(start, end, "token-shaped text") for start, end in _prefixed_spans(masked)]
    found += [(m.start(), m.end(), "token-shaped text") for m in _PREFIX2.finditer(masked)]
    if kind != "text":
        for m in _PIECE.finditer(masked):
            if _random_piece(m.group()):
                found.append((m.start(), m.end(), "random-looking text"))
    for rx in (_USERINFO, _BARE_USERINFO, _UINFO_SPAN):
        for m in rx.finditer(text):
            found.append((m.start(), m.end(), "userinfo"))
    for m in _NAMED.finditer(masked):
        found.append((m.start(1), m.end(1), "secret value"))
    found.sort()
    merged = []
    for start, end, what in found:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end), merged[-1][2])
        else:
            merged.append((start, end, what))
    return merged


def _density(run):
    """For a run of 16 or more letters and digits (symbols left out): how often neighbours change class (lower, upper, digit), and whether it mixes classes
    as random text does. Words, paths and CamelCase names change class rarely; random base62 and base64 change in about 6 of 10 steps."""
    alnum = [0 if c.islower() else 1 if c.isupper() else 2 for c in run if c.isalnum()]
    if len(alnum) < LMIN:
        return False
    changes = sum(1 for a, b in zip(alnum, alnum[1:]) if a != b)
    return changes >= 0.45 * (len(alnum) - 1) and (2 in alnum or (0 in alnum and 1 in alnum))


def _backstop_reason(text):
    """Why a string is not printed, by rules that are not layer 2's; None when it may be."""
    plain = _norm(text)
    if _BS_PEM.search(plain):
        return "a PEM marker"
    if _NAMED.search(plain):
        return "a named secret"
    if _BS_PREFIX.search(plain):
        return "a token prefix"
    if _USER_INFO.search(plain):
        return "user-info"
    masked = _mask(plain)
    if _BS_DIGITS.search(masked):
        return "a long digit run"
    if _BS_HEX.search(masked):
        return "a long hexadecimal run"
    for m in _BS_RUN.finditer(masked):
        if _density(m.group()):
            return "a random-looking run"
    return None


def _backstop_pieces(original, printed):
    """Whether 12 characters of a secret-shaped part of the original are still in what would be printed (a piece left between two cuts)."""
    plain, out = _norm(original), _norm(printed)
    masked = _mask(plain)
    spans = [m.span() for m in _BS_RUN.finditer(masked) if _density(m.group())]
    spans += [m.span(1) for m in _NAMED.finditer(plain)]
    spans += [m.span() for m in _BS_PREFIX.finditer(plain)]
    for start, end in spans[:16]:
        piece = plain[start:end]
        if len(piece) >= 12 and any(piece[i:i + 12] in out for i in range(0, len(piece) - 11)):
            return True
    return False


def _whole(text, why, key):
    BOUNDARY["withheld_whole"] += 1
    COUNTS[key] = COUNTS.get(key, 0) + 1
    return Shown("<withheld %d characters: %s>" % (len(text), why))


def shown(text, kind="name"):
    """What may be printed of a string read from the capture. kind: name, path, text, release or build."""
    if not isinstance(text, str):
        text = str(text)
    if isinstance(text, Shown):
        return text
    BOUNDARY["shown"] += 1
    key = "text" if kind == "text" else "names"
    if kind in ("release", "build"):
        if len(text) > (48 if kind == "release" else 64):
            return _whole(text, "not a version", key)
        found = (_RELEASE if kind == "release" else _BUILD).fullmatch(text)
        if not found or (kind == "release" and sum(len(d) for d in re.findall(r"[0-9]+", found.group(1))) > 16):
            return _whole(text, "not a %s string" % kind, key)
        return Shown(text)
    if _PLAIN_SHORT.fullmatch(text):
        return Shown(text)
    if len(text) > MAX_ONE:
        return _whole(text, "longer than %d characters" % MAX_ONE, key)
    if _hidden(text):
        return _whole(text, "invisible or non-text characters", key)
    if kind in ("name", "path") and any(len(part) > MAX_COMPONENT for part in text.split("/")):
        return _whole(text, "a component over %d characters" % MAX_COMPONENT, key)
    spans = _spans(text, kind)
    pieces, last = [], 0
    for start, end, what in spans:
        pieces.append(text[last:start])
        pieces.append(_withheld(what, end - start, key))
        BOUNDARY["withheld_spans"] += 1
        last = end
    pieces.append(text[last:])
    printed = _escaped("".join(pieces))
    why = _backstop_reason(printed)
    if why is None and spans and _backstop_pieces(text, printed):
        why = "a part of a secret-shaped text"
    if why is not None:
        BOUNDARY["backstop_replaced"] += 1
        BACKSTOP_WHY[why] += 1
        return _whole(text, "backstop: " + why, key)
    return Shown(printed)


def _seal_text(s):
    """The strongest rules of the backstop on a string the tool did not mark as read from the capture."""
    if len(s) < 12:
        return s
    if len(s) > 4 * MAX_ONE:
        BOUNDARY["backstop_replaced"] += 1
        BACKSTOP_WHY["longer than the judged size"] += 1
        return Shown("<withheld %d characters: backstop: longer than the judged size>" % len(s))
    BOUNDARY["swept"] += 1
    plain = _norm(s)
    why = ("a PEM marker" if _BS_PEM.search(plain) else "a named secret" if _NAMED_TEXT.search(plain)
           else "a token prefix" if _BS_PREFIX.search(plain) else "user-info" if _USER_INFO.search(plain) else None)
    if why is None:
        return s
    BOUNDARY["backstop_replaced"] += 1
    BACKSTOP_WHY[why] += 1
    return Shown("<withheld %d characters: backstop: %s>" % (len(s), why))


def sealed(obj):
    """The serialisation boundary: the same structure with every string that is not already judged put through the strongest backstop rules."""
    if isinstance(obj, Shown):
        return obj
    if isinstance(obj, str):
        return _seal_text(obj)
    if isinstance(obj, dict):
        return {(sealed(k) if isinstance(k, str) else k): sealed(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sealed(v) for v in obj]
    return obj


def boundary_summary():
    return {"strings_judged": BOUNDARY["shown"], "spans_withheld": BOUNDARY["withheld_spans"], "strings_withheld": BOUNDARY["withheld_whole"],
            "backstop_replaced": BOUNDARY["backstop_replaced"],
            "rule": "a string read from the capture is shown only when it fits the plain grammar of its kind and no deny-list or backstop rule "
                    "reads it as a secret; a placeholder says how many characters were withheld. Withholding is by shape: a plain password, "
                    "a pronounceable passphrase or anything under 16 characters in a name is printed. The originals of withheld names are "
                    "written only on write_values, in a job run as secret output."}
# END SHARED SHOWN
# BEGIN SHARED PAGE
# The same text is in mem_carve, mem_fs and mem_profile (tests/pack-memory-shared.test.ts holds the copies equal).
# LosslessPage keeps the page an agent reads small and, when there are more rows, writes the whole result as JSON Lines
# under work/<agent>/tool-output (in a job, $OUT/tool-output) and names it. A row is serialised with the default ASCII
# escapes, so a name that is not valid UTF-8 (a lone surrogate) is written as a \udcXX escape and cannot break the writer.
# The finished file is placed without replacing an earlier one (a rerun that stopped sooner never leaves a smaller file
# where a larger one was; the name actually used is the one in `shown`), and a stop removes or names the temporary file, under a name
# an answer may print (never the hidden one). Closing and placing the file is held against a stop, which is acted on right after.
# Only regular files are ever compared: both names are opened with O_NONBLOCK and O_NOFOLLOW and looked at with fstat before a byte is
# read, so a FIFO, a device, a directory or a link at a name (the caller's own results_to, say) is another result's and cannot hold the
# tool. The comparing of one call has PLACE_COMPARE_SECONDS in all; past it an earlier result is taken as different and this one takes
# the next free name (nothing is replaced, but an identical rerun may then be named anew).
# The name is taken with a hard link of the finished file, so it never holds an empty file, whatever stops the tool and when (SIGKILL
# included). Where the file system refuses the link, the name is taken with an exclusive create and the file is moved over it: a stop
# that unwinds (an exception) takes the empty name back while it is still the empty file this call made; a stop that ends the process
# without unwinding (SIGKILL, the handlers of the STOP block) between the create and the move leaves the empty name, and the next run takes -2.
# abort_pages() drops the temporary files of all the pages under that guard; the module's fail() calls it before it answers.
# The module that carries this block defines GUARD (a dict with "depth") and checkpoint().
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
    raise OSError(errno.EEXIST, "no free name beside %s" % path)


def place_visibly(tmp, wanted):
    """Give the kept `tmp` a name an answer may print: `wanted` (or the next free one), and when the directory refuses that, a plain
    rename to <wanted>.<pid>. Returns the path, or None when `tmp` is gone or could not be renamed. The hidden name of `tmp` is never
    what an answer prints: a caller that gets None says that nothing is named."""
    try:
        return place_without_replacing(tmp, wanted)
    except OSError:
        pass
    if not os.path.lexists(tmp):
        return None
    fallback = wanted.with_name("%s.%d" % (wanted.name, os.getpid()))
    try:
        os.rename(tmp, fallback)
    except OSError:
        return None
    return fallback


PAGES = []


def abort_pages():
    """Drop the hidden temporary file of every page that was being written, under the signal guard (GUARD["depth"], as emit holds it for an
    answer): a signal that lands in the loop is held until it is over, so that no page's file is left and the answer that follows is the one
    answer."""
    GUARD["depth"] += 1
    try:
        for page in list(PAGES):
            page.abort()
    finally:
        GUARD["depth"] -= 1


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self.bytes = 0                          # what the whole result takes as JSON Lines, kept in memory or not
        self._out = None
        self._tmp: Path | None = None
        self.placed = False                     # the finished file is under its final name (and, if a stop comes now, is kept and named)
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8", "surrogatepass")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        PAGES.append(self)

    def _write(self, line: str) -> None:
        assert self._out is not None
        self._out.write(line)
        self._out.write("\n")

    def add(self, row: object, line: str | None = None) -> None:
        self.total += 1
        if line is None:
            line = json.dumps(row, default=str)
        self.bytes += len(line) + 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # The object knows the hidden name before the file exists, so a stop at any point leaves nothing that abort() or
            # keep_partial() cannot find.
            self._tmp = self.path.parent / (".%s-%s" % (self.path.name, os.urandom(6).hex()))
            fd = os.open(str(self._tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            self._out = os.fdopen(fd, "w", encoding="ascii")
            for kept in self.page:
                self._write(json.dumps(kept, default=str))
        self._write(line)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            GUARD["depth"] += 1                 # closing the file and giving it its name is finished before a stop is acted on
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                self._out = None
                assert self._tmp is not None
                placed = place_without_replacing(self._tmp, self.path)
                self._tmp = None
                self.path = placed
                self.shown = self.shown[: len(self.shown) - len(self.shown.rsplit("/", 1)[-1])] + placed.name
                self.placed = True
            finally:
                GUARD["depth"] -= 1
            checkpoint()
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

    def abort(self) -> None:
        """Drop the hidden temporary file of a run that failed part way. Closing the file flushes what is buffered, and on a full disk
        (or past a quota) that raises: the file is unlinked all the same, and the error is not the caller's to meet while it is
        already giving up the page."""
        out, tmp = self._out, self._tmp
        self._out = None
        try:
            if out is not None:
                out.close()
        except OSError:
            pass
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
                self._tmp = None

    def keep_partial(self):
        """Close the temporary file and give it a visible name ending in .partial (never replacing a file); returns the
        path, or None when nothing was being written. Whole lines only are in it when the rows were added whole."""
        if self._tmp is None:
            return None
        if self._out is not None:
            try:
                self._out.flush()
                self._out.close()
            except OSError:
                pass
            self._out = None
        if not os.path.lexists(self._tmp):      # a stop between choosing the name and creating the file
            self._tmp = None
            return None
        placed = place_visibly(self._tmp, self.path.with_name(self.path.name + ".partial"))
        self._tmp = None
        return placed
# END SHARED PAGE


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


# --- the glue every answer uses (the same text as vol_readiness's, with the stop of run_engine added) ---------------------------------------

def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


GUARD = {"depth": 0, "pending": None, "stopping": False}


ANSWER = {"printed": False}


RESULTS = {}               # the views finished so far: what a stop answer carries


CLOCK = {"deadline": None}


def _hold_signal(signum, frame):
    if GUARD["stopping"]:
        return
    if GUARD["depth"]:
        GUARD["pending"] = signum            # the answer is being written or a file placed: finished first, then the stop is acted on
        return
    GUARD["stopping"] = True
    _on_signal(signum, frame)


def checkpoint():
    signum = GUARD["pending"]
    if signum is not None and not GUARD["depth"]:
        GUARD["pending"] = None
        GUARD["stopping"] = True
        _on_signal(signum, None)


def emit(answer):
    """The one way an answer leaves: whole, once, and not cut by a signal. A signal that arrives while it is written is held, and once it is
    out a later one changes nothing, so stdout never holds two documents."""
    text = json.dumps(sealed(answer), indent=2)
    GUARD["depth"] += 1
    try:
        if ANSWER["printed"]:
            return
        ANSWER["printed"] = True
        print(text, flush=True)
    finally:
        GUARD["depth"] -= 1
        GUARD["stopping"] = True


def fail(message, **extra):
    abort_pages()               # a page that was being written is dropped with its hidden temporary file, whatever ended the call
    emit({"error": message, "status": "failed", "parser": PARSER,
          "status_basis": "the call was refused or ended before an answer; nothing in this document is a finding about this host or the evidence",
          **extra})
    raise SystemExit(1)


def read_args():
    try:
        raw = sys.stdin.read(MAX_STDIN + 1)
    except (OSError, ValueError) as exc:
        fail("the arguments could not be read", reason=type(exc).__name__)
    if len(raw) > MAX_STDIN:
        fail("the arguments are larger than %d bytes" % MAX_STDIN)
    try:
        args = json.loads(raw)
    except (ValueError, RecursionError):
        fail("arguments are not valid JSON (or are nested too deeply)")
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def text_arg(args, key):
    value = args.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        fail("%s must be a non-empty string" % key)
    if len(value) > MAX_TEXT:
        fail("%s is longer than %d characters" % (key, MAX_TEXT))
    if "\x00" in value:
        fail("%s holds a NUL character" % key)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        fail("%s holds a character that is not text (a lone surrogate)" % key)
    return value


def argv_safe(value):
    """A caller's path goes to Volatility as one argument after its option; a leading "-" would be read as an option, so it is made a path."""
    return "./" + value if value.startswith("-") else value


def symbols_arg(args):
    """symbols_dir: one directory. Volatility's -s takes a semicolon-separated list of paths, so a semicolon would name a second path."""
    value = text_arg(args, "symbols_dir")
    if value and ";" in value:
        fail("symbols_dir must not contain a semicolon: Volatility's -s reads a semicolon-separated list of paths")
    return value


def left(cap):
    """Seconds a step may take: at most `cap`, and what is left of the call's clock less the reserve; 0 when there is none."""
    return max(0.0, min(cap, CLOCK["deadline"] - time.monotonic() - RESERVE))


def run_engine(argv, seconds, on_out, on_err, out_cap, err_cap, cwd=None, stop=None):
    """Run a program in this tool's own process group with its output read from pipes, in blocks, and handed to `on_out` and `on_err`.
    {"state": "ok" | "timeout" | "capped" | "not_started", "code": exit code or None, "error": text}. The program and what it started are
    ended at `seconds` or when either stream passes its cap (the cap is on bytes read, so an output that never ends cannot hold the tool)."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    except OSError as exc:
        return {"state": "not_started", "code": None, "error": describe(exc)}
    ACTIVE.append(proc)
    deadline = time.monotonic() + max(0.1, seconds)
    state, note, got = "ok", None, {"out": 0, "err": 0}
    caps = {"out": out_cap, "err": err_cap}
    sinks = {"out": on_out, "err": on_err}
    sel = selectors.DefaultSelector()
    open_streams = 0
    try:
        for name, pipe in (("out", proc.stdout), ("err", proc.stderr)):
            os.set_blocking(pipe.fileno(), False)
            sel.register(pipe, selectors.EVENT_READ, name)
            open_streams += 1
        ended_at = None
        while open_streams:
            now = time.monotonic()
            if now >= deadline:
                state = "timeout"
                break
            if proc.poll() is not None:
                ended_at = ended_at or now
                if now - ended_at > PIPE_GRACE:
                    break           # the program ended and something it started still holds its pipes: they are let go
            if stop is not None and stop():
                state = "stopped"      # the caller has what it wanted
                break
            _sample(proc.pid)
            for key, _events in sel.select(timeout=max(0.01, min(0.2, deadline - now))):
                try:
                    chunk = os.read(key.fd, 1 << 16)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    sel.unregister(key.fileobj)
                    open_streams -= 1
                    continue
                got[key.data] += len(chunk)
                if got[key.data] > caps[key.data]:
                    state = "capped"
                    break
                sinks[key.data](chunk)
            if state != "ok":
                break
        if state == "ok" and proc.poll() is None:
            try:
                proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                state = "timeout"
        if state != "ok" or proc.poll() is None:
            note = kill_tree(proc)
        elif open_streams:
            reap_orphans(_pipe_inodes(proc))
        try:
            proc.wait(timeout=PIPE_GRACE)
        except subprocess.TimeoutExpired:
            pass
        out = {"state": state, "code": proc.poll() if state == "ok" else None}
        if note:
            out["note"] = note
        return out
    finally:
        sel.close()
        for pipe in (proc.stdout, proc.stderr):
            try:
                pipe.close()
            except (OSError, ValueError):
                pass
        if proc in ACTIVE:
            ACTIVE.remove(proc)


class Collect:
    """Keeps the first `cap` bytes of a stream (run_engine ends the program at its own, larger, cap on what it reads)."""
    def __init__(self, cap):
        self.cap, self.data = cap, bytearray()

    def __call__(self, chunk):
        room = self.cap - len(self.data)
        if room > 0:
            self.data += chunk[:room]

    def text(self):
        return bytes(self.data).decode("utf-8", "replace")


def engine_failed(result, what):
    """Why a run did not give an answer to read, in a sentence, or None when it ran to its end."""
    if result["state"] == "not_started":
        return "%s could not be started (%s)" % (what, result["error"])
    if result["state"] == "timeout":
        return "%s was not finished in the time it was given and was ended" % what
    if result["state"] == "capped":
        return "%s wrote more than the tool reads and was ended" % what
    return None


def version_of(text):
    found = re.search(r"Volatility 3 Framework (\d{1,3}\.\d{1,3}\.\d{1,3})", text[:65536])
    return shown(found.group(1), "release") if found else None


def parse_plugins(text):
    names = set()
    for group in re.findall(r"\{([A-Za-z0-9_.,]+)\}", text):
        for name in group.split(","):
            if "." in name and NAME_RE.fullmatch(name):
                names.add(name)
    for found in re.finditer(r"^[ \t]{2,}([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)(?:[ \t]|$)", text, re.M):
        if NAME_RE.fullmatch(found.group(1)):
            names.add(found.group(1))
    return sorted(names)


def find_vol():
    return shutil.which("vol")


def image_problem(path):
    """Why `path` is not a memory file to hand to Volatility, or None. Opened without waiting and looked at with fstat, so a FIFO is refused."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
        st = os.fstat(fd)
    except OSError as exc:
        return "it cannot be opened (%s)" % errno.errorcode.get(exc.errno, "errno %s" % exc.errno)
    finally:
        if fd is not None:
            os.close(fd)
    if not stat.S_ISREG(st.st_mode):
        return "it is not a regular file"
    if st.st_size == 0:
        return "the file is empty"
    return None


# --- what this tool adds to the common glue ------------------------------------------------------------------------------------------------

SECRET = {"file": None}    # the hidden or placed file of withheld values, while one is being written


def last_word(signum):
    kept = []
    for page in list(PAGES):
        if page.placed:
            kept.append(page.shown)         # a finished list is whole: it is named
        else:
            named = page.keep_partial()     # whole lines only; a visible name ending in .partial, never the hidden one
            if named is not None:
                kept.append(str(named))
    values = SECRET["file"]
    if values is not None:
        named = values.stop()
        if named:
            kept.append(named)
    answer = {"error": "stopped by signal %d before the registry read was complete" % signum, "status": "failed", "interrupted": True,
              "status_basis": "the tool was stopped by signal %d; the programs it had started were ended, and what had been read is not an "
                              "answer%s" % (signum, "; files that were being written are kept and named in kept_results" if kept else ""),
              "signal": signum, "parser": PARSER, "partial_results": dict(RESULTS)}
    if kept:
        answer["kept_results"] = kept
        answer["kept_results_format"] = "JSON Lines, one complete result per line; a name ending in .partial was cut by the stop"
    notes = process_notes()
    if notes:
        answer["process_notes"] = notes
    emit(answer)


def drop_secret():
    if SECRET["file"] is not None:
        SECRET["file"].discard()
    SECRET["file"] = None


def job_dir():
    """$OUT of the job, or None."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    return (re.sub(r"[^A-Za-z0-9_.-]", "_", job), Path(out)) if job and out else None


class SecretFile:
    """The unjudged values withheld from the answer, written to $OUT/mem_registry (a directory with mode 0700) as a file with mode 0600, created
    exclusively under a hidden name and placed without replacing an earlier file. Opened by the first value; nothing exists before it."""
    def __init__(self, key):
        job, out = job_dir()
        self.dir = out / "mem_registry"
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8", "surrogatepass")).hexdigest()[:16]
        self.name = "mem_registry-%s-values.jsonl" % digest
        self.shown_dir = "store/jobs/%s/out/mem_registry" % job
        self.tmp, self.fh, self.count, self.final = None, None, 0, None

    def add(self, row):
        if self.fh is None:
            self.dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.dir, 0o700)
            self.tmp = self.dir / (".%s-%s" % (self.name, os.urandom(6).hex()))
            fd = os.open(str(self.tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            self.fh = os.fdopen(fd, "w", encoding="ascii")
        self.fh.write(json.dumps(row, default=str))
        self.fh.write("\n")
        self.count += 1

    def finish(self):
        """Close and place the file; returns the name an answer may print, or None when no value was written."""
        if self.fh is None:
            return None
        GUARD["depth"] += 1                 # closing the file and giving it its name is finished before a stop is acted on
        try:
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.fh.close()
            self.fh = None
            self.final = place_without_replacing(self.tmp, self.dir / self.name)
            self.tmp = None
        finally:
            GUARD["depth"] -= 1
        checkpoint()
        return "%s/%s" % (self.shown_dir, self.final.name)

    def discard(self):
        """After a failure: the hidden file, if one was started, is removed (values are never left behind unnamed)."""
        try:
            if self.fh is not None:
                self.fh.close()
        except OSError:
            pass
        self.fh = None
        if self.tmp is not None:
            try:
                os.unlink(self.tmp)
            except OSError:
                pass
            self.tmp = None

    def stop(self):
        """After a stop: the hidden file, closed, gets a visible name ending in .partial; returns it, or None."""
        if self.tmp is None:
            return "%s/%s" % (self.shown_dir, self.final.name) if self.final else None
        try:
            if self.fh is not None:
                self.fh.flush()
                self.fh.close()
                self.fh = None
        except OSError:
            pass
        placed = place_visibly(self.tmp, self.dir / (self.name + ".partial")) if os.path.lexists(self.tmp) else None
        self.tmp = None
        return "%s/%s" % (self.shown_dir, placed.name) if placed else None


class Lines:
    """Hands each complete line of a stream to `fn` (a line longer than MAX_LINE is counted and skipped; the end of the stream flushes the last)."""
    def __init__(self, fn):
        self.fn, self.carry, self.skipped = fn, b"", 0

    def __call__(self, chunk):
        parts = (self.carry + chunk).split(b"\n")
        self.carry = parts.pop()
        if len(self.carry) > MAX_LINE:
            self.carry = b""
            self.skipped += 1
        for line in parts:
            if len(line) > MAX_LINE:
                self.skipped += 1
            else:
                self.fn(line.rstrip(b"\r"))

    def close(self):
        if self.carry and len(self.carry) <= MAX_LINE:
            self.fn(self.carry.rstrip(b"\r"))
        self.carry = b""


MISSING = re.compile(rb"(?i)invalid address|paged out|page[d]? (?:fault|invalid)|PagedInvalid|not mapped|unable to read|could not read|unreadable|swapped")


class Log:
    """The engine's log: how many lines say pages were missing, the first lines quoted (judged), and the version line."""
    def __init__(self):
        self.lines = Lines(self._line)
        self.missing, self.quoted, self.version, self.head = 0, [], None, 0

    def __call__(self, chunk):
        self.lines(chunk)

    def _line(self, line):
        if self.version is None:
            found = re.search(rb"Volatility 3 Framework (\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if found:
                self.version = found.group(1).decode()
        if MISSING.search(line):
            self.missing += 1
            if len(self.quoted) < 3:
                self.quoted.append(shown(line.decode("utf-8", "replace").strip()[:200], "text"))
        if self.head < 3 and line.strip():
            self.head += 1


def parse_offset(value):
    """A hive offset given as an integer or as 0x followed by hexadecimal digits: the integer, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value < 1 << 64 else None
    if isinstance(value, str) and re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", value):
        return int(value, 16)
    return None


def parse_args(args):
    allowed = {"path", "mode", "offset", "key", "recurse", "write_values", "symbols_dir", "max_seconds", "limit", "max_records"}
    unknown = sorted(k for k in args if k not in allowed)
    if unknown:
        fail("unknown parameter; the parameters are %s" % ", ".join(sorted(allowed)), count=len(unknown))
    path = text_arg(args, "path")
    if not path:
        fail("path is required: the memory image whose registry hives are read")
    mode = args.get("mode", "hivelist")
    if mode not in MODES:
        fail("mode must be one of: %s" % ", ".join(MODES))
    offset = args.get("offset")
    if offset is not None:
        offset = parse_offset(offset)
        if offset is None:
            fail("offset must be an integer or 0x followed by hexadecimal digits: the offset of a hive in the hivelist")
    if mode == "printkey" and offset is None:
        fail("printkey needs offset: the offset of one hive, as hivelist lists it")
    if mode == "hivelist" and (offset is not None or args.get("key") is not None or args.get("recurse") is not None):
        fail("offset, key and recurse are read only in mode printkey")
    key = text_arg(args, "key") or ""
    recurse = args.get("recurse", False)
    write_values = args.get("write_values", False)
    for name, value in (("recurse", recurse), ("write_values", write_values)):
        if value is None:
            if name == "recurse":
                recurse = False
            else:
                write_values = False
        elif not isinstance(value, bool):
            fail("%s must be true or false" % name)
    symbols_dir = symbols_arg(args)
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds != seconds or not MIN_SECONDS <= seconds <= MAX_SECONDS:
        fail("max_seconds must be a number from %d to %d" % (MIN_SECONDS, MAX_SECONDS))
    limit = args.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        fail("limit must be an integer from 1 to %d" % MAX_LIMIT)
    records = args.get("max_records", DEFAULT_RECORDS)
    if isinstance(records, bool) or not isinstance(records, int) or not 1 <= records <= MAX_RECORDS:
        fail("max_records must be an integer from 1 to %d" % MAX_RECORDS)
    return {"path": path, "mode": mode, "offset": offset, "key": key, "recurse": bool(recurse), "write_values": bool(write_values),
            "symbols_dir": symbols_dir, "seconds": float(seconds), "limit": limit, "max_records": records}


# --- what is a credential ------------------------------------------------------------------------------------------------------------------

CRED_WORD = re.compile(r"(?i)password|passwd|pwd|passphrase|secret|credential|token|verifier|hash|ntlm|lsa|dpapi|masterkey|bootkey|syskey|"
                       r"private|api_?key|access_?key|auth_?key|cachedlogon|protectedstorage|wdigest|vault")
CRED_KEY = re.compile(r"(?i)^\\?(?:sam|security)(?:\\|$)|\\policy\\secrets|\\sam\\domains")
PLAIN_TYPES = ("REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ", "REG_DWORD", "REG_QWORD", "REG_DWORD_BIG_ENDIAN", "REG_LINK")
KNOWN_TYPES = PLAIN_TYPES + ("Key", "REG_BINARY", "REG_NONE", "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESCRIPTOR", "REG_RESOURCE_REQUIREMENTS_LIST")
TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:[+-]\d{2}:?\d{2}|Z| UTC)?")


def credential_hive(hive_path):
    """A hive path (\\REGISTRY\\MACHINE\\SAM, \\SystemRoot\\System32\\Config\\SECURITY) that is a credential-class hive. A hive whose path hivelist
    could not read (an empty path) is taken as credential-class too: nothing shows that it is not SAM or SECURITY."""
    if not hive_path.strip():
        return True
    return re.split(r"[\\/]", hive_path.strip())[-1].lower() in ("sam", "security")


ABSENT = ("", "-", "N/A", "Unreadable", "UnreadableValue", "<UnreadableValue>")   # UNVERIFIED: how the quick renderer prints an UnreadableValue is not confirmed


def shown_key(key):
    return "\\".join(str(shown(part, "name")) for part in key.split("\\"))


def withheld_value(length, why):
    return "<withheld %d characters: %s>" % (length, why)


# --- the plugins' output ---------------------------------------------------------------------------------------------------------------------

def columns(line_text, header):
    cols = line_text.split("\t")
    return {name: (cols[i].strip() if i < len(cols) else "") for name, i in header.items()}


def vol_offset(text):
    text = text.strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def read_hives(vol, p, plugin, deadline_cap):
    """hivelist: ({offset: path}, malformed lines, why it is not whole or None, the log)."""
    seconds = left(deadline_cap)
    if seconds < 1:
        return None, 0, "the call's clock had no time left for hivelist", None
    hives, state = {}, {"header": None, "bad": 0, "extra": 0}

    def row(line):
        text = line.decode("utf-8", "replace")
        if state["header"] is None:
            cols = text.split("\t")
            if any(c.strip() == "Offset" for c in cols):
                state["header"] = {c.strip(): i for i, c in enumerate(cols)}
            return
        if not text.strip():
            return
        c = columns(text, state["header"])
        offset = vol_offset(c.get("Offset", ""))
        if offset is None:
            state["bad"] += 1
        elif len(hives) >= MAX_HIVES:
            state["extra"] += 1
        else:
            hives[offset] = c.get("FileFullPath", "")

    out, log = Lines(row), Log()
    argv = [vol, "--offline", "-q"] + (["-s", argv_safe(p["symbols_dir"])] if p["symbols_dir"] else []) + ["-f", argv_safe(p["path"]), plugin]
    result = run_engine(argv, seconds, out, log, HIVELIST_CAP, ERR_SCAN_CAP)
    out.close()
    why = engine_failed(result, "hivelist")
    if why:
        return None, 0, why, log
    if result["code"] != 0:
        return None, 0, "hivelist exited with status %s%s" % (result["code"], ("; its log begins: " + " | ".join(log.quoted)) if log.quoted else ""), log
    if state["header"] is None:
        return None, 0, "hivelist printed no header line with an Offset column, so its output is not in the form this tool reads", log
    if out.skipped:
        return None, 0, "hivelist printed %d row(s) longer than %d bytes, which were not read" % (out.skipped, MAX_LINE), log
    return hives, state["bad"] + state["extra"], None, log


def main():
    GUARD["stopping"] = False
    STATE["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _hold_signal)
    p = parse_args(read_args())
    CLOCK["deadline"] = time.monotonic() + p["seconds"]
    secret_ok = False
    if p["write_values"]:
        # Values are written only to a sealed secret output: decided before anything is opened, listed or created.
        if job_dir() is None:
            fail("write_values writes withheld registry values to a file: it is refused outside a job, where the file would be an ordinary "
                 "one. Run this as job_run tool=mem_registry (its manifest makes the job secret output). Nothing was written and the image "
                 "was not read.", write_values="refused", written=False)
        if os.environ.get("SECRET_OUTPUT") != "1":
            fail("write_values is refused in a job that was not run as secret output: its file would be sealed as ordinary output. Run this "
                 "as job_run tool=mem_registry (its manifest makes the job secret output). Nothing was written and the image was not "
                 "read.", write_values="refused", written=False)
        secret_ok = True
    # A key under a credential-class root is refused before the image is looked at.
    if p["mode"] == "printkey" and CRED_KEY.search(p["key"]) and not secret_ok:
        fail("the key is under SAM, SECURITY, Policy\\Secrets or SAM\\Domains, where the registry holds credential material: ask for it with "
             "write_values: true, in a job run as secret output. Nothing was read or written.", key="refused", written=False)
    problem = image_problem(p["path"])
    if problem:
        fail("path is not a memory file to examine: " + problem)
    if p["symbols_dir"]:
        try:
            ok = stat.S_ISDIR(os.stat(p["symbols_dir"]).st_mode)
        except OSError:
            ok = False
        if not ok:
            fail("symbols_dir is not a directory")
    vol = find_vol()
    if vol is None:
        fail("there is no `vol` on PATH: Volatility is not installed here, and this tool reads the registry through it (vol_readiness says what is "
             "missing)")

    # 1. The plugins are the ones the installed Volatility lists.
    seconds = left(HELP_SECONDS)
    if seconds < 1:
        fail("the call's clock left no time to list the plugins")
    help_out, help_err = Collect(HELP_CAP), Log()
    result = run_engine([vol, "--offline", "--help"], seconds, help_out, help_err, HELP_CAP, ERR_SCAN_CAP)
    why = engine_failed(result, "`vol --offline --help`")
    if why or result["code"] != 0:
        fail(why or "`vol --offline --help` exited with status %s" % result["code"])
    text = help_out.text()
    names = parse_plugins(text)
    version = version_of(text) or help_err.version
    wanted = {"hivelist": "windows.registry.hivelist", "printkey": "windows.registry.printkey"}
    listed = {}
    for kind, module in wanted.items():
        found = [n for n in names if n == module or n.startswith(module + ".")]
        if found:
            listed[kind] = sorted(found)[0]
    for kind in ("hivelist", "printkey") if p["mode"] == "printkey" else ("hivelist",):
        if kind not in listed:
            fail("the installed Volatility does not list %s: this tool reads the registry through it and invents no plugin name" % wanted[kind],
                 plugins_listed=len(names))
    RESULTS["plugins"] = {"hivelist": listed.get("hivelist"), "printkey": listed.get("printkey"), "volatility": version}
    checkpoint()

    # 2. The hives.
    hives, malformed, why, log = read_hives(vol, p, listed["hivelist"], HIVELIST_SECONDS)
    if hives is None:
        fail("the hives could not be listed: " + why)
    version = version or log.version
    RESULTS["hivelist"] = {"hives_found": len(hives)}
    named = sum(1 for path in hives.values() if path)
    coverage = {"hives_found": len(hives), "hives_named": named, "hives_read": None, "pages_missing_lines": log.missing,
                "unreadable_rows": malformed}
    reasons = []
    if log.missing:
        reasons.append("the engine's log says %d time(s) that pages were missing (coverage.pages_missing_lines)" % log.missing)
    if named < len(hives):
        reasons.append("%d of %d hives have no readable name" % (len(hives) - named, len(hives)))
    if malformed:
        reasons.append("%d hivelist row(s) were not read (too many hives or an offset that is not one)" % malformed)
    if not hives:
        reasons.append("hivelist found no hive: the image may not be a Windows image Volatility can read, or its symbols are missing")

    plugin_used = listed["hivelist"] if p["mode"] == "hivelist" else listed["printkey"]
    out = {"parser": PARSER, "mode": p["mode"], "plugin": plugin_used, "volatility": version, "offline": True,
           "inputs": {"path": shown(p["path"], "path"), "symbols_dir": shown(p["symbols_dir"], "path") if p["symbols_dir"] else None}}
    secret = {"contains_secret_values": False, "values_written": 0, "values_file": None, "values_withheld": 0}

    if p["mode"] == "hivelist":
        page = LosslessPage("mem_registry_hives", {"path": p["path"], "mode": "hivelist", "hives": sorted(hives.items())}, p["limit"])
        for offset, hive_path in sorted(hives.items()):
            row = {"hive_offset": "0x%x" % offset, "hive_path": shown(hive_path, "path") if hive_path else None,
                   "credential_class": credential_hive(hive_path), "unnamed": not hive_path.strip(), "plugin": listed["hivelist"], "volatility": version}
            page.add(sealed(row))
        out["records"] = page.finish()
        out["records"]["rows"] = page.page
        coverage["hives_read"] = named
        coverage["note"] = "a hive counts as read when hivelist could name it; its keys are not read in this mode"
        out["coverage"] = coverage
    else:
        if p["offset"] not in hives:
            fail("offset is not the offset of a hive in this image's hivelist (hives_found %d); list them with mode hivelist" % len(hives),
                 hives_found=len(hives))
        hive_path = hives[p["offset"]]
        if credential_hive(hive_path) and not secret_ok:
            fail("the hive at that offset is a credential-class hive (SAM or SECURITY): ask for it with write_values: true, in a job run as "
                 "secret output. Nothing was read from it and nothing was written.", hive="refused", written=False)
        checkpoint()
        seconds = left(CLOCK["deadline"] - time.monotonic())
        if seconds < 2:
            fail("the call's clock left no time to read the key")
        counts = {"records": 0, "keys": 0, "values": 0, "withheld": 0, "binary": 0, "bad_rows": 0, "unreadable": 0, "stopped": None}
        state = {"header": None}
        page = LosslessPage("mem_registry_records", {"path": p["path"], "offset": p["offset"], "key": p["key"], "recurse": p["recurse"]}, p["limit"])
        sfile = SecretFile({"path": p["path"], "offset": p["offset"], "key": p["key"], "recurse": p["recurse"]}) if secret_ok else None
        SECRET["file"] = sfile
        cred_hive = credential_hive(hive_path)
        ended = {"stop": False}

        def row(line):
            text = line.decode("utf-8", "replace")
            if ended["stop"]:
                return
            if state["header"] is None:
                cols = text.split("\t")
                if any(c.strip() == "Hive Offset" for c in cols):
                    state["header"] = {c.strip(): i for i, c in enumerate(cols)}
                return
            if not text.strip():
                return
            c = columns(text, state["header"])
            rtype, key, name, data = c.get("Type", ""), c.get("Key", ""), c.get("Name", ""), c.get("Data", "")
            if not rtype or "Hive Offset" not in c:
                counts["bad_rows"] += 1
                return
            if counts["records"] >= p["max_records"]:
                counts["stopped"] = "max_records"
                ended["stop"] = True
                return
            counts["records"] += 1
            # Volatility 3 (printkey.py, 2.28.2) yields a placeholder row (an UnreadableValue in the name, type or data) for a key it could not find or a page it could not
            # read, and logs why at debug level only. How the quick renderer prints one is UNVERIFIED here; the cells of ABSENT are the guess.
            if (rtype == "Key" and name in ABSENT) or rtype in ABSENT or (rtype != "Key" and data in ABSENT[1:]):
                counts["unreadable"] += 1
            record = {"hive_offset": "0x%x" % p["offset"], "type": rtype if rtype in KNOWN_TYPES else "other", "key": shown_key(key),
                      "name": shown(name, "name") if name and name != "-" else None,
                      "last_write": c.get("Last Write Time") if TIME_RE.fullmatch(c.get("Last Write Time", "")) else shown(c.get("Last Write Time", ""), "name"),
                      "volatile": c.get("Volatile") or None, "plugin": listed["printkey"], "volatility": version}
            if rtype == "Key":
                counts["keys"] += 1
            else:
                counts["values"] += 1
                if cred_hive or CRED_KEY.search(key) or CRED_WORD.search(key) or CRED_WORD.search(name):
                    record["data_state"] = "withheld_credential"
                    record["data"] = withheld_value(len(data), "the key or value is named for a credential")
                    counts["withheld"] += 1
                    if sfile is not None:
                        sfile.add({"record": counts["records"], "hive_offset": record["hive_offset"], "key": key, "name": name, "type": rtype, "data": data})
                elif rtype in PLAIN_TYPES:
                    record["data_state"] = "shown"
                    record["data"] = shown(data, "text")
                else:
                    record["data_state"] = "not_printed"
                    record["data"] = withheld_value(len(data), "a value of type %s is not printed" % record["type"])
                    counts["binary"] += 1
            page.add(sealed(record))

        out_sink, log2 = Lines(row), Log()
        key_args = ["--key=" + p["key"]] if p["key"] else []
        argv = [vol, "--offline", "-q"] + (["-s", argv_safe(p["symbols_dir"])] if p["symbols_dir"] else []) + [
            "-f", argv_safe(p["path"]), listed["printkey"], "--offset=0x%x" % p["offset"]] + key_args + (["--recurse"] if p["recurse"] else [])
        result = run_engine(argv, seconds, out_sink, log2, ROWS_CAP, ERR_SCAN_CAP, stop=lambda: ended["stop"])
        out_sink.close()
        why = engine_failed(result, "printkey")
        if why:
            reasons.append(why + " (the records read so far are kept)")
        elif result["state"] == "stopped":
            pass                              # max_records: said below
        elif result["code"] != 0:
            drop_secret()
            fail("printkey exited with status %s%s" % (result["code"], ("; its log begins: " + " | ".join(log2.quoted)) if log2.quoted else ""))
        elif state["header"] is None:
            drop_secret()
            fail("printkey printed no header line with a Hive Offset column, so its output is not in the form this tool reads%s" % (
                ("; its log begins: " + " | ".join(log2.quoted)) if log2.quoted else ""))
        if out_sink.skipped:
            reasons.append("%d printkey row(s) longer than %d bytes were not read" % (out_sink.skipped, MAX_LINE))
        if counts["stopped"]:
            reasons.append("the read ended at max_records (%d); narrow key or raise it" % p["max_records"])
        if counts["bad_rows"]:
            reasons.append("%d printkey row(s) were not in the form this tool reads" % counts["bad_rows"])
        if log2.missing:
            reasons.append("the engine's log says %d time(s) that pages were missing (coverage.pages_missing_lines)" % log2.missing)
            coverage["pages_missing_lines"] += log2.missing
            coverage["pages_missing_quoted"] = log2.quoted
        if counts["unreadable"]:
            reasons.append("%d record(s) are placeholders for a key not found or a page not readable (coverage.records.unreadable; Volatility logs why at debug level only)" % counts["unreadable"])
        coverage["hives_read"] = 1 if counts["records"] - counts["unreadable"] > 0 else 0
        if not counts["records"] and not why:
            reasons.append("printkey printed no record: the key may not exist in this hive, or its pages were not readable")
        coverage["note"] = "one hive was asked for; hives_read is 1 when it gave a record"
        coverage["records"] = {k: counts[k] for k in ("records", "keys", "values", "withheld", "binary", "bad_rows", "unreadable")}
        out["coverage"] = coverage
        out["records"] = page.finish()
        out["records"]["rows"] = page.page
        written = sfile.finish() if sfile is not None else None
        secret = {"contains_secret_values": bool(sfile is not None and sfile.count), "values_written": sfile.count if sfile is not None else 0,
                  "values_file": written, "values_withheld": counts["withheld"],
                  "note": ("withheld values were written to values_file, unjudged, mode 0600" if written else
                           "withheld values were not written anywhere: ask with write_values: true, in a job run as secret output" if counts["withheld"] else None)}
    out["secret_values"] = secret
    out["notes"] = ["Every Volatility call is made with --offline. Key names and values come from the capture and were judged by the shared SHOWN "
                    "rules; withholding is by shape, so a plain password or a name under 16 characters is printed.",
                    "A value under a credential-named key or value name is withheld by that name, not by what it holds: a secret under an "
                    "innocent name is printed if it does not look like one.",
                    "Not run against the real Volatility here: the columns of hivelist and printkey were read from the 2.28.2 source; how the quick renderer prints an "
                    "unreadable cell, and the wording of the engine's log lines that coverage.pages_missing_lines counts, are UNVERIFIED."]
    notes = process_notes()
    if notes:
        out["process_notes"] = notes
    if reasons:
        out["status"] = "partial"
        out["status_basis"] = "; ".join(reasons)
    else:
        out["status"] = "complete"
        out["status_basis"] = ("every hive Volatility found was named and the key asked for was read to its end with no missing page reported" if
                               p["mode"] == "printkey" else "every hive Volatility found was named; no keys were read in this mode")
    out = sealed(out)
    out["boundary"] = boundary_summary()
    if BOUNDARY["backstop_replaced"]:
        out["status"] = "partial"
        out["status_basis"] += "; the backstop replaced %d string(s) it found secret-shaped (boundary)" % BOUNDARY["backstop_replaced"]
    emit(out)


def run_guarded():
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        kill_all()
        drop_secret()
        fail("unexpected failure: %s: %s" % (type(exc).__name__, exc))


if __name__ == "__main__":
    code = 0
    try:
        run_guarded()
    except SystemExit as exit_:
        code = exit_.code if isinstance(exit_.code, int) else (0 if exit_.code is None else 1)
    # The answer is out and flushed. Leave here and not through the interpreter's own shutdown, which puts every signal's default action
    # back before it is over: a stop that arrived in that time ended the process by the signal although the one document had been written.
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except (OSError, ValueError):
        pass
    os._exit(code)
