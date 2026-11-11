#!/usr/bin/env python3
"""Inventory the virtual machines, disks, snapshots and datastores that configuration files and inventory exports name.

The inputs read, from their public descriptions, and no others (a file of any other kind is counted, and a product's
file this tool recognises and does not read is listed as unsupported, never guessed at):

    VMware    .vmx (the VM's configuration: its name, guest OS, hardware version, devices and the disk files it names),
              .vmsd (the snapshot database), and ESXi's vmInventory.xml (the registered VMs' configuration paths)
    libvirt   a domain XML (<domain>: devices, disks with their backing stores), a domain snapshot XML (<domainsnapshot>)
              and a storage pool XML (<pool>)
    Proxmox   a VM or container configuration (/etc/pve/qemu-server/<id>.conf, /etc/pve/lxc/<id>.conf, with its snapshot
              sections; a [special:...] section such as the cloud-init settings is listed as special, not as a snapshot)
              and storage.cfg

What it is and is not. It lists what the files say exist, with the file and the line or element each statement came from.
A configuration that names a VM does not show the VM ran, exists on a host now, or was not deleted; a disk it names is
checked only against the files given, and "not in the set" is a statement about the set. Hyper-V (.vmcx, .vmrs),
VirtualBox (.vbox) and OVF are recognised by name or root element and are not read. The keys of a configuration that this
tool shows are the ones listed in the manifest; every other key is counted, and the names of those that look like
credentials are listed (never their values), so a reader knows a secret sits at that line.

SENSITIVE OUTPUT. A configuration can hold a console password, a cloud-init password, an SSH key or a user-data blob
under a key this tool does not show. Names, paths and values it does show pass the shape check of the shared block
(a token-shaped run or user-info is withheld; a long text is shown cut with its whole length); the original goes to one
private file only when write_text is asked for, in a job. XML files are read with entity declarations refused and the
element count and depth bounded. A credential-like key is named in every section it sits in (a snapshot keeps its own
copy of the settings), and credential-like attributes are named to a cap and counted past it. Every key and value of the
answer and of its paging files passes the one way out (SHARED BOUNDARY), which withholds by shape again and checks what it
wrote; a piece of a path (a datastore, a node, a storage name) is taken from the path after the whole was withheld.
"""
import collections
import datetime
import errno
import itertools
import json
import math
import os
import posixpath
import re
import secrets
import signal
import stat
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

TOOL = "virtualization_inventory"
PARSER = "virtualization_inventory/2"
DEFAULT_LIMIT = 200
DEFAULT_SECONDS = 50.0          # the manifest allows 60
MAX_SECONDS = 50.0
DEFAULT_MAX_FILE = 16 << 20
MAX_XML_ELEMENTS = 100000
MAX_XML_DEPTH = 64
MAX_LINE = 1 << 16
MAX_LINES = 500000
MAX_RECORDS_PER_FILE = 100000
MAX_NAMED_KEYS = 200

VMX_SHOWN = ("displayname", "guestos", "config.version", "virtualhw.version", "uuid.bios", "uuid.location", "vc.uuid", "memsize", "numvcpus",
             "cpuid.corespersocket", "nvram", "firmware", "vmx.hypervisor", "annotation.present")
VMX_ETHERNET = re.compile(r"^ethernet\d+\.(address|generatedaddress|networkname|virtualdev|present|addresstype)$", re.I)
VMX_DEVICE = re.compile(r"^((?:scsi|ide|sata|nvme)\d+:\d+)\.(\w+)$", re.I)
VMX_DEVICE_SHOWN = ("filename", "present", "devicetype", "mode", "redo", "writethrough", "sharing", "persistent")
SENSITIVE_KEY = re.compile(r"(?<![a-z])(pass(word|wd|phrase)?|secret|token|auth|cred(ential)?s?|userdata|user-data|cipassword|sshkeys?|encryption|vnc|(private|api|access|secret|ssh|license|licence)[-_.]?keys?)(?![a-z])", re.I)
UNSUPPORTED_NAMES = {".vmcx": "Hyper-V virtual machine configuration (binary)", ".vmrs": "Hyper-V runtime state", ".vmgs": "Hyper-V guest state",
                     ".vbox": "VirtualBox machine settings", ".vbox-prev": "VirtualBox machine settings (previous)", ".ovf": "OVF descriptor",
                     ".ova": "OVA archive", ".vmtx": "VMware template configuration", ".vmxf": "VMware team file", ".vmss": "VMware suspended state",
                     ".vmsn": "VMware snapshot state", ".utf16xml": "XML in a UTF-16 or UTF-32 encoding (not read)"}

# A value that is a number, a UUID or a run of hex bytes is shown as it is; anything else that comes from the evidence goes through the shape check.
SAFE_VALUE = re.compile(r"[0-9]{1,12}|[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}[ -]){3,31}[0-9A-Fa-f]{2}")
# Keys whose values the tool built itself (identifiers, constants, derived times), never the evidence's text.
TOOL_BUILT = {"id", "source_id", "vm", "found", "how", "in_set", "in_set_note", "role", "format", "locator", "note", "credential_note", "time_utc", "time_basis", "node_basis",
              "kind", "layer", "keys_not_shown", "credential_like_keys_total", "description_present", "pending_section_present",
              "comment_lines_not_shown", "configuration_in_set", "index", "line", "element", "first_line", "value_chars"}

VOCABULARY = frozenset()     # words the way out shows as they are (see SHARED BOUNDARY): none here

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
# BEGIN SHARED COMMON
# The same text is in virtualization_inventory, snapshot_chain_check and backup_audit_normalise (a tool is standalone, none
# imports another); tests/pack-virtualization-shared.test.ts holds the copies equal. Arguments, the status every answer
# carries, lossless paging, and the one place a withheld text is kept when, and only when, it was asked for.


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def describe(exc):
    """An exception as text for an answer: its type and errno name, and its message withheld by shape (the way out's whole
    rules, so that nothing they would take is split first), never cut."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return seal_head("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)), "text")


PAGING_OPEN = []        # the paging files being written (LosslessPage objects with a temporary file open)


def paging_left():
    """Close the paging files a stop leaves open and keep what they hold under a name that says so (`<name>.partial`): their
    rows were sealed as they were written. The names, as the answer shows them."""
    left = []
    for page in list(PAGING_OPEN):
        try:
            shown = page.abandon()
        except Exception:  # noqa: BLE001 - one file that cannot be closed must not hide the others
            shown = None
        if shown:
            left.append(shown)
    return left


def fail(message, **extra):
    """An error answer: JSON, exit 1, the same `status` every answer of this pack carries, through the one way out."""
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})     # one document: the stop handlers may not be in yet (a refusal can come before main() installs them), and one that is in would write a second, false, document after this one; a stop that arrives while this is written waits, and the tool leaves with it
    left = paging_left()
    if left:
        extra["paging_files_left"] = left
        extra["paging_files_note"] = "the rows written before the stop, sealed as they were written, kept under the name that says so"
    print(answer_text({"error": message, "tool": TOOL, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


def stop_word(signum):
    """The tool's last word when SIGTERM, SIGINT or SIGHUP ends it: one JSON answer through the one way out, naming the signal
    and any paging file it leaves. If the answer cannot be made (the signal came in the middle of the way out itself), a short
    one that says so."""
    name = {signal.SIGTERM: "SIGTERM", signal.SIGINT: "SIGINT", signal.SIGHUP: "SIGHUP"}.get(signum, "signal %d" % signum)
    left = []
    try:
        left = paging_left()
        print(answer_text({"tool": TOOL, "parser": PARSER, "status": "partial",
                           "status_basis": "the tool was stopped by %s before it finished: nothing after the stop was read or written" % name,
                           "stopped_by_signal": name, "paging_files_left": left,
                           "paging_files_note": "the rows written before the stop, sealed as they were written, kept under the name that says so" if left else "no paging file was open"}))
    except BaseException as exc:  # noqa: BLE001 - the last word is best effort, and never silent
        print(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "stopped_by_signal": name, "paging_files_left": left,
                          "status_basis": "the tool was stopped by %s; the full last word could not be made (%s)" % (name, type(exc).__name__)}))
    sys.stdout.flush()                      # the caller leaves with os._exit, which flushes nothing


def install_stop_handlers():
    """SIGTERM, SIGINT and SIGHUP: the last word, then exit 128 plus the signal number (snapshot_chain_check, which runs a program,
    gives its last word to the process block's handler instead)."""
    def on_signal(signum, _frame):
        try:
            stop_word(signum)
        except BaseException:  # noqa: BLE001 - a last word is best effort
            pass
        os._exit(128 + signum)
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, on_signal)


def read_args():
    try:
        raw = sys.stdin.buffer.read(8 << 20 | 1)
        if len(raw) > 8 << 20:
            fail("arguments are larger than 8 MiB: pass a list of files, not their contents")
        args = json.loads(raw.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError) as exc:
        fail("arguments are not valid JSON", reason=describe(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


MAX_ARG_STRING = 8192


def want_str(args, key, required=None, maximum=MAX_ARG_STRING):
    value = args.get(key)
    if value is None:
        if required:
            fail(required)
        return None
    if not isinstance(value, str):
        fail("%s must be a string" % key)
    if required and not value:
        fail(required)
    if len(value) > maximum:
        fail("%s is longer than %d characters" % (key, maximum))
    return value


def want_str_list(args, key, maximum=100000):
    value = args.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) and x and len(x) <= MAX_ARG_STRING for x in value):
        fail("%s must be a list of non-empty strings of at most %d characters" % (key, MAX_ARG_STRING))
    if len(value) > maximum:
        fail("%s holds more than %d entries: pass a directory as root instead" % (key, maximum))
    return value


def want_flag(args, key):
    value = args.get(key, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_int(args, key, default, minimum, maximum):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        fail("%s must be an integer from %d to %d" % (key, minimum, maximum))
    return value


def want_seconds(args, key, default, maximum):
    """A time budget: a finite number above zero and no more than `maximum` (NaN and Infinity are not budgets)."""
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 or value > maximum:
        fail("%s must be a number of seconds above 0 and at most %d" % (key, maximum))
    return float(value)


def status_of(complete, failed, basis_complete, basis_partial, basis_failed):
    """The `status` every answer of this pack carries, with the reason for it: complete (everything the request asked
    for was read and nothing was left out), partial (some of it was, and the answer names what was not) or failed."""
    if failed:
        return {"status": "failed", "status_basis": basis_failed}
    if complete:
        return {"status": "complete", "status_basis": basis_complete}
    return {"status": "partial", "status_basis": basis_partial}


class Overtime(Exception):
    pass


class Clock:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds
        self.count = 0

    def check(self, every=1):
        self.count += 1
        if self.count % every == 0 and time.monotonic() > self.deadline:
            raise Overtime()

    def left(self):
        return max(0.0, self.deadline - time.monotonic())


def blen(text):
    return len(text.encode("utf-8", "surrogatepass"))


def decode(data):
    """Bytes as text with no byte lost: an undecodable byte is a lone surrogate, which a JSON escape writes and which
    encodes back to the byte."""
    return data.decode("utf-8", "surrogateescape")


# Lossless paging: the page an agent reads stays small, and when there are more rows the whole result is written as JSON
# Lines under work/<agent>/tool-output (in a job, $OUT/tool-output) and named. The file name is random: it is never a
# digest of anything asked for (sixteen decimal digits), and the way out shows this exact name, registered here, as it is. Every row is sealed
# (the one way out, below) as it is written. A write that fails is an error answer naming the file, never a loss that
# goes unsaid.
# The rows an answer shows inline are cut by size as well as by count: the answer is judged, serialised and read back within
# the run's clock, and a `limit` of 100000 over rows of a few hundred bytes would make that take longer than max_seconds
# (and leave the answer without its keys). The cut is lossless: every row is in the paging file, named by all_results.
INLINE_BYTES = 1 << 19


class LosslessPage:
    def __init__(self, tool, key, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.key = re.sub(r"[^A-Za-z0-9_.-]", "_", key)
        self.limit = limit
        self.page = []
        self.page_bytes = 0
        self.total = 0
        self._out = None
        self._tmp = None
        name = "%s-%s-%016d.jsonl" % (self.tool, self.key, secrets.randbelow(10 ** 16))
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        OWN_NAMES.update((self.shown, str(self.path)))     # this exact name, and no other of its shape, is shown as it is

    def _write(self, row):
        line = row_text(row, "pages/%s/all_results" % self.key)
        try:
            self._out.write(line)
            self._out.write("\n")
        except OSError as exc:
            fail("the whole result could not be written: %s" % describe(exc), paging_file=str(self.path))

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit and self.page_bytes < INLINE_BYTES:
            self.page.append(row)
            self.page_bytes += len(repr(row))
            return
        if self._out is None:
            stops = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
            was = signal.pthread_sigmask(signal.SIG_BLOCK, stops)       # a stop must not come between the file and its registration
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="ascii", errors="backslashreplace")
                PAGING_OPEN.append(self)
            except OSError as exc:
                signal.pthread_sigmask(signal.SIG_SETMASK, was)
                fail("the whole result could not be written: the paging file cannot be created (%s)" % describe(exc), paging_file=str(self.path))
            signal.pthread_sigmask(signal.SIG_SETMASK, was)
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def abandon(self):
        """A stop with the file open: the rows written so far are kept as `<name>.partial`; the name as the answer shows it."""
        if self._out is None or self._tmp is None:
            return None
        keep = self.path.with_name(self.path.name + ".partial")
        try:
            os.replace(self._tmp, keep)         # the name first: it is atomic and touches no file object
        except OSError:
            return None
        try:
            self._out.flush()
            self._out.close()
        except (OSError, RuntimeError, ValueError):
            pass                                # a write was in progress when the signal came in: what the system already holds is kept
        self._out = None
        if self in PAGING_OPEN:
            PAGING_OPEN.remove(self)
        OWN_NAMES.update((self.shown + ".partial", str(keep)))
        return self.shown + ".partial"

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.total > len(self.page) and len(self.page) < self.limit:
            result["inline_cut_by_size"] = "the rows shown inline stop at about %d bytes whatever limit says; the whole list is in all_results" % INLINE_BYTES
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                os.replace(self._tmp, self.path)
                if self in PAGING_OPEN:
                    PAGING_OPEN.remove(self)
            except OSError as exc:
                fail("the whole result could not be written: %s" % describe(exc), paging_file=str(self.path))
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete row per line"
        return result


class TextRefused(Exception):
    pass


class TextFile:
    """Where the original of a withheld or shortened text goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan's SecretValues, for rows. With `enabled` false it writes
    nothing and `summary()` says so. Enabled, it is refused outside a job; inside one the file is created before
    anything is read (mode 0600, exclusively: a file or a link already at that name is refused by name) under $OUT, and
    the answer names it and says it may hold secrets. A job that was not run as secret output (the harness gives its process
    SECRET_OUTPUT=1 when it was) is refused too: the file would be sealed as an ordinary output. With nothing to keep it stays an empty file and says written: 0.
    """

    def __init__(self, name, enabled, what, flag="write_text"):
        self.enabled = enabled
        self.written = 0
        self.what = what
        self.flag = flag
        self._fh = None
        self.path = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise TextRefused("%s is refused outside a job: the originals written here would be an ordinary file, not a "
                              "sealed output. Run this as job_run tool=%s with secret_output: true, and ask again there. "
                              "Nothing was written." % (flag, TOOL))
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise TextRefused("%s is refused in a job that was not run as secret output: the originals would be sealed as ordinary "
                              "output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. Run this as "
                              "job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, TOOL))
        self.path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        OWN_NAMES.update((self.shown, str(self.path)))
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise TextRefused("the values file already exists: %s" % name)
        except OSError as exc:
            raise TextRefused("the values file could not be created (%s)" % describe(exc))
        self._fh = os.fdopen(fd, "wb")

    def add(self, row):
        if self._fh is None:
            return
        try:
            self._fh.write(json.dumps(row, default=str).encode("ascii") + b"\n")
        except OSError as exc:
            fail("the values file could not be written (%s)" % describe(exc))
        self.written += 1

    def close(self):
        if self._fh is not None:
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()
            except OSError as exc:
                fail("the values file could not be closed (%s)" % describe(exc))
            self._fh = None

    def summary(self):
        if not self.enabled:
            return {"requested": False, "written": 0, "file": None, "contains_text_that_may_hold_secrets": False,
                    "hint": "Nothing withheld or shortened is kept. %s: true, in a job run with secret_output: true, keeps the "
                            "original of each in a private file under $OUT." % self.flag}
        return {"requested": True, "written": self.written, "file": self.shown,
                "contains_text_that_may_hold_secrets": self.written > 0, "format": self.what}


class Shown(str):
    """A string that has been through the shape check: it is not checked again."""
    judged = True


# An open-ended authority or name:secret run at the point where a long text was cut might have its user-info separator beyond
# the cut, and a run of name characters the cut ends might be the head of a token: each is withheld whole.
_OPEN_AUTHORITY = re.compile(r"(?<=//)[^/?#\s]*$")
_OPEN_BARE = re.compile(r"[^\s/@:<>]{1,64}:[^\s/@<>]*$")
_RUN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+%/=.:@-")


def cut_safely(text, limit):
    """`text` cut to at most `limit` characters (plus a marker), never leaving the head of a run the cut split: a text
    is withheld by shape BEFORE it is cut, and what the cut leaves open is withheld whole, not shown in part."""
    if len(text) <= limit:
        return text
    head = text[:limit]
    if limit > 0 and text[limit] in _RUN_CHARS and head[-1] in _RUN_CHARS:      # the cut fell inside a run: the run's head is withheld whole
        start = limit
        while start > 0 and head[start - 1] in _RUN_CHARS:
            start -= 1
        head = head[:start] + _withheld("open run at a cut", limit - start, "cut")
    head = _OPEN_AUTHORITY.sub(lambda m: _withheld("userinfo", len(m.group()), "text"), head)
    return _OPEN_BARE.sub(lambda m: _withheld("userinfo", len(m.group()), "text"), head)


def brief(text, limit=300):
    """A message from a library or a program, withheld by shape whole and then cut safely: never cut first."""
    return cut_safely(seal_head(text if isinstance(text, str) else str(text), "text"), limit)


class Shower:
    """Every string the answer shows a name, a path or a value of passes through here: token-shaped runs and user-info are
    withheld, a text over `limit` characters is shown cut with its whole length, and the original of what was changed goes
    to the values file when one was asked for (never anywhere else). Only the first EXAMINED characters of a long text are
    checked (the check is not linear in the length of an adversary's text): a run of name characters, an authority or a
    name:secret run that the EXAMINED cut leaves open is withheld whole before the shape check, so that no fragment of a
    token the cut split can be shown; the check runs on the whole examined text, and the shorter cut to `limit` comes
    after it and leaves no run open either."""

    EXAMINED = 4096

    def __init__(self, values, limit=512):
        self.values = values
        self.limit = limit
        self.changed = 0
        self.cut = 0

    def __call__(self, text, where=None, field=None):
        if text is None:
            return None
        if not isinstance(text, str):
            text = str(text)
        total = len(text)
        head = text
        if total > self.EXAMINED:
            head = cut_safely(text, self.EXAMINED)
        RUN["record"] = False                      # this call records the original itself
        try:
            shown = seal_text(head, "text", field, where)
        finally:
            RUN["record"] = True
        was_cut = total > self.EXAMINED
        if len(shown) > self.limit:
            shown = cut_safely(shown, self.limit)
            was_cut = True
        if was_cut:
            shown += "...(whole text: %d characters)" % total
            self.cut += 1
        if shown != text:
            self.changed += 1
            if self.values.enabled:
                self.values.add({"record_type": "original", "where": where, "field": field, "value": text})
        return Shown(shown)


def withheld_summary(shower):
    return {"strings_withheld_by_shape": dict(COUNTS), "strings_changed": shower.changed, "strings_shortened": shower.cut,
            "note": ("Names, paths and values the answer shows are checked by shape: a token-shaped run, user-info in a URL and a key "
                     "are withheld, and a string over %d characters is shown cut with its whole length. A secret that does not look "
                     "like a token (a short password in a name) is not recognised, so run the tool as a job with secret_output: true.") % shower.limit}
# END SHARED COMMON
# The stop handlers are in as soon as the module has run this far, not when main() starts: a signal from here on gives the
# last word and exit 128 plus the signal number. What stays open is the start of the interpreter and the compiling of this file.
install_stop_handlers()


# BEGIN SHARED BOUNDARY
# BOUNDARY v2, the one text: the same text is in every tool that prints names, paths, event data, registry data, identifiers or table
# cells from evidence (tests/pack-boundary-shared.test.ts finds every copy under packs/ and tool-library/ and holds them equal: one variant, 16 carriers).
# It is the owner-approved HYBRID design: an allow-list for
# identifier-shaped fields, a deny-list for free text, and an independent backstop on the way out.
#
# Names defined here start with _b_ or _B_ where another shared block of a tool could define the same name (the WITHHOLDING block has _withheld and _USERINFO).
# THE CALLS A TOOL MAKES, and what the virtualization block called each (the three virtualization tools moved onto this text; the table is what they map to):
#   FIELDS, KEY_KINDS, bind_fields(table, key_kinds)           the table of field kinds, which the CALLER passes in (this text holds no tool's table);
#                                                              it was _FIELDS, _INHERIT and field_kind(); a digit run in a field name stands for any number
#                                                              (`ethernet#.address`), and a field the table does not list has the kind of the field above it
#   T(kind, text), show(s, kind, field)                        one string judged by its kind                         (the Shower, boundary_text, seal_text, seal_head)
#   sealed_text(text, kind, field), print_order(items, ...)    what an answer prints for a string; nothing counted    (seal_text without the count)
#   bind_values(enabled, tool), close_values(), values_summary()  the values file of a secret_output job            (bind_run(values, seconds))
#   seal_stop_after(seconds)                                   the clock: nothing is judged after it                  (bind_run's seconds, RUN["deadline"])
#   row_object(row)                                            one row of a paging file                               (row_text(row, where))
#   answer_object(doc), emit(doc)                              an answer, sealed and read back                        (answer_text(doc), backstop(value, where))
#   boundary_summary()                                         the "boundary" object; stopped_by is in it when judging stopped
#   OWN_NAMES                                                  the exact strings the run made and shows as they are   (OWN_NAMES)
# The kinds of a field: text (the default), name, path, key, url, host, hex, id (one of several forms of identifier: a GUID, a VMFS volume id, a device id, a VMware uuid, a MAC, a content id of 32 hexadecimal digits or a number; else a name), and the typed ones guid, digest, sid, mac, ip, time, number, version
# and, for virtualized storage and machines, vmfs (a VMFS volume id), device (naa., eui., wwn-0x, vml. and t10. ids), iqn, vmuuid (the VMware
# uuid of a machine), cid (a disk's content id), winhost (the name Windows gives a machine nobody named).
#
# LAYER 1, an allow-list per field type. A string the evidence supplied is shown as it is only when it fits the plain grammar of the
# type of the field it fills: a name (registry key and value names, event field names, provider and channel names, table and column
# names), a path (file names and paths, a registry path, a URL path), a key, a URL, or a typed id (GUID, SID, MAC, IP address, digest,
# time, number, version). The grammar is: letters of any script, digits, space and `_ - . $ @ ? : ~ + , # ( ) [ ] { } ' < > *`, at
# most 128 characters a component, no user-info shape (a `:` before an `@`), and no chain of 16 or more characters made of
# random-looking pieces (pieces that break into one- and two-character parts, flip between letters and digits, or are letters with
# no pronounceable word in them; a 16-hex id, a GUID or a number up to 18 digits is plain). Below 16 characters a chain is shown
# whatever it looks like: a short random password in a name is not recognised. A path is judged component by component and only the
# offending span is replaced; a string with a format, control or combining character is withheld whole.
#
# LAYER 2, for every kind, and it reads the string FIRST, as the evidence wrote it (the deny-list and the grammar cut spans out of a string
# and take with them the context these rules need: the user of `user:password@host`, the characters glued before `glpat-`): user-info up
# to the last `@` before the host (the password may hold a `/`, not a port); the value after a secret's name (password, secret, token,
# api/access/account/private key, credential, auth) found anywhere, up to a space or quote, and past a `& ; ,` that no `name=` follows;
# a PEM private key; a vendor token with its own prefix (AKIA, gh?_, github_pat_, xox?-, glpat-, sk_live_, SG., AIza, npm_, dop_v1_,
# ya29., sk-, JWT) in any case; a base64 key with its padding; and the same rules on a copy with invisible characters taken out and NFKC
# applied (a hit withholds the whole string). FREE TEXT (event data, messages, command lines, registry data strings, table cells) is on
# the deny-list: the same chain test applied to the text with its typed ids (GUID, SID, IP address, time, labelled digest, number) left
# alone, plus layer 2, and no character grammar.
#
# LAYER 3, the backstop, written apart from the layers above: every key and value of what is about to be written is read once more
# by its own normaliser and patterns (a PEM marker, a named secret, a run of 19 or more digits, a token prefix in any case, user-info, a
# run of 40 or more hex digits outside a typed field, a base64 run, a run that changes class as random text does; a typed field must hold
# the characters of its type; data written as hexadecimal is decoded and its printable text is read as text). It reads the shown string
# AND the original: a window of 12 characters of anything it calls secret in the original that is still in the shown string means the
# layers above left a piece of a secret between two cuts. A string it finds suspect is replaced by <withheld N bytes: backstop: why>,
# counted, its place named in boundary.replaced_at (built from the keys on the way as they are SHOWN, or their positions), and the
# answer is partial. A placeholder is only a placeholder when its reason is one of the fixed list. The names of the components of the Windows
# component store (WinSxS: lower case, a public key token, a language or `none`, a hash) are not judged by the backstop in a name or key slot:
# a real SOFTWARE hive lists them by the thousand and their hash looked random to it; layer 1 judges them as it does every name.
#
# ONE WAY OUT: emit() writes an answer, row_object() makes a row of a paging file, and both seal every key and value first (a value that is not
# a string, a number or a container is sealed as the text str() makes of it). Binary data written as hex (a REG_BINARY value, an ESE
# binary column) is decoded and its printable views (Latin-1, UTF-16LE and UTF-16BE, and runs holding full-width characters read as UTF-8 and UTF-16LE with
# the width folded) are judged by the free-text rules, by both layers and the
# backstop; hex that holds a secret-shaped text is withheld, and any other hex is shown (random bytes with no text in them are printed).
# What is withheld is a placeholder with its length and the reason; its original goes to the values file only when write_values was
# asked for in a job run as secret output. A list of names is printed in the order of the text shown for each, the placeholders of
# withheld names in a random order that is new every run (print_order); a `contains` filter is applied to the text the answer PRINTS (the
# string after the layers and the backstop, sealed_text), never to what is withheld or replaced, and contains_check says when the needle
# could have been in what is hidden. Every string is judged in linear time (a string is read to 256 KiB, the pieces the backstop compares
# are at most 64, a PEM body at most 20,000 characters), and an answer or a row that takes longer than SEAL_BUDGET seconds to seal, or that is
# still being sealed at the seal stop of the tool (seal_stop_after: a point in time after which nothing is judged, not a stop of the tool's own
# work, which has its own clock), has the rest of its strings replaced whole (<withheld N bytes: backstop: the judging time ran out>) and is
# partial; what stays readable past that point is the names the tool made itself (OWN_NAMES) and strings of 15 characters or fewer of letters,
# digits, `_` and `.` that do not start like a vendor token (and, in a field of a typed kind, fit the grammar of its type). The seal stop is 3.5 seconds before the
# tool's time limit: the string in progress finishes after it, and one string of 256 KiB takes up to 2.3 seconds to judge on a loaded machine (the worst measured).
# A run has a second bound: past MAX_JUDGED_CHARS characters judged (the final answer is always judged), a string not judged before is withheld by its size in the
# same way. boundary.stopped_by says which bound stopped the judging and boundary.strings_withheld_by_the_stop how many strings it withheld; the answer is partial.
# NOT RECOGNISED, by design: a secret that does not look like one (a plain password, a pronounceable passphrase, a UUID-shaped key,
# anything under 16 characters in a name, a secret hidden in words or in an encoding this block does not read).
import collections
import hashlib
import signal
import time
import unicodedata

LMIN = 16
MAX_ONE_STRING = 1 << 18
MAX_HEX_JUDGED = 1 << 20
MAX_PIECES = 64                 # the pieces of a string the backstop compares with what was shown (it stops collecting at this many)
MAX_PEM_BODY = 20000            # a PEM body is read to this many characters (a 16,384-bit RSA key is about 13,000)
SEAL_BUDGET = 10.0              # seconds one answer, or one row of a paging file, may take to be sealed; a tool may set another
_CLOCK = {"deadline": None, "stop": None}
_BIGRAMS_TEXT = "aaabacadaeafagahaiajakalamanaoapaqarasatauavawaxayazbabbbcbdbebfbhbibjblbmbnbobpbrbsbtbubvbycacbcccdcecfchcickclcncocqcrcsctcucydadbdcdddedfdgdhdidjdldmdndodpdrdsdtdudvdwdyeaebecedeeefegeheiejekelemeneoepeqereseteuevewexeyezfafbfcfdfefffiflfofrftfufygagbgdgegfggghgiglgmgngogrgsgtgugwgyhahbhchdhehfhhhihlhmhnhohphrhshthuhwhyiaibicidieifigihiiijikiliminioipiqirisitiuiviwixizjajejijojukakbkekfkhkikkklkmknkokpkrksktkukwkylalblcldlelflglhlilklllmlnlolplrlsltlulvlwlymambmemfmimlmmmnmompmrmsmumwmynanbncndnenfngnhninjnknlnmnnnonpnqnrnsntnunvnwnxnynzoaobocodoeofogohoiojokolomonooopoqorosotouovowoxoyozpapbpcpepfphpiplpmpnpoppprpsptpupwpyqurarbrcrdrerfrgrhrirjrkrlrmrnrorprqrrrsrtrurvrwryrzsasbscsdsesfsgshsiskslsmsnsospsqsrssstsusvswsytatbtctdtetftgthtitltmtntotptrtstttutvtwtytzuaubucudueufuguhuiukulumunuoupurusutuvuxuyuzvavevivovuvywawbwdwewfwhwiwkwlwmwnwowrwswtwuwyxaxcxexhxixoxpxtxuxxxyyaybycydyeyfygyhyiylymynyoypyrysytyuywyxyyyzzazezizlzozuzyzz"           # the 474 letter pairs that words and identifiers use (the system word list and Python identifiers)
_BIGRAMS = frozenset(_BIGRAMS_TEXT[i:i + 2] for i in range(0, len(_BIGRAMS_TEXT), 2))
BOUNDARY = {"withheld": 0, "by": collections.Counter(), "replaced": 0, "replaced_by": collections.Counter(), "where": [], "not_listed": 0}
OWN_NAMES = set()               # exact strings this run made and shows as they are (file names of its own results)
FIELDS = {}                     # a JSON key -> the kind of what it holds (a tool fills this in, or passes it to bind_fields); a key it does not list has the kind of the key above it (text at the top)
KEY_KINDS = {}                  # a JSON key holding a dict -> the kind of that dict's own keys (registry value names are paths); default: name
MAX_WHERE = 200
MAX_JUDGED_CHARS = 400000000    # characters one run may have judged (every string of its answers and paging files); past it a string not judged before is withheld by its size
FINAL_GRACE_CHARS = 4000000     # the final answer may always be judged: the cap is raised by this much, and is not spent again by the strings already withheld
_STOP = {"cap": MAX_JUDGED_CHARS, "chars": 0, "by": None, "strings": 0}   # why judging stopped (None: it did not), and how many strings it withheld by their size


class T(str):
    """A string with its field type, made by the tool where it knows the type (a registry type, an event field, a column)."""
    kind = "text"

    def __new__(cls, kind, text):
        self = super().__new__(cls, text)
        self.kind = kind
        return self


def _mark(n, label, unit="characters"):
    return "<withheld %d %s: %s>" % (n, unit, label)


# the reasons a placeholder can give: a fixed list, so that text which only looks like a placeholder is not taken for one (and not skipped by the rules)
_CHECKS = ("a PEM marker", "a named secret", "a token prefix", "user-info", "not the typed grammar", "a long digit run", "a long hexadecimal run",
           "a base64 run with / and +", "a padded base64 run", "a random-looking run", "a part of a secret-shaped text", "the judging time ran out")
_LABELS = ("not a plain name", "token-shaped text", "user-info", "secret value", "private key", "long number", "rest of a long string",
           "binary data over the judged size", "binary data holding a secret-shaped text", "invisible characters in a name", "not a port", "query value", "fragment",
           "not a guid", "not a digest", "not a sid", "not a mac", "not a ip", "not a time", "not a number", "not a version",
           "not a vmfs", "not a device", "not a iqn", "not a vmuuid", "not a cid", "not a winhost") + \
          tuple("backstop: " + c for c in _CHECKS) + tuple("backstop: in binary data: " + c for c in _CHECKS)
_MARK = re.compile(r"<withheld [0-9]{1,10} (?:characters|bytes)(?:: (?:%s))?>|\[withheld: [0-9]{1,10} (?:characters|bytes)\]"
                   % "|".join(re.escape(x) for x in sorted(_LABELS, key=len, reverse=True)))
_VALUES = {"fh": None, "shown": None, "written": 0, "seen": set(), "count": 0}   # "seen": 16-byte digests of the originals written (at most 200,000)


class ValuesRefused(Exception):
    pass


def bind_values(enabled, tool):
    """The values file: the originals of what the boundary withheld, in a job run as secret output and only when asked for. Decided before
    anything is opened or created (the harness sets SECRET_OUTPUT=1 for a secret job's process)."""
    if not enabled:
        return None
    job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
    if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
        raise ValuesRefused("write_values is refused: the originals of what was withheld are written only in a job the harness runs as secret output "
                            "(job_run with secret_output: true), where the file is a sealed secret output. Nothing was written.")
    name = "%s-values.jsonl" % re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
    path = Path(out) / name
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        raise ValuesRefused("the values file already exists: %s" % path)
    except OSError as exc:
        raise ValuesRefused("the values file could not be created: %s: %s" % (path, exc.strerror or exc))
    _VALUES["fh"] = os.fdopen(fd, "w", encoding="utf-8")
    _VALUES["shown"] = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
    return _VALUES["shown"]


def close_values():
    fh = _VALUES["fh"]
    if fh is not None:
        fh.flush()
        os.fsync(fh.fileno())
        fh.close()
        _VALUES["fh"] = None


def values_summary():
    return {"requested": _VALUES["shown"] is not None, "values_file": _VALUES["shown"], "written": _VALUES["written"], "contains_secret_values": _VALUES["written"] > 0,
            "format": "JSON Lines, mode 0600: id, field, label, length, value (the original text that was withheld)" if _VALUES["shown"] else None}


_EVENTS = [None]               # while a string is judged only to see what the answer would print (sealed_text): its withholdings, counted when the answer prints it
_QUIET = [False]


def _b_withheld(original, label, field=""):
    n = len(original)
    if _EVENTS[0] is not None:
        _EVENTS[0].append((original, label, field))
        return _mark(n, label)
    BOUNDARY["withheld"] += 1
    BOUNDARY["by"][label] += 1
    fh = _VALUES["fh"]
    digest = hashlib.blake2b(original.encode("utf-8", "surrogatepass"), digest_size=16).digest() if fh is not None else None
    if fh is not None and digest not in _VALUES["seen"]:
        if len(_VALUES["seen"]) < 200000:
            _VALUES["seen"].add(digest)
        _VALUES["count"] += 1
        text = json.dumps({"id": _VALUES["count"], "field": field, "label": label, "length": n, "value": original}, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps({"id": _VALUES["count"], "field": field, "label": label, "length": n, "value": original}, ensure_ascii=True)
        fh.write(text + "\n")
        _VALUES["written"] += 1
    return _mark(n, label)


# ---- normalisation ----------------------------------------------------------------------------------------------------------------
_STRIP_CATS = frozenset(("Cf", "Cc", "Mn", "Me", "Cs", "Co", "Cn", "Zl", "Zp"))
_FILLERS = frozenset((0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800))


class _Strip(dict):
    def __missing__(self, o):
        if len(self) > 20000:
            self.clear()
        keep = unicodedata.category(chr(o)) not in _STRIP_CATS and o not in _FILLERS
        self[o] = o if keep else None
        return self[o]


_STRIP = _Strip()
_ESCAPED = re.compile(r"(?<!\\)\\+(?:u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\})")


def _unescape_invisible(m):
    try:
        c = chr(int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if (unicodedata.category(c) in _STRIP_CATS or ord(c) in _FILLERS) else m.group(0)


def _flat(text):
    """The text with invisible characters (and the escapes of such characters) taken out, and past ASCII in NFKC form."""
    if "\\u" in text or "\\U" in text or "\\x" in text:          # (the escape pattern needs a backslash and one of these)
        text = _ESCAPED.sub(_unescape_invisible, text)
    if text.isascii():
        return text if text.isprintable() else text.translate(_STRIP)
    out = text.translate(_STRIP)
    return unicodedata.normalize("NFKC", out) if not out.isascii() else out


# ---- layer 1: the allow-list ------------------------------------------------------------------------------------------------------
_PIECE = re.compile(r"[A-Z]{2,}s(?![a-z])|[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")        # (GPOs, an acronym in the plural, is one piece)
_GUID = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?|[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}")
_SID = re.compile(r"S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}")
_IPV4 = re.compile(r"(?<![0-9A-Za-z.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9A-Za-z])")
_HEX_NUMBER = re.compile(r"(?<![0-9A-Za-z])0[xX][0-9A-Fa-f]{1,16}(?![0-9A-Za-z])")
# the publisher ids that follow the name of an AppX package family (the hash of the publisher's name), and the assembly public key tokens of Microsoft
_KNOWN_ID_WORDS = ("0x", "8wekyb", "cw5n1h", "kzf8qx", "31bf38", "b77a5c", "b03f5f")
_KNOWN_ID = re.compile(r"(?<![0-9A-Za-z])(?:8wekyb3d8bbwe|cw5n1h2txyewy|kzf8qxf38zg5c|31bf3856ad364e35|b77a5c561934e089|b03f5f7f11d50a3a|0x[0-9A-Fa-f]{1,16})(?![0-9A-Za-z])")
_NAME_SEPS = " _-.$@?:~+,#()[]{}'`<>*"
_PATH_EXTRA = "&!';=^%\""
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_PCT_UNRESERVED = re.compile(r"%((?:4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|3[0-9]|2[DdEe]|5[Ff]|7[Ee]))")
_JOIN_NAME, _JOIN_PATH = "-_+", "-_+/\\"
_CTRL = "\x01\x02\x03\x04\x05\x06\x07\x08\x09"


def _has(words, text):
    """Whether one of `words` is in `text` (a loop: a generator inside any() costs twice as much for the thousands of strings of a hive)."""
    for w in words:
        if w in text:
            return True
    return False


def _pronounceable(piece):
    p = piece.lower()
    bad = sum(1 for a, b in zip(p, p[1:]) if (a + b) not in _BIGRAMS)
    return bad <= 1 + len(p) // 10


_HEX_LOW_OR_UP = re.compile(r"[0-9a-f]+|[0-9A-F]+")
_HEX_ANY = re.compile(r"[0-9A-Fa-f]+")
_SEGMENT_MEMO = {}


def _structure_ok(seg):
    if seg.isdigit() and seg.isascii():
        return len(seg) <= 18
    if len(seg) <= 24 and _HEX_LOW_OR_UP.fullmatch(seg):
        return True                       # a hexadecimal id up to 24 digits (a USB serial, a 16-digit object id, a hash of a few bytes) is plain
    if len(seg) >= 20 and _HEX_ANY.fullmatch(seg):
        return False
    pieces = _PIECE.findall(seg)
    short = sum(1 for p in pieces if len(p) <= 2)
    if short > max(2, 0.4 * len(pieces)):
        return False
    flips = sum(1 for a, b in zip(seg, seg[1:]) if a.isdigit() != b.isdigit())
    if flips > 3 + len(seg) // 16:
        return False
    alpha = [p for p in pieces if p.isalpha()]
    if sum(len(p) for p in alpha) >= 12 and sum(len(p) for p in alpha) < 3.4 * len(alpha):
        return False
    return True


def _plain_segment(seg, lmin=None):
    lmin = LMIN if lmin is None else lmin
    if len(seg) < lmin:
        return True
    memo = (seg, lmin) if len(seg) <= 64 else None          # the same words come again and again in the records of one log
    if memo is not None:
        hit = _SEGMENT_MEMO.get(memo)
        if hit is not None:
            return hit
    if not _structure_ok(seg):
        ok = False
    else:
        ok = all(not (p.isalpha() and len(p) >= 6) or _pronounceable(p) for p in _PIECE.findall(seg))
    if memo is not None:
        if len(_SEGMENT_MEMO) >= 100000:
            _SEGMENT_MEMO.clear()
        _SEGMENT_MEMO[memo] = ok
    return ok


_EMBEDDED_ID = re.compile(r"(?<![A-Za-z0-9])(?:naa\.(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{16})|eui\.[0-9a-fA-F]{16}|wwn-0x[0-9a-fA-F]{16}|vml\.[0-9a-fA-F]{20,40}|vsan:[0-9a-f]{16}-[0-9a-f]{16})(?![A-Za-z0-9])")
_EMBEDDED_T10 = re.compile(r"(?<![A-Za-z0-9])t10\.[A-Za-z0-9_.+-]{8,120}")
_EMBEDDED_WORDS = ("naa.", "eui.", "wwn-0x", "vml.", "vsan:", "t10.")


def _t10_plain(text):
    """Whether a t10. id reads as the id of a drive: every piece between underscores is 19 characters or fewer, and the serial (the last) is not a run of 17 or more hexadecimal digits."""
    pieces = text.split("_")
    return all(len(piece) <= 19 for piece in pieces) and not (len(pieces[-1]) >= 17 and _HEX_ANY.fullmatch(pieces[-1]) is not None)


_ONE_CASE_TAIL = re.compile(r"[A-Za-z]{20,64}")


def _letter_serial_spans(t):
    """The t10. and iqn. ids in `t` whose serial (the last piece of a t10. id) or target (after the last colon of an iqn. name) is 20 or more letters of one case that do not read as a word."""
    if "t10." not in t and "iqn." not in t:
        return []
    spans = []
    for m in _EMBEDDED_T10.finditer(t):
        last = m.group().split("_")[-1]
        if _ONE_CASE_TAIL.fullmatch(last) and (last.islower() or last.isupper()) and not _word_letters(last):
            spans.append((m.start(), m.end()))
    for m in _IQN_NAME.finditer(t):
        last = m.group().rsplit(":", 1)[-1]
        if _ONE_CASE_TAIL.fullmatch(last) and (last.islower() or last.isupper()) and not _word_letters(last):
            spans.append((m.start(), m.end()))
    return spans


_IQN_NAME = re.compile(r"(?<![A-Za-z0-9])iqn[.][0-9]{4}-[0-9]{2}[.][a-z0-9.-]{1,60}(?::[A-Za-z0-9._-]{1,64})?")


def _t10_hex_spans(t):
    """The t10. ids in `t` whose serial is a run of 17 or more hexadecimal digits: a drive's serial is not one (a random one is), and a run of hexadecimal digits is otherwise plain."""
    if "t10." not in t and "iqn." not in t:
        return []
    spans = []
    for m in _EMBEDDED_T10.finditer(t):
        last = m.group().split("_")[-1]
        if len(last) >= 17 and _HEX_ANY.fullmatch(last) is not None:
            spans.append((m.start(), m.end()))
    return spans + _letter_serial_spans(t)


def _mask_embedded(t):
    """`t` with the well-formed ids of devices in it (naa., eui., wwn-0x, vml., vsan: and a t10. id of a drive) replaced by `~`, so that the judging of a name or a path does not take their digits for a random run."""
    if not _has(_EMBEDDED_WORDS, t):
        return t
    t = _EMBEDDED_ID.sub(lambda m: "~" * len(m.group()), t)
    return _EMBEDDED_T10.sub(lambda m: "~" * len(m.group()) if _t10_plain(m.group()) else m.group(), t)


def _prepare(s, typed=True):
    """A same-length copy of `s` in which a GUID, a SID, an IPv4 address and a %XX escape are replaced by `~` and a non-ASCII letter by `e`;
    None when `s` holds a format, control or combining character, a non-NFKC character or a stray space character."""
    if not s.isascii():
        for ch in s:
            cat = unicodedata.category(ch)
            if cat[0] in "CM" or (cat[0] == "Z" and ch != " "):
                return None
        if unicodedata.normalize("NFKC", s) != s:
            return None
        s = "".join(ch if ch.isascii() else "e" for ch in s)
    t = _GUID.sub(lambda m: "~" * len(m.group()), s) if s.count("-") >= 3 else s    # (each pattern is tried only when the text holds what it cannot match without: a GUID has three hyphens or more)
    if typed:
        if "S-1-" in t:
            t = _SID.sub(lambda m: "~" * len(m.group()), t)
        if "." in t:
            t = _IPV4.sub(lambda m: "~" * len(m.group()), t)
        if _has(_KNOWN_ID_WORDS, t):
            t = _KNOWN_ID.sub(lambda m: "~" * len(m.group()), t)
        t = _mask_embedded(t)
    return _PCT.sub("   ", t) if "%" in t else t


def _unpercent(s):
    if "%" not in s:
        return None
    out = _PCT_UNRESERVED.sub(lambda m: chr(int(m.group(1), 16)), s)
    return out if out != s else None


_CHAINS = {}
_SEGMENT = re.compile(r"[A-Za-z0-9]+")


_SEGMENT_PLAIN = {}


def _is_plain_segment(seg):
    """_plain_segment(seg, 0), remembered for the plain ones only (a dict that is asked a hundred thousand times for the same words)."""
    if not _plain_segment(seg, 0):
        return False
    if len(seg) <= 64:
        if len(_SEGMENT_PLAIN) >= 100000:
            _SEGMENT_PLAIN.clear()
        _SEGMENT_PLAIN[seg] = True
    return True


def _bad_runs(t, join):
    """Intervals of `t` that are not plain, judged on CHAINS: maximal sequences of alphanumeric segments joined only by `join` characters. A
    chain is bad when (A) its random-looking segments, adjacent ones taken together, add up to LMIN characters or more, or (B) it is LMIN
    characters or longer, holds 8 or more characters of letter-and-digit-mixed segments, and holds no word of five or more letters."""
    pattern = _CHAINS.get(join)
    if pattern is None:
        pattern = _CHAINS[join] = re.compile(r"[A-Za-z0-9]+(?:[%s]+[A-Za-z0-9]+)*" % "".join(re.escape(c) for c in join))
    plain = _SEGMENT_PLAIN
    if all(plain.get(seg) or _is_plain_segment(seg) for seg in _SEGMENT.findall(t)):
        return []                                       # no chain holds a random-looking segment, so none is bad (the same answer as the loop below, without building the chains)
    bad = []
    for found in pattern.finditer(t):
        if found.end() - found.start() < LMIN:
            continue                                    # a chain shorter than LMIN is neither a run of LMIN random characters nor a long mixed chain
        chain = [(m.start(), m.end()) for m in _SEGMENT.finditer(t, found.start(), found.end())]
        total = sum(b - a for a, b in chain)
        if total < LMIN:
            continue
        rnd = [not _plain_segment(t[a:b], 0) for a, b in chain]
        if not any(rnd):
            continue
        run = None
        for (a, b), r in zip(chain, rnd):
            if r:
                run = [a, b, b - a] if run is None else [run[0], b, run[2] + (b - a)]
            else:
                if run is not None and run[2] >= LMIN:
                    bad.append((run[0], run[1]))
                run = None
        if run is not None and run[2] >= LMIN:
            bad.append((run[0], run[1]))
        mixed = sum(b - a for a, b in chain if not _structure_ok(t[a:b]))
        if total >= LMIN and mixed >= 8 and not any(len(p) >= 5 and p.isalpha() and _pronounceable(p) for a, b in chain for p in _PIECE.findall(t[a:b])):
            bad.append((chain[0][0], chain[-1][1]))
    return bad


_CHARS = {}


def _chars_ok(comp, extra_ok):
    if comp.isascii():
        pattern = _CHARS.get(extra_ok)
        if pattern is None:
            pattern = _CHARS[extra_ok] = re.compile("[A-Za-z0-9%s]*" % re.escape(_NAME_SEPS + extra_ok))
        return pattern.fullmatch(comp) is not None
    return all(ch.isalnum() or ch in _NAME_SEPS or ch in extra_ok for ch in comp)


def _userinfo_shape(t):
    return ":" in t and "@" in t and t.index(":") < t.rindex("@")


def _plain_name(s, extra_ok=""):
    if not s or len(s) > 128:
        return False
    t = _prepare(s)
    if t is None or not _chars_ok(t, extra_ok) or _userinfo_shape(t) or _secret_in_ident(t) or _t10_hex_spans(t):
        return False
    u = _unpercent(s)
    if u is not None:
        pu = _prepare(u)
        if pu is None or _bad_runs(pu, _JOIN_NAME):
            return False
    return not _bad_runs(t, _JOIN_NAME)


def _merge(spans):
    merged = []
    for a, b in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


_SPLIT = re.compile(r"([\\/])")
_DRIVE = re.compile(r"[A-Za-z]:|\?|\.")


def _path_spans(s, extra_ok=_PATH_EXTRA):
    t = _prepare(s)
    if t is None:
        return [(0, len(s))]
    bad, pos = [], 0
    if len(t) <= 255 and "@" not in t and t.isascii() and _chars_ok(t, extra_ok + "\\/") and not _secret_in_ident(t):
        parts = ()                       # (every character is allowed, no part is long and none can hold a user-info shape: no part is bad)
    else:
        parts = _SPLIT.split(t)
    for part in parts:
        a, b = pos, pos + len(part)
        pos = b
        judged = part.lstrip(_CTRL)
        if part in ("\\", "/") or part == "" or _DRIVE.fullmatch(part):
            continue
        if len(part) - len(judged) > 1 or len(part) > 255 or not _chars_ok(judged, extra_ok) or _userinfo_shape(judged) or _secret_in_ident(judged):
            bad.append((a, b))
    bad += _bad_runs(t, _JOIN_PATH) + _t10_hex_spans(t)
    u = _unpercent(s)
    if u is not None:
        pu = _prepare(u)
        if pu is None or _bad_runs(pu, _JOIN_PATH):
            bad.append((0, len(s)))
    return _merge(bad)


def _replace_spans(s, spans, label, field):
    out, last = [], 0
    for a, b in spans:
        out.append(s[last:a])
        out.append(_b_withheld(s[a:b], label, field))
        last = b
    out.append(s[last:])
    return "".join(out)


def _show_name(s, field):
    return s if _plain_name(s) else _b_withheld(s, "not a plain name", field)


def _show_path(s, field, extra_ok=_PATH_EXTRA):
    return _replace_spans(s, _path_spans(s, extra_ok), "not a plain name", field)


def _show_key(s, field):
    return _show_path(s, field, _PATH_EXTRA + "*^<>")


_URL = re.compile(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)(?:([^/?#]*)@)?([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$", re.S)


def _show_host(s, field):
    """A host name is on the deny-list: a random-looking label of a host is evidence (a C2 name), not a secret. Layer 2 reads it first: the deny-list
    would replace a random user of `user:password@host` and leave the context layer 2 needs."""
    return _deny_text(_layer2(s, field), field)


def _show_value(v):
    return v if re.fullmatch(r"[0-9]{1,12}|true|false|null|yes|no", v) or (v.isalpha() and len(v) <= 24 and _plain_name(v)) else None


def _show_url(s, field):
    m = _URL.match(s)
    if not m:
        return _show_path(s, field)
    scheme, userinfo, host, path, query, frag = m.groups()
    out = scheme
    if userinfo is not None:
        out += (userinfo if _MARK.fullmatch(userinfo) else _b_withheld(userinfo, "user-info", field)) + "@"
    hostname, colon, port = host.partition(":") if not host.startswith("[") else (host, "", "")
    out += _show_host(hostname, field) + (colon + (port if port.isdigit() else _b_withheld(port, "not a port", field)) if colon else "")
    out += _show_path(path, field)
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            k, eq, v = pair.partition("=")
            kk = _show_name(k, field) if k else k
            if eq:
                sv = _show_value(v)
                pairs.append(kk + "=" + (sv if sv is not None else _b_withheld(v, "query value", field)))
            else:
                pairs.append(kk)
        out += "?" + "&".join(pairs)
    if frag is not None:
        sv = _show_value(frag)
        out += "#" + (sv if sv is not None else _b_withheld(frag, "fragment", field))
    return out


_TYPED = {
    "guid": re.compile(_GUID.pattern),
    "digest": re.compile(r"(?:sha256:|sha1:|md5:)?[0-9A-Fa-f]{32,128}|T1[0-9A-Fa-f]{60,72}|[0-9]{1,6}:[A-Za-z0-9+/]{3,}:[A-Za-z0-9+/]{3,}"),
    "sid": re.compile(_SID.pattern),
    "mac": re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"),
    "ip": re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]{2,45}(?:%[0-9A-Za-z_.-]{1,16})?"),
    "time": re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9:.]+(?:Z|[+-][0-9:]+)?)?|D:[0-9]{8,14}(?:[Zz+-][0-9']*)?|[0-9]{1,18}"),
    "number": re.compile(r"-?[0-9]{1,18}(?:\.[0-9]{1,18})?|0x[0-9A-Fa-f]{1,16}|(?:true|false|null)"),
    "version": re.compile(r"v?[0-9]+(?:\.[0-9A-Za-z]+){1,4}(?:[-+][0-9A-Za-z.]+)?"),
    # the identifiers of virtualized storage and machines: a VMFS volume id (8-8-4-12 hexadecimal digits), a SCSI device id (naa. with 16 or 32 digits, eui. and
    # wwn-0x with 16, vml. with 20 to 40, t10. with a vendor, a model and a serial), an iSCSI name, the VMware uuid of a machine (16 bytes, a `-` after the
    # eighth), the content id of a disk (8 digits) and the name Windows gives a machine nobody named (WIN- and 11 capitals and digits)
    "vmfs": re.compile(r"[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "device": re.compile(r"naa\.(?:[0-9a-fA-F]{16}|[0-9a-fA-F]{32})|eui\.[0-9a-fA-F]{16}|wwn-0x[0-9a-fA-F]{16}|vml\.[0-9a-fA-F]{20,40}|t10\.[A-Za-z0-9_.+-]{8,120}"),
    "iqn": re.compile(r"iqn\.[0-9]{4}-[0-9]{2}\.[a-z0-9][a-z0-9.-]{0,60}(?::[A-Za-z0-9._-]{1,40})?"),
    "vmuuid": re.compile(r"[0-9a-f]{2}(?: [0-9a-f]{2}){7}-[0-9a-f]{2}(?: [0-9a-f]{2}){7}"),
    "cid": re.compile(r"[0-9a-f]{8}"),
    "winhost": re.compile(r"WIN-[A-Z0-9]{11}"),
}
_ID_FORMS = ("guid", "vmfs", "vmuuid", "device", "mac", "cid", "number")      # the forms a field of kind `id` may hold (the kind of a field that holds one of several forms of identifier), else it is judged as a name
_CONTENT_ID = re.compile(r"[0-9A-Fa-f]{32}")
_NAMING_IDS = frozenset(("device", "iqn"))          # the ids that hold a name a person chose (a t10. vendor, model and serial; an iSCSI name): what they hold must read as a name, not as random text
_KNOWN_KINDS = frozenset(("text", "name", "path", "key", "url", "host", "hex", "label", "id")) | frozenset(_TYPED)
_NUMBER_RUN = re.compile(r"[0-9]+")


def bind_fields(table, key_kinds=None):
    """The field kinds of a tool, passed in by the tool (this text holds none): `table` maps a JSON key to the kind of what it holds, or to a function of
    the key of one item for a dict whose items have kinds of their own; `key_kinds` maps a key holding a dict to the kind of that dict's own keys. A kind
    this text does not know is refused (a misspelt kind would judge the field as free text without a word)."""
    for name, kind in list(table.items()) + list((key_kinds or {}).items()):
        if not isinstance(name, str) or not (callable(kind) or kind in _KNOWN_KINDS):
            raise ValueError("a field kind this text does not know: %r" % (name,))
    FIELDS.update(table)
    KEY_KINDS.update(key_kinds or {})


def _field_entry(name):
    """What FIELDS says of the field `name`; a digit run in a name stands for any number (`ethernet0.address` is `ethernet#.address`)."""
    entry = FIELDS.get(name)
    if entry is None and name and any(c.isdigit() for c in name):
        entry = FIELDS.get(_NUMBER_RUN.sub("#", name))
    return entry


# ---- layer 2: position and prefix rules -------------------------------------------------------------------------------------------
# user-info whose password holds a `/` (RFC 3986 says to encode it; people do not): after `//`, a user, a `:`, then everything up to the last `@` that is
# followed by a host; not `host:8080/...@...` (a port), whose first word after the colon is a number
_URL_USERINFO_SLASH = re.compile(r"(?<=//)(?![^\s/@:<>\"'`]*:[0-9]{1,5}(?:[/?#@]|$))[^\s/@:<>\"'`]{1,64}:[^\s<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
# a user the deny-list already replaced: `<withheld ...>:password@host`
_MARK_USERINFO = re.compile(r"(?P<mark><withheld \d+ (?:characters|bytes)[^<>]{0,70}>|\[withheld: \d+ characters\]):(?P<pw>[^\s/<>\"'`]{1,128})(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_B_USERINFO = re.compile(r"(?<![A-Za-z0-9._%+-])(?!mailto:)[^\s/@:<>\"'`]{1,64}:[^\s/<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_URL_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_NAMED_HEAD = r"(?i:(?<![Bb]y)(?<![Cc]om)(?<![Oo]ver)(?<![Uu]nder)(?<![Tt]res)(?<![Ee]ncom)(?<![Ss]ur)(?<![Ii]m)pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|client[_-]?secret|credential|auth(?:orization)?|(?<![A-Za-z])(?:pw|sig|sas|otp|psk))" r"s?[0-9]{0,2}[\"']?[ \t]{0,3}[=:][ \t]{0,3}[\"']?"
_NAMED = re.compile(_NAMED_HEAD + r"(?!line[ \t]+[0-9])" + r"(?P<value>(?:(?i:token|bearer|basic|negotiate)[ \t]+(?=[A-Za-z0-9+/._~=-]{8}))?(?:[^\s\"'<>;,&]|[;,&](?![A-Za-z0-9_. -]{1,40}=)){1,512})")
# a placeholder (<redacted>, <password>, <***>) is not a value, but what is glued behind it is
_PLACEHOLDER = r"<(?i:redacted|hidden|masked|removed|omitted|secret|password|passwd|passphrase|pwd|pass|token|key|value|placeholder|empty|none|null|unset|your[ _-]?(?:password|secret|token|key)|\*{1,16})?>"
_PH_END = r"(?=[\s\"';,&\\<>)\]}]|\.(?:\s|$)|$)"
# a value in angle brackets after a secret's name (password=<hJaXeuQz>): withheld unless it reads as a placeholder word
_ANGLE_SPLIT = re.compile(r"[-_.+/=~]")
_NAMED_ANGLE = re.compile(_NAMED_HEAD + r"(?!" + _PLACEHOLDER + r")(?P<value><(?P<inner>[A-Za-z0-9+/_.~=-]{6,128})>)")
_NAMED_PH = re.compile(_NAMED_HEAD + _PLACEHOLDER + r"(?P<value>[^\s\"'<>;,&\\]{1,512})")
# the name of a flag that takes a secret (`-password x`, `--token x`, `--api-key x`, `-auth x`): the words below, any word with `secret` in it or ending in `token`, `key` or
# (after a letter or a digit) Key, Token, Password, Pwd, Pass, Secret, also after up to four words joined by `-` or `_`; `--key-file x` and `--keyboard x` are not (the name ends where the value begins)
_FLAG_NAME = (r"(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?:(?i:passw(?:or)?d|passwd|pass(?:[-_]?phrase)?|pwd|pw|otp|[A-Za-z0-9]{0,20}secret[A-Za-z0-9]{0,20}|[A-Za-z0-9]{0,20}token|api[-_]?key|access[-_]?key|key|keypass|storepass|userpass|auth|authorization|bearer|psk|credentials?|community)"
              r"|[A-Za-z0-9]{1,20}(?-i:Key|Token|Password|Passwd|Pwd|Pass|Passphrase|Secret))")
# a placeholder, a space and a value built like a secret: the placeholder is not the value, the word after it is
_PH_SPACE = re.compile(r"(?:" + _NAMED_HEAD + r"|(?<![\w-])--?" + _FLAG_NAME + r"[ \t]+|(?<![\w-])(?i:set|enable)[ \t]+(?i:passw(?:or)?d|secret|passphrase|token)[ \t]+)"
                       + _PLACEHOLDER + r"[ \t]+(?P<value>[A-Za-z0-9]{8,40})(?![A-Za-z0-9])")
_NAMED_FLAG = re.compile(r"(?<![\w-])--?" + _FLAG_NAME + r"(?:=|[ \t]+)(?!-)(?!" + _PLACEHOLDER + _PH_END + r")(?![\x5ca-zA-Z0-9_./~:-]{1,120}[.](?i:key|pem|pub|crt|p12|pfx|jks)(?![A-Za-z0-9]))(?!(?:~|[.]{1,2})/[A-Za-z0-9_./-]{1,120}|/[A-Za-z0-9_.-]{1,40}(?:/[A-Za-z0-9_.-]{1,40})+)(?P<value>[^\s\"']+)")
_NAMED_SET = re.compile(r"(?<![\w-])(?i:set|enable)[ \t]+(?i:passw(?:or)?d|secret|passphrase|token)[ \t]+(?:[0-9][ \t]+)?(?!" + _PLACEHOLDER + _PH_END + r")(?P<value>[^\s\"']+)")
# in a name or a path component: a secret's name and, glued or after a separator or a space, something that is not a word (password-Zq7kP2mR, Token Zq7kP2mR, pwdZq7kP2mR), or a flag with its value
# (-password x, d--pwd x): a name that holds one is a command line, not a name
_IDENT_FLAG = re.compile(r"(?<![A-Za-z0-9])--?" + _FLAG_NAME + r"[ \t]+(?!-)\S")
_SECRET_THEN = re.compile(r"(?:(?i:passw(?:or)?d|passphrase|pwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|account[_-]?key)|(?<=-)(?i:pass|auth|bearer|psk))"
                          r"(?=s?[ \t_.-]*['\"(\[]?([A-Za-z0-9]{1,40}))")
_SECRET_THEN_TEXT = re.compile(r"(?<![A-Za-z0-9])(?i:passw(?:or)?d|passphrase|pwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|account[_-]?key)s?[ \t_.-]{1,3}['\"(\[]?(?P<value>[A-Za-z0-9]{7,40})(?![A-Za-z0-9])")
_GLUED_FLAG = re.compile(r"(?<![A-Za-z0-9])--?(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?i:key|token|pass|password|pwd|secret)(?P<value>[A-Za-z0-9]{8,40})(?![A-Za-z0-9])")
_FLAG_THEN = re.compile(r"(?<![A-Za-z0-9])--?" + _FLAG_NAME + r"(?=[ \t_.-]*['\"(\[]?([A-Za-z0-9]{1,40}))")
_ID_SECRET_WORDS = ("pass", "pwd", "secret", "token", "key", "cred", "auth", "bearer", "psk", "otp", "pw", "community")
_WORD_PARTS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


_FIVE_CONSONANTS = re.compile(r"[^aeiouy]{5}")
_VEEAM_GLUE = re.compile(r"D(?:19|20)[0-9]{2}$")
_DATE8 = re.compile(r"(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])(?:[0-2][0-9][0-5][0-9][0-5][0-9])?")


def _value_like(tok):
    """Whether a run of letters and digits after a secret's name is built like a secret and not like words: 7 or more characters with a digit among them (not the one to four
    digits of a counter at the end), or only digits, or a run of capitals of other than two or three, or a word of lower case letters that is not pronounceable."""
    if len(tok) < 7:
        return False
    tok = _VEEAM_GLUE.sub("", tok)                       # (the D2024 that Veeam glues to a job name before its time stamp)
    if len(tok) < 7:
        return False
    if tok.isdigit():
        return _DATE8.fullmatch(tok) is None             # (a date, 20240312, with or without a time of day, is not a value)
    parts = _WORD_PARTS.findall(tok)
    if parts and parts[-1].isdigit():
        if len(parts[-1]) > 4:
            return True
        parts.pop()
    for n, part in enumerate(parts):
        if part.isdigit():
            return True
        if part.isupper():
            if not 2 <= len(part) <= 3:
                return True
        elif len(part) < 3 or (n > 0 and not part[0].isupper()) or not _word_letters(part):
            return True
    return False


_TECH_WORDS = re.compile("vmware|vcenter|vsphere|vsan|proxmox|nextcloud|splunk|openvpn|pfsense|opnsense|switch|postgres(?:ql)?|pgsql|mysql|mssql|sqlserver|rabbitmq|kafka|"
                         "upgrad(?:e|ed|es|ing)|updat(?:e|ed|es|ing)|workstation|helpdesk|cloudhsm|hyperv|xenserver|netapp|nutanix|veeam|commvault|cohesity|wsus|sccm|pgbouncer|mongodb|redis|"
                         "kubernetes|openshift|jumpbox|gitlab|github|jfrog|zabbix|ldaps?|radius|kerberos|tacacs|cifs|ntnx|qemu|esxi|smtp|sftp|dhcp|https?|iscsi|ntfs|sshd|nightly|monthly|fortnightly|midnight|lightweight|scratch|snmp|crowdstrike|etcd|vmfs|btrfs|openbsd")
_NAME_TOKEN = re.compile(r"[A-Za-z0-9]+")
_TAG = re.compile(r"(?:[a-z]{3,5}|[A-Z]{3,5}|[A-Z][a-z]{2,4})[0-9]{1,4}|[A-Z][0-9][A-Z][0-9]")
_DATE_STAMP = re.compile(r"D?(?:19|20)[0-9]{2}[-_.]?(?:0[1-9]|1[0-2])[-_.]?(?:0[1-9]|[12][0-9]|3[01])(?:[-_.T ]?[0-2][0-9][0-5][0-9][0-5][0-9])?(?:_[0-9A-Fa-f]{4}(?![0-9A-Za-z]))?")


def _word_letters(word):
    """Whether a run of letters reads as a word: every pair of letters is one that words hold (the names of products and services are taken out first), and there are no five consonants in a row."""
    low = _TECH_WORDS.sub("", word.lower())
    for k in range(len(low) - 1):
        if low[k:k + 2] not in _BIGRAMS:
            return False
    return _FIVE_CONSONANTS.search(low) is None


_FILE_EXTS = frozenset(("vmdk", "vmx", "vmsd", "vmsn", "vmem", "vmss", "nvram", "log", "qcow2", "qcow", "vhdx", "avhdx", "vhd", "vdi", "ovf", "ova", "json", "jsonl", "yaml", "conf", "cfg", "flat", "delta", "sesparse", "iso", "img", "raw", "bak", "tmp"))


def _groupish(tok):
    """A run of 4 or more letters and digits that is not a tag (srv01, db02 are tags): the part of a value written in groups (ab12-cd34-ef56)."""
    if len(tok) < 4 or _TAG.fullmatch(tok) is not None:
        return False
    if tok.isalpha() and tok.isupper():
        return _TECH_WORDS.fullmatch(tok.lower()) is None            # (capitals of 4 or more letters are not a word: KHIL, not ESXI)
    if tok.isalpha() and not tok[1:].islower():
        return True                                                  # (a word is not written with a capital in the middle: paUn)
    base = tok.rstrip("0123456789")
    return not (base.isalpha() and len(base) >= 4 and len(tok) - len(base) <= 4 and _word_letters(base))


def _words_value(text, start):
    """Whether any word after a secret's name, from `start` on, is a value: built like a secret by itself, or one of two or more groups in a row (ab12-cd34), which are one value written in parts."""
    tokens = _NAME_TOKEN.findall(_DATE_STAMP.sub(" ", text[start:start + 400]))
    group, run, seen = [], [], False
    for tok in tokens[:40]:
        if _value_like(tok):
            return True
        if tok.lower() in _FILE_EXTS:
            run, seen = [], False                                    # (the end of a file name is not a part of a value)
        elif 4 <= len(tok) <= 6:                                     # (a short word between two groups, or next to one, is part of the value: yIgK-paUn)
            run.append(tok)
            seen = seen or (_groupish(tok) and not tok.isdigit())
            if seen and len(run) >= 2 and _value_like("".join(run)):
                return True
        else:
            run, seen = [], False
        if len(tok) == 5 or len(tok) == 6:
            if tok.isdigit() and tok[0] != "0":
                return True              # 5 or 6 digits that do not start like a counter (000001)
        if _groupish(tok):
            group.append(tok)
            if len(group) >= 2 and _value_like("".join(group)):
                return True
        else:
            group = []
    return False


def _secret_in_ident(text):
    """Whether a name or a path component holds a secret's name with a value after it (see above). Linear: each pattern is anchored on a name and reads at most 400 characters after it."""
    if not _has(_ID_SECRET_WORDS, text.lower()):
        return False
    if _IDENT_FLAG.search(text) is not None or _NAMED_SET.search(text) is not None:
        return True
    for pattern in (_SECRET_THEN, _FLAG_THEN):
        m = pattern.search(text)
        if m is not None and _words_value(text, m.start(1)):
            return True
    return False
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)", re.S)
_PREFIX = re.compile(r"(?i:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abeprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}"
                     r"|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,}|npm_[A-Za-z0-9]{30,}"
                     r"|dop_v1_[0-9a-f]{40,}|ya29\.[0-9A-Za-z_-]{30,})|sk-(?=[A-Za-z0-9_-]{0,39}[0-9])[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,300}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?")
_BASE64_PADDED = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={1,2}(?![A-Za-z0-9+=])")
_LONG_DIGITS = re.compile(r"(?<![0-9])[0-9]{19,}(?![0-9])")


_BASE64_PADDED_PATH = re.compile(r"[A-Za-z0-9+/]{22,90}={1,2}(?![A-Za-z0-9+=])")           # (bounded: a long run of these characters costs a step for each of the 90 before a start, not the rest of the run)


def _padded_in_path(field):
    """A padded base64 key that stands behind a `/` (a path ends in the key, or the key's own `/` cut it): the last 22 characters before two pads, 27 before one, are withheld."""
    def sub(m):
        body = m.group().rstrip("=")
        pad = len(m.group()) - len(body)
        keep = len(body) - (22 if pad == 2 else 27)
        if keep < 0:
            return m.group()
        tail = body[keep:]
        if "/" not in tail or len({"d" if c.isdigit() else "u" if c.isupper() else "l" for c in tail if c.isalnum()}) < 2 or not _b64_shape(tail + "=" * pad):
            return m.group()
        return body[:keep] + _b_withheld(tail + "=" * pad, "token-shaped text", field)
    return sub


def _b64_shape(run):
    """Whether a padded run can be base64 of random bytes: its length with the padding is a multiple of 4, and it holds a digit, `+` or `/` (a long
    identifier before an `=` in a line of text, RelatedActivityID=, is not one)."""
    return len(run) % 4 == 0 and re.search(r"[0-9+/]", run) is not None


_NAMED_WORDS = ("pass", "pwd", "secret", "token", "key", "credential", "auth")
_PREFIX_HINTS = ("akia", "asia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xox", "glpat-", "_live_", "_test_", "sg.", "aiza", "npm_", "dop_v1_",
                 "ya29.", "sk-", "eyj")


def _layer2_once(s, field):
    # each rule is tried only when the text holds what it needs (a character or a word it cannot match without): the same result, a lot less reading
    if "withheld" in s:
        s = _MARK_USERINFO.sub(lambda m: m.group("mark") + ":" + _b_withheld(m.group("pw"), "user-info", field), s)
    if "-----" in s:
        s = _outside(s, _MARK, lambda p: _PEM.sub(lambda m: _b_withheld(m.group(), "private key", field), p))
    if "@" in s:
        s = _outside(s, _MARK, lambda p: _URL_USERINFO_SLASH.sub(lambda m: _b_withheld(m.group(), "user-info", field), p))
        s = _outside(s, _MARK, lambda p: _URL_USERINFO.sub(lambda m: _b_withheld(m.group(), "user-info", field), p))
        s = _outside(s, _MARK, lambda p: _B_USERINFO.sub(lambda m: _b_withheld(m.group(), "user-info", field), p))
    low = s.lower()
    if _has(_NAMED_WORDS, low):
        s = _outside(s, _MARK, lambda p: _NAMED.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
        if "<" in s:
            s = _outside(s, _MARK, lambda p: _PH_SPACE.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if _value_like(m.group("value")) else m.group("value")), p))
            s = _outside(s, _MARK, lambda p: _NAMED_ANGLE.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if any(_value_like(x) for x in _ANGLE_SPLIT.split(m.group("inner"))) else m.group("value")), p))
            s = _outside(s, _MARK, lambda p: _NAMED_PH.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
    if _has(("pass", "pwd", "secret", "token", "credential", "key"), low):
        s = _outside(s, _MARK, lambda p: _SECRET_THEN_TEXT.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if _value_like(m.group("value")) else m.group("value")), p))
        if "-" in s:
            s = _outside(s, _MARK, lambda p: _GLUED_FLAG.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if _value_like(m.group("value")) else m.group("value")), p))
    if "-" in s or "set" in low or "enable" in low:
        s = _outside(s, _MARK, lambda p: _NAMED_FLAG.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
        s = _outside(s, _MARK, lambda p: _NAMED_SET.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
    if "=" in s:
        s = _outside(s, _MARK, lambda p: _BASE64_PADDED.sub(lambda m: _b_withheld(m.group(), "token-shaped text", field) if _b64_shape(m.group()) else m.group(), p))
        if "/" in s:
            s = _outside(s, _MARK, lambda p: _BASE64_PADDED_PATH.sub(_padded_in_path(field), p))
    s = _outside(s, _MARK, lambda p: _LONG_DIGITS.sub(lambda m: _b_withheld(m.group(), "long number", field), p))
    low = s.lower()
    if _has(_PREFIX_HINTS, low):
        s = _outside(s, _MARK, lambda p: _PREFIX.sub(lambda m: _b_withheld(m.group(), "token-shaped text", field), p))
    if "t10." in s or "iqn." in s:
        spans = _t10_hex_spans(s)
        if spans:
            s = _replace_spans(s, _merge(spans), "token-shaped text", field)
    return s


def _outside(text, pattern, fn):
    """`fn` applied to the parts of `text` that `pattern` does not match; the matches are kept as they are."""
    if "withheld" not in text:
        return fn(text)
    out, last = [], 0
    for m in pattern.finditer(text):
        out.append(fn(text[last:m.start()]) if m.start() > last else "")
        out.append(m.group())
        last = m.end()
    out.append(fn(text[last:]) if last < len(text) else "")
    return "".join(out)


def _layer2(s, field):
    out = s
    for _ in range(3):
        nxt = _layer2_once(out, field)
        if nxt == out:
            break
        out = nxt
    return out


# ---- free text: the deny-list ------------------------------------------------------------------------------------------------------
_LABELLED_DIGEST = re.compile(r"(?i)(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|imphash|hashes?|filehash|ssdeep|tlsh)[\"'=:> \t]{1,6}(?:(?:md5|sha-?1|sha-?256|imphash)=)?([0-9a-f]{32,128})")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]{1,9})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])")


def _mask_typed(s):
    """A same-length copy of free text in which what is a typed id (GUID, SID, IPv4, time, labelled digest) is `~`."""
    t = s
    if "-" in s:
        t = _GUID.sub(lambda m: "~" * len(m.group()), t)
        if "S-1-" in s:
            t = _SID.sub(lambda m: "~" * len(m.group()), t)
        if ":" in s:
            t = _TIME.sub(lambda m: "~" * len(m.group()), t)
    if "." in s:
        t = _IPV4.sub(lambda m: "~" * len(m.group()), t)
    low = s.lower()
    if _has(_KNOWN_ID_WORDS, low):
        t = _KNOWN_ID.sub(lambda m: "~" * len(m.group()), t)
    if "ash" in low or "md5" in low or "sha" in low:
        t = _LABELLED_DIGEST.sub(lambda m: m.group().replace(m.group(1), "~" * len(m.group(1))), t)
    return t


def _deny_text(s, field):
    t = _mask_typed(s)
    t = t.replace("\x00", " ")
    spans = _bad_runs(t, _JOIN_PATH)
    spans += [m.span() for m in _HEX_RUN.finditer(t)]
    return _replace_spans(s, _merge(spans), "token-shaped text", field) if spans else s


# ---- the entry point for one string ---------------------------------------------------------------------------------------------------
_MEMO = {}


_WIDE_RUN = re.compile(r"[\x20-\x7e\uff01-\uff5e]{4,}")


def _wide_views(raw):
    """Runs of ASCII and full-width ASCII in `raw` read as UTF-8 and as UTF-16LE (at both byte offsets), when it holds a full-width character at
    all: width is folded afterwards (NFKC), so a full-width token written as hexadecimal is read like a plain one."""
    views = []
    if b"\xef\xbc" in raw or b"\xef\xbd" in raw:
        views += _WIDE_RUN.findall(raw.decode("utf-8", "replace"))
    if b"\xff" in raw:
        for offset in (0, 1):
            views += _WIDE_RUN.findall(raw[offset:len(raw) - (len(raw) - offset) % 2].decode("utf-16-le", "replace"))
    return [unicodedata.normalize("NFKC", v) for v in views]


def _hex_views(s):
    """The printable views of binary data written as hex: Latin-1 runs of 6 or more, UTF-16LE and UTF-16BE runs of 4 or more, and the runs that hold
    full-width characters (UTF-8 and UTF-16LE), width folded."""
    try:
        raw = bytes.fromhex(s[: MAX_HEX_JUDGED])
    except ValueError:
        return None
    views = [m.group().decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{6,}", raw)]
    views += [m.group().decode("utf-16-le", "replace") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", raw)]
    views += [m.group().decode("utf-16-be", "replace") for m in re.finditer(rb"(?:\x00[\x20-\x7e]){4,}", raw)]
    return views + _wide_views(raw)


def _show_hex(s, field):
    if not s or not re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", s):
        return s if re.fullmatch(r"[0-9A-Fa-f]*", s) else _show_text(s, field)
    if len(s) > MAX_HEX_JUDGED:
        return _b_withheld(s, "binary data over the judged size", field)
    for v in _hex_views(s) or ():
        if _layer2(v, "") != v or _deny_text(v, "") != v or _suspect(v):
            return _b_withheld(s, "binary data holding a secret-shaped text", field)
    return s


def _show_text(s, field):
    # layer 2 reads the string as the evidence wrote it: the deny-list replaces a span and takes with it the context (`user:` of `user:pw@host`, the
    # characters glued before `glpat-`) the position and prefix rules need; what it leaves is read once more
    out = _layer2(s, field)
    denied = _deny_text(out, field)
    return _layer2(denied, field) if denied != out else out


def _show(s, kind, field):
    if s in OWN_NAMES or _MARK.fullmatch(s):
        return s
    if len(s) > MAX_ONE_STRING:
        return _show(s[:MAX_ONE_STRING], kind, field) + _b_withheld(s[MAX_ONE_STRING:], "rest of a long string", field)
    if kind == "id":
        if len(s) <= 3 or _CONTENT_ID.fullmatch(s):
            return s
        for form in _ID_FORMS:
            if _TYPED[form].fullmatch(s) and not (form in _NAMING_IDS and s[:4] in ("t10.", "iqn.") and _bad_runs(s, _JOIN_NAME)):
                return s
        kind = "name"
    if kind in _TYPED:
        if len(s) <= 3 or (_TYPED[kind].fullmatch(s) and not (kind in _NAMING_IDS and s[:4] in ("t10.", "iqn.") and _bad_runs(s, _JOIN_NAME))):
            return s
        return _b_withheld(s, "not a %s" % kind, field)
    if kind == "hex":
        return _show_hex(s, field)
    flat = _flat(s)
    if flat != s:
        # an invisible character, or the escape of one: identifiers fail closed; free text is judged without it
        if kind in ("name", "path", "key", "url"):
            return _b_withheld(s, "invisible characters in a name", field)
        sealed = _show_text(flat, field)
        return sealed if sealed != flat else s
    if kind not in ("name", "path", "key", "url", "host"):
        return _show_text(s, field)
    pre = _layer2(s, field)
    if kind == "name":
        base = _show_name(pre, field)
    elif kind == "path":
        base = _show_path(pre, field)
    elif kind == "key":
        base = _show_key(pre, field)
    elif kind == "url":
        base = _show_url(pre, field)
    else:
        base = _show_host(pre, field)
    return _layer2(base, field) if base != pre else base


def show(s, kind="text", field=""):
    """The text the answer may show for the string `s` of a field of type `kind` (a T carries its own)."""
    if not isinstance(s, str) or not s:
        return s
    kind = getattr(s, "kind", kind)
    memo = (kind, field, s) if len(s) <= 512 and kind not in _TYPED else None            # (a typed id is judged by one match: it is not worth a place in the memo)
    quiet = _QUIET[0]
    if memo is not None:
        hit = _MEMO.get(memo)
        if hit is not None:
            out, pending = hit
            if pending and not quiet:
                # judged earlier only to see what would be printed: it is withheld, counted and written to the values file now that it is printed (once)
                for original, label, where in pending:
                    _b_withheld(original, label, where)
                _MEMO[memo] = (out, None)
            return out
    events = _EVENTS[0] = [] if quiet and memo is not None else None
    try:
        out = _show(str(s), kind, field)
    finally:
        _EVENTS[0] = None
    if memo is not None:
        if len(_MEMO) > 40000:
            _MEMO.clear()
        _MEMO[memo] = (out, events or None)
    return out


_ORDER_SALT = os.urandom(16)


def _quietly(fn):
    """`fn()` with nothing counted, listed or written: judging a string to see what an answer would show of it is not withholding it."""
    saved = (BOUNDARY["withheld"], BOUNDARY["by"].copy(), BOUNDARY["replaced"], BOUNDARY["replaced_by"].copy(), BOUNDARY["where"][:], BOUNDARY["not_listed"], _VALUES["fh"])
    _VALUES["fh"] = None
    was, _QUIET[0] = _QUIET[0], True
    try:
        return fn()
    finally:
        _QUIET[0] = was
        (BOUNDARY["withheld"], BOUNDARY["by"], BOUNDARY["replaced"], BOUNDARY["replaced_by"], BOUNDARY["where"], BOUNDARY["not_listed"], _VALUES["fh"]) = saved


def sealed_text(text, kind="text", field=""):
    """The exact text an answer prints for the string `text` of a field of type `kind`: the layers, then the backstop (a string it replaces comes
    out as its placeholder). Nothing is counted, listed or written to the values file: this is for what must see what the answer shows (a
    `contains` filter, the order of a list)."""
    if not isinstance(text, str) or not text:
        return text
    return _quietly(lambda: _seal(text, kind, field, (), True))


def print_order(items, kind="name", text=str):
    """`items` in the order an answer prints them: by the text the answer PRINTS for each (the layers and the backstop, sealed_text), and the items
    whose text is the same placeholder in a random order that is new for every run. The rank of the withheld texts themselves (the order `sorted`
    would give, the order a directory or a hive lists them in) must never show in what an answer lists. `kind` is the kind of the field the items
    are printed in; `text` gives the string of an item."""
    def judge():
        out = []
        for n, i in enumerate(items):
            raw = text(i)
            shown = _seal(raw, kind, "", (), True) if isinstance(raw, str) and raw else raw
            out.append((shown, hashlib.blake2b(_ORDER_SALT + raw.encode("utf-8", "surrogatepass"), digest_size=8).digest(), n, i))
        return out
    items = list(items)
    keyed = _quietly(judge)
    keyed.sort(key=lambda k: (k[0], k[1], k[2]))
    return [k[3] for k in keyed]


def contains_check(needle_lower, text, kind="text", field=""):
    """(matched, blind) for a `contains` filter: the needle is looked for in the text the answer will PRINT for `text` (sealed_text: after the layers
    AND the backstop), never in what either of them withheld or replaced, so that a count of matches cannot tell a true guess of a hidden piece from
    a wrong one. `blind` is true when it was not found and that text holds a placeholder: the needle may be in what is hidden. It is the same
    whatever the needle, so counting it opens no way to test a guess."""
    sealed = sealed_text(text, kind, field)
    if needle_lower in sealed.lower():
        return True, False
    return False, _MARK.search(sealed) is not None


# ---- layer 3: the backstop, written apart from the layers above ------------------------------------------------------------------------
_S_ESC = re.compile(r"(?<!\\)\\+(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|[uU]\{([0-9a-fA-F]{1,8})\}|x([0-9a-fA-F]{2}))")
_S_FILL = "\u115f\u1160\u3164\uffa0\u2800"


def _s_gone(c):
    cat = unicodedata.category(c)
    return cat[0] == "C" or cat in ("Mn", "Me", "Zl", "Zp") or c in _S_FILL


def _s_unesc(m):
    try:
        c = chr(int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if _s_gone(c) else m.group(0)


def _s_normal(text):
    if "\\u" in text or "\\U" in text or "\\x" in text:
        text = _S_ESC.sub(_s_unesc, text)
    if text.isascii() and text.isprintable():
        return text
    kept = [c for c in text if not _s_gone(c)]
    return unicodedata.normalize("NFKC", "".join(kept))


_S_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY|PRIVATE KEY-----")
_S_DELIM = re.compile(r"[=:]")
_S_NAME_WORDS = ("pass", "pw", "auth", "sig", "sas", "secret", "token", "credential", "key", "psk", "otp", "bearer", "community", "dsn", "pin", "connection_string", "webhook_url")        # a name that ends in a word of _S_STRONG or _S_WEAK holds one of these
_S_FLAGWORD = (r"(?:[a-z0-9]{1,20}[-_]){0,4}(?:passw(?:or)?d|passwd|pass(?:[-_]?phrase)?|pwd|pw|otp|[a-z0-9]{0,20}secret[a-z0-9]{0,20}|[a-z0-9]{0,20}token|api[-_]?key|access[-_]?key|key|keypass|storepass|userpass|auth|authorization|bearer|psk|credentials?|community)")
_S_FLAGCAMEL = r"[A-Za-z0-9]{1,20}(?-i:Key|Token|Password|Passwd|Pwd|Pass|Passphrase|Secret)"
_S_NOVALUE = r"(?!<[^<>\s]{0,40}>(?:[\s;,]|$))(?![A-Za-z0-9_./~:-]{1,120}[.](?i:key|pem|pub|crt|p12|pfx|jks)(?![A-Za-z0-9]))(?!(?:~|[.]{1,2})/[A-Za-z0-9_./-]{1,120}|/[A-Za-z0-9_.-]{1,40}(?:/[A-Za-z0-9_.-]{1,40})+)"
_S_ARGNAME = re.compile(r"(?<![A-Za-z0-9])--?(?i:" + _S_FLAGWORD + r")[= ]" + _S_NOVALUE + r"\S|(?<![A-Za-z0-9])--?" + _S_FLAGCAMEL + r"[= ]" + _S_NOVALUE + r"\S")
_S_PREFIX_WORDS = ("akia", "asia", "agpa", "aida", "aroa", "anpa", "anva", "aipa", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xox", "xapp-",
                   "sk_live_", "rk_live_", "pk_live_", "sk_test_", "npm_", "pypi-", "shpat_", "dop_v1_", "aiza", "ya29.", "sg.", "sk-", "eyj")
_S_LINE = re.compile(r"[ \t]*line[ \t]+[0-9]")
_S_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_S_STRONG = ("password", "passwd", "passphrase", "passw", "pwd", "secret", "token", "credential", "apikey", "api_key", "api-key", "accesskey", "access_key", "access-key",
             "accountkey", "account_key", "account-key", "privatekey", "private_key", "private-key", "masterkey", "master_key", "sharedkey", "shared_key", "signingkey", "encryptionkey",
             "secretkey", "secret_key", "secret-key")
_S_WEAK = ("pass", "pw", "auth", "sig", "sas")
_S_NOT_PASS = ("bypass", "compass", "overpass", "underpass", "trespass", "encompass", "surpass", "impass")
_S_STRONG_ENDS = tuple(w + p for w in _S_STRONG for p in ("", "s"))       # a name that ends in one of these, or in one of them plural
_S_WEAK_ENDS = tuple(w + p for w in _S_WEAK for p in ("", "s"))
_S_NOT_PASS_ENDS = tuple(w + p for w in _S_NOT_PASS for p in ("", "s"))
_S_VALUEY_ENDS = ("psk", "otp", "bearer", "authorization", "sshkey", "ssh_key", "ssh-key", "snmp_community", "pass_word", "pass-word", "connection_string", "webhook_url", "dsn", "pin")        # names after which only a value built like a secret counts (a log line says `authorization: failed`)
_S_DIGITS = re.compile(r"[0-9]{19}")
_S_HEXRUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{40,}(?![0-9A-Za-z])")
_S_B64NOPAD = re.compile(r"[A-Za-z0-9+/]{20,}")
_S_B64PADPATH = re.compile(r"[A-Za-z0-9+/]{22,90}={1,2}(?![A-Za-z0-9+=])")
_S_B64PAD = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{15,}={1,2}(?![A-Za-z0-9+=])")
# in any case where an upper-case spelling of a lower-case prefix is a likely leak (the vendors' prefixes with a body of 12 or more characters)
_S_PREFIX = re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{12}|(?i:(?<![A-Za-z0-9])(?:akia|asia)[a-z0-9]{12}|(?:gh[pousr]_|github_pat_|glpat-|xox[a-z]-|xapp-|sk_live_|rk_live_|pk_live_|sk_test_)[A-Za-z0-9_-]{12})"
                       r"|(?:npm_|pypi-|shpat_|dop_v1_|AIza|ya29\.|SG\.)[A-Za-z0-9_-]{12}|sk-(?=[A-Za-z0-9_-]{0,39}[0-9])[A-Za-z0-9_-]{12}|eyJ[A-Za-z0-9_-]{12}")
_S_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_S_PWHOST = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9]{12,64})@[^\s/@<>\"']")
_S_USERINFO = re.compile(r"[^\s/@:<>\"']{1,64}:(?P<pw>[^\s/<>\"']{1,128})@[^\s/@<>\"']")
_S_USERINFO_MARK = re.compile(r"<>:(?P<pw>[^\s/<>\"']{1,128})@[^\s/@<>\"']")
_S_USERINFO_URL = re.compile(r"(?<=//)(?![^\s/@:<>\"']*:[0-9]{1,5}(?:[/?#@]|$))[^\s/@:<>\"']{1,64}:(?P<pw>[^\s<>\"']{1,128})@[^\s/@<>\"']")
_S_VALUE = re.compile(r"(?:[^\s\"'<>;,&]|[;,&](?![A-Za-z0-9_. -]{1,40}=)){1,512}")
_S_ARGVAL = re.compile(r"(?<![A-Za-z0-9])--?(?:(?i:" + _S_FLAGWORD + r")|" + _S_FLAGCAMEL + r")[= ]" + _S_NOVALUE + r"(\S{1,512})")
# `set password x` and `enable secret x`, and a value glued behind a placeholder (password=<redacted>x, --password <redacted>x, token: <secret>x)
_S_PH_SPACE = re.compile(r"(?:pass|pwd|secret|token|credential|key|auth|psk|otp|pw|sig|sas)[a-z]{0,10}[0-9]{0,2}[\"']?[ \t]{0,2}(?:[=:]|[ \t])[ \t]{0,2}<[^<>\s]{0,40}>[ \t]+([A-Za-z0-9]{8,40})(?![A-Za-z0-9])", re.I)
_S_GLUED = re.compile(r"(?<![A-Za-z0-9])--?(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?:(?i:key|token|pass|password|pwd|secret)|[A-Za-z]{1,20}(?:Key|Token|Pass|Password|Pwd|Secret))([A-Za-z0-9]{8,40})(?![A-Za-z0-9])")
_S_AUTHZ = re.compile(r"(?i:authorization)[\"']?[ \t]{0,2}[=:][ \t]{0,2}[\"']?(?i:token|bearer|basic|negotiate)[ \t]+[A-Za-z0-9+/._~=-]{8,}")
_S_T10TAIL = re.compile(r"t10[.][A-Za-z0-9_.+-]{0,100}?_([A-Za-z]{20,64})(?![A-Za-z0-9])|iqn[.][0-9]{4}-[0-9]{2}[.][a-z0-9.-]{1,60}:([A-Za-z]{20,64})(?![A-Za-z0-9])|iqn[.][0-9]{4}-[0-9]{2}[.]([A-Za-z]{20,64})(?![A-Za-z0-9])")
_S_SET = re.compile(r"(?<![\w-])(?:set|enable)[ \t]+(?:passw(?:or)?d|secret|passphrase|token)[ \t]+(?:[0-9][ \t]+)?[^\s<]", re.I)
_S_ANGLE = re.compile(r"(?:pass|pwd|secret|token|credential|key|auth|psk|otp|pw|sig|sas)[a-z]{0,10}[0-9]{0,2}[\"']?[ \t]{0,2}(?:[=:]|[ \t])[ \t]{0,2}<([A-Za-z0-9+/_.~=-]{6,128})>", re.I)
_S_PH_GLUED = re.compile(r"(?:pass|pwd|secret|token|credential|key|auth|psk|otp|pw|sig|sas)[a-z]{0,10}[0-9]{0,2}[\"']?[ \t]{0,2}(?:[=:]|[ \t])[ \t]{0,2}<[^<>\s]{0,40}>[^\s<>;,&\"']", re.I)
_S_PEMLINE = re.compile(r"[A-Za-z0-9+/=]{12,}")
_S_SHORTRUN = re.compile(r"[A-Za-z0-9]{16,19}")
_S_RUN = re.compile(r"[A-Za-z0-9+/_-]{20,}")
_S_HEX = re.compile(r"[0-9A-Fa-f-]+")
_S_IDS = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}|[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+Z?")
_S_MARK = re.compile(r"<withheld [0-9]{1,10} (?:characters|bytes)(?:: [a-z][a-z ,/+-]{0,60}(?:: [a-z][a-z ,/+-]{0,60})?)?>|\[withheld: [0-9]{1,10} (?:characters|bytes)\]")
_S_DIGEST_LABEL = re.compile(r"(?i)(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|imphash|hashes?|filehash|ssdeep|tlsh)[\"'=:> \t]{1,6}(?:(?:md5|sha-?1|sha-?256|imphash)=)?[0-9a-f]{32,128}")
_TYPED_KINDS = frozenset(("guid", "digest", "sid", "mac", "ip", "time", "number", "version", "hex", "label", "vmfs", "device", "iqn", "vmuuid", "cid", "winhost"))
# what a typed field may hold, by the characters of its type (apart from the grammar the first layer checks, and wider than it)
_S_TYPED = {
    "guid": re.compile(r"[0-9A-Fa-f{}-]{1,64}"), "sid": re.compile(r"[Ss0-9-]{1,400}"), "mac": re.compile(r"[0-9A-Fa-f:-]{1,64}"),
    "ip": re.compile(r"[0-9A-Fa-f:.]{1,64}(?:%[0-9A-Za-z_.-]{1,16})?"), "time": re.compile(r"[0-9TtZzDd:.,+' -]{1,64}"),
    "number": re.compile(r"-?[0-9.]{1,64}|0[xX][0-9A-Fa-f]{1,16}|true|false|null"), "version": re.compile(r"(?=.{1,64}\Z)[vV]?[0-9]+(?:\.[0-9A-Za-z]{1,16}){0,6}(?:[-+][0-9A-Za-z.]{1,32}){0,3}"),
    "digest": re.compile(r"(?:sha256:|sha1:|md5:)?[0-9A-Fa-f]{16,128}|T1[0-9A-Fa-f]{16,80}|[0-9]{1,6}:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+"),
    "vmfs": re.compile(r"[0-9A-Fa-f-]{1,40}"), "cid": re.compile(r"[0-9A-Fa-f]{1,16}"), "vmuuid": re.compile(r"[0-9A-Fa-f -]{1,64}"),
    "winhost": re.compile(r"[Ww][Ii][Nn]-[A-Za-z0-9]{1,16}"), "iqn": re.compile(r"iqn\.[0-9A-Za-z.:_-]{1,120}"),
    "device": re.compile(r"(?:naa|eui|vml|t10)\.[A-Za-z0-9_.+-]{1,130}|wwn-0x[0-9A-Fa-f]{1,32}"),
}
_S_LONG = re.compile(r"[A-Za-z0-9+/_-]{19}")           # the shortest run any check below needs (19 digits); the hexadecimal run needs 40, the others 20
_S_PLAIN_NUM = re.compile(r"[0-9TZ:.+ -]+")
_S_HEXONLY = re.compile(r"(?:[0-9A-Fa-f]{2})+")
_S_PRINT_L1 = re.compile(rb"[\x20-\x7e]{6,}")
_S_PRINT_U16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_S_PRINT_U16BE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")


def _class(c):
    return 0 if c.isdigit() else 1 if c.isupper() else 2


def _random_run(run, shortest=20):
    if _S_HEX.fullmatch(run):
        return False
    pieces = [p for p in re.split(r"[/_+-]", run) if p]
    alnum = "".join(pieces)
    if len(alnum) < shortest or max(len(p) for p in pieces) < 12:
        return False
    kinds = {_class(c) for c in alnum}
    if len(kinds) < 2:
        return False
    lower = [len(r) for r in re.findall(r"[a-z]+", alnum)]
    if lower and sum(lower) >= 3 * len(lower) and not re.search(r"[A-Z]{2}", alnum):
        return False
    changes = sum(1 for a, b in zip(alnum, alnum[1:]) if _class(a) != _class(b)) / (len(alnum) - 1)
    digit_runs = len(re.findall(r"[0-9]+", alnum))
    if kinds == {0, 1, 2}:
        return changes >= 0.42 or (changes >= 0.3 and digit_runs >= 4 and len(set(alnum)) >= 0.6 * len(alnum))
    if kinds == {1, 2}:
        return changes >= 0.5 and len(alnum) >= 24
    return changes >= 0.4 and digit_runs >= 5 and len(set(alnum)) >= 0.5 * len(alnum)


def _s_letters_random(word):
    """Letters of one case that no word is made of: some pair of them is one that words do not hold (the second check's own test of the serial of a t10. id and the target of an iqn. name)."""
    if not (word.islower() or word.isupper()):
        return False
    low = word.lower()
    return any(low[k:k + 2] not in _BIGRAMS for k in range(len(low) - 1))


def _s_valuey(tok):
    """Whether a run after a placeholder is built like a secret (the second check's own test): a digit among letters that is not a counter at the end, 8 or more digits, or letters with a pair no word holds."""
    body = tok.rstrip("0123456789")
    if not body:
        return len(tok) >= 8
    if len(tok) - len(body) > 4 or any(c.isdigit() for c in body):
        return True
    low = body.lower()
    return any(low[k:k + 2] not in _BIGRAMS for k in range(len(low) - 1)) or re.search("[^aeiouy]{4}", low) is not None


def _s_named(flat, values=None):
    """Whether `flat` holds a value after a secret's name; with a list, the values themselves are added to it (until it holds MAX_PIECES)."""
    pos, found = 0, False
    while True:
        m = _S_DELIM.search(flat, pos)
        if not m or (values is not None and len(values) >= MAX_PIECES):
            return found
        i = m.start()
        pos = m.end()
        after = flat[i + 1:i + 6].lstrip(" \t\"'\\")
        if not after or after[0] in "<>" or _S_LINE.match(flat, i + 1):
            continue
        j = i
        while j > 0 and flat[j - 1] in " \t\"'\\" and i - j < 5:
            j -= 1
        k = j
        while k > 0 and j - k < 64 and flat[k - 1] in _S_NAME_CHARS:
            k -= 1
        low = flat[k:j].lower()
        if low.endswith(_S_STRONG_ENDS) or (low.endswith(_S_WEAK_ENDS) and not low.endswith(_S_NOT_PASS_ENDS)):
            if values is None:
                return True
            found = True
            v = i + 1
            while v < len(flat) and flat[v] in " \t\"'\\" and v - i <= 6:
                v += 1
            vm = _S_VALUE.match(flat, v)
            if vm:
                values.append(vm.group())
        elif low.rstrip("0123456789").endswith(_S_VALUEY_ENDS) or low.rstrip("0123456789").endswith(_S_STRONG_ENDS):
            v = i + 1
            while v < len(flat) and flat[v] in " \t\"'\\" and v - i <= 6:
                v += 1
            vm = _S_VALUE.match(flat, v)
            if vm and _s_valuey(vm.group()):
                if values is None:
                    return True
                found = True
                values.append(vm.group())


def _s_hex_views(text):
    """The printable text inside data written as hexadecimal (Latin-1 runs of 6 or more, UTF-16LE and UTF-16BE runs of 4 or more), or None when `text` is not such data."""
    if len(text) < 2 or not _S_HEXONLY.fullmatch(text[:MAX_HEX_JUDGED]):
        return None
    try:
        raw = bytes.fromhex(text[:MAX_HEX_JUDGED])
    except ValueError:
        return None
    return ([m.group().decode("latin-1") for m in _S_PRINT_L1.finditer(raw)] + [m.group().decode("utf-16-le", "replace") for m in _S_PRINT_U16.finditer(raw)]
            + [m.group().decode("utf-16-be", "replace") for m in _S_PRINT_U16BE.finditer(raw)] + _wide_views(raw))


def _suspect(text, kind="text"):
    """The name of the check a string fails, or None. A string of a typed kind is not tested for runs of hexadecimal digits or random-looking runs, but
    for the characters of its type; data written as hexadecimal is decoded and its printable text is tested as text."""
    if not text or text in OWN_NAMES:
        return None
    if len(text) > MAX_ONE_STRING:
        text = text[:MAX_ONE_STRING]
    if kind == "hex":
        views = _s_hex_views(text)
        if views is not None:
            for view in views:
                hit = _suspect(view, "text")
                if hit:
                    return "in binary data: " + hit
            return None
        kind = "text"
    if kind in _S_TYPED and len(text) <= 64 and _S_PLAIN_NUM.fullmatch(text):
        # digits, `. : + -`, a space, T and Z: no rule above the typed grammar can fire on these (no name, no prefix, no `@`), so the grammar alone decides
        return None if len(text) <= 3 or _S_TYPED[kind].fullmatch(text) else "not the typed grammar"
    flat = _s_normal(text)
    if "withheld" in flat:
        flat = _S_MARK.sub("<>", flat)
    low = flat.lower()
    if "private key" in low and _S_PEM.search(flat):
        return "a PEM marker"
    bare = _S_IDS.sub(" ", flat) if "-" in flat else flat            # (all three kinds of id hold a `-`)
    bare = _mask_embedded(bare)
    named_words = _has(_S_NAME_WORDS, low)
    if named_words and _S_AUTHZ.search(flat):
        return "a named secret"
    if (named_words and ("=" in bare or ":" in bare) and _s_named(bare)) or ("-" in flat and named_words and _S_ARGNAME.search(flat))             or (named_words and "-" in flat and any(_s_valuey(m.group(1)) for m in _S_GLUED.finditer(flat)))             or (named_words and ("<" in flat and (_S_PH_GLUED.search(flat) or any(_s_valuey(x) for m in _S_ANGLE.finditer(flat) for x in _ANGLE_SPLIT.split(m.group(1))) or any(_s_valuey(m.group(1)) for m in _S_PH_SPACE.finditer(flat))) or ("set" in low or "enable" in low) and _S_SET.search(flat))):
        return "a named secret"
    if _has(_S_PREFIX_WORDS, low) and _S_PREFIX.search(flat):
        return "a token prefix"
    if ("t10." in flat or "iqn." in flat) and any(_s_letters_random(m.group(1) or m.group(2) or m.group(3)) for m in _S_T10TAIL.finditer(flat)):
        return "a random-looking run"
    if "@" in flat:
        flat_user = re.sub("(?i)mailto:", "mailto ", flat)
        if _S_USERINFO.search(flat_user) or _S_USERINFO_URL.search(flat_user) or _S_USERINFO_MARK.search(flat_user):       # (the last: a user that was replaced is still a user)
            return "user-info"
        for m in _S_PWHOST.finditer(flat_user):
            word = m.group(1)
            if len({_class(c) for c in word}) == 3 and sum(1 for a, b2 in zip(word, word[1:]) if _class(a) != _class(b2)) >= 0.3 * len(word):
                return "user-info"            # (the password of a user-info whose user was cut off at a colon: a long run of capitals, small letters and digits before the host)
    if kind in _TYPED_KINDS:
        grammar = _S_TYPED.get(kind)
        return "not the typed grammar" if grammar is not None and len(text) > 3 and not grammar.fullmatch(text) else None
    if 16 <= len(bare) <= 19 and _S_SHORTRUN.fullmatch(bare) and _random_run(bare, 16):
        return "a random-looking run"          # (a whole value of 16 to 19 characters: the length of a generated password, as the first layer takes it too)
    if "=" not in bare and not _S_LONG.search(bare):
        return None                       # no run of 19 characters of these, and no `=` for a padded run: none of the checks below can find anything
    if _S_DIGITS.search(bare):
        return "a long digit run"
    labelled = _S_DIGEST_LABEL.sub(" ", bare) if "ash" in low or "sha" in low or "md5" in low else bare
    if _S_HEXRUN.search(labelled):
        return "a long hexadecimal run"
    for m in _S_B64NOPAD.finditer(labelled):
        if "/" in m.group() and "+" in m.group() and len({_class(c) for c in m.group() if c.isalnum()}) == 3:
            return "a base64 run with / and +"
    for m in _S_B64PAD.finditer(labelled):
        body = m.group().rstrip("=")
        if len(m.group()) % 4 == 0 and re.search(r"[0-9+/]", body) and len({_class(c) for c in body}) >= 2 and (("/" in body or "+" in body) or len(body) >= 20):
            return "a padded base64 run"
    if "=" in labelled:
        for m in _S_B64PADPATH.finditer(labelled):
            # a padded key behind the `/` of a path (inputs/Zk0khEa1Ge/Do3O4Hd43iH==): the key is the last 22 (two pads) or 27 (one pad) characters before the padding
            pad = len(m.group()) - len(m.group().rstrip("="))
            tail = m.group().rstrip("=")[-(22 if pad == 2 else 27):]
            if len(tail) >= 22 and "/" in tail and len({_class(c) for c in tail if c.isalnum()}) >= 2:
                return "a padded base64 run"
    for m in _S_RUN.finditer(labelled):
        if _random_run(m.group()):
            return "a random-looking run"
    return None


def _where_text(where, names=True):
    return "/" + "/".join((w[0][:60] if names else str(w[1])) for w in where)


def _replace(value, where, check, positions=False):
    BOUNDARY["replaced"] += 1
    BOUNDARY["replaced_by"][check] += 1
    if len(BOUNDARY["where"]) < MAX_WHERE:
        # the place is the keys on the way, each of them already sealed; their joining is read once more, and when it is not clean the place is the
        # positions (a key that was replaced or withheld must never come back whole through the report of where something was replaced)
        at = _where_text(where, False) if positions else _where_text(where)
        if not positions and _suspect(at, "label"):
            at = _where_text(where, False)
        BOUNDARY["where"].append({"at": at, "check": check})
    else:
        BOUNDARY["not_listed"] += 1
    return _mark(len(value.encode("utf-8", "replace")), "backstop: %s" % check, "bytes")


_CHECKED = {}
_SHORT_PLAIN = re.compile(r"[A-Za-z0-9_.]{0,15}")      # what the late path may print unjudged: 15 characters or fewer of letters, digits, `_` and `.` (no space, no `-`, so no
                                                          # argument after a flag and no `xox?-` token), and not starting like a vendor token (_unjudged)


def _unjudged(text, kind=None):
    """Whether a string may be printed past the judging time: a name this run made itself (OWN_NAMES: its schema keys, its file names), or a short plain
    string that does not start like one of the vendor tokens the block knows (a prefix and 12 characters are 15) and, in a field of a typed kind (a SID, a
    GUID, a digest ...), fits the grammar of that type as the backstop checks it."""
    if text in OWN_NAMES:
        return True
    if _SHORT_PLAIN.fullmatch(text) is None or text.lower().startswith(_S_PREFIX_WORDS):
        return False
    grammar = _S_TYPED.get(kind)
    return grammar is None or len(text) <= 3 or grammar.fullmatch(text) is not None


def _late(n=0):
    """Whether judging must stop for the string about to be judged, which has `n` characters (counted against the cap of the run, unless the string is
    only being judged to see what an answer would print). It says why, once, in _STOP["by"]: the cap of characters, or the clock of the seal."""
    if n and not _QUIET[0]:
        _STOP["chars"] += n
        if _STOP["chars"] > _STOP["cap"]:
            if _STOP["by"] is None:
                _STOP["by"] = "the cap of %d characters judged in one run" % MAX_JUDGED_CHARS
            return True
    deadline = _CLOCK["deadline"]
    if deadline is not None and time.monotonic() > deadline:
        if _STOP["by"] is None:
            _STOP["by"] = "the judging time (the budget of one answer or row, or the seal stop of the tool)"
        return True
    return False


def _stopped(value, where):
    """A string not judged because judging stopped: withheld whole, by its size, counted (what is let through is only _unjudged)."""
    if not _QUIET[0]:
        _STOP["strings"] += 1
    return _replace(value, where, "the judging time ran out", True)


def seal_stop_after(seconds):
    """The seal stop of a tool: no seal runs on past `seconds` from now (its manifest's time limit less 3.5 seconds); what is left is withheld whole,
    except what _unjudged lets through. It stops the judging only, not the tool's own work: that has its own clock, which must run out first."""
    _CLOCK["stop"] = time.monotonic() + seconds


def _timed(fn):
    """`fn()` with the clock of the seal running: SEAL_BUDGET seconds from the outermost call, and never past the seal stop of the tool."""
    first = _CLOCK["deadline"] is None
    if first:
        _CLOCK["deadline"] = time.monotonic() + SEAL_BUDGET
        if _CLOCK["stop"] is not None:
            _CLOCK["deadline"] = min(_CLOCK["deadline"], _CLOCK["stop"])
    try:
        return fn()
    finally:
        if first:
            _CLOCK["deadline"] = None


# the name of a component of the Windows component store (WinSxS), as a whole name or as a component of a key or a path: architecture, words (lower case, letters up
# to 40 or letters and digits up to 16, with `.`, `-` or `_` between them, never a hexadecimal hash), the 16-digit public key token, a four-part version (not always
# there), a language or `none`, and a hash of 8 to 16 hexadecimal digits; a placeholder that layer 1 put in the place of a word, or of the architecture and a word (a
# 32-digit hash), stands for it. A real SOFTWARE hive lists them by the thousand and the backstop took their hash for a random run, so it judges the text with such a
# component taken out; layer 1 judges them as it does every name. Names, keys and paths only, lower case only; every alternative starts with a different character,
# so that a failing match is not retried in a second way.
_WORD = r"(?:[a-z]{1,40}|(?=[a-z0-9]*[0-9])[a-z0-9]{1,16}|<withheld [0-9]{1,10} (?:characters|bytes): not a plain name>)"
_WINSXS = re.compile(r"(?<![^\\/])(?:(?:amd64|x86|wow64|msil|arm64|arm|ia64)_(?![0-9a-f]+_)%s(?:[._-]{1,3}%s){0,12}|<withheld [0-9]{1,10} (?:characters|bytes): not a plain name>)"
                     r"_[0-9a-f]{16}(?:_[0-9]{1,5}(?:\.[0-9]{1,5}){3})?_[a-z0-9-]{2,12}_[0-9a-f]{8,16}(?![^\\/])" % (_WORD, _WORD))


def _without_components(text, kind):
    """`text` as the backstop judges a name, key or path: a component of the component store is one plain word."""
    return _WINSXS.sub("w", text) if kind in ("name", "key", "path") and text.count("_") >= 3 else text


def _verdict(text, kind):
    memo = (kind, text) if len(text) <= 512 and kind not in _S_TYPED else None
    hit = _CHECKED.get(memo, False) if memo else False
    if hit is False:
        hit = None if _MARK.fullmatch(text) else _suspect(_without_components(text, kind), kind)
        if memo:
            if len(_CHECKED) >= 30000:
                _CHECKED.clear()
            _CHECKED[memo] = hit
    return hit


# ---- the backstop reads the original too: what of a secret-shaped text is still in what was shown
def _pem_pieces(flat, found):
    """The base64 lines of the bodies of PEM keys: after each `PRIVATE KEY-----` (found with str.find, at most MAX_PIECES of them) up to the next
    `-----END` or MAX_PEM_BODY characters."""
    pos, bodies = 0, 0
    while bodies < MAX_PIECES and len(found) < MAX_PIECES:
        i = flat.find("PRIVATE KEY-----", pos)
        if i < 0:
            return
        start = i + 16
        end = flat.find("-----END", start, start + MAX_PEM_BODY)
        stop = start + MAX_PEM_BODY if end < 0 else end
        bodies += 1
        for m in _S_PEMLINE.finditer(flat, start, stop):
            found.append(m.group())
            if len(found) >= MAX_PIECES:
                return
        pos = max(stop, start)


def _s_pieces(flat, kind):
    """The parts of `flat` (the original text, normalised) the backstop's own rules call secret: a value after a secret's name, the password of
    user-info, a vendor token, a key's base64, and (outside typed fields) the long random-looking runs. At most MAX_PIECES of them, in this
    order; every walk over the text stops when the list is full."""
    found = []
    bare = _S_IDS.sub(" ", flat)
    _s_named(bare, found)
    for pattern, group in ((_S_ARGVAL, 1), (_S_USERINFO, "pw"), (_S_USERINFO_URL, "pw")):
        for m in pattern.finditer(flat):
            if len(found) >= MAX_PIECES:
                return found
            found.append(m.group(group))
    for m in _S_PREFIX.finditer(flat):
        if len(found) >= MAX_PIECES:
            return found
        end = m.end()
        stop = min(len(flat), end + 512)
        while end < stop and flat[end] in _S_TOKEN_CHARS:
            end += 1
        found.append(flat[m.start():end])
    _pem_pieces(flat, found)
    if kind not in _TYPED_KINDS:
        labelled = _S_DIGEST_LABEL.sub(" ", bare) if "ash" in bare or "sha" in bare.lower() or "md5" in bare.lower() or "ASH" in bare else bare
        for m in _S_B64PAD.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if _b64_shape(m.group()):
                found.append(m.group())
        for m in _S_HEXRUN.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            found.append(m.group())
        for m in _S_B64NOPAD.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if "/" in m.group() and "+" in m.group():
                found.append(m.group())
        for m in _S_RUN.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if _random_run(m.group()):
                found.append(m.group())
    return found


_RESIDUE = {}


def _residue_worthy(win):
    """Whether a window of a piece is a secret's and not the words of a path the piece ran into (a run of base64 characters takes in `/vmfs/volumes/ds1/` before a key): a window with a `/` needs 3 capitals, digits or `+`."""
    return "/" not in win or sum(1 for c in win if c.isupper() or c.isdigit() or c == "+") >= 3


def _residue(original, shown, kind):
    """A window of 12 characters (the whole piece when it is shorter, from 8) of something the backstop calls secret in the ORIGINAL that is still
    in what was shown: the layers above cut spans out of a string and can leave a piece of a secret between two cuts."""
    memo = (kind, original) if len(original) <= 512 else None
    if memo is not None and memo in _RESIDUE:
        return _RESIDUE[memo]
    verdict = None
    flat = _s_normal(original[:MAX_ONE_STRING])
    pieces = _s_pieces(flat, kind)[:MAX_PIECES]
    if pieces:
        kept = _S_MARK.sub("\x00", _s_normal(shown[:MAX_ONE_STRING]))
        rest = flat                                    # the original without those parts: a window that is also here is the text's own words, not the secret
        for piece in sorted(set(pieces), key=len, reverse=True):
            rest = rest.replace(piece, "\x00")
        for piece in pieces:
            n = len(piece)
            if n < 8:
                continue
            w = min(12, n)
            step = 1 if n * len(kept) <= 4000000 else max(1, (n - w + 1) // 64)       # a long piece in a long string: 64 windows, spread over it
            if any(piece[i:i + w] in kept and piece[i:i + w] not in rest and _residue_worthy(piece[i:i + w]) for i in range(0, n - w + 1, step)):
                verdict = "a part of a secret-shaped text"
                break
    if memo is not None:
        if len(_RESIDUE) >= 30000:
            _RESIDUE.clear()
        _RESIDUE[memo] = verdict
    return verdict


# ---- the walker ----------------------------------------------------------------------------------------------------------------------------
_SCALARS = (bool, int, float)
_SCALAR_TYPES = frozenset(_SCALARS)


_KEYS = {}


def _seal(value, kind, field, where, guard, fname=""):
    """`value` with every string sealed by the type of its field, and (guard) read back by the backstop. Keys are names. FIELDS maps a JSON key to the
    kind of what it holds, or to a function of the key of one item for a dict whose items have kinds of their own (event data, registry values).
    `where` is the tuple of (sealed key or position, position) on the way down."""
    if isinstance(value, str):
        k = getattr(value, "kind", kind)
        if _late(len(value)):
            # past the budget the rest is withheld whole, fail closed; what is let through is only a name of this run's own and a short plain string (_unjudged)
            return value if _unjudged(value, k) else _stopped(value, where)
        out = show(value, k, field)
        if guard:
            check = _verdict(out, k)
            if not check and out != value:
                check = _residue(str(value), out, k)
            if check:
                return _replace(out, where, check)
        return out
    if value is None or isinstance(value, _SCALARS):
        return value
    if isinstance(value, dict):
        hook = _field_entry(fname)
        hook = hook if callable(hook) else None
        kk = KEY_KINDS.get(fname, "name")
        out, dupes = {}, {}
        for idx, (key, v) in enumerate(value.items()):
            if isinstance(key, str):
                if _late(len(key)):
                    sk = key if _unjudged(key) else _stopped(key, where + (("(key)", idx),))
                else:
                    sk = _KEYS.get((kk, field, key, guard))
                    if sk is None:
                        sk = show(key, kk, field)
                        if guard:
                            check = _verdict(sk, kk)
                            if check:
                                sk = _replace(sk, where + (("(key)", idx),), check)
                        if sk == key and len(key) <= 128:
                            # a key that comes out as it went in changed nothing (no count, no list): its judging is not repeated for the next row
                            if len(_KEYS) >= 20000:
                                _KEYS.clear()
                            _KEYS[(kk, field, key, guard)] = sk
            elif key is None or isinstance(key, _SCALARS):
                sk = key
            else:
                key = str(key)
                sk = show(key, "name", field)
            if sk in out:
                # many names become one placeholder: the next free " #n" of that placeholder, counted (a probe from the first would be quadratic)
                n = dupes.get(sk, 1)
                while True:
                    n += 1
                    renamed = "%s #%d" % (sk, n)
                    if renamed not in out:
                        break
                dupes[sk] = n
                sk = renamed
            if v is None or type(v) in _SCALAR_TYPES:
                out[sk] = v                               # (a number, a truth value or nothing: there is no string to seal)
                continue
            fk = key if isinstance(key, str) else ""
            sub_kind = (hook(key) if hook else None) or _kind_of(fk, kind)
            label = sk if isinstance(sk, str) else str(sk)
            out[sk] = _seal(v, sub_kind, (field + "." + fk) if field and fk else (fk or field), where + ((label, idx),), guard, fk)
        return out
    if isinstance(value, (list, tuple)):
        return [_seal(v, kind, field, where + ((str(i), i),), guard, fname) for i, v in enumerate(value)]
    return _seal(str(value), "text", field, where, guard, fname)       # anything else the serialiser would have printed with str()


def _kind_of(field, inherited):
    k = _field_entry(field)
    return k if isinstance(k, str) else inherited


def seal(value, kind="text", field=""):
    return _timed(lambda: _seal(value, kind, field, (), True))


_ROW_TYPES = frozenset((str, int, float, bool))
_ROW = [None, None]             # the last row of plain scalars that was sealed without anything being replaced, and what it came out as


def row_object(row):
    """A row of a paging file, sealed and read back: what the file may hold. A tool that writes the same row to two files (every key listed, and
    the nodes of a walk) has it judged once: the second is the first's result, the same judging with nothing to count or list."""
    key = None
    if isinstance(row, dict):
        for k, v in row.items():
            if type(k) is not str or (v is not None and type(v) not in _ROW_TYPES):
                break
        else:
            # (the type is part of the key: 1, True and 1.0 are equal and print differently; a float by its repr, as -0.0 equals 0.0)
            key = tuple((k, type(v), repr(v) if type(v) is float else v) for k, v in row.items())
    if key is not None and _ROW[0] == key:
        return dict(_ROW[1])
    replaced = BOUNDARY["replaced"]
    out = _timed(lambda: _seal(row, "text", "", (), True))
    if key is not None and BOUNDARY["replaced"] == replaced:
        _ROW[0], _ROW[1] = key, dict(out)
    return out


def boundary_summary():
    stopped = {"stopped_by": _STOP["by"], "strings_withheld_by_the_stop": _STOP["strings"]} if _STOP["by"] is not None else {}
    return {"strings_withheld": BOUNDARY["withheld"], "withheld_by_reason": dict(BOUNDARY["by"]),
            "strings_replaced_by_the_backstop": BOUNDARY["replaced"], "replaced_by_check": dict(BOUNDARY["replaced_by"]),
            "replaced_at": list(BOUNDARY["where"]), "replaced_not_listed": BOUNDARY["not_listed"], "values": values_summary(), **stopped,
            "note": "every key and value of this answer and of its paging files was judged by the type of its field: a name, path, key or URL is shown only when it "
                    "fits a plain grammar (a path component by component), free text has token-shaped runs, user-info and the value after a secret's name withheld, "
                    "and a second check written apart from both read it back. A withheld text is <withheld N characters: reason>. Not recognised: a secret that does "
                    "not look like one (a plain password or passphrase, a UUID-shaped key, anything under 16 characters in a name)."}


def _last_look(obj):
    """What this block adds to an answer after the walker (the report of what it did) is read once more by the backstop, keys and values."""
    if isinstance(obj, str):
        return _mark(len(obj), "backstop: a part of a secret-shaped text") if _suspect(obj, "label") else obj
    if isinstance(obj, dict):
        return {_last_look(k): _last_look(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_last_look(v) for v in obj]
    return obj


def answer_object(doc):
    """The answer (or an error answer), sealed and read back. A string the backstop had to replace makes a complete answer partial."""
    _STOP["cap"] = max(_STOP["cap"], _STOP["chars"]) + FINAL_GRACE_CHARS            # (the final answer is always judged: the cap of the run does not take it)
    out = _timed(lambda: _seal(doc, "text", "", (), True))
    if isinstance(out, dict):
        out["boundary"] = _last_look(boundary_summary())
        if (BOUNDARY["replaced"] > 0 or _STOP["by"] is not None) and out.get("status") == "complete":
            out["status"] = "partial"
            basis = out.get("status_basis")
            why = []
            if BOUNDARY["replaced"] > 0:
                why.append("%d string(s) still held a secret-shaped text when the answer was checked on its way out and were replaced" % BOUNDARY["replaced"])
            if _STOP["by"] is not None:
                why.append("judging the strings stopped at %s: %d string(s) after it were withheld by their size" % (_STOP["by"], _STOP["strings"]))
            out["status_basis"] = "%s%s (see boundary)" % (basis + "; " if isinstance(basis, str) and basis else "", "; ".join(why))
    return out


def emit(doc, **dumps_kwargs):
    """Print an answer through the boundary (the only way an answer leaves a tool that carries this block)."""
    obj = answer_object(doc)
    try:
        text = json.dumps(obj, ensure_ascii=False, default=str, **dumps_kwargs)
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = json.dumps(obj, ensure_ascii=True, default=str, **dumps_kwargs)
    try:
        # a signal that arrives while the answer is being written must not start a second one: signals are held from here (the answer is whole)
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    print(text, flush=True)
# END SHARED BOUNDARY
# ---- this tool's side of the one way out ------------------------------------------------------------------------------------------------
# The table of field kinds is this tool's, not the block's: a JSON key or the label a call site gives the Shower -> the kind of what it holds
# (a digit run in a name stands for any number: ethernet0.address is ethernet#.address). A field not listed has the kind of the key above it (text at the
# top: a description, an annotation, an audit action or actor, a message, a tool's own words are judged as free text).
_FIELD_KINDS = (
    # a name a person chose (a machine, a snapshot, a datastore): may hold a `/` (a date in a snapshot name), so it is judged as a path, component by component
    ("path", "name|display_name|displayName|snapshot name|parent snapshot name|current_parent_snapshot|snapshot_sections|snapshot|version"
             "|file|leaf_file|rel|root|links|special|unreadable|too_deep|lock directory|parent_hint|parentFileNameHint|parent name|parent_name|backing_file|backing_filename"
             "|external_data_file|parent_absolute_win32_path|parent_relative_path|parent_volume_path|disk_files|snapshot disk file|state_file|snapshot state file"
             "|extent file name|configuration_path|vmxCfgPath|datastore_hint|datastore path|nvram|disk file|volume|vm_state_volume|vmstate|path|named|export|special_sections|section|disk source|source_name|object"),
    ("name", "domain_name|job|storage|storage name|networkName|ethernet#.networkName|disk key|domain name|datastore|pool|vgname|thinpool|key"
             "|create_type|createType|encoding|backing_format|backing format|native_snapshot|isNativeSnapshot|hardware_version|config_version|arch|bios|firmware|machine"
             "|os_type|virt_type|guest_os|guestOS|cores|vcpus|memory_mb|memory|device|device_type|deviceType|disk_format|mode|present|snapshot_mode|bus|backup|size|state|type"
             "|source_protocol|ddb.adapterType|ddb.virtualHWVersion|ddb.toolsVersion|ddb.thinProvisioned|time_raw|createTimeHigh|createTimeLow|create_time_high_raw"
             "|create_time_low_raw|extent type|type_raw|content|shared|disable|maxfiles|mkdir|is_mountpoint|nodes|ethernet#.virtualDev|ethernet#.present|ethernet#.addressType"),
    # an identifier: one of several forms (a GUID, a VMFS volume id, a device id, a VMware uuid, a MAC, a content id, a number), else a name
    ("id", "uid|snapshot uid|snapshot parent|snapshot id|parent_uid|uuid|bios_uuid|location_uuid|vcenter_instance_uuid|cid_raw|parent_cid_raw|CID|parentCID|entry_id|object_id|vmid"
           "|ddb.uuid|ddb.longContentID|current|lastuid|lastUID|numsnapshots|numSnapshots|source_id|own_id|leaf|base|child|ethernet#.address|ethernet#.generatedAddress|address"
           "|virtual_disk_id|unique_id|parent_unique_id|data_write_guid|file_write_guid|log_guid|parent_identity|parent_identity_2|recorded_by_child|carried_by_parent|descriptor_id"),
)
_FIELD_TABLE = {}
for _kind, _names in _FIELD_KINDS:
    for _n in _names.split("|"):
        _FIELD_TABLE[_n] = _kind
bind_fields(_FIELD_TABLE, {})
OWN_NAMES.update(VOCABULARY)        # a word of the tool's own closed vocabulary is shown as it is
RUN = {"record": True}              # the Shower of the COMMON block sets this; the originals of what the boundary withheld are written by the block itself (bind_values)
_DIGIT_RUN = re.compile(r"[0-9]+")


def field_kind(field):
    """The kind of the field a call site names (the label the Shower is given): the table above, `text` for a field it does not list."""
    if not isinstance(field, str) or not field:
        return "text"
    kind = _FIELD_TABLE.get(field)
    if kind is None and any(c.isdigit() for c in field):
        kind = _FIELD_TABLE.get(_DIGIT_RUN.sub("#", field))
    return kind or "text"


# The calls the COMMON block makes (it stays as it is in the three tools): each is the one text's call under the name COMMON uses.
def seal_text(text, kind="text", field=None, where=""):
    """One string judged by the kind of its field, the layers and the backstop (counted; the original goes to the values file when one was asked for)."""
    return seal(text if isinstance(text, str) else str(text), field_kind(field), field or "")


def seal_head(text, kind="text", field=None, where=""):
    """seal_text for a text a call site reads a piece of: at most the first Shower.EXAMINED characters are judged and a longer text is shown with its whole length."""
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= Shower.EXAMINED:
        return seal_text(text, kind, field, where)
    return seal_text(cut_safely(text, Shower.EXAMINED), kind, field, where) + "...(whole text: %d characters)" % len(text)


def big_ints(value, depth=0):
    """`value` with every integer of more than 18 digits turned into text (the one text then withholds it as a long number): no format this pack reads carries one,
    and its digits can be a secret's. A structure deeper than 64 levels is written as text."""
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value) if abs(value) >= 10 ** 18 else value
    if depth > 64 and isinstance(value, (dict, list, tuple)):
        return json.dumps(value, default=str)
    if isinstance(value, dict):
        return {k: big_ints(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [big_ints(v, depth + 1) for v in value]
    return value


def row_text(row, where=""):
    """One row of a paging file: sealed, read back by the backstop, serialised."""
    return json.dumps(row_object(big_ints(row)))


def answer_text(doc):
    """An answer that COMMON prints itself (an error answer, the last word of a signal): sealed and read back, with the values file closed."""
    text = json.dumps(answer_object(big_ints(doc)), indent=2)
    close_values()
    return text
# BEGIN SHARED FILES
# The same text is in virtualization_inventory and snapshot_chain_check; tests/pack-virtualization-shared.test.ts holds the
# copies equal. The evidence is a set of files: a directory walked without following a link, and/or files named one by one.
# Nothing outside that set is ever opened, whatever a file inside it names.


def open_regular(path):
    """Open a regular file for reading without following a final link and without blocking on a pipe; None and the
    reason when it is not one."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        return None, describe(exc)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None, "not a regular file"
    except OSError as exc:
        os.close(fd)
        return None, describe(exc)
    return os.fdopen(fd, "rb"), None


class FileSet:
    """The files an examination covers, in a fixed order (names sorted), each with an id that is a sequence number and
    derived from nothing. What was not reached is counted and named: a link, a special file, a directory too deep, a
    listing that was cut at a cap."""

    def __init__(self, shower):
        self.files = []
        self.by_rel = {}
        self.shower = shower
        self.skipped = {"links": [], "special": [], "unreadable": [], "too_deep": []}
        self.skipped_counts = {"links": 0, "special": 0, "unreadable": 0, "too_deep": 0}
        self.lock_dirs = []
        self.lock_dirs_total = 0
        self.entries_seen = 0
        self.truncated = None
        self.root_shown = None

    def note(self, which, rel):
        self.skipped_counts[which] += 1
        if len(self.skipped[which]) < 200:
            self.skipped[which].append(self.shower(rel, "walk", which))

    def add_file(self, rel, path, size):
        if len(self.files) >= self.max_files:
            self.truncated = self.truncated or "max_files (%d) was reached: the files after the last one listed were not examined" % self.max_files
            return False
        fid = "S%06d" % (len(self.files) + 1)
        rec = {"id": fid, "rel": rel, "path": path, "size": size}
        self.files.append(rec)
        self.by_rel[rel] = rec
        return True

    def walk(self, root, paths, max_files, max_entries, max_depth, clock):
        self.max_files = max_files
        if root is not None:
            if os.path.islink(root):
                fail("refusing a symlink root: pass the evidence directory itself", root=root)
            if not os.path.isdir(root):
                fail("root is not a directory", root=root)
            self.root_shown = self.shower(root, "root", "root")
            stack = [("", 0)]
            while stack:
                rel_dir, depth = stack.pop()
                clock.check()
                here = os.path.join(root, rel_dir) if rel_dir else root
                try:
                    with os.scandir(here) as it:
                        entries = list(itertools.islice(it, max_entries - self.entries_seen + 1))
                except OSError as exc:
                    self.note("unreadable", (rel_dir or ".") + ": " + describe(exc))
                    continue
                if self.entries_seen + len(entries) > max_entries:
                    entries = entries[:max(0, max_entries - self.entries_seen)]
                    self.truncated = self.truncated or "max_entries (%d) was reached: the directories after the last one listed were not read" % max_entries
                    stack = []
                self.entries_seen += len(entries)
                entries.sort(key=lambda e: e.name)
                subdirs = []
                for e in entries:
                    clock.check(256)
                    rel = (rel_dir + "/" + e.name) if rel_dir else e.name
                    try:
                        if e.is_symlink():
                            self.note("links", rel)
                        elif e.is_dir(follow_symlinks=False):
                            if e.name.lower().endswith(".lck") or e.name.lower().startswith(".lck-"):
                                self.lock_dirs_total += 1
                                if len(self.lock_dirs) < 1000:
                                    self.lock_dirs.append(rel)
                            if depth + 1 > max_depth:
                                self.note("too_deep", rel)
                            else:
                                subdirs.append((rel, depth + 1))
                        elif e.is_file(follow_symlinks=False):
                            self.add_file(rel, os.path.join(root, rel), e.stat(follow_symlinks=False).st_size)
                        else:
                            self.note("special", rel)
                    except OSError as exc:
                        self.note("unreadable", rel + ": " + describe(exc))
                for item in reversed(subdirs):
                    stack.append(item)
                if self.truncated and "max_entries" in self.truncated:
                    break
        for p in paths:
            clock.check()
            try:
                st = os.lstat(p)
            except OSError as exc:
                self.note("unreadable", p + ": " + describe(exc))
                continue
            if stat.S_ISLNK(st.st_mode):
                self.note("links", p)
            elif not stat.S_ISREG(st.st_mode):
                self.note("special", p)
            else:
                rel = p
                if rel not in self.by_rel:
                    self.add_file(rel, p, st.st_size)

    def skipped_summary(self):
        return {"counts": dict(self.skipped_counts), "named": self.skipped,
                "note": "A link is listed and never followed; a special file is never opened; at most 200 of each are named, all are counted."}
class Index:
    def __init__(self, files):
        self.exact = {f["rel"]: f for f in files}
        self.fold = collections.defaultdict(list)
        self.base = collections.defaultdict(list)
        for f in files:
            self.fold[f["rel"].casefold()].append(f)
            self.base[posixpath.basename(f["rel"]).casefold()].append(f)

    def resolve(self, from_rel, hint):
        """(file or None, how). The hint is a string some file wrote; it is looked up among the files given and never opened."""
        if not hint or "\x00" in hint:
            return None, "no_name"
        h = hint.replace("\\", "/") if ("\\" in hint and "/" not in hint) else hint
        drive = bool(re.match(r"^[A-Za-z]:", h)) or h.startswith("/") or h.startswith("//") or h.startswith("vmfs/") or h.startswith("[")
        joined = None
        if not drive:
            joined = posixpath.normpath(posixpath.join(posixpath.dirname(from_rel), h))
            if joined.startswith("../") or joined == "..":
                joined = None
        if joined is not None:
            f = self.exact.get(joined)
            if f:
                return f, "relative_exact"
            hits = self.fold.get(joined.casefold(), [])
            if len(hits) == 1:
                return hits[0], "relative_case_insensitive"
        hits = self.base.get(posixpath.basename(h.rstrip("/")).casefold(), [])
        if len(hits) == 1:
            return hits[0], "basename_only"
        if len(hits) > 1:
            return None, "ambiguous_basename"
        return None, "not_in_set"


EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,10}")


def ext_of(rel):
    """The extension a file is counted under: a short one of letters and digits as it is (lower case), none as (none),
    and any other under one bucket that shows nothing of it (a file name can carry a token after its last dot)."""
    ext = posixpath.splitext(posixpath.basename(rel))[1]
    if not ext:
        return "(none)"
    return ext.lower() if EXTENSION.fullmatch(ext) else "(other extensions)"
# END SHARED FILES


def iso_epoch(value):
    try:
        number = int(str(value).strip())
        return datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc).__add__(datetime.timedelta(seconds=number)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError):
        return None


# ---- XML, bounded ----------------------------------------------------------------------------------------------------

class Node:
    __slots__ = ("tag", "attrib", "text", "kids")

    def __init__(self, tag, attrib):
        self.tag, self.attrib, self.text, self.kids = tag, attrib, None, []

    def __iter__(self):
        return iter(self.kids)


def load_xml(source, limit):
    """(root Node, None) or (None, reason). `source` is read in chunks, never whole. Built on expat directly: a DOCTYPE or an entity declaration is refused whatever the
    encoding, no external entity is fetched, and the element count, the depth and the text of one element are bounded."""
    import xml.parsers.expat as expat

    def refuse(*_a):
        raise ValueError("a DOCTYPE or ENTITY declaration is refused: no entity is expanded")
    state = {"root": None, "count": 0, "stack": []}

    def start(tag, attrs):
        state["count"] += 1
        if state["count"] > MAX_XML_ELEMENTS:
            raise ValueError("more than %d elements" % MAX_XML_ELEMENTS)
        if len(state["stack"]) >= MAX_XML_DEPTH:
            raise ValueError("nested deeper than %d" % MAX_XML_DEPTH)
        node = Node(tag, attrs)
        if state["stack"]:
            state["stack"][-1].kids.append(node)
        elif state["root"] is None:
            state["root"] = node
        state["stack"].append(node)

    def end(_tag):
        state["stack"].pop()

    def chars(text):
        if state["stack"]:
            node = state["stack"][-1]
            if node.text is None or len(node.text) < (1 << 20):
                node.text = (node.text or "") + text

    parser = expat.ParserCreate()
    parser.buffer_text = True
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    total = 0
    try:
        while True:
            chunk = source.read(65536)
            total += len(chunk)
            if total > limit:
                raise ValueError("the file is over max_file_bytes (%d)" % limit)
            if not chunk:
                break
            parser.Parse(chunk, False)
        parser.Parse(b"", True)
    except (expat.ExpatError, ValueError, LookupError, RecursionError, MemoryError) as exc:
        # an encoding the reader does not know (LookupError) is this file's failure, never the run's
        return None, "not well-formed, in an encoding the reader does not know, or over a limit (%s)" % brief(exc, 160)
    return state["root"], None


def local(tag):
    return tag.rsplit(":", 1)[-1] if isinstance(tag, str) else ""


def child(el, name):
    for c in el:
        if local(c.tag) == name:
            return c
    return None


def children(el, name):
    return [c for c in el if local(c.tag) == name]


def text_of(el, name):
    c = child(el, name)
    return (c.text or "").strip() if c is not None else None


# ---- the sink: every record passes through here ----------------------------------------------------------------------

class Sink:
    def __init__(self, limit, shown, index, clock):
        self.shown, self.index, self.clock = shown, index, clock
        self.long_lines = collections.Counter()        # file id -> lines of MAX_LINE bytes or more, which no parser reads
        self.long_first = {}                           # file id -> the first such line
        self.pages = {k: LosslessPage(TOOL, k, limit) for k in ("vms", "disks", "snapshots", "datastores", "hosts", "sources")}
        self.counts = collections.Counter()
        self.seq = collections.Counter()
        self.per_file = collections.Counter()
        self.over_cap = collections.Counter()
        self.current_file = None

    def new_id(self, prefix):
        self.seq[prefix] += 1
        return "%s%06d" % (prefix, self.seq[prefix])

    def clean(self, value, key=None, depth=0):
        """The net under every record: a string from the evidence that no call site has checked is checked here."""
        if isinstance(value, str):
            if isinstance(value, Shown) or key in TOOL_BUILT or SAFE_VALUE.fullmatch(value):
                return value
            return self.shown(value, self.current_file["id"], key)
        if key in TOOL_BUILT or depth > 5:
            return value
        if isinstance(value, dict):
            return {k: self.clean(v, k, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [self.clean(v, key, depth + 1) for v in value]
        return value

    def emit(self, kind, row):
        self.clock.check(64)                    # a file of a hundred thousand records is read inside max_seconds too
        row = self.clean(row)
        fid = self.current_file["id"]
        if self.per_file[fid] >= MAX_RECORDS_PER_FILE:
            self.over_cap[fid] += 1
            return None
        self.per_file[fid] += 1
        self.counts[kind] += 1
        row = {"id": self.new_id({"vms": "V", "disks": "D", "snapshots": "N", "datastores": "T", "hosts": "H"}[kind]), "source_id": fid, **row}
        self.pages[kind].add(row)
        return row["id"]

    def disk_ref(self, vm, rel, name, file_like=True, **fields):
        """A disk file a configuration names: checked against the files given, and nothing else. A storage volume of a
        hypervisor (an LVM volume, a Ceph image) is not a file: it is listed and not looked up."""
        target, how = None, "no_name"
        if name and file_like:
            target, how = self.index.resolve(rel, name)
        elif name:
            how = "storage_volume_not_a_file"
        row = {"vm": vm, "file": self.shown(name, self.current_file["id"], "disk file") if name is not None else None,
               "in_set": ("yes" if target else ("ambiguous" if how == "ambiguous_basename" else "no")) if (name and file_like) else ("not_a_file" if name else "no_name"),
               "found": target["id"] if target else None, "how": how if name else "no_name", **fields}
        if how == "basename_only":
            row["in_set_note"] = "matched by file name alone: the configuration's path is not a path in the set"
        return self.emit("disks", row)


# ---- VMware ----------------------------------------------------------------------------------------------------------

CONFIG_KV = re.compile(r'^\s*([A-Za-z0-9_.:\-]+)\s*=\s*"(.*)"\s*$')


def read_lines(fh, sink):
    """(line number, text) a line at a time; None as the text past MAX_LINES. A line of MAX_LINE bytes or more is not read: it is
    counted for its file in the sink (long_lines, long_first), which makes the file partial, and yields an empty text."""
    n = 0
    fid = sink.current_file["id"]
    while True:
        sink.clock.check(256)
        raw = fh.readline(MAX_LINE + 1)
        if not raw:
            return
        n += 1
        if n > MAX_LINES:
            yield n, None
            return
        if len(raw) > MAX_LINE:
            while raw and not raw.endswith(b"\n"):
                raw = fh.readline(MAX_LINE)
            sink.long_lines[fid] += 1
            sink.long_first.setdefault(fid, n)
            yield n, ""
            continue
        yield n, raw.decode("utf-8", "surrogateescape").rstrip("\r\n")


def key_report(not_shown, sensitive):
    return {"keys_not_shown": not_shown, "keys_that_look_like_credentials": [dict({"name": e[0], "line": e[1], "value_chars": e[2]}, **({"section": e[3]} if len(e) > 3 else {}))
                                                                             for e in sensitive[:MAX_NAMED_KEYS]],
            "credential_like_keys_total": len(sensitive),
            "note": "a value under such a key is at that line of the file, not in this answer; treat it as a secret to rotate"}


def parse_vmx(fh, sink, rec, shown):
    shown_vals, devices, not_shown, sensitive, bad, capped = {}, collections.OrderedDict(), 0, [], 0, False
    for n, line in read_lines(fh, sink):
        if line is None:
            capped = True
            break
        m = CONFIG_KV.match(line)
        if not m:
            bad += 1 if line.strip() and not line.lstrip().startswith("#") else 0
            continue
        key, value = m.group(1), m.group(2)
        low = key.lower()
        dm = VMX_DEVICE.match(key)
        if low in VMX_SHOWN or VMX_ETHERNET.match(key):
            shown_vals[key] = (value, n)
        elif dm and dm.group(2).lower() in VMX_DEVICE_SHOWN:
            devices.setdefault(dm.group(1), {})[dm.group(2).lower()] = (value, n)
        else:
            not_shown += 1
            if SENSITIVE_KEY.search(key):
                sensitive.append((shown(key, rec["id"], "key"), n, len(value)))
    get = lambda k: shown_vals.get(k, (None, None))[0]
    lowered = {k.lower(): v for k, v in shown_vals.items()}
    vm = sink.emit("vms", {"format": "vmx", "name": shown(lowered.get("displayname", (None,))[0], rec["id"], "displayName"), "guest_os": shown(lowered.get("guestos", (None,))[0], rec["id"], "guestOS"),
                           "config_version": lowered.get("config.version", (None,))[0], "hardware_version": lowered.get("virtualhw.version", (None,))[0],
                           "bios_uuid": lowered.get("uuid.bios", (None,))[0], "location_uuid": lowered.get("uuid.location", (None,))[0],
                           "vcenter_instance_uuid": lowered.get("vc.uuid", (None,))[0], "memory_mb": lowered.get("memsize", (None,))[0], "vcpus": lowered.get("numvcpus", (None,))[0],
                           "firmware": lowered.get("firmware", (None,))[0], "nvram": shown(lowered.get("nvram", (None,))[0], rec["id"], "nvram"),
                           "network_adapters": sorted({k.split(".")[0] for k in shown_vals if VMX_ETHERNET.match(k)}),
                           "network": {k: shown(v[0], rec["id"], k) for k, v in shown_vals.items() if VMX_ETHERNET.match(k)},
                           "locator": {"file": rec["id"], "first_line": 1}, **key_report(not_shown, sensitive)})
    if vm is None:
        return "partial", "record cap reached"
    for dev, fields in devices.items():
        name, line = fields.get("filename", (None, None))
        if name is None:
            continue
        raw_type = fields.get("devicetype", (None,))[0]
        kind = (raw_type or "").lower()        # folded for the comparison only: the value is shown as written, through the shape check
        sink.disk_ref(vm, rec["rel"], name, device=dev, device_type=shown(raw_type, rec["id"], "deviceType") if raw_type else None, present=fields.get("present", (None,))[0],
                      mode=fields.get("mode", (None,))[0], locator={"file": rec["id"], "line": line},
                      role="optical or image" if "cdrom" in kind or name.lower().endswith(".iso") else "disk")
    if capped:
        return "partial", "the file has more than %d lines: read to that point, and what was read is listed" % MAX_LINES
    return ("parsed", None) if not bad else ("parsed", "%d line(s) were neither a key = \"value\" line nor a comment: counted, not read" % bad)


def parse_vmsd(fh, sink, rec, shown):
    entries, top, over, capped = collections.OrderedDict(), {}, 0, False
    for n, line in read_lines(fh, sink):
        if line is None:
            capped = True
            break
        m = CONFIG_KV.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        low = key.lower()
        if low in ("snapshot.numsnapshots", "snapshot.current", "snapshot.lastuid"):
            top[low.split(".", 1)[1]] = value
            continue
        sm = re.match(r"^snapshot(\d+)\.(.+)$", key, re.I)
        if not sm:
            continue
        idx = int(sm.group(1))
        if idx not in entries:
            if len(entries) >= MAX_RECORDS_PER_FILE:
                over += 1
                continue
            entries[idx] = {"index": idx, "line": n, "disks": []}
        sub, e = sm.group(2).lower(), entries[idx]
        dm = re.match(r"^disk(\d+)\.(.+)$", sub)
        if dm:
            if dm.group(2) == "filename":
                e["disks"].append((value, n))
        elif sub in ("uid", "filename", "displayname", "parent", "createtimehigh", "createtimelow", "description", "type"):
            e[sub] = (value, n)
    for e in entries.values():
        sid = sink.emit("snapshots", {"vm": None, "format": "vmsd", "index": e["index"], "uid": e.get("uid", (None,))[0], "parent_uid": e.get("parent", (None,))[0],
                                      "name": shown(e.get("displayname", (None,))[0], rec["id"], "displayName"),
                                      "description_present": "description" in e, "state_file": shown(e.get("filename", (None,))[0], rec["id"], "snapshot state file"),
                                      "time_raw": {"createTimeHigh": e.get("createtimehigh", (None,))[0], "createTimeLow": e.get("createtimelow", (None,))[0]},
                                      "time_utc": None, "time_basis": "two raw fields as written; how they encode a time is not decoded here",
                                      "snapshot_database": {"numSnapshots": top.get("numsnapshots"), "current": top.get("current"), "lastUID": top.get("lastuid")},
                                      "locator": {"file": rec["id"], "line": e["line"]}})
        for name, line in e["disks"]:
            sink.disk_ref(sid, rec["rel"], name, role="snapshot disk", locator={"file": rec["id"], "line": line})
    if capped:
        return "partial", "the file has more than %d lines: read to that point, and what was read is listed" % MAX_LINES
    if over:
        return "partial", "%d snapshot index(es) past the cap of %d were counted and not listed" % (over, MAX_RECORDS_PER_FILE)
    return "parsed", None


def vmware_path(path):
    """The datastore a /vmfs/volumes/<datastore>/... path names, which is all this tool takes from the path. The piece
    is taken from the path AFTER the whole was withheld by shape: a token split at `/` is withheld as one, never shown
    piece by piece."""
    m = re.match(r"^/vmfs/volumes/([^/]+)/", seal_head(path, "boundary", "vmxCfgPath") if path else "")
    return m.group(1) if m else None


def parse_vm_inventory_xml(root, sink, rec, shown):
    entries = [c for c in root if local(c.tag) == "ConfigEntry"]
    for i, e in enumerate(entries, 1):
        path = text_of(e, "vmxCfgPath")
        sink.emit("vms", {"format": "esxi_vm_inventory_xml", "name": None, "entry_id": e.attrib.get("id"), "object_id": text_of(e, "objID"),
                          "configuration_path": shown(path, rec["id"], "vmxCfgPath"), "datastore_hint": shown(vmware_path(path), rec["id"], "datastore path"),
                          "configuration_in_set": ("yes" if sink.index.resolve(rec["rel"], path)[0] else "no") if path else "no_name",
                          "locator": {"file": rec["id"], "element": "/ConfigRoot/ConfigEntry[%d]" % i},
                          "note": "a VM registered in the inventory when the file was written; it is not evidence that it ran, still exists, or is on this host now"})
    return ("parsed", None) if entries else ("parsed", "no ConfigEntry element: the file holds no registered VM (or is another layout)")


# ---- libvirt ---------------------------------------------------------------------------------------------------------

def disk_entries(disk, sink, vm, rec, base_loc, shown):
    """A <disk> and its <backingStore> chain, one disk reference per layer."""
    dev = child(disk, "target")
    driver = child(disk, "driver")
    layer, cur, loc = 0, disk, base_loc
    while cur is not None and layer < 256:
        src = child(cur, "source")
        fmt = child(cur, "format")
        name = None
        if src is not None:
            name = src.attrib.get("file") or src.attrib.get("dev") or src.attrib.get("name") or src.attrib.get("volume")
        kind = (cur.attrib.get("type") or "") if cur is not disk else (disk.attrib.get("type") or "")
        proto = src.attrib.get("protocol") if src is not None else None
        if name is not None or layer == 0:
            sink.disk_ref(vm, rec["rel"], name if kind in ("file", "block", "dir", "") else None, layer=layer, role=("disk" if layer == 0 else "backing store"),
                          device=dev.attrib.get("dev") if dev is not None else None, bus=dev.attrib.get("bus") if dev is not None else None,
                          device_type=disk.attrib.get("device"), source_type=kind or None, source_protocol=proto,
                          source_name=shown(name, rec["id"], "disk source") if (kind not in ("file", "block", "dir", "") and name is not None) else None,
                          disk_format=(fmt.attrib.get("type") if fmt is not None else (driver.attrib.get("type") if (driver is not None and layer == 0) else None)),
                          locator={"file": rec["id"], "element": loc})
        nxt = child(cur, "backingStore")
        if nxt is None or (not list(nxt) and not nxt.attrib):
            break
        cur, layer = nxt, layer + 1
        loc += "/backingStore"


def parse_libvirt_domain(root, sink, rec, shown):
    name = text_of(root, "name")
    os_el = child(root, "os")
    type_el = child(os_el, "type") if os_el is not None else None
    mem = child(root, "memory")
    devices = child(root, "devices")
    credential_attrs, credential_total = [], 0
    if devices is not None:
        for i, g in enumerate(children(devices, "graphics"), 1):
            if "passwd" in g.attrib:
                credential_total += 1
                if len(credential_attrs) < MAX_NAMED_KEYS:          # named up to the cap, all counted
                    credential_attrs.append({"where": "/domain/devices/graphics[%d]@passwd" % i, "value_chars": len(g.attrib["passwd"])})
    vm = sink.emit("vms", {"format": "libvirt_domain", "name": shown(name, rec["id"], "name"), "uuid": text_of(root, "uuid"), "virt_type": root.attrib.get("type"),
                           "machine": type_el.attrib.get("machine") if type_el is not None else None, "arch": type_el.attrib.get("arch") if type_el is not None else None,
                           "memory": (mem.text or "").strip() + " " + mem.attrib.get("unit", "KiB") if mem is not None else None,
                           "vcpus": text_of(root, "vcpu"), "locator": {"file": rec["id"], "element": "/domain"},
                           "credential_like_attributes": credential_attrs, "credential_like_attributes_total": credential_total,
                           "credential_note": "a console password sits at that attribute; it is not shown and is a secret to rotate" if credential_attrs else None})
    if devices is None:
        return "parsed", "the domain has no <devices> element"
    for i, d in enumerate(children(devices, "disk"), 1):
        disk_entries(d, sink, vm, rec, "/domain/devices/disk[%d]" % i, shown)
    return "parsed", None


def parse_libvirt_snapshot(root, sink, rec, shown):
    name = text_of(root, "name")
    parent = child(root, "parent")
    dom = child(root, "domain")
    memory = child(root, "memory")
    disks = child(root, "disks")
    sid = sink.emit("snapshots", {"vm": None, "format": "libvirt_domainsnapshot", "name": shown(name, rec["id"], "name"), "uid": None,
                                  "parent_name": shown(text_of(parent, "name") if parent is not None else None, rec["id"], "parent snapshot name"),
                                  "state": text_of(root, "state"), "time_raw": text_of(root, "creationTime"), "time_utc": iso_epoch(text_of(root, "creationTime")),
                                  "time_basis": "creationTime is seconds since 1970-01-01T00:00:00Z", "description_present": bool(text_of(root, "description")),
                                  "memory": memory.attrib.get("snapshot") if memory is not None else None, "domain_name": shown(text_of(dom, "name") if dom is not None else None, rec["id"], "domain name"),
                                  "locator": {"file": rec["id"], "element": "/domainsnapshot"}})
    if disks is not None:
        for i, d in enumerate(children(disks, "disk"), 1):
            src = child(d, "source")
            f = src.attrib.get("file") if src is not None else None
            sink.disk_ref(sid, rec["rel"], f, role="snapshot disk", device=d.attrib.get("name"), snapshot_mode=d.attrib.get("snapshot"), locator={"file": rec["id"], "element": "/domainsnapshot/disks/disk[%d]" % i})
    return "parsed", None


def parse_libvirt_pool(root, sink, rec, shown):
    target = child(root, "target")
    sink.emit("datastores", {"format": "libvirt_pool", "name": shown(text_of(root, "name"), rec["id"], "name"), "type": root.attrib.get("type"), "uuid": text_of(root, "uuid"),
                             "path": shown(text_of(target, "path") if target is not None else None, rec["id"], "path"), "locator": {"file": rec["id"], "element": "/pool"}})
    return "parsed", None


# ---- Proxmox ---------------------------------------------------------------------------------------------------------

PVE_DISK = re.compile(r"^(virtio|scsi|sata|ide|efidisk|tpmstate|unused)(\d*)$")
PVE_SHOWN = ("name", "hostname", "ostype", "machine", "bios", "cores", "sockets", "vcpus", "memory", "boot", "agent", "onboot", "lock", "template", "arch", "cpu", "scsihw", "vmgenid", "protection", "tags")
PVE_SNAP_SHOWN = ("parent", "snaptime", "vmstate", "snapstate", "description")


def pve_ids(rel):
    parts = seal_head(rel, "boundary", "file").split("/")      # the pieces of the path after the whole was judged as a path
    node = parts[parts.index("nodes") + 1] if "nodes" in parts and parts.index("nodes") + 1 < len(parts) - 1 else None
    m = re.match(r"^(\d+)\.conf$", parts[-1])
    return node, (m.group(1) if m else None)


def pve_section_kind(sname):
    """current (the configuration), pending (changes not applied yet), special (Proxmox's own sections such as
    [special:cloudinit], the cloud-init settings last applied) or snapshot (every other section is named by a snapshot)."""
    name = sname.split("#dup")[0]
    if sname == "":
        return "current"
    if name == "PENDING":
        return "pending"
    if name.startswith("special:"):
        return "special"
    return "snapshot"


def parse_pve_conf(fh, sink, rec, shown):
    node, vmid = pve_ids(rec["rel"])
    sections = collections.OrderedDict([("", {"line": 1, "kv": collections.OrderedDict(), "comment_lines": 0})])
    cur, bad, sensitive, not_shown, capped, sections_over = "", 0, [], 0, False, False
    for n, line in read_lines(fh, sink):
        if line is None:
            capped = True
            break
        if not line.strip():
            continue
        if line.startswith("#"):
            sections[cur]["comment_lines"] += 1
            continue
        m = re.match(r"^\[([^\]]*)\]\s*$", line)
        if m:
            cur = m.group(1)
            if cur in sections:
                cur = cur + "#dup%d" % n
            sections[cur] = {"line": n, "kv": collections.OrderedDict(), "comment_lines": 0}
            if len(sections) > MAX_RECORDS_PER_FILE:
                sections_over = True
                del sections[cur]
                break
            continue
        m = re.match(r"^([A-Za-z0-9_\-]+):\s?(.*)$", line)
        if not m:
            bad += 1
            continue
        sections[cur]["kv"][m.group(1)] = (m.group(2), n)
    main = sections[""]["kv"]
    if node:
        sink.emit("hosts", {"node": shown(node, rec["id"], "node"), "node_basis": "a directory name in the path of the configuration file; no host record was read",
                            "locator": {"file": rec["id"]}})
    for sname, sec in sections.items():
        sink.clock.check(256)
        for k, (v, n) in sec["kv"].items():
            if sname == "" and k not in PVE_SHOWN and not PVE_DISK.match(k) and not re.match(r"^net\d+$", k) and k not in PVE_SNAP_SHOWN:
                not_shown += 1
            # a credential-like key is named wherever it sits: a snapshot or a special section keeps its own copy of the settings
            if SENSITIVE_KEY.search(k) and (sname != "" or k not in PVE_SHOWN):
                sensitive.append((shown(k, rec["id"], "key"), n, len(v), "current" if sname == "" else shown(sname.split("#dup")[0], rec["id"], "section")))
    snapshot_names = [s for s in sections if pve_section_kind(s) == "snapshot"]
    special_names = [s for s in sections if pve_section_kind(s) == "special"]
    vm = sink.emit("vms", {"format": "pve_conf", "vmid": vmid, "node": shown(node, rec["id"], "node"), "name": shown((main.get("name") or main.get("hostname") or (None,))[0], rec["id"], "name"),
                           "kind": "container" if "/lxc/" in "/" + rec["rel"] else "qemu", "os_type": (main.get("ostype") or (None,))[0], "machine": (main.get("machine") or (None,))[0],
                           "bios": (main.get("bios") or (None,))[0], "cores": (main.get("cores") or (None,))[0], "sockets": (main.get("sockets") or (None,))[0],
                           "memory_mb": (main.get("memory") or (None,))[0], "lock": (main.get("lock") or (None,))[0], "template": (main.get("template") or (None,))[0],
                           "current_parent_snapshot": shown((main.get("parent") or (None,))[0], rec["id"], "parent snapshot name"),
                           "snapshot_sections": [shown(s.split("#dup")[0], rec["id"], "snapshot") for s in snapshot_names[:MAX_NAMED_KEYS]],
                           "snapshot_sections_total": len(snapshot_names),
                           "snapshot_sections_note": "the first %d section names; every snapshot section is a row of snapshots (paged whole)" % MAX_NAMED_KEYS,
                           "special_sections": [shown(s.split("#dup")[0], rec["id"], "section") for s in special_names[:MAX_NAMED_KEYS]],
                           "special_sections_total": len(special_names),
                           "special_sections_note": "a [special:...] section is Proxmox's own (such as the cloud-init settings last applied), not a snapshot; the first %d are named" % MAX_NAMED_KEYS,
                           "pending_section_present": "PENDING" in sections, "comment_lines_not_shown": sections[""]["comment_lines"],
                           "locator": {"file": rec["id"], "first_line": 1}, **key_report(not_shown, sensitive)})
    for sname, sec in sections.items():
        is_snap = pve_section_kind(sname) == "snapshot"
        label = "snapshot %s" % sname if is_snap else ""
        sid = None
        if is_snap:
            kv = sec["kv"]
            snaptime = (kv.get("snaptime") or (None,))[0]
            sid = sink.emit("snapshots", {"vm": vm, "format": "pve_conf_section", "name": shown(sname.split("#dup")[0], rec["id"], "snapshot"), "uid": None,
                                          "parent_name": shown((kv.get("parent") or (None,))[0], rec["id"], "parent snapshot name"), "time_raw": snaptime, "time_utc": iso_epoch(snaptime) if snaptime else None,
                                          "time_basis": "snaptime is seconds since 1970-01-01T00:00:00Z", "vm_state_volume": shown((kv.get("vmstate") or (None,))[0], rec["id"], "vmstate"),
                                          "snapstate": (kv.get("snapstate") or (None,))[0], "description_present": "description" in kv,
                                          "locator": {"file": rec["id"], "line": sec["line"]}})
        for k, (v, n) in sec["kv"].items():
            m = PVE_DISK.match(k)
            if m or re.match(r"^(mp\d+|rootfs)$", k):
                volume, _, options = v.partition(",")
                storage, _, vol = volume.partition(":")      # each piece is judged as the field it fills (a storage name, a volume path) ...
                if vol and seal_head(volume, "boundary", "volume") != volume:      # ... and the whole is judged first: a secret that spans the `:` withholds both pieces
                    storage = vol = _b_withheld(volume, "not a plain name", "volume")
                opts = dict(o.split("=", 1) for o in options.split(",") if "=" in o) if options else {}
                sink.disk_ref(sid or vm, rec["rel"], volume if (":" in volume or "/" in volume) else None, file_like=bool(re.search(r"\.(qcow2|raw|vmdk|vhdx?|img|iso)$", volume, re.I)), section=sname or "current", device=k, role=("snapshot disk" if is_snap else "disk"),
                              storage=shown(storage, rec["id"], "storage") if vol else None, volume=shown(vol, rec["id"], "volume") if vol else None,
                              size=opts.get("size"), backup=opts.get("backup"), media=opts.get("media"), options_count=len(opts), locator={"file": rec["id"], "line": n})
    if capped:
        return "partial", "the file has more than %d lines: read to that point, and what was read is listed" % MAX_LINES
    if sections_over:
        return "partial", "more than %d sections: the first %d are listed and the rest were not read" % (MAX_RECORDS_PER_FILE, MAX_RECORDS_PER_FILE)
    if len(special_names) > MAX_NAMED_KEYS:
        return "partial", "%d [special:...] sections: the first %d are named and the rest are counted (special_sections_total)" % (len(special_names), MAX_NAMED_KEYS)
    return ("parsed", None) if not bad else ("parsed", "%d line(s) matched no key: value shape: counted, not read" % bad)


def parse_pve_storage(fh, sink, rec, shown):
    cur, capped = None, False
    allowed = ("path", "content", "shared", "nodes", "disable", "prune-backups", "maxfiles", "server", "export", "pool", "vgname", "thinpool", "datastore", "username", "mkdir", "is_mountpoint")
    sensitive, not_shown = [], 0
    def flush():
        if cur is not None:
            sink.emit("datastores", {"format": "pve_storage_cfg", "type": cur["type"], "name": shown(cur["name"], rec["id"], "storage name"),
                                     "settings": {k: shown(v, rec["id"], k) for k, v in cur["kv"].items() if k in allowed},
                                     "locator": {"file": rec["id"], "line": cur["line"]}, **key_report(cur["not_shown"], cur["sensitive"])})
    for n, line in read_lines(fh, sink):
        if line is None:
            capped = True
            break
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            m = re.match(r"^([A-Za-z0-9_\-]+):\s+(\S.*)$", line)
            flush()
            cur = {"type": m.group(1), "name": m.group(2).strip(), "kv": {}, "line": n, "not_shown": 0, "sensitive": []} if m else None
            continue
        if cur is None:
            continue
        parts = line.strip().split(None, 1)
        key, value = parts[0], parts[1] if len(parts) > 1 else ""
        if key in allowed:
            cur["kv"][key] = value
        else:
            cur["not_shown"] += 1
            if SENSITIVE_KEY.search(key):
                cur["sensitive"].append((shown(key, rec["id"], "key"), n, len(value)))
    flush()
    if capped:
        return "partial", "the file has more than %d lines: read to that point, and what was read is listed" % MAX_LINES
    return "parsed", None


# ---- dispatch --------------------------------------------------------------------------------------------------------

def classify(rec, head, max_file):
    name = posixpath.basename(rec["rel"]).lower()
    ext = posixpath.splitext(name)[1]
    if head[:2] in (b"\xff\xfe", b"\xfe\xff") or head[:4] in (b"\x00\x00\xfe\xff", b"<\x00?\x00", b"\x00<\x00?", b"<\x00d\x00", b"\x00<\x00d"):
        return "unsupported:.utf16xml"
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped[:1] == b"<":
        pos = 0
        while pos < len(stripped):              # skip an XML declaration and comments by position: no pattern can backtrack over a hostile prefix
            while pos < len(stripped) and stripped[pos:pos + 1] in (b" ", b"\t", b"\r", b"\n"):
                pos += 1
            if stripped.startswith(b"<?", pos):
                end = stripped.find(b"?>", pos)
            elif stripped.startswith(b"<!--", pos):
                end = stripped.find(b"-->", pos)
            elif stripped[pos:pos + 9].upper() in (b"<!DOCTYPE", b"<!ENTITY "):
                return "refused:doctype"
            else:
                break
            if end < 0:
                pos = len(stripped)
                break
            pos = end + (2 if stripped.startswith(b"<?", pos) else 3)
        m = re.match(rb"<([A-Za-z_][\w.\-]*)", stripped[pos:pos + 256])
        tag = m.group(1).decode("ascii", "replace") if m else ""
        if tag == "domain":
            return "libvirt_domain"
        if tag == "domainsnapshot":
            return "libvirt_snapshot"
        if tag == "pool":
            return "libvirt_pool"
        if tag == "ConfigRoot":
            return "vm_inventory_xml" if name in ("vminventory.xml",) or b"vmxCfgPath" in head else "xml_other"
        if tag == "VirtualBox":
            return "unsupported:.vbox"
        if tag in ("Envelope",) or ext == ".ovf":
            return "unsupported:.ovf"
        return "xml_other"
    if ext == ".vmsd":
        return "vmsd"
    if ext == ".vmx":
        return "vmx"
    if name == "storage.cfg":
        return "pve_storage"
    if ext == ".conf" and ("qemu-server/" in rec["rel"] + "" or "/lxc/" in "/" + rec["rel"] or "qemu-server" in rec["rel"]):
        return "pve_conf"
    if ext in UNSUPPORTED_NAMES:
        return "unsupported:" + ext
    if ext == ".conf":
        lines = [l for l in head.decode("utf-8", "replace").splitlines() if l and not l.startswith("#")][:30]
        hits = sum(1 for l in lines if re.match(r"^(boot|cores|memory|ostype|scsihw|sockets|vmgenid|smbios1|bios|machine|net\d+|virtio\d+|scsi\d+|ide\d+|sata\d+|efidisk0|name|cpu|agent|onboot|rootfs|hostname|arch):\s", l))
        if hits >= 3:
            return "pve_conf"
    return "other"


def main():
    args = read_args()
    root = want_str(args, "root")
    paths = want_str_list(args, "paths", 100000)
    if root is None and not paths:
        fail("name the evidence: root is a directory of configuration files and exports, paths is a list of files")
    limit = want_int(args, "limit", DEFAULT_LIMIT, 1, 100000)
    max_files = want_int(args, "max_files", 20000, 1, 200000)
    max_entries = want_int(args, "max_entries", 200000, 1, 2000000)
    max_depth = want_int(args, "max_depth", 16, 1, 64)
    max_file = want_int(args, "max_file_bytes", DEFAULT_MAX_FILE, 4096, 256 << 20)
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    write_text = want_flag(args, "write_text")
    try:
        values = TextFile("inventory-values.jsonl", write_text, "JSON Lines, mode 0600: record_type original, where (a source id), field, value (the original text of "
                          "a name, path or value the answer shows withheld or shortened)")
    except TextRefused as exc:
        fail(str(exc))
    try:
        bind_values(write_text, TOOL)         # the originals of what the one way out withholds (the same job and secret-output rules as the text file: it was checked first)
    except ValuesRefused as exc:
        values.close()
        fail(str(exc))
    seal_stop_after(seconds + 6.5)            # no judging runs on past this (the manifest allows 60); the tool's own clock below runs out first
    shown = Shower(values)
    clock = Clock(seconds)
    files = FileSet(shown)
    partial = []
    try:
        files.walk(root, paths, max_files, max_entries, max_depth, clock)
    except Overtime:
        partial.append("the walk stopped at max_seconds (%s): the files after the last one listed were not reached" % seconds)
    if files.truncated:
        partial.append(files.truncated)
    index = Index(files.files)
    sink = Sink(limit, shown, index, clock)
    kinds, other_ext, states = collections.Counter(), collections.Counter(), collections.Counter()
    unreadable = []
    parsers_xml = {"libvirt_domain": parse_libvirt_domain, "libvirt_snapshot": parse_libvirt_snapshot, "libvirt_pool": parse_libvirt_pool, "vm_inventory_xml": parse_vm_inventory_xml}
    parsers_text = {"vmx": parse_vmx, "vmsd": parse_vmsd, "pve_conf": parse_pve_conf, "pve_storage": parse_pve_storage}
    problems = 0
    try:
        for rec in files.files:
            clock.check()
            fh, why = open_regular(rec["path"])
            if fh is None:
                files.note("unreadable", rec["rel"] + ": " + (why or ""))
                continue
            with fh:
                head = fh.read(65536)
                kind = classify(rec, head, max_file)
                kinds[kind.split(":")[0] if kind.startswith(("unsupported", "refused")) else kind] += 1
                if kind == "other":
                    ext = ext_of(rec["rel"])
                    other_ext[ext if (ext in other_ext or len(other_ext) < 2000) else "(other extensions)"] += 1
                    continue
                sink.current_file = rec
                row = {"source_id": rec["id"], "file": shown(rec["rel"], rec["id"], "file"), "size": rec["size"], "kind": kind}
                state, reason = "parsed", None
                before = sum(sink.counts.values())
                stopped = False
                try:
                    if kind == "refused:doctype":
                        state, reason = "failed", "a DOCTYPE or ENTITY declaration is refused: no entity is expanded, and the file was not handed to a parser"
                    elif kind.startswith("unsupported:"):
                        state, reason = "unsupported_recognised", "%s: recognised and not read" % UNSUPPORTED_NAMES.get(kind.split(":", 1)[1], "a product file")
                    elif kind == "xml_other":
                        state, reason = "unsupported_recognised", "an XML file whose root is not one this tool reads"
                    elif rec["size"] > max_file:
                        state, reason = "failed", "the file is %d bytes, over max_file_bytes (%d): named and not read" % (rec["size"], max_file)
                    elif kind in parsers_xml:
                        fh.seek(0)
                        xml_root, err = load_xml(fh, max_file)
                        if xml_root is None:
                            state, reason = "failed", err
                        else:
                            state, reason = parsers_xml[kind](xml_root, sink, rec, shown)
                    elif kind in parsers_text:
                        fh.seek(0)
                        state, reason = parsers_text[kind](fh, sink, rec, shown)
                except (ValueError, LookupError, OverflowError, RecursionError, MemoryError, IndexError, KeyError, AttributeError) as exc:
                    state, reason = "failed", "the structure could not be read (%s)" % describe(exc)
                except OSError as exc:
                    state, reason = "failed", "a read failed (%s)" % describe(exc)
                except Overtime:
                    state, reason = "partial", "max_seconds (%s) was reached while this file was read: the records read before it are listed and the rest of the file was not read" % seconds
                    stopped = True
            if sink.over_cap[rec["id"]]:
                state, reason = "partial", "%d record(s) past the cap of %d for one file were counted and not listed" % (sink.over_cap[rec["id"]], MAX_RECORDS_PER_FILE)
            if sink.long_lines[rec["id"]] and state in ("parsed", "partial"):
                note = "%d line(s) of %d bytes or more were not read (the first is line %d): counted here, nothing in them is in the answer" % (
                    sink.long_lines[rec["id"]], MAX_LINE, sink.long_first[rec["id"]])
                state, reason = "partial", "%s; %s" % (reason, note) if reason else note
            states[state] += 1
            if state in ("failed", "partial"):
                problems += 1
            row.update(state=state, reason=reason, records=sum(sink.counts.values()) - before)
            sink.pages["sources"].add(row)
            if stopped:
                raise Overtime()
    except Overtime:
        partial.append("the examination stopped at max_seconds (%s): the files after the last one listed in sources were not read" % seconds)
    values.close()
    result_pages = {k: v.finish() for k, v in sink.pages.items()}
    unsupported = sum(c for k, c in kinds.items() if k.startswith("unsupported") or k == "xml_other")
    complete = not problems and not partial and not files.skipped_counts["unreadable"] and not files.skipped_counts["too_deep"]
    outcome = status_of(complete, bool(files.files) and not sum(sink.counts.values()) and problems and not unsupported and not partial,
                        "every file of a kind this tool reads was read and nothing was left out" + ("; %d file(s) of a recognised kind it does not read are listed as unsupported" % unsupported if unsupported else ""),
                        "%d file(s) were not read whole, %d unreadable, %d directory(ies) too deep%s: the answer names them" % (
                            problems, files.skipped_counts["unreadable"], files.skipped_counts["too_deep"], ("; " + "; ".join(partial)) if partial else ""),
                        "no file could be read")
    recognised = sum(c for k, c in kinds.items() if k != "other")
    if files.files and not recognised and outcome["status"] == "complete":
        outcome = {"status": "complete", "status_basis": "the set holds no file of a kind this tool reads (%d other file(s), counted by extension): zero records is a statement about this tool's formats, not about the system" % sum(other_ext.values())}
    if not files.files:
        skipped = sum(files.skipped_counts.values())
        outcome = ({"status": "partial", "status_basis": "the set holds no file that could be read; %d entr(ies) were skipped (links, special files, directories too deep, unreadable)%s: the answer names them" % (skipped, ("; " + "; ".join(partial)) if partial else "")}
                   if skipped or partial else {"status": "failed", "status_basis": "the set holds no file"})
    emit(big_ints({
        "parser": PARSER, **outcome,
        "root": files.root_shown, "files_in_set": len(files.files), "kinds": dict(kinds), "states": dict(states),
        "other_files_by_extension": dict(other_ext.most_common(20)),
        "other_files_note": "files of no kind this tool reads are counted by extension and not examined; absence of a configuration here is not absence of a VM",
        "counts": {"vms": sink.counts["vms"], "disks": sink.counts["disks"], "snapshots": sink.counts["snapshots"], "datastores": sink.counts["datastores"], "hosts": sink.counts["hosts"]},
        "sources": sink.pages["sources"].page, "vms": sink.pages["vms"].page, "disks": sink.pages["disks"].page, "snapshots": sink.pages["snapshots"].page,
        "datastores": sink.pages["datastores"].page, "hosts": sink.pages["hosts"].page, "pages": result_pages,
        "walk": files.skipped_summary(), "walk_truncated": files.truncated, "partial_reasons": partial,
        "text": values.summary(), "withheld": withheld_summary(shown),
        "truncated": any(p["truncated"] for p in result_pages.values()),
        "limits": {"max_files": max_files, "max_entries": max_entries, "max_depth": max_depth, "max_file_bytes": max_file, "max_records_per_file": MAX_RECORDS_PER_FILE,
                   "xml_elements": MAX_XML_ELEMENTS, "xml_depth": MAX_XML_DEPTH},
        "note": "An inventory lists what the files say exist. A configuration or an inventory entry does not show that a VM ran, still exists or was not deleted; a disk 'not in the set' is a "
                "statement about the files given. Versions are the strings the files carry; what they mean for a given product release is for the vendor's documentation of that release.",
    }), indent=2)
    close_values()
    return 0 if outcome["status"] != "failed" else 1


def _code(stop):
    return stop.code if isinstance(stop.code, int) else (0 if stop.code is None else 1)


def _leave(code):
    """End the call at once, after the answer is out. The interpreter's own teardown resets the signal handlers to their defaults before it frees
    what the call held, and a stop signal that lands there kills the process by its default action (exit null, not 128 + the signal) with a whole
    answer already printed. What the interpreter would have run at its end (the atexit hooks that remove a temporary file) is run here, with the
    handlers still in; a signal before this point is answered by the handlers as before."""
    try:
        sys.stdout.flush()
    except SystemExit as stop:
        code = _code(stop)
    except Exception:  # noqa: BLE001 - a reader that is gone: the exit code is the one the call had
        pass
    try:
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass
    try:
        import atexit as _atexit
        _atexit._run_exitfuncs()
    except Exception:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    os._exit(code)


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            raise SystemExit(main())
        except SystemExit:
            raise
        except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
            fail("unexpected failure: %s" % describe(exc))
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
