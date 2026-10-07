#!/usr/bin/env python3
"""Read an executable's structure from its bytes, and never run it.

What a binary declares to its loader is in its headers: which libraries it asks for, how its
file is laid out in memory, which fields name an entry point. This tool reads those fields
for three formats and says, for each structure, whether it read it whole:

    PE        the DOS and COFF headers, the optional header's fields, the data directory
              table, the section table with the entropy of each section's raw bytes, the
              import directory (library names, function names, ordinals), the export
              directory's image name and the certificate table's declaration
    ELF       the header, the program headers, the section headers, and the dynamic array
              (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH), read through PT_DYNAMIC as the
              loader reads it, then through an SHT_DYNAMIC section when there is none
    Mach-O    thin files of either width and byte order, and universal binaries: every
              slice, with its load commands, linked libraries and segments

Everything is parsing. Nothing is executed, and nothing here verifies a signature, resolves a
resource or lists an export symbol (the answer's `coverage.structures_not_read` names what is
left). A field is named for what it holds: a certificate table is *declared*, not verified; a
file with no section headers is `stripped: null`, not stripped.

Every table is read through checked ranges: a field is read only from bytes the file holds
inside the structure that contains it, a traversal is bounded, and what the tool could not read
is in `problems` and in the answer's `status` (complete, partial, failed, unsupported). Exit 0
means the engine ran; `status` says whether the structures it reads were read in full.
"""
import bisect
import datetime
import errno
import hashlib
import json
import math
import mmap
import os
import re
import stat
import struct
import sys
import time
from collections import Counter
from pathlib import Path

TOOL = {"name": "pe_info", "version": 2}
PARSER = "pe_info/2"

NOTE = ("Static structural inventory only. Size differences, entropy and imports are triage features, not proof "
        "of packing, intent or execution. Read `status`, `problems` and `coverage` first: they say what was read "
        "and what was not. Corroborate any material conclusion.")

# Bounds. Each is a count of what is read, never a way of cutting a result: a table longer than the
# inline limit is kept whole in a file, and what a bound leaves unread is in `problems`.
DEFAULT_LIMIT = 5000                    # rows of one table in the answer; the whole of a longer one is in a file
DEFAULT_ENTROPY_BUDGET = 256 << 20      # bytes measured for entropy in one call (overlapping ranges count twice)
CHUNK = 1 << 20
NAME_CAP = 4096                         # bytes read for one name
MAX_SECTIONS = 65535                    # a PE's section count is a 16-bit field
MAX_ELF_SECTIONS = 262144
MAX_IMPORT_DESCRIPTORS = 65536
MAX_THUNKS_PER_LIBRARY = 1 << 20
MAX_FUNCTIONS = 4_000_000
MAX_DYNAMIC_ENTRIES = 65536
MAX_NEEDED = 4096
MAX_SLICES = 256
MAX_LOAD_COMMANDS = 65536
MAX_PROBLEMS = 100
DEFAULT_SECONDS = 100                   # the tool's own clock: below the manifest's 120 s, so a slow file is a partial answer, not a kill
MAX_SECONDS = 110
MAX_PHDRS = 65535
OVERLAP_LOOK_BACK = 64                  # sections whose address range is searched backwards from the nearest start

MACHINES = {0x014c: "i386", 0x8664: "x86-64", 0x01c0: "ARM", 0x01c4: "ARMNT", 0xaa64: "ARM64", 0x0200: "IA64",
            0x5032: "RISC-V 32", 0x5064: "RISC-V 64", 0x0166: "MIPS R4000"}
SUBSYSTEMS = {1: "native", 2: "GUI", 3: "console", 5: "OS/2 console", 7: "POSIX console", 9: "Windows CE",
              10: "EFI application", 11: "EFI boot service driver", 12: "EFI runtime driver", 13: "EFI ROM",
              14: "Xbox", 16: "Windows boot application"}
SECTION_FLAGS = [(0x20000000, "execute"), (0x40000000, "read"), (0x80000000, "write"),
                 (0x00000020, "code"), (0x00000040, "initialised data"),
                 (0x00000080, "uninitialised data"), (0x02000000, "discardable")]
PE_DIRECTORIES = ["export", "import", "resource", "exception", "certificate", "base_relocation", "debug",
                  "architecture", "global_ptr", "tls", "load_config", "bound_import", "iat", "delay_import",
                  "clr_runtime_header", "reserved"]
NOT_PE = {b"NE": "NE (16-bit New Executable)", b"LE": "LE (Linear Executable)", b"LX": "LX (OS/2 Linear Executable)"}
WIN_CERT_TYPES = {1: "WIN_CERT_TYPE_X509", 2: "WIN_CERT_TYPE_PKCS_SIGNED_DATA", 4: "WIN_CERT_TYPE_TS_STACK_SIGNED"}

ELF_TYPES = {0: "none", 1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}
ELF_MACHINES = {0x02: "SPARC", 0x03: "i386", 0x04: "Motorola 68000", 0x08: "MIPS", 0x14: "PowerPC", 0x15: "PowerPC64",
                0x16: "S390", 0x28: "ARM", 0x2a: "SuperH", 0x2b: "SPARC V9", 0x32: "IA-64", 0x3e: "x86-64",
                0x53: "AVR", 0xb7: "AArch64", 0xf3: "RISC-V", 0xf7: "BPF", 0x102: "LoongArch"}
ELF_PT = {0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 4: "PT_NOTE", 5: "PT_SHLIB", 6: "PT_PHDR",
          7: "PT_TLS", 0x6474e550: "PT_GNU_EH_FRAME", 0x6474e551: "PT_GNU_STACK", 0x6474e552: "PT_GNU_RELRO",
          0x6474e553: "PT_GNU_PROPERTY"}
ELF_SHT = {0: "SHT_NULL", 1: "SHT_PROGBITS", 2: "SHT_SYMTAB", 3: "SHT_STRTAB", 4: "SHT_RELA", 5: "SHT_HASH",
           6: "SHT_DYNAMIC", 7: "SHT_NOTE", 8: "SHT_NOBITS", 9: "SHT_REL", 10: "SHT_SHLIB", 11: "SHT_DYNSYM",
           14: "SHT_INIT_ARRAY", 15: "SHT_FINI_ARRAY", 16: "SHT_PREINIT_ARRAY", 17: "SHT_GROUP",
           18: "SHT_SYMTAB_SHNDX", 0x6ffffff6: "SHT_GNU_HASH", 0x6ffffffd: "SHT_GNU_verdef",
           0x6ffffffe: "SHT_GNU_verneed", 0x6fffffff: "SHT_GNU_versym"}

# A thin Mach-O's magic is stored in the file's own byte order; a fat header is always big-endian, so a file
# that begins with FAT_CIGAM (be ba fe ca) stores its fat header little-endian.
MACHO_MAGICS = {b"\xce\xfa\xed\xfe": (False, "<"), b"\xcf\xfa\xed\xfe": (True, "<"),
                b"\xfe\xed\xfa\xce": (False, ">"), b"\xfe\xed\xfa\xcf": (True, ">")}
FAT_MAGICS = {b"\xca\xfe\xba\xbe": (False, ">"), b"\xbe\xba\xfe\xca": (False, "<"),
              b"\xca\xfe\xba\xbf": (True, ">"), b"\xbf\xba\xfe\xca": (True, "<")}
MACHO_TYPES = {1: "object", 2: "executable", 3: "fixed VM library", 4: "core", 5: "preload", 6: "dylib",
               7: "dynamic linker", 8: "bundle", 9: "dylib stub", 10: "dSYM companion", 11: "kext bundle",
               12: "fileset"}
MACHO_CPUS = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000c: "ARM64", 0x0200000c: "ARM64_32",
              18: "PowerPC", 0x01000012: "PowerPC64"}
LC_SEGMENT, LC_SEGMENT_64, LC_ID_DYLIB, LC_CODE_SIGNATURE, LC_MAIN = 0x1, 0x19, 0x0d, 0x1d, 0x80000028
LC_LINKED = {0x0c: "LC_LOAD_DYLIB", 0x80000018: "LC_LOAD_WEAK_DYLIB", 0x8000001f: "LC_REEXPORT_DYLIB",
             0x20: "LC_LAZY_LOAD_DYLIB", 0x80000023: "LC_LOAD_UPWARD_DYLIB"}
LC_NAMES = {0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0x4: "LC_THREAD", 0x5: "LC_UNIXTHREAD", 0xb: "LC_DYSYMTAB",
            0x0d: "LC_ID_DYLIB", 0x0e: "LC_LOAD_DYLINKER", 0x0f: "LC_ID_DYLINKER", 0x19: "LC_SEGMENT_64",
            0x1b: "LC_UUID", 0x1d: "LC_CODE_SIGNATURE", 0x1e: "LC_SEGMENT_SPLIT_INFO", 0x21: "LC_ENCRYPTION_INFO",
            0x22: "LC_DYLD_INFO", 0x80000022: "LC_DYLD_INFO_ONLY", 0x24: "LC_VERSION_MIN_MACOSX",
            0x80000028: "LC_MAIN", 0x26: "LC_FUNCTION_STARTS", 0x29: "LC_DATA_IN_CODE", 0x2a: "LC_SOURCE_VERSION",
            0x2c: "LC_ENCRYPTION_INFO_64", 0x32: "LC_BUILD_VERSION", **LC_LINKED}


class Stop(Exception):
    """A format that cannot be read at all: `failed` (the headers are unusable) or `unsupported` (a variant not read)."""

    def __init__(self, status, message, partial=None):
        Exception.__init__(self, message)
        self.status, self.message, self.partial = status, message, partial or {}
        self.extra = {}


class Short(Exception):
    """A read that would run past the end of the file."""


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


NOTHING_READ = ["every structure: the file was not read"]


def answer_base(status, error=None, partial=None, problems=None, limits=None, coverage=None):
    """The fields every answer carries, whether it read the file or not: a status, the problems, the limits hit and the
    structures read and not read."""
    return {"tool": TOOL, "parser": PARSER, "status": status, **(partial or {}),
            **({"error": error, "status_basis": error} if error else {}),
            "problems": list(problems or []), "limits_hit": list(limits or []),
            "coverage": coverage or {"structures_read": [], "structures_not_read": NOTHING_READ}}


def fail(message, **extra):
    status = extra.pop("status", "failed")
    print(json.dumps({**answer_base(status, message), **extra}))
    raise SystemExit(1)


def file_problem(path):
    """Why `path` is not a file this tool can read, in words that fit: a missing file, a directory, a pipe, a loop."""
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError:
        return "no such file"
    except OSError as exc:
        return "the file could not be examined: %s" % describe(exc)
    if stat.S_ISREG(mode):
        return None
    kinds = ((stat.S_ISDIR, "a directory"), (stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
             (stat.S_ISCHR, "a character device"))
    return "not a regular file (%s)" % next((n for t, n in kinds if t(mode)), "a special file")


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


def show(ctx, field, text, offset):
    """A string read from the sample as it may be printed. A library path, a search path or an install name can carry
    user-info or a query value: those are withheld, the field is listed in `withheld_fields` with where the string lies
    in the file, and the file is the whole."""
    if not isinstance(text, str):
        return text
    if "://" in text or text.startswith("//") or "?" in text:
        shown = redact_url(text)
    else:
        shown = "/".join(scrub(part, "names") for part in text.split("/"))
    if shown != text:
        ctx.withheld_fields.append({"field": field, "file_offset": offset, "length": len(text)})
    return shown


# --- lossless paging: the answer a table gets when it is long, and the whole of it in a file ------------------------

class LosslessPage:
    """The first `limit` rows of a table in the answer; when there are more, the whole table as JSON Lines in a
    file that is never a file another call wrote (it is created exclusively, under a new name when the name is
    taken) and is named in the answer. A table that cannot be written whole says so, and the call goes partial."""

    def __init__(self, tool, key, limit):
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page = []
        self.total = 0
        self._out = None
        self.path = None
        self.shown = None
        self.not_written = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        self.stem = "%s-%s" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if out:
            self.dir = Path(out) / "tool-output"
            self.prefix = ("store/jobs/%s/out/tool-output/" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)) if job else str(self.dir) + "/"
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.dir = Path("work") / agent / "tool-output"
            self.prefix = str(self.dir) + "/"

    def _open(self):
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            for n in range(1, 100):
                name = "%s.jsonl" % self.stem if n == 1 else "%s-%d.jsonl" % (self.stem, n)
                try:
                    fd = os.open(str(self.dir / name), flags, 0o644)
                except FileExistsError:
                    continue
                self.path, self.shown = self.dir / name, self.prefix + name
                self._out = os.fdopen(fd, "w", encoding="utf-8")
                for kept in self.page:
                    self._write(kept)
                return
            self.not_written = "ninety-nine files of this name already exist in %s" % self.dir
        except OSError as exc:
            self.not_written = "the file could not be created in %s (%s)" % (self.dir, describe(exc))

    def _write(self, row):
        self._out.write(json.dumps(row, default=str))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None and self.not_written is None:
            self._open()
        if self._out is not None:
            try:
                self._write(row)
            except OSError as exc:
                self.not_written = "writing the file failed (%s)" % describe(exc)
                self._out = None

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
            except OSError as exc:
                self.not_written = "writing the file failed (%s)" % describe(exc)
            else:
                result["all_results"] = self.shown
                result["all_results_format"] = "JSON Lines, one complete row per line"
        if self.not_written:
            result["not_written"] = self.not_written
        return result


# --- the image, with checked access ----------------------------------------------------------------------------------

class Image:
    def __init__(self, mm):
        self.mm = mm
        self.size = len(mm)

    def unpack(self, fmt, at):
        n = struct.calcsize(fmt)
        if at < 0 or at + n > self.size:
            raise Short("%d byte(s) at offset %d run past the end of the file (%d bytes)" % (n, at, self.size))
        return struct.unpack_from(fmt, self.mm, at)

    def cstr(self, at, end=None, cap=NAME_CAP):
        """(text, complete): the C string at `at`, read no further than `end` or `cap` bytes."""
        end = self.size if end is None else min(end, self.size)
        if at < 0 or at >= end:
            return None, False
        stop = min(end, at + cap)
        nul = self.mm.find(b"\x00", at, stop)
        if nul >= 0:
            return self.mm[at:nul].decode("utf-8", "replace"), True
        return self.mm[at:stop].decode("utf-8", "replace"), False


class Ctx:
    def __init__(self, key, limit, entropy_budget, with_imports, seconds):
        self.key = key
        self.limit = limit
        self.with_imports = with_imports
        self.seconds = seconds
        self.deadline = time.monotonic() + seconds
        self.budget = {"limit": entropy_budget, "used": 0, "refused": 0}
        self.problems = []
        self.problems_dropped = 0
        self.limits = []
        self.pages = {}
        self.withheld_fields = []

    def problem(self, text):
        if text in self.problems:
            return
        if len(self.problems) >= MAX_PROBLEMS:
            self.problems_dropped += 1
            return
        self.problems.append(text)

    def limit_hit(self, text):
        if text not in self.limits:
            self.limits.append(text)

    def expired(self, where):
        if time.monotonic() <= self.deadline:
            return False
        self.limit_hit("time: %s stopped at max_seconds (%d); what was read is reported" % (where, self.seconds))
        return True

    def page(self, name):
        if name not in self.pages:
            self.pages[name] = LosslessPage("pe_info-" + name, [self.key, name], self.limit)
        return self.pages[name]


def entropy_of(img, start, end, ctx):
    """(entropy to 3 decimals or None, a note or None): Shannon entropy of the file bytes in [start, end), streamed in chunks,
    against the call's work budget. A range that runs past the end of the file is measured over the bytes the file holds,
    and the note says over how many of how many. Pages already counted are given back to the system as the pass goes."""
    wanted = max(0, end - start)
    end = min(end, img.size)
    if start < 0 or start >= end:
        return None, "no bytes of this range are in the file"
    want = end - start
    if ctx.budget["used"] + want > ctx.budget["limit"]:
        ctx.budget["refused"] += 1
        ctx.limit_hit("entropy: the work budget of %d bytes was reached; later ranges were not measured" % ctx.budget["limit"])
        return None, "not measured: the entropy work budget (%d bytes) was reached" % ctx.budget["limit"]
    counts = Counter()
    at = start
    while at < end:
        n = min(CHUNK, end - at)
        counts.update(img.mm[at:at + n])
        release(img, at, n)
        at += n
    ctx.budget["used"] += want
    value = 0.0
    for c in counts.values():
        p = c / want
        value -= p * math.log2(p)
    note = "measured over %d of %d bytes: the range runs past the end of the file" % (want, wanted) if want < wanted else None
    return round(value, 3), note


def release(img, at, n):
    """Tell the system the pages of a measured chunk can go: a read-only file mapping is clean, and its resident size would
    otherwise follow the bytes measured."""
    madvise, dontneed = getattr(img.mm, "madvise", None), getattr(mmap, "MADV_DONTNEED", None)
    if madvise is None or dontneed is None:
        return
    first = at - at % mmap.PAGESIZE
    try:
        madvise(dontneed, first, min(img.size - first, at + n - first))
    except (OSError, ValueError):
        pass


def when(stamp):
    if not stamp:
        return None
    try:
        return datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


# --- PE --------------------------------------------------------------------------------------------------------------

PE_READ = ["DOS header (e_lfanew)", "COFF file header", "optional header fields listed in this answer",
           "data directory table", "section table and the entropy of each section's raw bytes",
           "import directory: library names, function names and ordinals", "export directory image name",
           "certificate table declaration (offset, size and the first entry's header)"]
PE_NOT_READ = ["resources (version information, icons, embedded files)", "export symbols (names, ordinals, forwarders)",
               "delay-load imports and bound imports", "TLS directory and callbacks",
               "CLR (managed code) header and metadata", "debug directory", "base relocations",
               "load configuration directory", "the Rich header", "Authenticode: the signature is not parsed or verified",
               "the contents of an overlay"]


def read_pe(img, ctx):
    out = {"format": "PE"}
    if img.size < 0x40:
        raise Stop("failed", "shorter than a DOS header (64 bytes): the file is %d bytes" % img.size, out)
    pe_at, = img.unpack("<I", 0x3C)
    sig = bytes(img.mm[pe_at:pe_at + 4]) if pe_at <= img.size else b""
    if sig != b"PE\x00\x00":
        other = NOT_PE.get(sig[:2])
        if other:
            raise Stop("unsupported", "the DOS header points to a %s header, not a PE one" % other, out)
        raise Stop("failed", "no PE signature where the DOS header points (offset %d of %d)" % (pe_at, img.size), out)
    if pe_at + 24 > img.size:
        raise Stop("failed", "the COFF header at offset %d runs past the end of the file (%d bytes)" % (pe_at + 4, img.size), out)
    machine, nsec, stamp, _sym, _nsym, opt_size, characteristics = img.unpack("<HHIIIHH", pe_at + 4)
    out.update({
        "machine": MACHINES.get(machine, hex(machine)),
        "sections_declared": nsec,
        "header_timestamp_raw": stamp,
        "header_timestamp_utc": when(stamp),
        "header_timestamp_note": ("The COFF TimeDateStamp read as seconds since 1970-01-01T00:00:00Z. A linker may write a value that is not a time "
                                  "(a reproducible build writes a hash), so a date here is a reading of a number, not a compile time."),
        "characteristics": hex(characteristics),
        "is_dll": bool(characteristics & 0x2000),
        "is_system_file": bool(characteristics & 0x1000),
        "is_executable_image": bool(characteristics & 0x0002),
    })

    opt_at = pe_at + 24
    avail = max(0, min(opt_size, img.size - opt_at))
    wide = None
    dirs = []
    size_of_headers = 0
    header_problems = []

    def header_problem(text):
        header_problems.append(text)
        ctx.problem(text)

    if opt_size == 0:
        header_problem("SizeOfOptionalHeader is 0: the file declares no optional header, which a PE image has")
    else:
        missing = []
        if avail < opt_size:
            header_problem("the file ends %d bytes into an optional header that declares %d bytes" % (avail, opt_size))

        def opt(fmt, off, name):
            if off + struct.calcsize(fmt) > avail:
                missing.append(name)
                return None
            return struct.unpack_from(fmt, img.mm, opt_at + off)[0]

        magic = opt("<H", 0, "magic")
        if magic is None:
            header_problem("the optional header is shorter than its magic")
        elif magic == 0x107:
            raise Stop("unsupported", "the optional header magic is 0x107, a ROM image: not read", out)
        elif magic not in (0x10b, 0x20b):
            raise Stop("failed", "the optional header magic is 0x%x, neither PE32 (0x10b) nor PE32+ (0x20b)" % magic, out)
        else:
            wide = magic == 0x20b
            out["bits"] = 64 if wide else 32
            entry = opt("<I", 16, "entry point")
            base = opt("<Q" if wide else "<I", 24 if wide else 28, "image base")
            salign = opt("<I", 32, "section alignment")
            falign = opt("<I", 36, "file alignment")
            soi = opt("<I", 56, "size of image")
            soh = opt("<I", 60, "size of headers")
            subsystem = opt("<H", 68, "subsystem")
            dllflags = opt("<H", 70, "DLL characteristics")
            count = opt("<I", 108 if wide else 92, "number of data directories")
            if entry is not None:
                out["entry_point"] = hex(entry)
            if base is not None:
                out["image_base"] = hex(base)
            if salign is not None:
                out["section_alignment"] = salign
            if falign is not None:
                out["file_alignment"] = falign
            if soi is not None:
                out["size_of_image"] = soi
            if soh is not None:
                out["size_of_headers"] = soh
                size_of_headers = soh
            if subsystem is not None:
                out["subsystem"] = SUBSYSTEMS.get(subsystem, "unknown (%d)" % subsystem)
            if dllflags is not None:
                out["dll_characteristics"] = hex(dllflags)
                out["aslr"] = bool(dllflags & 0x0040)
                out["dep"] = bool(dllflags & 0x0100)
            dirs_off = 112 if wide else 96
            if count is not None:
                out["data_directories_declared"] = count
                fit = max(0, (avail - dirs_off) // 8)
                want = min(count, 16)
                if want > fit:
                    header_problem("data directories: %d declared, %d fit inside the %d bytes of optional header the file declares and holds"
                                   % (want, fit, avail))
                for i in range(min(want, fit)):
                    rva, size = struct.unpack_from("<II", img.mm, opt_at + dirs_off + i * 8)
                    dirs.append({"index": i, "name": PE_DIRECTORIES[i], "rva": rva, "size": size})
        if missing:
            header_problem("the optional header declares %d bytes and the file holds %d of them; not read: %s"
                           % (opt_size, avail, ", ".join(missing)))
    if header_problems:
        out["header_problem"] = "; ".join(header_problems)
    declared = [d for d in dirs if d["size"]]
    out["data_directories"] = declared
    out["certificate_table_declared"] = None if wide is None else any(d["index"] == 4 for d in declared)
    if wide is not None:
        for flag, idx in (("declares_resources", 2), ("declares_tls", 9), ("declares_delay_imports", 13),
                          ("declares_clr_runtime_header", 14)):
            out[flag] = any(d["index"] == idx for d in declared)

    # Section table: after the optional header the file declares, whatever it holds.
    table_at = opt_at + opt_size
    sections = ctx.page("sections")
    maps = []
    read = 0
    last_raw_end = 0
    for i in range(min(nsec, MAX_SECTIONS)):
        at = table_at + i * 40
        if at + 40 > img.size:
            ctx.problem("section table: %d of %d section headers are in the file" % (i, nsec))
            break
        read += 1
        name = bytes(img.mm[at:at + 8]).rstrip(b"\x00").decode("utf-8", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", img.mm, at + 8)
        flags, = struct.unpack_from("<I", img.mm, at + 36)
        row = {"name": name, "virtual_size": vsize, "virtual_address": hex(vaddr), "raw_size": rawsize,
               "raw_pointer": rawptr, "characteristics": hex(flags),
               "permissions": [n for bit, n in SECTION_FLAGS if flags & bit]}
        if rawsize:
            if rawptr >= img.size:
                row["raw_range_in_file"] = False
                row["entropy"], row["entropy_note"] = None, "the raw data pointer is past the end of the file"
                ctx.problem("section %s: its raw data starts at %d, past the end of the file" % (name or i, rawptr))
            else:
                row["raw_range_in_file"] = rawptr + rawsize <= img.size
                if not row["raw_range_in_file"]:
                    ctx.problem("section %s: its raw data runs %d byte(s) past the end of the file" % (name or i, rawptr + rawsize - img.size))
                row["entropy"], why = entropy_of(img, rawptr, rawptr + rawsize, ctx)
                if why:
                    row["entropy_note"] = why
            last_raw_end = max(last_raw_end, min(img.size, rawptr + rawsize))
            maps.append((vaddr, min(vsize or rawsize, rawsize), rawptr, min(img.size, rawptr + rawsize), len(maps)))
        else:
            row["entropy"], row["entropy_note"] = None, "no raw data"
        if rawsize and vsize > rawsize * 4 and (row["entropy"] or 0) > 7.0:
            row["size_entropy_pattern"] = True
        if "write" in row["permissions"] and "execute" in row["permissions"]:
            row["writable_and_executable"] = True
        sections.add(row)
    if nsec > MAX_SECTIONS:
        ctx.problem("section table: %d sections are declared, and %d are read" % (nsec, MAX_SECTIONS))
    out["sections_read"] = read
    if size_of_headers:
        maps.append((0, size_of_headers, 0, min(size_of_headers, img.size), len(maps)))
    # Sorted by address once, so that finding the section behind an RVA is a search and not a pass over every section for
    # every thunk (65,535 sections times 30,000 thunks took 170 seconds). Sections that overlap in memory are looked for a
    # few entries back from the nearest start, and the one first in the table wins, as it did before.
    by_start = sorted(maps)
    starts = [m[0] for m in by_start]

    def to_range(rva):
        """(file offset, end of the file-backed bytes of the section or headers holding it) or None."""
        i = bisect.bisect_right(starts, rva) - 1
        best = None
        for j in range(i, max(-1, i - OVERLAP_LOOK_BACK), -1):
            vaddr, span, rawptr, file_end, order = by_start[j]
            delta = rva - vaddr
            if 0 <= delta < max(span, 1) and rawptr + delta < file_end and (best is None or order < best[4]):
                best = (rawptr + delta, file_end, 0, 0, order)
        return (best[0], best[1]) if best else None

    # Imports.
    out["imports"] = [] if ctx.with_imports else None
    if ctx.with_imports and wide is not None:
        import_dir = next((d for d in declared if d["index"] == 1), None)
        if import_dir is not None:
            read_imports(img, ctx, out, import_dir, to_range, wide)
    # Exports: the directory's image name only.
    export_dir = next((d for d in declared if d["index"] == 0), None)
    if export_dir is not None:
        mapped = to_range(export_dir["rva"])
        if mapped is None or mapped[0] + 40 > mapped[1]:
            ctx.problem("the export directory is not backed by file bytes")
        else:
            name_rva, = struct.unpack_from("<I", img.mm, mapped[0] + 12)
            name_range = to_range(name_rva)
            if name_range is None:
                ctx.problem("the export directory's name is not backed by file bytes")
            else:
                text, complete = img.cstr(name_range[0], name_range[1])
                out["export_name"] = show(ctx, "export_name", text, name_range[0])
                if not complete:
                    ctx.problem("the export directory's image name has no terminator within its section or %d bytes" % NAME_CAP)
    # Certificate table: a file offset and a size, declared by the header.
    cert = next((d for d in declared if d["index"] == 4), None)
    cert_range = None
    if cert is not None:
        off, size = cert["rva"], cert["size"]
        inside = off > 0 and off + size <= img.size
        table = {"offset": off, "size": size, "within_file": inside,
                 "note": "A declaration in the header. The table is read no further than its first entry's header, and nothing is verified."}
        if not inside:
            ctx.problem("the certificate table [%d, %d) is not inside the %d-byte file: its first entry's header was not read" % (off, off + size, img.size))
        if off > 0 and size >= 8 and off + 8 <= img.size:
            length, revision, ctype = struct.unpack_from("<IHH", img.mm, off)
            table["first_entry"] = {"length": length, "revision": hex(revision), "certificate_type": hex(ctype),
                                    "certificate_type_name": WIN_CERT_TYPES.get(ctype)}
        if inside:
            cert_range = (off, off + size)
        out["certificate_table"] = table
    if last_raw_end and img.size > last_raw_end:
        out["overlay_offset"] = last_raw_end
        out["overlay_bytes"] = img.size - last_raw_end
        if cert_range is not None:
            covered = max(0, min(img.size, cert_range[1]) - max(last_raw_end, cert_range[0]))
            out["overlay_bytes_outside_certificate_table"] = out["overlay_bytes"] - covered
            out["overlay_is_certificate_table"] = covered == out["overlay_bytes"]
    read_list = [x for x in PE_READ if ctx.with_imports or not x.startswith("import directory")]
    not_read = PE_NOT_READ + ([] if ctx.with_imports else ["import directory: names and ordinals (not requested: with_imports is false)"])
    out["coverage"] = {"structures_read": read_list, "structures_not_read": not_read}
    return out


def read_imports(img, ctx, out, import_dir, to_range, wide):
    start = to_range(import_dir["rva"])
    functions = ctx.page("imports")
    libs = []
    out["imports"] = libs
    inline_left = ctx.limit
    total = 0
    if start is None:
        out["import_table_problem"] = "the import directory points outside file-backed bytes"
        ctx.problem(out["import_table_problem"])
        return
    first, end = start
    declared = import_dir["size"] // 20
    if declared == 0:
        out["import_table_problem"] = "the import directory's size (%d) is smaller than one descriptor (20 bytes)" % import_dir["size"]
        ctx.problem(out["import_table_problem"])
        return
    count = min(declared, MAX_IMPORT_DESCRIPTORS)
    terminated = False
    index = 0
    while index < count:
        if ctx.expired("the import read"):
            out["import_table_problem"] = "the import read stopped at the tool's own clock after %d of %d descriptors" % (index, declared)
            ctx.problem(out["import_table_problem"])
            break
        at = first + index * 20
        if at + 20 > end:
            out["import_table_problem"] = ("the import directory runs past the file-backed bytes of its section "
                                           "(descriptor %d of %d declared)" % (index + 1, declared))
            ctx.problem(out["import_table_problem"])
            break
        original_thunk, stamp, forward, name_rva, first_thunk = struct.unpack_from("<IIIII", img.mm, at)
        if not (original_thunk or stamp or forward or name_rva or first_thunk):
            terminated = True
            break
        index += 1
        name_range = to_range(name_rva)
        library, name_ok = img.cstr(name_range[0], name_range[1]) if name_range else ("?", False)
        entry = {"library": library, "descriptor_offset": at, "functions": [], "function_count": 0}
        if name_range is None:
            entry["name_problem"] = "the library name RVA 0x%x is not backed by file bytes" % name_rva
            ctx.problem("import descriptor %d: %s" % (index, entry["name_problem"]))
        elif not name_ok:
            ctx.problem("import descriptor %d: the library name has no terminator within its section or %d bytes" % (index, NAME_CAP))
        thunk_range = to_range(original_thunk or first_thunk)
        step = 8 if wide else 4
        ordinal_bit = 1 << (63 if wide else 31)
        unresolved = 0
        thunk_terminated = False
        if thunk_range is not None:
            thunk_at, thunk_end = thunk_range
            n = 0
            while thunk_at + step <= thunk_end:
                if n % 1024 == 1023 and ctx.expired("the import read"):
                    entry["thunk_table_problem"] = "the read of this thunk table stopped at the tool's own clock"
                    break
                if n >= MAX_THUNKS_PER_LIBRARY or total >= MAX_FUNCTIONS:
                    ctx.limit_hit("imports: the read stopped at %d functions in one library or %d in all" % (MAX_THUNKS_PER_LIBRARY, MAX_FUNCTIONS))
                    entry["thunk_table_problem"] = "the read of this thunk table stopped at a limit"
                    break
                value, = struct.unpack_from("<Q" if wide else "<I", img.mm, thunk_at)
                if not value:
                    thunk_terminated = True
                    break
                n += 1
                thunk_at += step
                if value & ordinal_bit:
                    name = "#%d" % (value & 0xFFFF)
                else:
                    hint_range = to_range(value)
                    name, complete = img.cstr(hint_range[0] + 2, hint_range[1]) if hint_range else (None, False)
                    if name is None:
                        unresolved += 1
                        continue
                    if not complete:
                        ctx.problem("an import name in %s has no terminator within its section or %d bytes" % (library, NAME_CAP))
                total += 1
                entry["function_count"] += 1
                functions.add({"library": library, "function": name})
                if inline_left > 0:
                    entry["functions"].append(name)
                    inline_left -= 1
            if "thunk_table_problem" not in entry and not thunk_terminated:
                entry["thunk_table_problem"] = "the thunk table has no terminator in its section"
        else:
            entry["thunk_table_problem"] = "the thunk RVA is not backed by file bytes"
        if unresolved:
            entry["unresolved_function_names"] = unresolved
            ctx.problem("%s: %d import name(s) point outside file-backed bytes" % (library, unresolved))
        if "thunk_table_problem" in entry:
            ctx.problem("%s: %s" % (library, entry["thunk_table_problem"]))
        libs.append(entry)
    if not terminated and index == count and "import_table_problem" not in out:
        out["import_table_problem"] = "the import directory has no terminating descriptor within its declared size"
        ctx.problem(out["import_table_problem"])
    out["import_library_count"] = len(libs)
    out["import_function_count"] = total
    if len(libs) <= 2 and total <= 6:
        out["few_imports"] = ("Few imports are declared. That is consistent with packing, static linking, managed code or "
                              "imports resolved at runtime; it does not by itself show any of them.")


# --- ELF -------------------------------------------------------------------------------------------------------------

ELF_READ = ["ELF header (class, byte order, type, machine, entry, table locations)", "program headers",
            "section headers and the entropy of each section's bytes",
            "the dynamic array (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH)", "the program interpreter (PT_INTERP)"]
ELF_NOT_READ = ["symbol tables and relocations", "notes, including the GNU build ID (readelf -n prints them)",
                "version definitions and requirements",
                "core-file notes and mappings (a core file is read as a header and tables only)", "debug sections"]


def read_elf(img, ctx):
    out = {"format": "ELF"}
    if img.size < 16:
        raise Stop("failed", "shorter than the 16-byte ELF identification: the file is %d bytes" % img.size, out)
    cls, data, version = img.mm[4], img.mm[5], img.mm[6]
    if cls not in (1, 2):
        raise Stop("unsupported", "EI_CLASS is %d: neither ELFCLASS32 (1) nor ELFCLASS64 (2)" % cls, out)
    if data not in (1, 2):
        raise Stop("unsupported", "EI_DATA is %d: neither ELFDATA2LSB (1) nor ELFDATA2MSB (2)" % data, out)
    wide = cls == 2
    e = ">" if data == 2 else "<"
    hsize = 64 if wide else 52
    out["bits"] = 64 if wide else 32
    out["endian"] = "big" if data == 2 else "little"
    if img.size < hsize:
        raise Stop("failed", "shorter than an ELF%d header (%d bytes): the file is %d bytes" % (out["bits"], hsize, img.size), out)
    if version != 1:
        ctx.problem("EI_VERSION is %d, not 1" % version)
    out["os_abi"] = img.mm[7]
    elf_type, machine = img.unpack(e + "HH", 16)
    out["type"] = ELF_TYPES.get(elf_type, "OS- or processor-specific (0x%x)" % elf_type)
    out["machine"] = ELF_MACHINES.get(machine, hex(machine))
    if wide:
        entry, phoff, shoff = img.unpack(e + "QQQ", 24)
        eflags, = img.unpack(e + "I", 48)
        _ehsize, phentsize, phnum, shentsize, shnum, shstrndx = img.unpack(e + "HHHHHH", 52)
    else:
        entry, phoff, shoff = img.unpack(e + "III", 24)
        eflags, = img.unpack(e + "I", 36)
        _ehsize, phentsize, phnum, shentsize, shnum, shstrndx = img.unpack(e + "HHHHHH", 40)
    out["entry_point"] = hex(entry)
    out["flags"] = hex(eflags)
    phmin, shmin = (56, 64) if wide else (32, 40)

    # Section header 0 holds the real counts when a field overflows (PN_XNUM, SHN_XINDEX, a zero e_shnum).
    sh0 = None
    if shoff and shentsize >= shmin and shoff + shmin <= img.size:
        sh0 = img.unpack(e + ("IIQQQQIIQQ" if wide else "IIIIIIIIII"), shoff)
    sh_size0, sh_link0, sh_info0 = (sh0[5], sh0[6], sh0[7]) if sh0 else (0, 0, 0)
    out["program_headers"] = phnum
    if phnum == 0xFFFF:
        if sh0:
            phnum = sh_info0
            out["program_headers"] = phnum
            out["extended_program_header_count"] = True
        else:
            ctx.problem("e_phnum is 0xFFFF (PN_XNUM) and section header 0, which holds the real count, could not be read")
    if shnum == 0 and shoff:
        if sh0:
            shnum = sh_size0
            out["extended_section_count"] = True
        else:
            ctx.problem("e_shnum is 0 with e_shoff set, and section header 0, which holds the real count, could not be read")
    if shstrndx == 0xFFFF and sh0:
        shstrndx = sh_link0
    out["section_headers"] = shnum

    # Program headers.
    pages_seg = ctx.page("segments")
    loads, pt_dynamic, pt_interp = [], None, None
    if phnum:
        if phentsize < phmin:
            ctx.problem("e_phentsize is %d, smaller than the %d-byte Elf%d_Phdr: the program headers were not read" % (phentsize, phmin, out["bits"]))
        else:
            fit = max(0, (img.size - phoff) // phentsize) if phoff <= img.size else 0
            if phnum > fit:
                ctx.problem("program headers: %d declared, %d fit inside the file" % (phnum, fit))
            if min(phnum, fit) > MAX_PHDRS:
                ctx.limit_hit("program headers: the read stopped at %d of %d" % (MAX_PHDRS, min(phnum, fit)))
            for i in range(min(phnum, fit, MAX_PHDRS)):
                at = phoff + i * phentsize
                if wide:
                    p_type, flags, offset, vaddr, _paddr, file_size, mem_size, align = struct.unpack_from(e + "IIQQQQQQ", img.mm, at)
                else:
                    p_type, offset, vaddr, _paddr, file_size, mem_size, flags, align = struct.unpack_from(e + "IIIIIIII", img.mm, at)
                row = {"index": i, "type": p_type, "type_name": ELF_PT.get(p_type), "offset": offset,
                       "virtual_address": hex(vaddr), "file_size": file_size, "memory_size": mem_size,
                       "permissions": {"read": bool(flags & 0x4), "write": bool(flags & 0x2), "execute": bool(flags & 0x1)},
                       "alignment": align, "file_range_in_file": offset + file_size <= img.size}
                if file_size:
                    if offset + file_size > img.size:
                        ctx.problem("segment %d (%s): its file range [%d, %d) runs %d byte(s) past the end of the %d-byte file"
                                    % (i, ELF_PT.get(p_type) or hex(p_type), offset, offset + file_size, offset + file_size - img.size, img.size))
                    row["entropy"], why = entropy_of(img, offset, offset + file_size, ctx)
                    if why:
                        row["entropy_note"] = why
                else:
                    row["entropy"] = None
                pages_seg.add(row)
                if p_type == 1:
                    loads.append((vaddr, offset, file_size))
                elif p_type == 2 and pt_dynamic is None:
                    pt_dynamic = (offset, file_size)
                elif p_type == 3 and pt_interp is None:
                    pt_interp = (offset, file_size)

    # Section headers.
    pages_sec = ctx.page("sections")
    shdrs = []
    declared = bool(shoff and shnum)
    if declared and shentsize < shmin:
        ctx.problem("e_shentsize is %d, smaller than the %d-byte Elf%d_Shdr: the section headers were not read" % (shentsize, shmin, out["bits"]))
    elif declared:
        fit = max(0, (img.size - shoff) // shentsize) if shoff <= img.size else 0
        count = min(shnum, fit, MAX_ELF_SECTIONS)
        if shnum > count:
            ctx.problem("section headers: %d declared, %d read (the rest are past the end of the file or over the limit)" % (shnum, count))
        if min(shnum, fit) > MAX_ELF_SECTIONS:
            ctx.limit_hit("section headers: the read stopped at %d of %d" % (MAX_ELF_SECTIONS, min(shnum, fit)))
        for i in range(count):
            at = shoff + i * shentsize
            if wide:
                name_off, sh_type, flags, addr, offset, size, link, _info, _align, _entsize = struct.unpack_from(e + "IIQQQQIIQQ", img.mm, at)
            else:
                name_off, sh_type, flags, addr, offset, size, link, _info, _align, _entsize = struct.unpack_from(e + "IIIIIIIIII", img.mm, at)
            shdrs.append((name_off, sh_type, flags, addr, offset, size, link))
        names_at = names_end = None
        if 0 <= shstrndx < len(shdrs):
            _n, n_type, _f, _a, n_start, n_size, _l = shdrs[shstrndx]
            if n_type == 3:
                names_at, names_end = n_start, n_start + n_size
            else:
                ctx.problem("the section name string table index (%d) names a section that is not an SHT_STRTAB" % shstrndx)
        else:
            ctx.problem("the section name string table index (%d) is outside the %d section headers read" % (shstrndx, len(shdrs)))
        for i, (name_off, sh_type, flags, addr, offset, size, _link) in enumerate(shdrs):
            if names_at is not None:
                name, _ok = img.cstr(names_at + name_off, names_end)
                name = name if name is not None else ""
            else:
                name = str(i)
            row = {"index": i, "name": name, "type": sh_type, "type_name": ELF_SHT.get(sh_type), "address": hex(addr),
                   "offset": offset, "size": size, "executable": bool(flags & 0x4), "writable": bool(flags & 0x1)}
            if sh_type not in (0, 8) and size:
                row["file_range_in_file"] = offset + size <= img.size
                if not row["file_range_in_file"]:
                    ctx.problem("section %d (%s): its bytes [%d, %d) run %d byte(s) past the end of the %d-byte file"
                                % (i, name or "unnamed", offset, offset + size, offset + size - img.size, img.size))
            if sh_type != 8 and size:
                row["entropy"], why = entropy_of(img, offset, offset + size, ctx)
                if why:
                    row["entropy_note"] = why
            else:
                row["entropy"] = None
            pages_sec.add(row)
    out["section_headers_absent"] = not declared
    out["section_headers_read"] = len(shdrs)
    if shdrs:
        has_symtab = any(s[1] == 2 for s in shdrs)
        out["symbol_table_section_present"] = has_symtab
        out["stripped"] = False if has_symtab else (True if len(shdrs) == shnum else None)
    else:
        out["stripped"] = None
    out["stripped_basis"] = ("an SHT_SYMTAB section is present" if out["stripped"] is False else
                             "section headers are present and none is an SHT_SYMTAB (a stripped file still has .dynsym)" if out["stripped"] else
                             "section headers are absent or not all read: whether symbols were removed is not determined")

    if pt_interp is not None:
        text, _ok = img.cstr(pt_interp[0], pt_interp[0] + pt_interp[1])
        if text is not None:
            out["interpreter"] = show(ctx, "interpreter", text, pt_interp[0])
    read_dynamic(img, ctx, out, e, wide, loads, pt_dynamic, shdrs)
    out["coverage"] = {"structures_read": ELF_READ, "structures_not_read": ELF_NOT_READ}
    return out


def read_dynamic(img, ctx, out, e, wide, loads, pt_dynamic, shdrs):
    entsz = 16 if wide else 8
    source = file_offset = size = link = None
    if pt_dynamic is not None:
        source, (file_offset, size) = "PT_DYNAMIC", pt_dynamic
    else:
        for s in shdrs:
            if s[1] == 6:
                source, file_offset, size, link = "SHT_DYNAMIC section (the file has no PT_DYNAMIC program header)", s[4], s[5], s[6]
                break
    out["needed_libraries"] = []
    if source is None:
        out["dynamic"] = {"source": None,
                          "note": ("The file has no PT_DYNAMIC program header and no SHT_DYNAMIC section, so no dependency list was "
                                   "read. That does not by itself show static linking.")}
        return
    dynamic = {"source": source, "file_offset": file_offset, "entries_read": 0, "terminated": False}
    out["dynamic"] = dynamic
    fit = max(0, (img.size - file_offset) // entsz) if file_offset <= img.size else 0
    n = min(size // entsz, fit, MAX_DYNAMIC_ENTRIES)
    if size // entsz > n:
        ctx.problem("dynamic array: %d entries are declared, %d read (the rest are past the end of the file or over the limit)" % (size // entsz, n))
    needed, soname, rpath, runpath = [], None, None, None
    strtab = strsz = None
    for i in range(n):
        if wide:
            tag, value = struct.unpack_from(e + "qQ", img.mm, file_offset + i * entsz)
        else:
            tag, value = struct.unpack_from(e + "iI", img.mm, file_offset + i * entsz)
        dynamic["entries_read"] += 1
        if tag == 0:
            dynamic["terminated"] = True
            break
        if tag == 1:
            if len(needed) < MAX_NEEDED:
                needed.append(value)
            elif len(needed) == MAX_NEEDED:
                needed.append(None)
                ctx.limit_hit("dynamic array: more than %d DT_NEEDED entries; the rest were not read" % MAX_NEEDED)
        elif tag == 5:
            strtab = value
        elif tag == 10:
            strsz = value
        elif tag == 14:
            soname = value
        elif tag == 15:
            rpath = value
        elif tag == 29:
            runpath = value
    if not dynamic["terminated"]:
        ctx.problem("the dynamic array has no DT_NULL terminator within the bytes it declares")
    needed = [v for v in needed if v is not None]

    start = end = None
    via = None
    if strtab is not None:
        for vaddr, offset, filesz in loads:
            if vaddr <= strtab < vaddr + filesz:
                start, via = offset + (strtab - vaddr), "PT_LOAD segment that maps DT_STRTAB"
                break
        if start is None:
            for s in shdrs:
                if s[1] == 3 and s[3] == strtab and s[3] != 0:
                    start, via, end = s[4], "SHT_STRTAB section whose address is DT_STRTAB", s[4] + s[5]
                    break
    elif link is not None and 0 <= link < len(shdrs) and shdrs[link][1] == 3:
        start, via, end = shdrs[link][4], "sh_link of the SHT_DYNAMIC section", shdrs[link][4] + shdrs[link][5]
    if start is None:
        if needed or soname is not None or rpath is not None or runpath is not None:
            ctx.problem("DT_STRTAB (%s) is not mapped by any PT_LOAD segment and names no string-table section: the names of "
                        "DT_NEEDED, DT_SONAME, DT_RPATH and DT_RUNPATH were not read" % (hex(strtab) if strtab is not None else "absent"))
        dynamic["string_table"] = {"resolved_via": None, "needed_entries_unread": len(needed)}
        return
    if strsz is not None:
        end = start + strsz if end is None else min(end, start + strsz)
    dynamic["string_table"] = {"resolved_via": via, "file_offset": start, "size": strsz}

    def string(offset, what, field):
        text, complete = img.cstr(start + offset, end)
        if text is None:
            ctx.problem("%s: its string offset %d is outside the string table" % (what, offset))
            return None
        if not complete:
            ctx.problem("%s: the string has no terminator within the string table or %d bytes" % (what, NAME_CAP))
        return show(ctx, field, text, start + offset)

    for off in needed:
        s = string(off, "DT_NEEDED", "needed_libraries")
        if s is not None:
            out["needed_libraries"].append(s)
    for key, tag_name, off in (("soname", "DT_SONAME", soname), ("rpath", "DT_RPATH", rpath), ("runpath", "DT_RUNPATH", runpath)):
        if off is not None:
            s = string(off, tag_name, key)
            if s is not None:
                out[key] = s


# --- Mach-O ----------------------------------------------------------------------------------------------------------

MACHO_READ = ["the Mach-O header (byte order, width, CPU, file type)", "load commands, bounded by sizeofcmds and the slice",
              "linked libraries (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB) and the install name",
              "segments (name, addresses, sizes, protections)", "LC_MAIN's entry offset",
              "the presence and location of LC_CODE_SIGNATURE"]
MACHO_NOT_READ = ["symbol tables and the dyld information", "code signature contents: nothing is parsed or verified",
                  "sections inside segments", "the contents of any segment"]


def read_macho_slice(img, base, end, label, ctx, slice_index):
    """The thin Mach-O at [base, end): (fields with a `status`, problems). Offsets are file offsets; the offsets a Mach-O
    names itself (segments, the code signature) are relative to the start of the slice."""
    problems = []
    out = {}
    if end - base < 4:
        return {"status": "failed", "reason": "fewer than 4 bytes"}, problems
    magic = bytes(img.mm[base:base + 4])
    if magic in FAT_MAGICS:
        return {"status": "unsupported", "reason": "a universal binary nested inside a slice: not read (nesting is one level)"}, problems
    if magic not in MACHO_MAGICS:
        return {"status": "unsupported", "reason": "the slice does not begin with a Mach-O magic (first bytes %s)" % magic.hex()}, problems
    wide, e = MACHO_MAGICS[magic]
    hsize = 32 if wide else 28
    if end - base < hsize:
        return {"status": "failed", "reason": "shorter than a %d-bit Mach-O header (%d bytes)" % (64 if wide else 32, hsize)}, problems
    length = end - base
    cputype, _sub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(e + "IIIIII", img.mm, base + 4)
    out.update({"bits": 64 if wide else 32, "byte_order": "big" if e == ">" else "little",
                "cpu_type": hex(cputype), "cpu_type_name": MACHO_CPUS.get(cputype), "type": MACHO_TYPES.get(filetype, str(filetype)),
                "flags": hex(flags), "load_commands": ncmds, "sizeofcmds": sizeofcmds})
    region_end = base + hsize + sizeofcmds
    if region_end > end:
        problems.append("%ssizeofcmds (%d) runs %d byte(s) past the slice" % (label, sizeofcmds, region_end - end))
        region_end = end
    expected = min(ncmds, (region_end - base - hsize) // 8)
    if ncmds > expected:
        problems.append("%sncmds is %d, more than the %d load commands the %d bytes of commands can hold: the traversal is bounded by the bytes"
                        % (label, ncmds, expected, region_end - base - hsize))
    if expected > MAX_LOAD_COMMANDS:
        ctx.limit_hit("load commands: %sthe read stopped at %d of %d" % (label, MAX_LOAD_COMMANDS, expected))
        problems.append("%sthe slice holds %d load commands and %d were read" % (label, expected, MAX_LOAD_COMMANDS))
    commands_table = ctx.page("load_commands")
    libraries, kinds, segments = [], [], []
    out["install_name"] = None
    align = 8 if wide else 4
    at = base + hsize
    read = 0
    for _ in range(min(expected, MAX_LOAD_COMMANDS)):
        if read % 1024 == 1023 and ctx.expired("the load-command read"):
            problems.append("%sthe load-command read stopped at the tool's own clock" % label)
            break
        if at + 8 > region_end:
            problems.append("%sa load command starts at %d, with fewer than 8 bytes left in the commands" % (label, at))
            break
        cmd, size = struct.unpack_from(e + "II", img.mm, at)
        if size < 8 or at + size > region_end:
            problems.append("%sload command %d (0x%x) declares %d bytes at offset %d, which does not fit the commands region: the traversal stopped"
                            % (label, read + 1, cmd, size, at))
            break
        read += 1
        if size % align:
            problems.append("%sload command %d (0x%x) declares %d bytes, which is not a multiple of %d" % (label, read, cmd, size, align))
        commands_table.add({"slice": slice_index, "cmd": LC_NAMES.get(cmd, hex(cmd)), "size": size, "offset": at})
        if cmd in LC_LINKED or cmd == LC_ID_DYLIB:
            name_off = struct.unpack_from(e + "I", img.mm, at + 8)[0] if size >= 12 else 0
            text, complete = img.cstr(at + name_off, at + size) if 12 <= name_off < size else (None, False)
            if text is None:
                problems.append("%sa dylib command at offset %d has a name offset (%d) outside the command" % (label, at, name_off))
            else:
                if not complete:
                    problems.append("%sthe library name in the command at offset %d has no terminator inside the command" % (label, at))
                if cmd == LC_ID_DYLIB:
                    out["install_name"] = show(ctx, "install_name", text, at + name_off)
                else:
                    shown = show(ctx, "linked_libraries", text, at + name_off)
                    libraries.append(shown)
                    kinds.append({"name": shown, "command": LC_LINKED[cmd]})
        elif cmd == LC_SEGMENT_64 and size >= 72 and wide or cmd == LC_SEGMENT and size >= 56 and not wide:
            segname = bytes(img.mm[at + 8:at + 24]).rstrip(b"\x00").decode("utf-8", "replace")
            fmt = e + ("QQQQiiI" if wide else "IIIIiiI")
            vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects = struct.unpack_from(fmt, img.mm, at + 24)
            segments.append({"name": segname, "vm_address": hex(vmaddr), "vm_size": vmsize, "file_offset": fileoff, "file_size": filesize,
                             "max_protection": maxprot, "initial_protection": initprot, "sections": nsects})
            if filesize and fileoff + filesize > length:
                problems.append("%ssegment %s: its file range [%d, %d) runs %d byte(s) past the end of the %d-byte slice"
                                % (label, segname, fileoff, fileoff + filesize, fileoff + filesize - length, length))
        elif cmd == LC_MAIN and size >= 24:
            out["entry_offset"] = struct.unpack_from(e + "Q", img.mm, at + 8)[0]
        elif cmd == LC_CODE_SIGNATURE and size >= 16:
            dataoff, datasize = struct.unpack_from(e + "II", img.mm, at + 8)
            out["code_signature"] = {"offset": dataoff, "size": datasize}
            if datasize and dataoff + datasize > length:
                problems.append("%sthe code signature [%d, %d) runs %d byte(s) past the end of the %d-byte slice"
                                % (label, dataoff, dataoff + datasize, dataoff + datasize - length, length))
        at += size
    out["load_commands_read"] = read
    out["linked_libraries"] = libraries
    out["linked_library_commands"] = kinds
    out["segments"] = segments
    out["status"] = "partial" if problems else "complete"
    return out, problems


def read_macho(img, ctx):
    magic = bytes(img.mm[:4])
    if magic in MACHO_MAGICS:
        body, problems = read_macho_slice(img, 0, img.size, "", ctx, None)
        body["format"] = "Mach-O"
        status = body.pop("status")
        if status in ("failed", "unsupported"):
            raise Stop(status, body.pop("reason", "unreadable"), body)
        for p in problems:
            ctx.problem(p)
        body["coverage"] = {"structures_read": MACHO_READ, "structures_not_read": MACHO_NOT_READ}
        return body
    wide, e = FAT_MAGICS[magic]
    out = {"format": "Mach-O universal binary", "fat_byte_order": "big" if e == ">" else "little", "fat_arch_width": 64 if wide else 32}
    if img.size < 8:
        raise Stop("failed", "shorter than a fat header (8 bytes)", out)
    nfat, = img.unpack(e + "I", 4)
    entry = 32 if wide else 20
    out["slices_declared"] = nfat
    fit = max(0, (img.size - 8) // entry)
    java = "0xCAFEBABE is also the first word of a Java class file, whose version fields are read here as a slice count"
    if magic == b"\xca\xfe\xba\xbe" and 45 <= (nfat & 0xFFFF) <= 100:
        # A class file: minor_version, then major_version (45 is JDK 1.1). A universal binary with 45 or more slices does not exist.
        raise Stop("unsupported", "a Java class file (version %d.%d), which begins with the universal-binary magic: not a Mach-O" % (nfat & 0xFFFF, nfat >> 16),
                   {"format": "Java class file", "class_file_version": {"major": nfat & 0xFFFF, "minor": nfat >> 16}})
    if nfat == 0 or nfat > MAX_SLICES:
        raise Stop("failed", "a file that begins with the universal-binary magic declares %d slices, which is not a plausible architecture table (%s)"
                   % (nfat, java), out)
    if nfat > fit:
        ctx.problem("slices: %d declared, %d architecture entries fit inside the file" % (nfat, fit))
    slices = []
    out["slices"] = slices
    spans = []
    for i in range(min(nfat, fit)):
        at = 8 + i * entry
        if wide:
            cputype, subtype, offset, size, align, _res = struct.unpack_from(e + "IIQQII", img.mm, at)
        else:
            cputype, subtype, offset, size, align = struct.unpack_from(e + "IIIII", img.mm, at)
        row = {"index": i, "cpu_type": hex(cputype), "cpu_type_name": MACHO_CPUS.get(cputype), "cpu_subtype": hex(subtype),
               "offset": offset, "size": size, "alignment_power": align, "in_file": size > 0 and offset + size <= img.size}
        if not row["in_file"]:
            row["status"] = "failed"
            row["reason"] = "the slice [%d, %d) is not inside the %d-byte file" % (offset, offset + size, img.size)
            ctx.problem("slice %d: %s" % (i, row["reason"]))
        else:
            for j, (o2, e2) in spans:
                if offset < e2 and o2 < offset + size:
                    ctx.problem("slices %d and %d overlap: [%d, %d) and [%d, %d)" % (j, i, o2, e2, offset, offset + size))
            spans.append((i, (offset, offset + size)))
            macho, problems = read_macho_slice(img, offset, offset + size, "slice %d: " % i, ctx, i)
            row["status"] = macho.pop("status")
            if "reason" in macho:
                row["reason"] = macho.pop("reason")
                ctx.problem("slice %d: %s" % (i, row["reason"]))
            if macho:
                row["macho"] = macho
            for p in problems:
                ctx.problem(p)
        slices.append(row)
    if not slices or all(s["status"] == "failed" for s in slices):
        raise Stop("failed", "no slice of this file is a readable Mach-O (%s)" % java, out)
    if any(s["status"] != "complete" for s in slices):
        ctx.problem("at least one slice was not read in full: see the slices table")
    out["coverage"] = {"structures_read": ["the fat header and its architecture table"] + MACHO_READ, "structures_not_read": MACHO_NOT_READ,
                       "slices_read_in_full": sum(1 for s in slices if s["status"] == "complete"), "slices_declared": nfat}
    return out


# --- the call --------------------------------------------------------------------------------------------------------

def positive_int(args, key, default, minimum=1, maximum=None):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or (maximum is not None and value > maximum):
        fail("%s must be an integer from %d%s" % (key, minimum, " to %d" % maximum if maximum is not None else ""))
    return value


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a PE, ELF or Mach-O file")
    with_imports = args.get("with_imports", True)
    if not isinstance(with_imports, bool):
        fail("with_imports must be true or false")
    limit = positive_int(args, "limit", DEFAULT_LIMIT)
    budget = positive_int(args, "max_entropy_bytes", DEFAULT_ENTROPY_BUDGET, 0)
    seconds = positive_int(args, "max_seconds", DEFAULT_SECONDS, 1, MAX_SECONDS)
    why_not = file_problem(path)
    if why_not:
        fail(why_not, path=path)

    ctx = Ctx(os.path.realpath(path), limit, budget, with_imports, seconds)
    size = os.path.getsize(path)
    try:
        fh = open(path, "rb")
    except OSError as exc:
        fail("the file could not be opened: %s" % describe(exc), path=path)
    with fh:
        try:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            fail("the file is empty", path=path)
        except OSError as exc:
            fail("the file could not be mapped: %s" % describe(exc), path=path)
        img = Image(mm)
        head = bytes(mm[:4])
        body, stop = {}, None
        try:
            try:
                if head[:2] == b"MZ":
                    body = read_pe(img, ctx)
                elif head == b"\x7fELF":
                    body = read_elf(img, ctx)
                elif head in MACHO_MAGICS or head in FAT_MAGICS:
                    body = read_macho(img, ctx)
                else:
                    stop = Stop("unsupported", "this is not a PE, ELF or Mach-O file")
                    stop.extra = {"head_hex": head.hex(), "note": "file_type will say what it is instead"}
            except Stop as exc:
                stop = exc
            except Short as exc:
                stop = Stop("failed", "a structure runs past the end of the file: %s" % exc)
        finally:
            mm.close()

    # The tables, whole in a file when they are longer than the answer holds.
    tables = {}
    for name, page in ctx.pages.items():
        tables[name] = page.finish()
        if page.not_written:
            ctx.problem("the whole %s table could not be written to a file: %s" % (name, page.not_written))
    truncated = any(p["truncated"] for p in tables.values())
    if stop is not None:
        coverage = stop.partial.pop("coverage", None)
        result = {**answer_base(stop.status, stop.message, stop.partial, ctx.problems, ctx.limits, coverage), "path": path, "bytes": size,
                  **stop.extra, "note": NOTE}
        print(json.dumps(result, indent=2))
        raise SystemExit(1)
    for name in ("sections", "segments"):
        if name in ctx.pages:
            body[name] = ctx.pages[name].page
    if "load_commands" in ctx.pages:
        body["commands"] = ctx.pages["load_commands"].page
    status = "partial" if (ctx.problems or ctx.limits or ctx.budget["refused"]) else "complete"
    basis = ("every structure this tool reads was read in full" if status == "complete" else
             "%d problem(s) and %d limit(s): see `problems` and `limits_hit`; what was read is in the tables" % (len(ctx.problems), len(ctx.limits)))
    result = {"tool": TOOL, "parser": PARSER, "path": path, "bytes": size, **body, "status": status, "status_basis": basis,
              "problems": ctx.problems, "limits_hit": ctx.limits, "tables": tables, "truncated": truncated,
              "entropy_work": {"bytes_measured": ctx.budget["used"], "budget": ctx.budget["limit"]}, "note": NOTE}
    if ctx.withheld_fields:
        result["withheld_fields"] = ctx.withheld_fields
        result["withheld_note"] = ("User-info, query values and token-shaped text in these strings are withheld from the answer; each entry gives "
                                   "the field and where the string lies in the sample, which is the whole of it.")
    if ctx.problems_dropped:
        result["problems_not_listed"] = ctx.problems_dropped
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never a traceback and never a clean answer for a failure
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)))
