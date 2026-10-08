#!/usr/bin/env python3
"""Read a Windows shell link (.lnk), or every link structure in a slice of a dump.

What is decoded, by the layout MS-SHLLINK gives it: the 76-byte header (flags,
attributes, the three FILETIMEs with their raw values, size, show command), the
LinkInfo structure (flags, VolumeID with drive type, serial number and label,
LocalBasePath and CommonPathSuffix in ANSI and in Unicode, CommonNetworkRelativeLink
with net name, device name and provider type), the string data, and the extra data
blocks it recognises. What is only a heuristic: `idlist_ascii`, `idlist_paths` and
`utf16_strings` are printable runs searched for in the bytes, not a decode of the
shell item list. ANSI strings are in the writer's code page, which the file does
not say; they are shown as Latin-1 and the Unicode form, where the file has one,
is preferred. The tool executes nothing, resolves no target and reads no file the
link points to.

Args, JSON on stdin: path (or dump), offset, size, scan, each, max. A read that ends
inside the structure says so under `problems` and `structure_complete`.
"""
import json, sys, struct, datetime, os, stat
from pathlib import Path

PARSER = "lnk_parse/4"
MAX_READ = 256 * 1024 * 1024

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

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def ft(raw):
    """A FILETIME (100 ns ticks since 1601-01-01 UTC) as ISO 8601 UTC with all seven
    fractional digits, from integer arithmetic only; None for 0, all ones or a date
    past year 9999. The raw value is kept beside it by the caller."""
    if not raw or raw == 0xFFFFFFFFFFFFFFFF:
        return None
    try:
        whole, ticks = divmod(raw, 10_000_000)
        moment = FILETIME_EPOCH + datetime.timedelta(seconds=whole)
        return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError):
        return None


class SecretValuesRefused(Exception):
    pass


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The secret-safe output pattern of docs/packs.md ("Secrets and sensitive output"),
    copied from its reference implementation (recovery_key_scan, encrypted-containers)
    and parameterised by the tool, the flag and the file's name. Call `add` once per
    finding with the finding's id, its locator and the value. With `enabled` false it
    writes nothing and `summary()` says so.
    """

    def __init__(self, enabled, tool, flag, name):
        self.enabled = enabled
        self.tool = tool
        self.flag = flag
        self.name = name
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "%s is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=%s with "
                "secret_output: true, and ask again there. Nothing was written." % (flag, tool)
            )
        self.path = Path(self.out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), name)
        # Created now, before anything is scanned: a file or a link already at that name is
        # refused by name at once (O_EXCL does not follow a link, a dangling one included),
        # instead of failing, or writing through it, after the scan. With nothing found it
        # stays as an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if not self.enabled:
            return
        text = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps({"finding_id": finding_id, **locator, "value": value}, ensure_ascii=True)
        self._fh.write(text)
        self._fh.write("\n")
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self, format_note):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": format_note if self.enabled else None,
        }


# --- what a link can carry that the answer must not print ---------------------------------------------------
#
# A link carries free text a person or a program wrote: its arguments, a description, a working directory, a path. Any of
# it can hold a secret (`-u admin --password Hunter2`, `https://user:pw@host/`, a token in a path). Arguments and the
# string scan are never printed inline (only their length, whether there are any and, for the arguments, a first word that
# can only be a switch name or a program). A path-like field is printed unless it has the shape of a secret, when a marker
# holding only its length stands in its place. The values themselves go, when `write_strings` asks for them and only in a job,
# to a 0600 file under $OUT, each under a finding id the answer cites.
SECRET_SHAPES = re.compile(
    r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[-_]?key|access[-_]?key|client[-_]?secret|credential|private[-_]?key|bearer|authorization)s?\s*[=:]\s*\S"
    r"|[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY"
    r"|(?:^|\s)--?(?:p|pw|pass|passw|password|passwd|pwd|token|secret|apikey|api-key)\s+\S"
)
SWITCH = re.compile(r"^[-/]{1,2}[A-Za-z][A-Za-z0-9_-]{0,31}$")
PROGRAM_FILE = re.compile(r"^[A-Za-z0-9_.:\\ -]{1,80}\.(?:exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|dll|msi|msc|cpl|scr|py|jar|lnk)$", re.I)
PROGRAM_WORDS = {"cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "msiexec", "explorer",
                 "python", "perl", "node", "java", "bash", "sh", "wsl", "schtasks", "sc", "net", "reg", "start"}


def withheld_marker(text):
    return "[withheld: %d characters]" % len(text)


class Held:
    """What the answer withholds, and where it goes when the caller asked: one finding id each, in order. With the
    values file off nothing is written, and the ids still say which locator is which."""

    def __init__(self, values):
        self.values = values
        self.count = 0

    def _next(self):
        self.count += 1
        return "L%06d" % self.count

    def hold(self, locator, value):
        finding = self._next()
        self.values.add(finding, locator, value)
        return finding

    def hold_text(self, locator, pieces):
        """A long text, written (when asked) in pieces, a surrogate pair never split; `pieces` is not iterated otherwise."""
        finding = self._next()
        if self.values.enabled:
            previous, index = None, 0
            for piece in pieces():
                if previous is not None:
                    self.values.add(finding, {**locator, "piece": index - 1, "continued_in_next": True}, previous)
                previous, index = piece, index + 1
            if previous is not None:
                self.values.add(finding, {**locator, "piece": index - 1, "continued_in_next": False}, previous)
        return finding


def guard(held, sink, locator, text):
    """A string of the link as the answer may show it: itself, or, when it has the shape of a secret, a marker."""
    if isinstance(text, str) and SECRET_SHAPES.search(text):
        finding = held.hold(locator, text)
        sink.append({"field": locator["field"], "chars": len(text), "finding_id": finding})
        return withheld_marker(text)
    return text


def guard_keys(held, sink, base_off, container, keys, prefix=""):
    for key in keys:
        if key in container:
            container[key] = guard(held, sink, {"link_offset": base_off, "field": prefix + key}, container[key])


def first_token(arguments):
    """The first word of the arguments when it can only be a switch's name, a program or a script (the value of a
    `--switch=value` is cut off), else None: any other first word may be the secret itself."""
    text = arguments.strip()
    if not text:
        return None
    if text[0] in "\"'":
        end = text.find(text[0], 1)
        token = text[1:end] if end > 0 else text[1:]
    else:
        token = text.split(None, 1)[0]
    token = token.split("=", 1)[0]
    if SECRET_SHAPES.search(token):
        return None
    if SWITCH.match(token) or PROGRAM_FILE.match(token) or token.lower() in PROGRAM_WORDS:
        return token
    return None


# --- the UTF-16 string scan, a window at a time ---------------------------------------------------------------------
UNIT_WINDOW = 1 << 20
NONZERO_UNITS = re.compile(rb"[^\x00]+")
MIN_STRING_UNITS = 6


def utf16_runs(data, start):
    """The runs of non-zero 16-bit units in data[start:], even-aligned to `start`, as (first unit, end unit). One
    window of units is looked at at a time: a unit is non-zero when either of its two bytes is, found by one
    OR over the two halves, so a file of zeros or of one repeated byte costs a pass, not a Python loop per unit."""
    units = (len(data) - start) // 2
    run = None
    pos = 0
    while pos < units:
        take = min(UNIT_WINDOW, units - pos)
        base = start + 2 * pos
        low = data[base:base + 2 * take:2]
        high = data[base + 1:base + 2 * take:2]
        mask = (int.from_bytes(low, "little") | int.from_bytes(high, "little")).to_bytes(take, "little")
        for m in NONZERO_UNITS.finditer(mask):
            a, b = pos + m.start(), pos + m.end()
            if run is not None and run[1] == a:
                run = (run[0], b)
            else:
                if run is not None:
                    yield run
                run = (a, b)
        pos += take
    if run is not None:
        yield run


LETTER_CANDIDATE = re.compile(r"[^\W\d_]")


def run_has_letter(data, start, a, b):
    """Whether the run holds a letter (str.isalpha). The regular expression finds the candidates at C speed, a run of
    digits or punctuation costs a pass and no Python loop, and each candidate is confirmed by isalpha itself."""
    step = 1 << 16
    for u in range(a, b, step):
        chunk = data[start + 2 * u:start + 2 * min(u + step, b)]
        if any(m.group().isalpha() for m in LETTER_CANDIDATE.finditer(chunk.decode("utf-16-le", "replace"))):
            return True
    return False


def run_pieces(data, start, a, b, size=1 << 16):
    """The text of a run in pieces of at most `size` units (a high surrogate takes its pair with it)."""
    u = a
    while u < b:
        e = min(u + size, b)
        if e < b and 0xD8 <= data[start + 2 * (e - 1) + 1] <= 0xDB:
            e += 1
        yield data[start + 2 * u:start + 2 * e].decode("utf-16-le", "replace")
        u = e


DRIVE_TYPES = {0: "unknown", 1: "no root directory", 2: "removable", 3: "fixed", 4: "remote", 5: "CD-ROM", 6: "RAM disk"}
# WNNC_NET_* values MS-SHLLINK lists; only the one every SMB share carries is named here,
# and the raw value is always returned beside it.
PROVIDER_TYPES = {0x00020000: "LANMAN (Microsoft Windows Network, SMB)"}


def cstr(buf, off, wide=False):
    """A NUL-terminated string at `off` in `buf`, ANSI (Latin-1, the code page is not
    recorded) or UTF-16LE, or None when `off` is outside the buffer."""
    if off < 0 or off >= len(buf):
        return None
    if wide:
        end = off
        while end + 1 < len(buf) and (buf[end] or buf[end + 1]):
            end += 2
        return buf[off:end].decode("utf-16-le", "replace")
    z = buf.find(b"\x00", off)
    return buf[off:len(buf) if z < 0 else z].decode("latin1")


def parse_volume_id(vid, problems):
    """VolumeID (MS-SHLLINK 2.3.1): size, drive type, serial number, label offset, and
    the Unicode label offset when the label offset is 0x14."""
    if len(vid) < 0x10:
        problems.append("VolumeID is %d bytes, shorter than its 16-byte fixed part" % len(vid))
        return None
    size, drive, serial, label_off = struct.unpack_from("<IIII", vid, 0)
    out = {
        "size": size,
        "drive_type": drive,
        "drive_type_name": DRIVE_TYPES.get(drive, "not a defined drive type"),
        "serial_number": "%08X" % serial,
    }
    if label_off == 0x14 and len(vid) >= 0x14:
        wide_off = struct.unpack_from("<I", vid, 0x10)[0]
        out["label_unicode"] = cstr(vid, wide_off, wide=True)
        out["label"] = out["label_unicode"]
    else:
        out["label_ansi"] = cstr(vid, label_off)
        out["label"] = out["label_ansi"]
    return out


def parse_network_link(cnrl, problems):
    """CommonNetworkRelativeLink (MS-SHLLINK 2.3.2): size, flags, net name offset, device
    name offset, provider type, and the Unicode offsets when the net name offset is above 0x14."""
    if len(cnrl) < 0x14:
        problems.append("CommonNetworkRelativeLink is %d bytes, shorter than its 20-byte fixed part" % len(cnrl))
        return None
    size, flags, net_off, dev_off, provider = struct.unpack_from("<IIIII", cnrl, 0)
    out = {
        "size": size,
        "flags": flags,
        "valid_device": bool(flags & 1),
        "valid_net_type": bool(flags & 2),
        "net_name": cstr(cnrl, net_off),
        "device_name": cstr(cnrl, dev_off) if flags & 1 else None,
        "provider_type": "0x%08X" % provider if flags & 2 else None,
    }
    if flags & 2 and provider in PROVIDER_TYPES:
        out["provider_name"] = PROVIDER_TYPES[provider]
    if net_off > 0x14 and len(cnrl) >= 0x1C:
        net_u, dev_u = struct.unpack_from("<II", cnrl, 0x14)
        out["net_name_unicode"] = cstr(cnrl, net_u, wide=True)
        if flags & 1 and dev_u:
            out["device_name_unicode"] = cstr(cnrl, dev_u, wide=True)
    return out


def parse_linkinfo(li, problems):
    """LinkInfo (MS-SHLLINK 2.3), field by field in the order the specification gives:
    LinkInfoSize, LinkInfoHeaderSize, LinkInfoFlags, VolumeIDOffset, LocalBasePathOffset,
    CommonNetworkRelativeLinkOffset, CommonPathSuffixOffset, then LocalBasePathOffsetUnicode
    and CommonPathSuffixOffsetUnicode when the header is 0x24 bytes or more. Every offset
    is from the start of LinkInfo."""
    size, hsize, flags, vol_off, local_off, net_off, suffix_off = struct.unpack_from("<7I", li, 0)
    out = {"linkinfo_size": size, "linkinfo_header_size": hsize, "linkinfo_flags": flags}
    if hsize < 0x1C:
        problems.append("LinkInfoHeaderSize is %d, below the 28 bytes the layout needs; LinkInfo is not decoded" % hsize)
        return out
    local_u = suffix_u = 0
    if hsize >= 0x24:
        if len(li) < 0x24:
            problems.append("LinkInfo is shorter than the header it declares")
            return out
        local_u, suffix_u = struct.unpack_from("<II", li, 0x1C)
    has_volume = bool(flags & 1)
    has_network = bool(flags & 2)
    out["has_volume_id_and_local_base_path"] = has_volume
    out["has_common_network_relative_link"] = has_network
    if has_volume:
        vid_size = struct.unpack_from("<I", li, vol_off)[0] if 0 < vol_off <= len(li) - 4 else 0
        vid = li[vol_off:vol_off + vid_size] if vid_size else b""
        if not vid:
            problems.append("VolumeIDOffset %d is outside LinkInfo (%d bytes)" % (vol_off, len(li)))
        else:
            out["volume"] = parse_volume_id(vid, problems)
        out["local_base_path_ansi"] = cstr(li, local_off) if local_off else None
        if local_u:
            out["local_base_path_unicode"] = cstr(li, local_u, wide=True)
        out["local_base_path"] = out.get("local_base_path_unicode") or out["local_base_path_ansi"]
    if has_network:
        cn_size = struct.unpack_from("<I", li, net_off)[0] if 0 < net_off <= len(li) - 4 else 0
        cnrl = li[net_off:net_off + cn_size] if cn_size else b""
        if not cnrl:
            problems.append("CommonNetworkRelativeLinkOffset %d is outside LinkInfo (%d bytes)" % (net_off, len(li)))
        else:
            out["network"] = parse_network_link(cnrl, problems)
    out["common_path_suffix_ansi"] = cstr(li, suffix_off) if suffix_off else None
    if suffix_u:
        out["common_path_suffix_unicode"] = cstr(li, suffix_u, wide=True)
    out["common_path"] = out.get("common_path_suffix_unicode") or out["common_path_suffix_ansi"]
    # The target path MS-SHLLINK defines: the local base path joined to the suffix, or the
    # network name joined to it.
    if has_volume and out.get("local_base_path") is not None:
        out["linkinfo_target"] = out["local_base_path"] + (out["common_path"] or "")
        out["linkinfo_target_kind"] = "local"
    elif has_network and out.get("network") and out["network"].get("net_name") is not None:
        net_name = out["network"].get("net_name_unicode") or out["network"]["net_name"]
        out["linkinfo_target"] = net_name + ("\\" + out["common_path"] if out["common_path"] else "")
        out["linkinfo_target_kind"] = "network"
    return out


def parse_idlist(data, off, size):
    items = []
    end = off + size
    p = off
    while p+2 <= end:
        sz = struct.unpack_from('<H', data, p)[0]
        if sz < 2 or p+sz > end:
            break
        blob = data[p:p+sz]
        # try ascii and utf16
        s = ''.join(chr(b) if 32<=b<127 else '' for b in blob)
        items.append({'size': sz, 'ascii': s})
        p += sz
    return items

def parse_lnk(data, base_off, held, strings):
    if len(data) < 0x4C or data[0:4] != b'L\x00\x00\x00' or data[4:20] != bytes.fromhex('0114020000000000c000000000000046'):
        return {'ok': False, 'error': 'not a LNK header'}
    flags = struct.unpack_from('<I', data, 0x14)[0]
    attr = struct.unpack_from('<I', data, 0x18)[0]
    c,a,w = struct.unpack_from('<QQQ', data, 0x1C)
    flen, icon_idx, show, hot = struct.unpack_from('<IIII', data, 0x34)
    p = 0x4C
    problems = []
    sink = []          # what this link's answer withholds: field, characters, finding id
    stop_reading = False
    out = {
        'ok': True,
        'parser': PARSER,
        'offset': base_off,
        'flags': flags,
        'flags_hex': hex(flags),
        'file_attr': attr,
        'created': ft(c),
        'accessed': ft(a),
        'written': ft(w),
        # Raw FILETIMEs as decimal strings: a JSON number past 2**53 is not exact in every reader.
        'created_filetime': str(c),
        'accessed_filetime': str(a),
        'written_filetime': str(w),
        'time_basis': 'FILETIME, 100 ns ticks since 1601-01-01 UTC, as the link recorded them; they are the target file\'s times when the link was last written, not the link file\'s',
        'file_length': flen,
        'show_cmd': show,
    }
    if flags & 0x1 and p+2 <= len(data):
        id_size = struct.unpack_from('<H', data, p)[0]
        p += 2
        out['idlist_size'] = id_size
        if p + id_size > len(data):
            problems.append("the shell item list declares %d bytes and %d were read; read more bytes (size)" % (id_size, len(data) - p))
            stop_reading = True
        blob = data[p:p+id_size]
        out['idlist_ascii'] = guard(held, sink, {'link_offset': base_off, 'field': 'idlist_ascii'}, ''.join(chr(b) if 32<=b<127 else '.' for b in blob))
        # extract path-like utf16/ascii from extra
        paths = []
        # SHELL_ITEM file entries often have utf16 name at end
        q = 0
        while q+2 <= len(blob):
            isz = struct.unpack_from('<H', blob, q)[0]
            if isz < 2 or q+isz > len(blob):
                break
            item = blob[q:q+isz]
            # look for drive "C:\\" ascii
            if b':' in item:
                ascii = ''.join(chr(b) if 32<=b<127 else '' for b in item)
                if ascii:
                    paths.append(ascii)
            # utf16 strings
            try:
                u = item.decode('utf-16le', errors='ignore')
                u = ''.join(ch if ch.isprintable() else ' ' for ch in u).strip()
                if len(u) >= 3 and any(x in u.lower() for x in ['.exe','.lnk','.dll','.ps1','users','windows','temp','appdata',':\\','http']):
                    paths.append(u)
            except Exception:
                pass
            q += isz
        out['idlist_paths'] = [guard(held, sink, {'link_offset': base_off, 'field': 'idlist_paths[%d]' % n}, x) for n, x in enumerate(paths)]
        p += id_size
    if flags & 0x2:
        if p + 4 > len(data):
            problems.append("HasLinkInfo is set but the read ends before LinkInfo starts; read more bytes")
        else:
            li_size = struct.unpack_from('<I', data, p)[0]
            if li_size < 0x1C:
                problems.append("LinkInfoSize is %d, below the 28 bytes of its header; LinkInfo and what follows it are not read" % li_size)
                stop_reading = True
            elif li_size > len(data) - p:
                problems.append("LinkInfo declares %d bytes and %d were read from it; read more bytes (size)" % (li_size, len(data) - p))
                stop_reading = True
            else:
                info = parse_linkinfo(data[p:p + li_size], problems)
                guard_keys(held, sink, base_off, info, ('local_base_path_ansi', 'local_base_path_unicode', 'local_base_path',
                                                         'common_path_suffix_ansi', 'common_path_suffix_unicode', 'common_path', 'linkinfo_target'))
                if isinstance(info.get('volume'), dict):
                    guard_keys(held, sink, base_off, info['volume'], ('label', 'label_ansi', 'label_unicode'), 'volume.')
                if isinstance(info.get('network'), dict):
                    guard_keys(held, sink, base_off, info['network'], ('net_name', 'net_name_unicode', 'device_name', 'device_name_unicode'), 'network.')
                out.update(info)
                p += li_size
    # string data in order based on flags
    def read_str(pp, nm, unicode=bool(flags & 0x80)):
        if pp+2 > len(data):
            problems.append("the %s string starts past the end of what was read" % nm)
            return None, pp
        n = struct.unpack_from('<H', data, pp)[0]
        pp += 2
        if unicode:
            nbytes = n*2
        else:
            nbytes = n
        if pp + nbytes > len(data):
            problems.append("the %s string declares %d characters and the read ends inside it; it is cut at the end of what was read" % (nm, n))
        raw = data[pp:pp+nbytes]
        s = raw.decode('utf-16le', errors='replace') if unicode else raw.decode('latin1', errors='replace')
        pp += nbytes
        return s, pp
    names = []
    bit_names = [(0x4,'name'),(0x8,'relative_path'),(0x10,'working_dir'),(0x20,'arguments'),(0x40,'icon_location')]
    out['arguments_present'] = False
    for bit, nm in bit_names:
        if flags & bit and not stop_reading:
            s, p = read_str(p, nm)
            if nm == 'arguments':
                # Never printed: its length, whether there are any, and a first word only when that can only be a
                # switch name or a program. The text goes to the values file when it was asked for.
                out['arguments_present'] = True
                out['arguments_chars'] = len(s) if s is not None else 0
                token = first_token(s) if s else None
                out['arguments_first_token'] = token
                if s:
                    out['arguments_finding_id'] = held.hold({'link_offset': base_off, 'field': 'arguments'}, s)
                    if token is None:
                        out['arguments_first_token_withheld'] = True
                    sink.append({'field': 'arguments', 'chars': len(s), 'finding_id': out['arguments_finding_id']})
            else:
                out[nm] = guard(held, sink, {'link_offset': base_off, 'field': nm}, s)
            names.append((nm, s))
    # extra blocks, up to the terminal block. When the bytes read end first the
    # structure runs past them, and structure_complete says so.
    extras = []
    complete = False
    while p+4 <= len(data) and not stop_reading:
        bsz = struct.unpack_from('<I', data, p)[0]
        if bsz < 4:
            complete = True
            break
        if bsz < 8 or p+bsz > len(data):
            break
        sig = struct.unpack_from('<I', data, p+4)[0]
        blk = data[p:p+bsz]
        rec = {'size': bsz, 'sig': hex(sig)}
        if sig == 0xA0000001:  # environment
            rec['env_ascii'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].env_ascii' % len(extras)}, blk[8:8+260].split(b'\x00',1)[0].decode('latin1','replace'))
            rec['env_u16'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].env_u16' % len(extras)}, blk[8+260:].decode('utf-16le','replace').split('\x00',1)[0] if len(blk)>268 else None)
        elif sig == 0xA0000003:  # tracker
            rec['tracker'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].tracker' % len(extras)}, blk[8:64].decode('latin1','replace',).split('\x00')[0] if len(blk)>16 else None)
            # machine name at +16 typically
            rec['machine'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].machine' % len(extras)}, blk[16:16+16].split(b'\x00',1)[0].decode('latin1','replace') if len(blk)>32 else None)
            # the two 32-byte droid pairs (volume and object identifiers), whole
            if len(blk) >= 96:
                rec['droid_hex'] = blk[32:64].hex()
                rec['droid_birth_hex'] = blk[64:96].hex()
        elif sig == 0xA0000007:  # icon environment: the same two paths as the environment block
            icon_ascii = blk[8:8+260].split(b'\x00',1)[0].decode('latin1','replace')
            icon_u16 = blk[8+260:].decode('utf-16le','replace').split('\x00',1)[0] if len(blk)>268 else None
            rec['icon_env_ascii'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].icon_env_ascii' % len(extras)}, icon_ascii)
            rec['icon_env_u16'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].icon_env_u16' % len(extras)}, icon_u16)
            if rec['icon_env_ascii'] == icon_ascii and rec['icon_env_u16'] == icon_u16:
                rec['hex'] = blk.hex()          # the hex would give a withheld path back
        else:
            # A block this reader does not know can hold anything: the first characters inline (their shape judged
            # like any other field), its length, and the whole of it in the values file when it was asked for.
            printable = ''.join(chr(b) if 32<=b<127 else '.' for b in blk[:128])
            rec['ascii'] = guard(held, sink, {'link_offset': base_off, 'field': 'extra[%d].ascii' % len(extras)}, printable)
            rec['ascii_chars'] = len(blk)
            if len(blk) > 128:
                rec['ascii_inline_cut'] = True
                rec['ascii_finding_id'] = held.hold({'link_offset': base_off, 'field': 'extra[%d].block_hex' % len(extras)}, blk.hex())
        extras.append(rec)
        p += bsz
        if bsz == 0:
            break
    out['extra'] = extras
    out['structure_complete'] = complete
    if not complete and not problems:
        problems.append("the read ends before the terminal block; read more bytes (size) to complete the structure")
    out['problems'] = problems
    out['heuristic_fields'] = ['idlist_ascii', 'idlist_paths', 'utf16_strings (locators; the text is in the values file)', 'extra[].ascii', 'extra[].tracker', 'extra[].machine']
    out['bytes_read'] = len(data)
    # The UTF-16 string scan: a run of at least six non-zero units with a letter in it, even-aligned from the end of
    # the header. The text is never in the answer: its offset and length are (the page `strings`), and the text is
    # in the values file under the finding id when write_strings asked for it.
    found = 0
    for a, b in utf16_runs(data, 0x4C):
        if b - a >= MIN_STRING_UNITS and run_has_letter(data, 0x4C, a, b):
            found += 1
            at = 0x4C + 2 * a
            finding = held.hold_text({'link_offset': base_off, 'field': 'utf16_string', 'offset': at},
                                     lambda a=a, b=b: run_pieces(data, 0x4C, a, b))
            strings.add({'link_offset': base_off, 'offset': at, 'file_offset': base_off + at, 'chars': b - a, 'finding_id': finding})
    out['utf16_string_count'] = found
    if sink:
        out['sensitive_fields_withheld'] = sink
    return out

def fail(message, **extra):
    print(json.dumps({'error': message, **extra}))
    sys.exit(1)


def whole(args, name, default, low=0, high=None):
    v = args.get(name)
    if v is None or v == 0 and name in ('size', 'max'):
        v = default
    if isinstance(v, bool) or not isinstance(v, int) or v < low or (high is not None and v > high):
        fail('%s must be a whole number%s' % (name, ' from %d to %d' % (low, high) if high is not None else ' of at least %d' % low), got=args.get(name))
    return v


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail('arguments are not valid JSON', reason=str(exc))
    if not isinstance(args, dict):
        fail('the arguments must be a JSON object')
    path = args.get('path')
    offset = whole(args, 'offset', 0)
    size = whole(args, 'size', 4096, 1, MAX_READ)
    limit = whole(args, 'limit', 50, 1)
    write_strings = args.get('write_strings', False)
    if not isinstance(write_strings, bool):
        fail('write_strings must be true or false')
    dump = args.get('dump')  # if set, read from dump at offset
    src = dump or path
    if not src:
        fail('need path or dump')
    if not isinstance(src, str):
        fail('path and dump must be file paths', got=src)
    if not os.path.isfile(src):
        if os.path.exists(src):
            fail('not a regular file (a directory, a FIFO, a socket or a device is not opened)', path=src, not_attempted=1)
        fail('no such file', path=src)

    values = None
    for number in range(1, 1000):
        name = 'lnk-strings.jsonl' if number == 1 else 'lnk-strings-%d.jsonl' % number
        try:
            values = SecretValues(write_strings, 'lnk_parse', 'write_strings', name)
            break
        except SecretValuesRefused as exc:
            # A values file of an earlier run in this job is never replaced and never a reason not to read the link:
            # the next free number is this run's file, and the answer names it.
            if write_strings and 'already exists' in str(exc):
                continue
            fail(str(exc))
    if values is None:
        fail('no free name for the values file after 999 tries')
    held = Held(values)

    try:
        with open(src, 'rb') as f:
            f.seek(offset)
            data = f.read(size)
    except OSError as exc:
        values.close()
        fail('the file could not be read', path=src, reason=describe(exc))
    strings = LosslessPage("lnk_parse", [src, offset, size, 'strings'], limit)
    summary = lambda: {
        'secret_values': values.summary('JSON Lines, mode 0600: finding_id, link_offset, field, [offset, piece, continued_in_next,] value'),
        'findings_held': held.count,
    }

    def string_paging(answer):
        page = strings.finish()
        answer['utf16_strings'] = strings.page
        answer['utf16_strings_page'] = page
        answer['utf16_strings_note'] = ('offsets and lengths of the UTF-16 text found by search (runs of six or more non-zero units with a letter); '
                                        'the text is not in this answer: write_strings, in a job, writes it to the values file under each finding_id')

    if args.get('scan'):
        limit_hits = whole(args, 'max', 50, 1)
        each = args.get('each')
        if each is not None:
            each = whole(args, 'each', 0, 1)
        hits = LosslessPage("lnk_parse", [src, offset, size, each], limit_hits)
        magic = bytes.fromhex('4c0000000114020000000000c000000000000046')
        starts = []
        i = 0
        while True:
            j = data.find(magic, i)
            if j < 0:
                break
            starts.append(j)
            i = j+4
        incomplete = 0
        for n, j in enumerate(starts):
            # Without `each`, a link runs to the next header or to the end of
            # what was read, never to a fixed cut.
            stop = j + each if each else (starts[n+1] if n+1 < len(starts) else len(data))
            rec = parse_lnk(data[j:stop], offset+j, held, strings)
            rec['rel'] = j
            rec['source'] = src
            if not rec.get('structure_complete'):
                incomplete += 1
            hits.add(rec)
        page = hits.finish()
        values.close()
        answer = {'parser': PARSER, 'source': src, 'count': page['matched'], 'hits': hits.page, **page,
                  'structures_incomplete': incomplete,
                  'offset': offset, 'bytes_read': len(data),
                  **summary(),
                  'note': 'a scan finds link structures by their 20-byte header signature (carving); a hit is a candidate, and `structure_complete` and `problems` say how much of it was read. Arguments and the string scan are not printed: see arguments_chars, utf16_strings and secret_values'}
        string_paging(answer)
        print(json.dumps(answer, indent=2))
        return
    rec = parse_lnk(data, offset, held, strings)
    rec['source'] = src
    values.close()
    if not rec.get('ok'):
        # Not what it was read as: how many bytes, and nothing of their content (it can be anything).
        rec['bytes_read'] = len(data)
        rec['starts_with_link_header'] = False
        print(json.dumps(rec, indent=2))
        sys.exit(1)
    rec.update(summary())
    string_paging(rec)
    print(json.dumps(rec, indent=2))

if __name__ == '__main__':
    try:
        main()
    except OSError as exc:
        fail('a file operation failed: %s' % describe(exc), reason=type(exc).__name__)
