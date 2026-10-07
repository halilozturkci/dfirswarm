#!/usr/bin/env python3
"""Say what an archive or document shows about its own protection, and what it does not.

The question people ask is "can we open it". The question that decides an
exfiltration case is a different one: are the member names readable without a
password. They are two findings, and this tool reports both where it can.

What it establishes, and how:

    ZIP      structurally: the End Of Central Directory record and each central
             directory entry, read with the standard library. Per member: the
             encryption flag, the scheme (the AES extra field is parsed: strength
             and AE version), the DOS time with its raw words (no zone) and an
             extended timestamp where one is recorded. Empty and self-extracting
             archives are read too: the container is found from its end, not from
             byte zero.
    7-Zip    through the installed 7z (a bounded run, no password prompt) when
             there is one: the member list, each member's encryption flag, and
             whether the header is encrypted. The start header is read
             structurally either way (its CRCs are checked); a byte search for the
             AES coder id is kept as a hint when 7z is absent or cannot read it.
    RAR      identified. Its protection is not determined here.
    PDF, OLE compound file (Office)
             markers only, found by a byte search, reported as a heuristic: where
             the marker is, never a verdict. A marker in the file does not say
             which revision of the document it belongs to, and no marker does not
             say the document is not encrypted (binary Office files record their
             encryption inside the document stream, not in a stream with a name).
             The structural reader for these is not provided by this pack.

Evidence is hostile input: nothing is extracted or executed, only metadata is read,
and what is read is bounded (`max_metadata_bytes`); a result that is cut says so.
"""
import heapq
import json
import mmap
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import zipfile
import zlib
from datetime import datetime, timedelta, timezone

PARSER = "archive_probe/2"


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

    def _write(self, row: object) -> None:
        assert self._out is not None
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(
                dir=self.path.parent, prefix=f".{self.path.name}-"
            )
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
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
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            assert self._tmp is not None
            os.replace(self._tmp, self.path)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


ZIP_ENCRYPTED = 0x0001
ZIP_STRONG = 0x0040
MAX_METADATA_DEFAULT = 32 << 20
# The 7-Zip AES-256 + SHA-256 coder id. In an encoded (packed) header it means
# the header itself is encrypted, so the names need the password.
SEVENZIP_AES = b"\x06\xf1\x07\x01"
SEVENZIP_PROGRAMS = ("7z", "7zz", "7za")
SEVENZIP_TIMEOUT = 60
# Given to 7z so that it never stops to ask for one: an archive whose header is
# encrypted then fails to open, which is the answer wanted. It is not a secret.
NO_PASSWORD = "dfirswarm-no-password"
ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")
WIDE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){3,}")
ENCRYPTED_ARCHIVE = re.compile(r"(?i)(can ?not|can't) open encrypted archive|wrong password")
MARKER_OFFSETS = 20
MARKER_COUNT_CAP = 10000
NEXT_DOCUMENT_READER = ("none is provided by this pack: a structural document reader (doc_structure, planned for the "
                        "reverse-engineering pack) is not available yet")


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def extra_fields(extra):
    """The (id -> data) of a ZIP extra field block; the first of an id wins."""
    out, i = {}, 0
    while i + 4 <= len(extra):
        ident, size = struct.unpack_from("<HH", extra, i)
        out.setdefault(ident, extra[i + 4:i + 4 + size])
        i += 4 + size
    return out


def filetime_iso(value):
    """A Windows FILETIME (100 ns since 1601-01-01 UTC) as ISO 8601 UTC, keeping the fraction."""
    seconds, ticks = divmod(value, 10_000_000)
    moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks


def recorded_time(fields):
    """An extended timestamp a ZIP entry records beside its DOS time, with its source, or (None, None)."""
    try:
        ntfs = fields.get(0x000A)
        if ntfs and len(ntfs) >= 4:
            i = 4
            while i + 4 <= len(ntfs):
                tag, size = struct.unpack_from("<HH", ntfs, i)
                if tag == 1 and size >= 8 and i + 4 + 8 <= len(ntfs):
                    return filetime_iso(struct.unpack_from("<Q", ntfs, i + 4)[0]), "NTFS times (extra 0x000a), 100 ns, UTC"
                i += 4 + size
        ut = fields.get(0x5455)
        if ut and len(ut) >= 5 and ut[0] & 1:
            when = datetime.fromtimestamp(struct.unpack_from("<i", ut, 1)[0], tz=timezone.utc)
            return when.strftime("%Y-%m-%dT%H:%M:%SZ"), "extended timestamp (extra 0x5455), 1 s, UTC"
    except (OverflowError, ValueError, OSError):
        return None, "an extended timestamp is recorded but its value is out of range"
    return None, None


def aes_of(fields):
    """The WinZip AES extra field (0x9901): AE version, strength in bits, the real method."""
    data = fields.get(0x9901)
    if not data or len(data) < 7 or data[2:4] != b"AE":
        return None
    version, strength, method = struct.unpack_from("<H", data, 0)[0], data[4], struct.unpack_from("<H", data, 5)[0]
    return {"ae_version": version, "strength_bits": {1: 128, 2: 192, 3: 256}.get(strength), "method": method}


def read_eocd(path, size):
    """The End Of Central Directory record from the last 64 KiB, or None.

    Zip64 sizes are taken from the Zip64 record where the locator is present.
    Python's zipfile takes the last such signature in the tail, and so does this.
    """
    tail_len = min(size, 65535 + 22 + 20)
    with open(path, "rb") as fh:
        fh.seek(size - tail_len)
        tail = fh.read(tail_len)
        at = tail.rfind(b"PK\x05\x06")
        if at < 0 or at + 22 > len(tail):
            return None
        _sig, _disk, _cd_disk, n_disk, n_total, cd_size, cd_offset, comment_len = struct.unpack_from("<IHHHHIIH", tail, at)
        out = {"entries": n_total, "cd_bytes": cd_size, "cd_offset": cd_offset, "comment_bytes": comment_len,
               "zip64": False, "eocd_at": size - tail_len + at}
        if n_total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
            if at >= 20 and tail[at - 20:at - 16] == b"PK\x06\x07":
                where = struct.unpack_from("<Q", tail, at - 20 + 8)[0]
                if where + 56 <= size:
                    fh.seek(where)
                    rec = fh.read(56)
                    if len(rec) == 56 and rec[:4] == b"PK\x06\x06":
                        out["entries"], out["cd_bytes"], out["cd_offset"] = (
                            struct.unpack_from("<Q", rec, 32)[0], struct.unpack_from("<Q", rec, 40)[0],
                            struct.unpack_from("<Q", rec, 48)[0])
                        out["zip64"] = True
            out.setdefault("zip64_unresolved", not out["zip64"])
        return out


def zip_behind_a_prefix(path, size):
    """Whether the end of the file is a ZIP's, though the file does not start like one (a self-extracting stub).

    zipfile.is_zipfile decides this too, and newer Pythons (3.14) refuse an End Of
    Central Directory record whose declared directory does not fit the file, so a
    ZIP is not recognised by it alone: this reads the record and looks for the
    central directory's first header where it says it is, or for an empty archive
    whose record ends the file.
    """
    eocd = read_eocd(path, size)
    if eocd is None:
        return False
    if eocd["cd_bytes"] == 0:
        return eocd["entries"] == 0 and eocd["eocd_at"] + 22 + eocd["comment_bytes"] == size
    at = eocd["eocd_at"] - eocd["cd_bytes"]
    if at < 0 or eocd["zip64"]:
        return False
    with open(path, "rb") as fh:
        fh.seek(at)
        return fh.read(4) == b"PK\x01\x02"


def probe_zip(path, size, limit, max_metadata):
    out = {"container": "ZIP", "protection": "structural: the central directory's flags and extra fields"}
    eocd = read_eocd(path, size)
    if eocd is None:
        return {**out, "listing": "failed", "protected": None,
                "error": "a ZIP signature but no End Of Central Directory record in the last 64 KiB: the archive is "
                         "truncated, damaged or carved short",
                "not_determined": ["the member list", "which members are encrypted"]}
    out["entry_count_declared"] = eocd["entries"]
    out["central_directory_bytes"] = eocd["cd_bytes"]
    if eocd["cd_bytes"] > max_metadata:
        return {**out, "listing": "not attempted", "protected": None, "partial": True,
                "reason": "the central directory is %d bytes (%d entries declared), above max_metadata_bytes (%d): "
                          "it was not loaded. Raise max_metadata_bytes to list it" % (eocd["cd_bytes"], eocd["entries"], max_metadata),
                "not_determined": ["the member list", "which members are encrypted"]}
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, NotImplementedError, OSError, ValueError, OverflowError) as exc:
        return {**out, "listing": "failed", "protected": None, "error": "%s: %s" % (type(exc).__name__, exc),
                "not_determined": ["the member list", "which members are encrypted"]}
    entries = LosslessPage("archive_probe", [os.path.realpath(path), "zip entries"], limit)
    encrypted, schemes = 0, set()
    with archive:
        for index, info in enumerate(archive.infolist()):
            fields = extra_fields(info.extra)
            scheme, is_encrypted, aes = None, bool(info.flag_bits & ZIP_ENCRYPTED), None
            if is_encrypted:
                encrypted += 1
                aes = aes_of(fields)
                if info.compress_type == 99:
                    scheme = ("WinZip AES-%s (AE-%d)" % (aes["strength_bits"] or "?", aes["ae_version"])) if aes \
                        else "WinZip AES (the extra field is unreadable)"
                elif info.flag_bits & ZIP_STRONG:
                    scheme = "strong encryption"
                else:
                    scheme = "ZipCrypto (legacy, weak)"
                schemes.add(scheme)
            y, mo, d, h, mi, s = info.date_time
            row = {"index": index, "name": info.filename, "bytes": info.file_size, "compressed": info.compress_size,
                   "header_offset": info.header_offset, "method": info.compress_type,
                   "modified": "%04d-%02d-%02dT%02d:%02d:%02d" % info.date_time,
                   "modified_raw": "dos_date=0x%04x dos_time=0x%04x" % (((y - 1980) << 9) | (mo << 5) | d,
                                                                      (h << 11) | (mi << 5) | (s // 2)),
                   "timezone_unknown": True,
                   "encrypted": is_encrypted, "scheme": scheme}
            if aes:
                row["aes"] = aes
            utc, source = recorded_time(fields)
            if utc:
                row["modified_utc"], row["modified_utc_source"] = utc, source
            elif source:
                row["modified_utc_problem"] = source
            entries.add(row)
    page = entries.finish()
    out["entries"] = entries.page
    out["entry_count"] = page["matched"]
    out.update(page)
    out["encrypted_entries"] = encrypted
    out["schemes"] = sorted(schemes)
    out["names_readable"] = True
    out["protected"] = encrypted > 0
    out["entry_count_matches_declared"] = page["matched"] == eocd["entries"]
    out["time_note"] = ("`modified` is the MS-DOS date and time of the archiving machine's local clock: no zone, 2-second "
                        "resolution (timezone_unknown). `modified_utc`, where present, is a separate recorded time in UTC.")
    out["not_determined"] = ["whether an encrypted member's data is intact or openable", "why or by whom it was encrypted"]
    return out


def find_7z():
    for name in SEVENZIP_PROGRAMS:
        found = shutil.which(name)
        if found:
            return found
    return None


def list_with_7z(path, limit):
    """List an archive through 7z, bounded in time, never asking for a password.

    Returns (listing, members): `listing` says what happened (status, exit code,
    the first diagnostic lines); `members` is the LosslessPage of members.
    """
    exe = find_7z()
    if exe is None:
        return {"status": "unavailable", "reason": "none of %s is on PATH" % ", ".join(SEVENZIP_PROGRAMS)}, None
    cmd = [exe, "l", "-slt", "-y", "-p" + NO_PASSWORD, "--", path]
    members = LosslessPage("archive_probe", [os.path.realpath(path), "7z members"], limit)
    info = {"via": exe, "timeout_seconds": SEVENZIP_TIMEOUT}
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, errors="replace")
    except OSError as exc:
        return {**info, "status": "unavailable", "reason": "7z could not be started: %s" % exc}, None
    timed_out = []
    timer = threading.Timer(SEVENZIP_TIMEOUT, lambda: (timed_out.append(True), proc.kill()))
    timer.start()
    archive, current, in_members, diagnostics, encrypted_message = {}, {}, False, [], False
    seen = {"members": 0, "encrypted": 0, "not_encrypted": 0, "flag_missing": 0}

    def flush():
        nonlocal current
        if current.get("Path") is not None:
            flag = current.get("Encrypted")
            seen["members"] += 1
            seen["encrypted" if flag == "+" else "not_encrypted" if flag == "-" else "flag_missing"] += 1
            members.add({"index": members.total, "name": current["Path"],
                         "bytes": int(current["Size"]) if current.get("Size", "").isdigit() else None,
                         "packed": int(current["Packed Size"]) if current.get("Packed Size", "").isdigit() else None,
                         "modified_as_printed": current.get("Modified") or None, "timezone_unknown": True,
                         "encrypted": True if flag == "+" else (False if flag == "-" else None),
                         "method": current.get("Method"), "crc": current.get("CRC") or None,
                         "attributes": current.get("Attributes") or None})
        current = {}

    try:
        for raw in proc.stdout:
            line = raw.rstrip("\r\n")
            if ENCRYPTED_ARCHIVE.search(line):
                encrypted_message = True
            if re.match(r"^(ERROR|WARNING|Errors|Warnings)\b", line) and len(diagnostics) < 5:
                diagnostics.append(line)
            if line == "----------":
                in_members = True
                continue
            if line == "--" and not in_members:
                continue
            if not line.strip():
                if in_members:
                    flush()
                continue
            key, sep, value = line.partition(" = ")
            if not sep:
                continue
            if not in_members:
                archive.setdefault(key, value)
            else:
                if key == "Path" and current.get("Path") is not None:
                    flush()
                current[key] = value
        flush()
        code = proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
    info["exit_code"] = code
    info["members_seen"] = seen
    if diagnostics:
        info["diagnostics"] = diagnostics
    if archive:
        info["archive"] = {k: archive[k] for k in ("Type", "Physical Size", "Headers Size", "Method", "Solid", "Blocks") if k in archive}
    if timed_out:
        return {**info, "status": "timed_out", "reason": "7z was stopped after %d seconds; %d members were read before it" % (SEVENZIP_TIMEOUT, members.total)}, members
    if code in (0, 1) and archive.get("Type"):
        return {**info, "status": "listed" if code == 0 else "listed_with_warnings"}, members
    if encrypted_message:
        return {**info, "status": "header_encrypted",
                "reason": "7z reports that it cannot open the archive without a password"}, None
    return {**info, "status": "failed", "reason": "7z could not list this file (exit %s)" % code}, None


def probe_7z(view, path, limit, max_metadata):
    """The 32-byte start header points at the real header, at the end of the file.

    That header is either plain (0x01), where the names sit in the clear, or
    encoded (0x17): packed, and encrypted as well when its coder list names AES.
    """
    out = {"container": "7-Zip", "names_readable": None, "protected": None,
           "protection": "7z's own listing where it could read the archive; otherwise a heuristic from the start header"}
    # The header is read in place, through the mapping: nothing of it is copied,
    # and what is searched is the first `searched` bytes from `at`.
    at, searched = 0, 0
    out["start_header"] = {}
    sh = out["start_header"]
    if len(view) < 32:
        sh["problem"] = "the file is shorter than the 32-byte start header"
    else:
        start_crc, = struct.unpack_from("<I", view, 8)
        sh["crc_ok"] = zlib.crc32(view[12:32]) == start_crc
        next_offset, next_size, next_crc = struct.unpack_from("<QQI", view, 12)
        at = 32 + next_offset
        sh["header_offset"], sh["header_bytes"] = at, next_size
        out["header_offset"], out["header_bytes"] = at, next_size
        if next_size and at + next_size <= len(view):
            searched = min(next_size, max_metadata)
            if searched < next_size:
                sh["search_truncated"] = True
                sh["search_note"] = "the header is %d bytes: only the first %d (max_metadata_bytes) were searched" % (next_size, searched)
            else:
                crc = 0
                for chunk_at in range(at, at + next_size, 1 << 20):
                    crc = zlib.crc32(view[chunk_at:min(chunk_at + (1 << 20), at + next_size)], crc)
                sh["header_crc_ok"] = crc == next_crc
        else:
            at = 0
            sh["problem"] = ("the start header places the header past the end of the file: the archive is truncated "
                             "or was carved short")
            out["header_problem"] = sh["problem"]
    hint = {}
    if searched:
        kind = view[at]
        has_aes = view.find(SEVENZIP_AES, at, at + searched) >= 0
        if kind == 0x01:
            hint["header_kind"] = "plain"
            hint["data_encryption_coder_in_header"] = has_aes
        elif kind == 0x17:
            hint["header_kind"] = "encoded"
            hint["header_encrypted"] = has_aes
            hint["basis"] = ("the AES coder id appears in the encoded header's own coder list: a byte search, not a "
                             "parse of the coder graph")
        else:
            hint["header_kind"] = "unknown (0x%02x)" % kind
    listing, members = list_with_7z(path, limit)
    out["listing"] = listing
    status = listing["status"]
    if members is not None:
        page = members.finish()
        out["members"] = members.page
        out["member_count"] = page["matched"]
        out.update(page)
        seen = listing["members_seen"]
        out["names_readable"] = True
        out["header_encrypted"] = False
        if seen["encrypted"]:
            out["payload_encrypted"] = True
        elif seen["members"] and not seen["flag_missing"]:
            out["payload_encrypted"] = False
        else:
            out["payload_encrypted"] = None
        out["protected"] = out["payload_encrypted"]
        out["encrypted_members"] = seen["encrypted"]
        out["protection"] = "7z's listing (each member's Encrypted flag)"
    elif status == "header_encrypted":
        out["names_readable"] = False
        out["header_encrypted"] = True
        out["payload_encrypted"] = None
        out["protected"] = True
        out["protection"] = "7z cannot open the archive without a password"
    else:
        out["protection"] = "heuristic: 7z gave no listing (%s)" % status
        out["hints"] = hint
        strings = LosslessPage("archive_probe", [os.path.realpath(path), "7z header strings (hint)"], limit)
        # Both patterns are walked lazily over the mapped header and merged by
        # offset, straight into the paging file: no match is collected first.
        ascii_runs = ((m.start(), m.group().decode("ascii", "replace")) for m in ASCII_RUN.finditer(view, at, at + searched))
        wide_runs = ((m.start(), m.group().decode("utf-16-le", "replace")) for m in WIDE_RUN.finditer(view, at, at + searched))
        if searched:
            for _start, text in heapq.merge(ascii_runs, wide_runs, key=lambda found: found[0]):
                strings.add(text)
        page = strings.finish()
        out["header_strings_hint"] = strings.page
        out["header_strings_hint_count"] = page["matched"]
        out["header_strings_hint_page"] = page
        out["header_strings_note"] = ("Printable strings in the header region, not a member list: they include "
                                      "internal names and can miss names. Treat them as a hint.")
    out["next_reader"] = "7z l -slt on a complete copy of every volume of the archive" if status != "listed" else None
    out["not_determined"] = ["whether an encrypted member's data is intact", "the member names where the header is encrypted"] \
        if status in ("header_encrypted",) else ["whether an encrypted member's data is intact or openable"]
    return out


def probe_rar(blob):
    version = 5 if bytes(blob[:8]) == b"Rar!\x1a\x07\x01\x00" else 4
    return {"container": "RAR%d" % version, "protected": None,
            "protection": "not determined: this tool identifies the format only",
            "listing": "not attempted",
            "next_reader": "a RAR-capable reader (7-Zip or unrar), on every volume; none is run here",
            "not_determined": ["whether the data is encrypted", "whether the file names are encrypted", "the member list"],
            "note": "A RAR may encrypt its data, and in RAR5 its names as well; this tool reads neither."}


def markers(blob, needle):
    """Offsets of a byte string in the whole file: the first few, and the count (capped)."""
    offsets, count, at = [], 0, blob.find(needle)
    while at >= 0 and count < MARKER_COUNT_CAP:
        count += 1
        if len(offsets) < MARKER_OFFSETS:
            offsets.append(at)
        at = blob.find(needle, at + 1)
    return {"found": count > 0, "count": count, "count_capped": at >= 0, "first_offsets": offsets}


def whole_search(blob):
    """What a byte search over a PDF or an OLE file covered: all of it, bounded only by the tool's timeout."""
    return {"bytes_searched": len(blob), "search_complete": True,
            "search_note": "the whole file was searched, in a linear pass per marker: max_metadata_bytes does not bound "
                           "it (a PDF's marker sits in its trailer, at the end), and a file too large to search within "
                           "the tool's timeout fails with no partial answer"}


def probe_pdf(blob):
    encrypt = markers(blob, b"/Encrypt")
    out = {"container": "PDF", "protected": None, "protection": "heuristic: a byte search for the /Encrypt marker",
           "encrypt_marker": encrypt,
           "next_reader": NEXT_DOCUMENT_READER,
           "not_determined": ["whether the file's current trailer points at an encryption dictionary (a marker may "
                              "belong to an earlier revision or to unrelated text)",
                              "whether an opening (user) password is needed, or an empty one opens it",
                              "the permission restrictions (a separate setting from the opening password)",
                              "the security handler and its revision"]}
    if encrypt["found"]:
        version, revision, permissions = (re.search(rb"/V\s+(\d+)", blob), re.search(rb"/R\s+(\d+)", blob),
                                          re.search(rb"/P\s+(-?\d+)", blob))
        out["unresolved_hints"] = {
            "v": int(version.group(1)) if version else None, "r": int(revision.group(1)) if revision else None,
            "p": int(permissions.group(1)) if permissions else None,
            "note": "the first /V, /R and /P anywhere in the file, not read through the trailer: they may belong to "
                    "another object or revision"}
    out.update(whole_search(blob))
    out["note"] = ("A PDF can be encrypted and still open with an empty user password; encryption, the opening password "
                   "and the permission restrictions are three separate facts, and none is read here.")
    return out


def probe_ole(blob):
    wanted = [("EncryptionInfo", "an Office 2007-and-later encrypted document's stream"),
              ("EncryptedPackage", "an Office 2007-and-later encrypted document's stream"),
              ("DataSpaces", "the storage that records an encrypted package's transforms")]
    found = []
    for name, meaning in wanted:
        for encoding, needle in (("UTF-16LE", name.encode("utf-16-le")), ("ASCII", name.encode("ascii"))):
            m = markers(blob, needle)
            if m["found"]:
                found.append({"name": name, "encoding": encoding, "meaning": meaning, **m})
    return {**whole_search(blob), "container": "OLE compound file", "protected": None,
            "protection": "heuristic: a byte search for stream names that mark an encrypted OOXML package",
            "markers_found": found, "marker_names_searched": [n for n, _ in wanted],
            "next_reader": NEXT_DOCUMENT_READER,
            "not_determined": ["whether the document is encrypted: binary Word, Excel and PowerPoint files record "
                               "their encryption inside the document's own stream, under no marker searched for here",
                               "which scheme and key derivation it uses",
                               "whether a marker is a live directory entry or text inside a stream",
                               "editing restrictions and rights management, which are not the opening password"],
            "note": "No marker found does not mean the document is not encrypted."}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an archive or a document")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    max_metadata = args.get("max_metadata_bytes", MAX_METADATA_DEFAULT)
    if not isinstance(max_metadata, int) or isinstance(max_metadata, bool) or max_metadata < 4096:
        fail("max_metadata_bytes must be an integer of at least 4096")

    size = os.path.getsize(path)
    body = None
    with open(path, "rb") as fh:
        head = fh.read(8)
        if head[:6] == b"7z\xbc\xaf\x27\x1c" or head[:4] == b"Rar!" or head[:5] == b"%PDF-" \
                or head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            # The whole file, mapped rather than read: the part that decides a
            # PDF is usually its trailer, and a 7-Zip header sits at the end.
            if size == 0:
                fail("the file is empty", path=path)
            with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as view:
                if head[:6] == b"7z\xbc\xaf\x27\x1c":
                    body = probe_7z(view, path, limit, max_metadata)
                elif head[:4] == b"Rar!":
                    body = probe_rar(view)
                elif head[:5] == b"%PDF-":
                    body = probe_pdf(view)
                else:
                    body = probe_ole(view)
    if body is None and (head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08") or zipfile.is_zipfile(path)
                         or zip_behind_a_prefix(path, size)):
        # Whatever zipfile.is_zipfile says of a file that starts with a ZIP signature: the answer
        # about it (listed, not attempted over budget, or failed) comes from probe_zip.
        body = probe_zip(path, size, limit, max_metadata)
    if body is None:
        fail("this is not a container this tool reads", path=path, bytes=size,
             reads=["ZIP (found from its end, so empty and self-extracting archives count)", "7-Zip", "RAR", "PDF",
                    "OLE compound file"],
             next_reader="crypto_id names other schemes from the first bytes")

    print(json.dumps({
        "path": path, "bytes": size, "parser": PARSER, "max_metadata_bytes": max_metadata, **body,
        "reminder": "Whether the member names are readable and whether the data is encrypted are two findings; report "
                    "both. A list of names shows the names the container records: not that the contents are what the "
                    "names suggest, that anything was copied, or where it went.",
    }, indent=2))


if __name__ == "__main__":
    main()
