#!/usr/bin/env python3
"""Say what kind of protection a container carries, and what is readable anyway.

The question people ask is "can we open it". The question that decides an
exfiltration case is usually different: **are the file names readable**. A
standard ZIP or 7-Zip archive leaves its central directory in the clear, so the
list of names, sizes and timestamps is available with no password at all — and a
list of names is often the whole answer. Header encryption hides that too, and
the difference is worth reporting explicitly.

The other distinction that matters: a PDF has two passwords. The user password
opens it; the owner password restricts printing and copying. A PDF with an empty
user password and only an owner password set is not meaningfully encrypted — it
opens with nothing, and the restriction is advisory. Reporting one as a
protected document is a mistake this tool exists to prevent.

Nothing here reads a sample. A PDF names its encryption dictionary in the
trailer, at the end of the file, so the whole file is searched; every ZIP entry
is counted, and when there are more than `limit` the whole list is written to a
file the output names.
"""
import json
import mmap
import os
import re
import struct
import sys
import zipfile

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
# The 7-Zip AES-256 + SHA-256 coder id. In an encoded (packed) header it means
# the header itself is encrypted, so the names need the password.
SEVENZIP_AES = b"\x06\xf1\x07\x01"


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def probe_zip(path, limit):
    out = {"container": "ZIP", "entries": [], "encrypted_entries": 0, "schemes": set()}
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        return {"container": "ZIP", "error": str(exc)}
    entries = LosslessPage("archive_probe", [os.path.realpath(path), "zip entries"], limit)
    with archive:
        for info in archive.infolist():
            encrypted = bool(info.flag_bits & ZIP_ENCRYPTED)
            scheme = None
            if encrypted:
                out["encrypted_entries"] += 1
                if info.compress_type == 99:
                    scheme = "AES (WinZip)"
                elif info.flag_bits & ZIP_STRONG:
                    scheme = "strong encryption"
                else:
                    scheme = "ZipCrypto (legacy, weak)"
                out["schemes"].add(scheme)
            entries.add({"name": info.filename, "bytes": info.file_size,
                         "compressed": info.compress_size,
                         "modified": "%04d-%02d-%02dT%02d:%02d:%02d" % info.date_time,
                         "encrypted": encrypted, "scheme": scheme})
    page = entries.finish()
    out["entries"] = entries.page
    out["entry_count"] = page["matched"]
    out.update(page)
    out["schemes"] = sorted(out["schemes"])
    out["names_readable"] = True
    out["protected"] = out["encrypted_entries"] > 0
    if "ZipCrypto (legacy, weak)" in out["schemes"]:
        out["note"] = ("ZipCrypto is weak, and where a known file from the same archive is "
                       "available it is breakable outright by known-plaintext. AES-256 is not.")
    return out


def probe_7z(view, path, limit):
    """The 32-byte start header points at the real header, at the end of the file.

    That header is either plain (0x01), where the names sit in the clear, or
    encoded (0x17): packed, and encrypted as well when its coder list names AES.
    The strings are read from that header, all of them.
    """
    out = {"container": "7-Zip", "names_readable": None, "protected": None}
    out["note"] = ("7-Zip encrypts the data by default and can encrypt the header as well. "
                   "Where the header is encrypted, even the file names need the password: "
                   "7z l on the file answers in one command, and asks for a password when it "
                   "cannot read the names.")
    region = b""
    if len(view) < 32:
        out["header_problem"] = "the file is shorter than the 32-byte start header"
    else:
        next_offset, next_size = struct.unpack_from("<QQ", view, 12)
        at = 32 + next_offset
        out["header_offset"] = at
        out["header_bytes"] = next_size
        if next_size and at + next_size <= len(view):
            region = view[at:at + next_size]
        else:
            out["header_problem"] = ("the start header places the header past the end of the "
                                     "file: the archive is truncated or was carved short")
    if region:
        kind = region[0]
        if kind == 0x01:
            out["header_kind"] = "plain"
            out["names_readable"] = True
            out["protected"] = SEVENZIP_AES in region
        elif kind == 0x17:
            out["header_kind"] = "encoded"
            if SEVENZIP_AES in region:
                out["names_readable"] = False
                out["protected"] = True
            else:
                # Packed but not encrypted: 7z l lists the names without a password.
                out["names_readable"] = True
        else:
            out["header_kind"] = "unknown (0x%02x)" % kind
    strings = LosslessPage("archive_probe", [os.path.realpath(path), "7z header strings"], limit)
    found = [(m.start(), m.group().decode("ascii", "replace"))
             for m in re.finditer(rb"[\x20-\x7e]{6,}", region)]
    found += [(m.start(), m.group().decode("utf-16-le", "replace"))
              for m in re.finditer(rb"(?:[\x20-\x7e]\x00){3,}", region)]
    for _at, text in sorted(found):
        strings.add(text)
    page = strings.finish()
    out["strings_in_header"] = strings.page
    out["strings_in_header_count"] = page["matched"]
    out.update(page)
    return out


def probe_rar(blob):
    version = 5 if bytes(blob[:8]) == b"Rar!\x1a\x07\x01\x00" else 4
    return {"container": "RAR%d" % version,
            "protected": None,
            "note": "RAR carries a per-file check value, which is enough to verify a password "
                    "without extracting. RAR5 can encrypt the file names as well; where it has, "
                    "unrar l asks for a password before listing anything."}


def probe_pdf(blob):
    encrypt = blob.find(b"/Encrypt") >= 0
    out = {"container": "PDF", "protected": encrypt}
    if not encrypt:
        out["note"] = "No encryption dictionary: this document opens with nothing."
        return out
    # The encryption dictionary is usually an indirect object, so /V and /R are not
    # beside /Encrypt. Read them from wherever in the file they are declared.
    version = re.search(rb"/V\s+(\d+)", blob)
    revision = re.search(rb"/R\s+(\d+)", blob)
    if version:
        out["v"] = int(version.group(1))
    if revision:
        out["r"] = int(revision.group(1))
    if out.get("r"):
        out["scheme"] = {2: "40-bit RC4", 3: "128-bit RC4", 4: "128-bit RC4 or AES-128",
                         5: "AES-256 (older draft)", 6: "AES-256"}.get(out["r"], "revision %d" % out["r"])
    permissions = re.search(rb"/P\s+(-?\d+)", blob)
    if permissions:
        out["permissions_flags"] = int(permissions.group(1))
    out["note"] = ("A PDF has two passwords. The user password opens it; the owner password only "
                   "restricts printing and copying. Try opening it with an EMPTY user password "
                   "first: a document with only an owner password set opens with nothing, and the "
                   "restriction is advisory. Do not report that one as protected.")
    return out


def probe_ole(blob):
    protected = (blob.find(b"EncryptionInfo") >= 0 or
                 blob.find(b"E\x00n\x00c\x00r\x00y\x00p\x00t\x00i\x00o\x00n") >= 0)
    return {"container": "OLE compound file", "protected": protected,
            "note": "An EncryptionInfo stream names the algorithm and the key derivation. The "
                    "2007-era scheme and the 2013-and-later one differ by orders of magnitude in "
                    "cost, and an older .doc may use 40-bit RC4, which is trivially breakable."
            if protected else "No EncryptionInfo stream: this document is not encrypted."}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an archive or a document")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")

    with open(path, "rb") as fh:
        head = fh.read(8)
        if head[:4] == b"PK\x03\x04":
            body = probe_zip(path, limit)
        elif head[:4] in (b"7z\xbc\xaf", b"Rar!", b"%PDF") or \
                head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            # The whole file, mapped rather than read: the part that decides a
            # PDF is usually its trailer, and a 7-Zip header sits at the end.
            with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as view:
                if head[:6] == b"7z\xbc\xaf\x27\x1c":
                    body = probe_7z(view, path, limit)
                elif head[:4] == b"Rar!":
                    body = probe_rar(view)
                elif head[:5] == b"%PDF-":
                    body = probe_pdf(view)
                elif head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                    body = probe_ole(view)
                else:
                    body = None
        else:
            body = None
    if body is None:
        fail("this is not a container this tool reads", path=path, head_hex=head.hex(),
             reads=["ZIP", "7-Zip", "RAR", "PDF", "OLE compound file"])

    print(json.dumps({
        "path": path, "bytes": os.path.getsize(path), **body,
        "reminder": "Whether the file NAMES are readable is often the whole answer to an "
                    "exfiltration question, and it is a different question from whether the data "
                    "can be decrypted. Report both.",
    }, indent=2))


if __name__ == "__main__":
    main()
