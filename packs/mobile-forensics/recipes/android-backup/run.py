#!/usr/bin/env python3
"""Catalogue an Android adb backup without extracting it.

An `.ab` file is a text header (the signature `ANDROID BACKUP`, a format version, a
compression flag and an encryption scheme) followed by a tar, compressed with zlib when the flag
says so, and encrypted when the scheme is not `none`. This reads the header and, for a payload
that is not encrypted, lists every member of the embedded tar; it extracts nothing.

    run.py detect --target T [--probe-out DIR]
    run.py run --target T --out DIR [--max-decompressed-bytes N]

What it does and does not read:

  Versions. Header versions 1 to 5 are read; any other version is `unsupported`, and nothing but
  the header is reported (status partial). The versions are those the format is known to have; the
  payload of an unencrypted backup is a plain tar after the header whichever it is.

  Encryption. `none` is listed. `AES-256` is the one scheme with a documented header layout (user
  salt, checksum salt, rounds, IV, master key blob); its header is parsed for its shape and its
  payload is NOT opened (no password is read or accepted). Any other scheme is `unsupported`. The
  salts, the IV and the master key blob are what an offline password attack starts from: backup.json
  reports their lengths and the rounds, never their values.

  Decompression is bounded. A zlib stream is read in pieces with an output budget
  (`--max-decompressed-bytes`, default 32 GiB): a payload that expands past it stops the listing and
  the run says partial, names the budget and the number of members listed. After the tar's end the
  rest of the zlib stream is read, within the same budget, so that its end marker and checksum are
  verified: `payload_stream` says reached, not_reached (the budget), truncated or damaged. Bytes after
  the stream's end marker (a second stream, padding, other data) are counted in `bytes_after_stream`;
  they are not read, and the run says partial.

  The tar is followed as it flows past, header by header, apart from the library that reads it: an
  extended header (a GNU long name, a pax header) that declares more than 16 MiB is not read, since the
  library would hold it whole in memory; the archive is complete only when its end-of-archive block was
  seen (`tar_end`: reached, missing or not_reached), so a backup cut at a member boundary is partial; a
  header the library would refuse (a checksum that does not match, a number that does not parse) ends its
  listing quietly, and the run says so and where; and the number of members listed is compared with the
  number of headers counted, so a reader that stopped early is not mistaken for a complete listing.

  A run never writes over an earlier run's output: if the output directory already holds one of its
  files, it refuses (exit 2) and leaves them as they are.

  A member name is kept as the tar reader returned it: tabs, newlines, backslashes and bytes that are
  not UTF-8 are escaped in `path`, and `path_b64` is the exact bytes of that name. The reader drops the
  trailing slash of a directory's name; `type` says it is a directory.
"""
import argparse
import base64
import datetime
import io
import json
import os
import re
import struct
import sys
import tarfile
import zlib

MAGIC = b"ANDROID BACKUP\n"
SUPPORTED_VERSIONS = (1, 2, 3, 4, 5)
DEFAULT_BUDGET = 32 << 30
PIECE = 1 << 20
SCHEME_WORD = re.compile(r"[A-Za-z0-9._-]{1,16}\Z")
OUTPUTS = ("backup.json", "members.tsv", "index.tsv", "coverage.json")


# --- tar watch: begin ----------------------------------------------------------------------------
# Held byte for byte equal in the four recipes that read a tar (a test compares the copies). The watch
# follows a tar header by header, apart from the library that lists it, and says what that library does
# not: whether the end-of-archive block came, whether a header would be refused (a checksum that does not
# match, a number that does not parse), how many members there are, and whether an extended header declares
# more than the library should be allowed to hold in memory (it reads a GNU long name or a pax header whole).
EXTENDED_HEADER_LIMIT = 16 << 20
NO_DATA_TYPES = set(b"123456")        # hard link, symbolic link, character and block device, directory, fifo: the size is not followed by data


def tar_number(field):
    """A tar numeric field as the tar library reads it: octal text, or base-256 when the top bit is set."""
    if field[0] in (0o200, 0o377):
        n = 0
        for i in range(len(field) - 1):
            n = (n << 8) + field[i + 1]
        return -(256 ** (len(field) - 1) - n) if field[0] == 0o377 else n
    return int(bytes(field).split(b"\0")[0].decode("ascii").strip() or "0", 8)


def tar_header(block):
    """The size field of a header the tar library would accept, or None if it would refuse it."""
    try:
        for start, end in ((100, 108), (108, 116), (116, 124), (136, 148), (329, 337), (337, 345)):
            tar_number(block[start:end])
        checksum = tar_number(block[148:156])
        size = tar_number(block[124:136])
    except ValueError:
        return None
    unsigned = 256 + sum(block[:148]) + sum(block[156:])
    signed = 256 + sum(struct.unpack_from("148b", block)) + sum(struct.unpack_from("356b", block, 156))
    return size if checksum in (unsigned, signed) else None


def pax_size(data):
    """The `size` record of a pax header ("<length> <key>=<value>\\n" records), or None; one that is not a number reads as 0, as the library reads it."""
    size, pos = None, 0
    while pos < len(data):
        space = data.find(b" ", pos)
        if space < 0:
            break
        try:
            length = int(data[pos:space])
        except ValueError:
            break
        if length <= 0 or pos + length > len(data):
            break
        key, _, value = data[space + 1:pos + length - 1].partition(b"=")
        if key == b"size":
            try:
                size = int(value)
            except ValueError:
                size = 0
        pos += length
    return size


class TarWatch:
    def __init__(self):
        self.block = bytearray()
        self.skip = 0
        self.collect = 0
        self.collect_padding = 0
        self.collecting = None
        self.acc = bytearray()
        self.position = 0
        self.ended = False
        self.end_at = None           # where the end-of-archive block starts
        self.violation = None        # the size an extended header declares, over the limit
        self.violation_at = None     # where that header starts
        self.bad_at = None           # where a header starts that the tar library would refuse
        self.truncated = False       # a walk reached the end of the file inside a header or its data
        self.members = 0
        self.next_size = None        # a pax `size` for the next member
        self.global_size = None      # one from a global pax header
        self.in_ext = False          # inside the extension blocks of a GNU sparse header
        self.after_ext = 0

    def stopped(self):
        return self.ended or self.violation is not None or self.bad_at is not None

    def stop_at(self):
        """Where the library must see the end of the data: before a header it must not read, or at the end block."""
        for at in (self.violation_at, self.bad_at, self.end_at):
            if at is not None:
                return at
        return None

    def feed(self, data):
        """Follow bytes as they flow past."""
        i, n = 0, len(data)
        while i < n and not self.stopped():
            if self.collect:
                take = min(self.collect, n - i)
                self.acc += data[i:i + take]
                self.collect -= take
                i += take
                self.position += take
                if not self.collect:
                    self.finish_pax()
                continue
            if self.skip:
                step = min(self.skip, n - i)
                self.skip -= step
                i += step
                self.position += step
                continue
            take = min(512 - len(self.block), n - i)
            self.block += data[i:i + take]
            i += take
            self.position += take
            if len(self.block) == 512:
                self.header(bytes(self.block))
                self.block.clear()
        if self.stopped():
            self.position += n - i

    def walk(self, fh, size, until=None):
        """Follow a file that can seek, header to header: the data between headers is jumped over, not read."""
        while not self.stopped() and not self.truncated and (until is None or self.position < until):
            if self.collect:
                data = fh.read(self.collect)
                if len(data) < self.collect:
                    self.truncated = True
                    return
                self.acc += data
                self.position += len(data)
                self.collect = 0
                self.finish_pax()
                continue
            if self.skip:
                if self.position + self.skip > size:
                    self.truncated = True
                    return
                fh.seek(self.position + self.skip)
                self.position += self.skip
                self.skip = 0
                continue
            fh.seek(self.position)
            block = fh.read(512)
            if len(block) < 512:
                self.truncated = True
                return
            self.position += 512
            self.header(block)

    def finish_pax(self):
        size = pax_size(bytes(self.acc))
        if self.collecting in (ord("x"), ord("X")):
            # The library starts from the global records and lets this header's override them.
            self.next_size = size if size is not None else self.global_size
        else:
            if size is not None:
                self.global_size = size
            self.next_size = self.global_size     # a global header applies to the member that follows it
        self.acc.clear()
        self.skip = self.collect_padding

    def header(self, block):
        start = self.position - 512
        if self.in_ext:
            if not block[504]:
                self.in_ext = False
                self.skip = self.after_ext
            return
        if block == b"\0" * 512:
            self.ended, self.end_at = True, start
            return
        size = tar_header(block)
        if size is None or size < 0:
            self.bad_at = start
            return
        flag = block[156]
        if flag in b"xgX":
            if size > EXTENDED_HEADER_LIMIT:
                self.violation, self.violation_at = size, start
                return
            self.collecting, self.collect, self.collect_padding = flag, size, -size % 512
            if not size:
                self.finish_pax()
            return
        if flag in b"LK":
            if size > EXTENDED_HEADER_LIMIT:
                self.violation, self.violation_at = size, start
                return
            self.skip = -(-size // 512) * 512
            return
        self.members += 1
        if flag in NO_DATA_TYPES:
            self.next_size = None
            return
        if self.next_size is not None:
            # A pax `size` record is the size of the entry it precedes, over the header's own.
            size = self.next_size
        self.next_size = None
        padded = -(-size // 512) * 512
        if flag == ord("S") and block[482]:
            self.in_ext, self.after_ext = True, padded
        else:
            self.skip = padded


def tar_verdict(watch, listed, cut_short=False):
    """What the watch saw, set against the `listed` members the library returned: (tar_end, limits, errors).

    `cut_short`: the bytes were stopped by a budget, so neither the end block nor the count is judged.
    """
    limits, errors = [], []
    if watch.violation is not None:
        tar_end = "not_reached"
        limits.append("a tar extended header at offset %d declares %d bytes, over the limit of %d: it is not read, and the listing stopped after %d members"
                      % (watch.violation_at, watch.violation, EXTENDED_HEADER_LIMIT, listed))
    elif watch.bad_at is not None:
        tar_end = "not_reached"
        errors.append("the tar header at offset %d is not one the tar reader accepts (a checksum that does not match, or a number that does not parse): the listing stopped there, after %d members"
                      % (watch.bad_at, listed))
    elif watch.ended:
        tar_end = "reached"
    elif cut_short:
        tar_end = "not_reached"
    else:
        tar_end = "missing"
        errors.append("the tar ends without its end-of-archive block (%d bytes read): the archive is cut short or damaged, and the listing is what came before the cut" % watch.position)
    if not cut_short and listed != watch.members:
        errors.append("the tar reader listed %d members and a header-by-header walk counted %d: the two disagree, so the listing may be missing members" % (listed, watch.members))
    return tar_end, limits, errors
# --- tar watch: end ------------------------------------------------------------------------------


class ZlibReader(io.RawIOBase):
    """A zlib stream as a file: read in pieces, with an output budget, and its end checked."""

    def __init__(self, source, budget, watch):
        self.source = source
        self.watch = watch
        self.decoder = zlib.decompressobj()
        self.budget = budget
        self.produced = 0
        self.buffer = bytearray()
        self.pending = b""
        self.finished = False
        self.exceeded = False
        self.truncated = False
        self.trailing = 0
        self.damaged = False

    def readable(self):
        return True

    def readinto(self, target):
        wanted = len(target)
        while len(self.buffer) < wanted and not self.finished:
            if self.produced >= self.budget:
                self.exceeded = True
                self.finished = True
                break
            if not self.pending and not self.decoder.eof:
                chunk = self.source.read(PIECE)
                if not chunk:
                    self.truncated = not self.decoder.eof
                    self.finished = True
                    break
                self.pending = chunk
            produced = self.decoder.decompress(self.pending, min(PIECE, self.budget - self.produced))
            self.pending = self.decoder.unconsumed_tail
            self.produced += len(produced)
            self.watch.feed(produced)
            if self.watch.violation is not None:
                # What the library would read next is an extended header too large to hold: the stream ends here.
                self.buffer.extend(produced)
                self.finished = True
                break
            self.buffer.extend(produced)
            if self.decoder.eof:
                # The end marker, and with it the Adler-32 checksum, was read: zlib raises on a mismatch.
                self.trailing = len(self.decoder.unused_data) + len(self.pending)
                self.finished = True
        count = min(wanted, len(self.buffer))
        target[:count] = self.buffer[:count]
        del self.buffer[:count]
        return count

    def drain(self):
        """Read the stream to its end (within the budget), so that its end marker is verified."""
        sink = bytearray(PIECE)
        while not self.finished:
            self.readinto(memoryview(sink))
            self.buffer.clear()

    def rest(self):
        """The bytes that follow the end marker: those read along with it, and the rest of the file."""
        if not self.decoder.eof:
            return 0
        count = self.trailing
        while True:
            chunk = self.source.read(PIECE)
            if not chunk:
                return count
            count += len(chunk)


class Tap(io.RawIOBase):
    """An uncompressed payload as a file, followed by the same watch."""

    def __init__(self, source, watch):
        self.source = source
        self.watch = watch

    def readable(self):
        return True

    def readinto(self, target):
        if self.watch.violation is not None:
            return 0
        data = self.source.read(len(target))
        self.watch.feed(data)
        target[:len(data)] = data
        return len(data)

    def drain(self):
        """The rest of the payload after the library stopped, so that the watch sees it."""
        while not self.watch.stopped():
            data = self.source.read(PIECE)
            if not data:
                break
            self.watch.feed(data)


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return paths[0]


def line(handle, label):
    raw = handle.readline(4096)
    if not raw.endswith(b"\n"):
        raise ValueError("Android backup header has no complete %s line" % label)
    try:
        return raw[:-1].decode("ascii", "strict")
    except UnicodeDecodeError:
        raise ValueError("Android backup header %s line is not ASCII" % label) from None


def label(text):
    """A header word that is printed: a short word of letters, digits and . _ - (a scheme name), and
    otherwise only its length: the line is evidence, and may hold anything."""
    if SCHEME_WORD.match(text):
        return text
    return "<not a scheme word: %d characters, not printed>" % len(text)


def header(handle):
    if handle.read(len(MAGIC)) != MAGIC:
        raise ValueError("no Android backup signature")
    version = line(handle, "version")
    compressed = line(handle, "compression")
    encryption = line(handle, "encryption")
    if not version.isdigit():
        raise ValueError("Android backup version is not numeric")
    if compressed not in ("0", "1"):
        raise ValueError("Android backup compression flag is not 0 or 1")
    details = {"version": int(version), "compressed": compressed == "1", "encryption": label(encryption)}
    details["version_supported"] = details["version"] in SUPPORTED_VERSIONS
    if encryption == "AES-256":
        # What an offline attack on the password starts from: the shape is reported, the values are not.
        fields = {"user_salt": line(handle, "user salt"), "checksum_salt": line(handle, "checksum salt"),
                  "rounds": line(handle, "rounds"), "user_iv": line(handle, "user IV"),
                  "master_key_blob": line(handle, "master key blob")}
        details["encryption_header"] = {
            "layout": "user salt, checksum salt, rounds, IV, master key blob (as the format documents it)",
            "user_salt_chars": len(fields["user_salt"]), "checksum_salt_chars": len(fields["checksum_salt"]),
            "rounds": int(fields["rounds"]) if fields["rounds"].isdigit() else None,
            "user_iv_chars": len(fields["user_iv"]), "master_key_blob_chars": len(fields["master_key_blob"]),
            "values_printed": False,
        }
    details["payload_offset"] = handle.tell()
    return details


def escaped(value):
    """One line, one field, nothing hidden; a byte that is not UTF-8 shows as \\xNN."""
    out = []
    for ch in value:
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def b64(value):
    return base64.b64encode(value.encode("utf-8", "surrogateescape")).decode("ascii")


def utc(value):
    try:
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def member_type(member):
    if member.isfile():
        return "file"
    if member.isdir():
        return "dir"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    return "other"


def detect(path):
    try:
        with open(path, "rb") as handle:
            details = header(handle)
        return True, "Android backup header version %d, encryption %s" % (details["version"], details["encryption"])
    except (OSError, UnicodeError, ValueError) as exc:
        return False, str(exc)


def run(path, out, budget):
    present = [name for name in OUTPUTS if os.path.lexists(os.path.join(out, name))]
    if present:
        # Before anything is written: an earlier run's files stay as they are.
        print(json.dumps({"ok": False, "status": "refused", "why": "the output directory already holds a file of an earlier run (%s): the recipe does not write over it" % ", ".join(present)}))
        return None
    os.makedirs(out, exist_ok=True)
    errors, limits_hit = [], []
    member_count = 0
    stream, tar_end = "not_applicable", "not_applicable"
    produced = bytes_after_stream = 0
    with open(path, "rb") as source:
        details = header(source)
        with open(os.path.join(out, "backup.json"), "w", encoding="utf-8") as handle:
            json.dump(details, handle, indent=2, sort_keys=True)
            handle.write("\n")
        listable = details["encryption"] == "none" and details["version_supported"]
        members_path = os.path.join(out, "members.tsv")
        with open(members_path, "w", encoding="utf-8", newline="\n") as listing:
            listing.write("n\ttype\tpath\tbytes\tmtime_utc\tmode\tlink\tpath_b64\n")
            if listable:
                watch = TarWatch()
                reader = ZlibReader(source, budget, watch) if details["compressed"] else None
                tap = Tap(source, watch) if reader is None else None
                payload = io.BufferedReader(reader if reader is not None else tap)
                try:
                    with tarfile.open(fileobj=payload, mode="r|", encoding="utf-8", errors="surrogateescape") as archive:
                        for member in archive:
                            listing.write("%d\t%s\t%s\t%d\t%s\t%o\t%s\t%s\n" % (
                                member_count, member_type(member), escaped(member.name), member.size,
                                utc(member.mtime), member.mode, escaped(member.linkname or ""), b64(member.name)))
                            member_count += 1
                            archive.members = []
                except zlib.error as exc:
                    if reader is not None:
                        reader.damaged = True
                    errors.append("the zlib stream is damaged: %s" % exc)
                except (tarfile.TarError, EOFError, OSError) as exc:
                    errors.append("embedded tar traversal stopped: %s" % exc)
                if watch.violation is None and not (reader and reader.damaged):
                    try:
                        (reader or tap).drain()
                    except zlib.error as exc:
                        reader.damaged = True
                        errors.append("the zlib stream is damaged after the tar's end: %s" % exc)
                cut_short = False
                if reader is not None:
                    produced = reader.produced
                    if reader.damaged:
                        stream, cut_short = "damaged", True
                    elif reader.exceeded:
                        stream, cut_short = "not_reached", True
                        limits_hit.append("decompressed output budget of %d bytes (the listing stopped after %d members)" % (budget, member_count))
                    elif reader.truncated:
                        stream = "truncated"
                        errors.append("the zlib stream ends before its end marker: the backup is cut short")
                    elif watch.violation is None:
                        stream = "reached"
                        bytes_after_stream = reader.rest()
                        if bytes_after_stream:
                            errors.append("%d byte(s) follow the zlib stream's end marker (a second stream, or other data): they are not read, and the listing does not include them" % bytes_after_stream)
                    else:
                        stream = "not_reached"
                else:
                    stream = "not_compressed"
                tar_end, found_limits, found_errors = tar_verdict(watch, member_count, cut_short)
                limits_hit += found_limits
                errors += found_errors
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("file\twhat\n")
        handle.write("backup.json\tAndroid backup header fields and payload offset (key-derivation values are not printed)\n")
        handle.write("members.tsv\tevery embedded tar member when the payload is unencrypted and the version is supported\n")
    if not details["version_supported"]:
        status = "partial"
        covered = "header only; version %d is not one this recipe reads (1 to 5)" % details["version"]
        errors.append("unsupported: header version %d" % details["version"])
    elif details["encryption"] != "none":
        status = "partial"
        covered = "header only; encrypted payload not opened"
        if details["encryption"] == "AES-256":
            errors.append("payload encryption is AES-256; opening it needs a password, and this recipe reads none")
        else:
            errors.append("unsupported: payload encryption scheme %s" % details["encryption"])
    else:
        status = "partial" if errors or limits_hit else "complete"
        covered = "%d embedded tar members" % member_count
    coverage = {
        "recipe": "android-backup",
        "status": status,
        "covered": covered,
        "not_covered": "files excluded by adb backup policy, deleted data, artifact contents, password recovery",
        "limits_hit": limits_hit,
        "errors": errors,
        "payload_stream": stream,
        "tar_end": tar_end,
        "decompressed_bytes": produced,
        "bytes_after_stream": bytes_after_stream,
    }
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump(coverage, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return coverage, member_count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    # The kickoff's census asks every detect step with --probe-out DIR, a
    # place for what the probe wants kept (evidence_catalog.py). Refused here,
    # it was a usage error (exit 2) for every input of a run, and a phone's
    # tar was catalogued as a member list only. Detect reads the backup's header
    # and keeps nothing, so the directory is taken and left empty.
    parser.add_argument("--probe-out")
    parser.add_argument("--max-decompressed-bytes", type=int, default=DEFAULT_BUDGET)
    args = parser.parse_args()
    try:
        path = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    if args.command == "detect":
        applies, why = detect(path)
        print(json.dumps({"applies": applies, "why": why}))
        return 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    if args.max_decompressed_bytes < 1:
        print(json.dumps({"ok": False, "error": "--max-decompressed-bytes must be positive"}))
        return 2
    applies, why = detect(path)
    if not applies:
        print(json.dumps({"ok": False, "status": "unsupported", "why": why}))
        return 2
    try:
        answer = run(path, args.out, args.max_decompressed_bytes)
    except (OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    if answer is None:
        return 2
    coverage, members = answer
    print(json.dumps({"ok": True, "status": coverage["status"], "members": members}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
