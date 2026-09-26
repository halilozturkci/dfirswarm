#!/usr/bin/env python3
"""archive-members: the member list of a tar, zip or 7z archive, nothing extracted.

    run.py detect --target TARGET          exit 0 applies, 1 does not, 2 error
    run.py run --target TARGET --out DIR   members.tsv + coverage.json in DIR

TARGET is JSON (inline or a file path): {"paths": [...], "ref": ..., "name": ...};
the archive is paths[0]. Every member is one row of members.tsv:

    n  type  path  path_b64  size  packed  mtime  tz  mode  uid  gid  link  locator  flags

`path` and `link` are shown with control characters, tabs, newlines and
backslashes escaped; `path_b64` is the name's exact bytes. `n` counts from 0
in archive order and is what archive_extract takes, so two members with the
same name are still two rows. A tar's times are UTC; a zip's DOS times carry
no zone (`tz` is `unknown`) unless the member has an extended timestamp.
`flags` names what an examiner should know before extracting: escapes-root,
encrypted, ratio>1000, and name-not-utf8 (macOS refuses such a name, so an
extraction there must rename the member; its bytes are path_b64).
"""
import base64
import datetime
import json
import lzma
import os
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def name_flags(raw):
    """A name that is not UTF-8: APFS will not store it as it is."""
    try:
        raw.decode("utf-8")
        return []
    except UnicodeDecodeError:
        return ["name-not-utf8"]
SEVEN_Z_MAGIC = b"7z\xbc\xaf\x27\x1c"
COLUMNS = ["n", "type", "path", "path_b64", "size", "packed", "mtime", "tz", "mode", "uid", "gid", "link", "locator", "flags"]


def limits():
    try:
        spec = json.load(open(os.path.join(HERE, "recipe.json")))
        lim = spec.get("limits", {})
    except Exception:
        lim = {}
    seconds = int(os.environ.get("RECIPE_SECONDS") or lim.get("seconds") or 1800)
    members = int(os.environ.get("RECIPE_MEMBERS") or lim.get("members") or 2000000)
    return seconds, members


def target_of(arg):
    text = open(arg, encoding="utf-8").read() if os.path.isfile(arg) else arg
    t = json.loads(text)
    paths = t.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise SystemExit(json.dumps({"ok": False, "error": "the target names no path"}))
    return t, paths[0]


def esc(raw):
    """A name for a reader: one line, one field, nothing hidden."""
    out = []
    for ch in raw.decode("utf-8", "surrogateescape"):
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def utc(ts):
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def detect(path):
    """(format, why) or (None, why)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError as e:
        return None, "unreadable: %s" % (e.strerror or e)
    if head.startswith(SEVEN_Z_MAGIC):
        return "7z", "7z signature"
    if zipfile.is_zipfile(path):
        return "zip", "zip end-of-central-directory record"
    # tarfile.is_tarfile says yes to a file of zeros (an empty tar is two
    # zero blocks), and a memory or disk image can start with zeros: a tar
    # here is one whose first member header reads.
    try:
        with tarfile.open(path, mode="r:*") as tf:
            first = tf.next()
        if first is not None:
            return "tar", "tar header"
        return None, "no tar member (zero blocks, or not a tar)"
    except Exception:
        return None, "no tar, zip or 7z structure"


class Writer:
    def __init__(self, out_dir):
        self.fh = open(os.path.join(out_dir, "members.tsv"), "w", encoding="utf-8", newline="\n")
        self.fh.write("\t".join(COLUMNS) + "\n")
        self.rows = 0

    def row(self, **v):
        self.fh.write("\t".join(str(v.get(c, "")) for c in COLUMNS) + "\n")
        self.rows += 1

    def close(self):
        self.fh.close()


def tar_type(m):
    if m.isreg():
        return "file"
    if m.isdir():
        return "dir"
    if m.issym():
        return "symlink"
    if m.islnk():
        return "hardlink"
    if m.ischr():
        return "char"
    if m.isblk():
        return "block"
    if m.isfifo():
        return "fifo"
    return "other"


def list_tar(path, w, deadline, max_members, cov):
    compressed = False
    with open(path, "rb") as fh:
        magic = fh.read(6)
    if magic[:2] == b"\x1f\x8b" or magic[:3] == b"BZh" or magic[:6] == b"\xfd7zXZ\x00":
        compressed = True
    cov["format"] = "tar" + (" (compressed)" if compressed else "")
    # A plain tar is walked header to header, seeking over the data; a
    # compressed one is read once, front to back, in stream mode.
    tf = tarfile.open(path, mode="r|*" if compressed else "r:")
    n = 0
    last = None
    try:
        for m in tf:
            raw = m.name.encode("utf-8", "surrogateescape")
            link = m.linkname.encode("utf-8", "surrogateescape") if m.linkname else b""
            loc = "tar:index=%d" % n if compressed else "tar:index=%d;header=%d;data=%d" % (n, m.offset, m.offset_data)
            flags = name_flags(raw)
            if raw.startswith(b"/") or b"/../" in b"/" + raw + b"/":
                flags.append("escapes-root")
            w.row(n=n, type=tar_type(m), path=esc(raw), path_b64=b64(raw), size=m.size, packed="",
                  mtime=utc(m.mtime), tz="utc", mode="%o" % m.mode, uid=m.uid, gid=m.gid,
                  link=esc(link), locator=loc, flags=",".join(flags))
            n += 1
            last = (m.offset_data, m.size if m.isreg() else 0)
            tf.members = []  # the listing is on disk; do not hold every header in memory
            if n >= max_members:
                cov["limits_hit"].append("members: stopped at %d" % max_members)
                break
            if time.monotonic() > deadline:
                cov["limits_hit"].append("seconds: stopped after %d members" % n)
                break
    except (tarfile.TarError, EOFError, OSError, zlib.error, lzma.LZMAError) as e:
        cov["errors"].append("the archive ended or broke after %d members: %s" % (n, e))
    finally:
        tf.close()
    if not compressed and not cov["limits_hit"]:
        tar_tail(path, last, n, cov)
    return n


def tar_tail(path, last, n, cov):
    """tarfile takes a header it cannot read for the end of the archive and
    says nothing. A plain tar ends in zero blocks right after its last
    member's data: anything else after it is a part this listing never read."""
    size = os.path.getsize(path)
    end = 0 if last is None else last[0] + ((last[1] + 511) // 512) * 512
    if end > size:
        cov["errors"].append("member %d's data runs %d bytes past the end of the file: the archive is truncated" % (n - 1, end - size))
        return
    with open(path, "rb") as fh:
        fh.seek(end)
        rest = fh.read(1 << 20)
    if rest.strip(b"\0"):
        cov["errors"].append("%d bytes after member %d are not a tar header this listing could read (truncated or damaged at offset %d)"
                             % (size - end, n - 1, end))


def zip_ext_time(extra):
    """The UTC mtime from an extended-timestamp field (0x5455), or None."""
    i = 0
    while i + 4 <= len(extra):
        hid, size = struct.unpack_from("<HH", extra, i)
        body = extra[i + 4:i + 4 + size]
        if hid == 0x5455 and len(body) >= 5 and body[0] & 1:
            return struct.unpack_from("<I", body, 1)[0]
        i += 4 + size
    return None


def zip_declared_entries(path):
    """The member count the end-of-central-directory record declares (zip64
    too), read before zipfile loads the whole directory into memory."""
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        fh.seek(max(0, size - 65557))
        tail = fh.read()
    at = tail.rfind(b"PK\x05\x06")
    if at < 0 or at + 22 > len(tail):
        return None
    total = struct.unpack_from("<H", tail, at + 10)[0]
    if total == 0xFFFF:
        loc = tail.rfind(b"PK\x06\x07", 0, at)
        if loc >= 0:
            with open(path, "rb") as fh:
                fh.seek(struct.unpack_from("<Q", tail, loc + 8)[0])
                rec = fh.read(56)
            if rec[:4] == b"PK\x06\x06":
                total = struct.unpack_from("<Q", rec, 32)[0]
    return total


def list_zip(path, w, deadline, max_members, cov):
    cov["format"] = "zip"
    n = 0
    declared = zip_declared_entries(path)
    if declared is not None and declared > max_members:
        # zipfile reads every entry of the directory into memory before the
        # first one can be listed: past the limit nothing is listed, and says so.
        cov["limits_hit"].append("members: the central directory declares %d, more than the limit of %d; not listed (raise RECIPE_MEMBERS for this archive)" % (declared, max_members))
        return 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            utf8 = bool(info.flag_bits & 0x800)
            raw = info.filename.encode("utf-8" if utf8 else "cp437", "surrogateescape")
            ext = zip_ext_time(info.extra)
            if ext is not None:
                mtime, tz = utc(ext), "utc"
            else:
                try:
                    mtime = "%04d-%02d-%02dT%02d:%02d:%02d" % info.date_time
                except TypeError:
                    mtime = ""
                tz = "unknown"
            mode = (info.external_attr >> 16) & 0xFFFF
            kind = "dir" if info.is_dir() else ("symlink" if (mode & 0o170000) == 0o120000 else "file")
            flags = name_flags(raw)
            if info.flag_bits & 0x1:
                flags.append("encrypted")
            if info.compress_size and info.file_size / max(info.compress_size, 1) > 1000:
                flags.append("ratio>1000")
            if raw.startswith(b"/") or b"/../" in b"/" + raw.replace(b"\\", b"/") + b"/":
                flags.append("escapes-root")
            w.row(n=n, type=kind, path=esc(raw), path_b64=b64(raw), size=info.file_size, packed=info.compress_size,
                  mtime=mtime, tz=tz, mode=("%o" % mode) if mode else "", uid="", gid="", link="",
                  locator="zip:index=%d;header=%d" % (n, info.header_offset), flags=",".join(flags))
            n += 1
            if n >= max_members:
                cov["limits_hit"].append("members: stopped at %d" % max_members)
                break
            if time.monotonic() > deadline:
                cov["limits_hit"].append("seconds: stopped after %d members" % n)
                break
    return n


def list_7z(path, w, deadline, max_members, cov):
    cov["format"] = "7z"
    env = dict(os.environ, TZ="UTC", LANG="C.UTF-8", LC_ALL="C.UTF-8")
    try:
        proc = subprocess.run(["7z", "l", "-slt", "-ba", "--", path], capture_output=True, env=env,
                              timeout=max(5, deadline - time.monotonic()))
    except FileNotFoundError:
        cov["status_override"] = "unsupported"
        cov["errors"].append("7z is not in this image")
        return 0
    except subprocess.TimeoutExpired:
        cov["limits_hit"].append("seconds: 7z did not finish listing")
        return 0
    if proc.returncode != 0 and not proc.stdout:
        cov["errors"].append("7z could not list it: %s" % proc.stderr.decode("utf-8", "replace").strip())
        return 0
    n = 0
    for block in proc.stdout.split(b"\n\n"):
        fields = {}
        for line in block.split(b"\n"):
            if b" = " in line:
                k, v = line.split(b" = ", 1)
                fields[k.strip()] = v
        if b"Path" not in fields:
            continue
        raw = fields[b"Path"]
        attrs = fields.get(b"Attributes", b"").decode("ascii", "replace")
        kind = "dir" if attrs.startswith("D") or fields.get(b"Folder") == b"+" else "file"
        mod = fields.get(b"Modified", b"").decode("ascii", "replace").strip()
        flags = name_flags(raw) + (["encrypted"] if fields.get(b"Encrypted") == b"+" else [])
        w.row(n=n, type=kind, path=esc(raw), path_b64=b64(raw), size=fields.get(b"Size", b"").decode(),
              packed=fields.get(b"Packed Size", b"").decode(), mtime=mod.replace(" ", "T") + ("Z" if mod else ""),
              tz="utc" if mod else "", mode="", uid="", gid="", link="", locator="7z:index=%d" % n, flags=",".join(flags))
        n += 1
        if n >= max_members:
            cov["limits_hit"].append("members: stopped at %d" % max_members)
            break
    if proc.returncode != 0:
        cov["errors"].append("7z exited %d: %s" % (proc.returncode, proc.stderr.decode("utf-8", "replace").strip()))
    return n


def run(path, out_dir):
    seconds, max_members = limits()
    deadline = time.monotonic() + seconds * 0.9
    os.makedirs(out_dir, exist_ok=True)
    fmt, why = detect(path)
    cov = {"recipe": "archive-members", "target": path, "format": fmt, "members": 0,
           "covered": "the archive's list of members", "not_covered": "member contents; archives inside the archive",
           "limits_hit": [], "errors": []}
    if fmt is None:
        cov.update(status="unsupported", why=why)
        json.dump(cov, open(os.path.join(out_dir, "coverage.json"), "w"), indent=2)
        return 2
    w = Writer(out_dir)
    try:
        n = {"tar": list_tar, "zip": list_zip, "7z": list_7z}[fmt](path, w, deadline, max_members, cov)
    except Exception as e:
        n = w.rows
        cov["errors"].append("%s: %s" % (type(e).__name__, e))
    finally:
        w.close()
    cov["members"] = n
    status = cov.pop("status_override", None)
    if status is None:
        status = "complete" if not cov["limits_hit"] and not cov["errors"] else ("partial" if n else "failed")
    cov["status"] = status
    json.dump(cov, open(os.path.join(out_dir, "coverage.json"), "w"), indent=2)
    with open(os.path.join(out_dir, "index.tsv"), "w", encoding="utf-8") as fh:
        fh.write("members.tsv\t%s member list (%d): n, type, path, path_b64, size, packed, mtime, tz, mode, uid, gid, link, locator, flags; archive_extract takes n\n"
                 % (cov.get("format") or "archive", n))
    print(json.dumps({"ok": status in ("complete", "partial"), "status": status, "format": cov["format"], "members": n}))
    return 0 if status in ("complete", "partial") else 2


def main(argv):
    if len(argv) < 2 or argv[1] not in ("detect", "run"):
        print(json.dumps({"ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR"}))
        return 2
    args = dict(zip(argv[2::2], argv[3::2]))
    if "--target" not in args:
        print(json.dumps({"ok": False, "error": "--target is required"}))
        return 2
    _t, path = target_of(args["--target"])
    if argv[1] == "detect":
        fmt, why = detect(path)
        print(json.dumps({"applies": fmt is not None, "format": fmt, "why": why}))
        return 0 if fmt else 1
    if "--out" not in args:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    return run(path, args["--out"])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
