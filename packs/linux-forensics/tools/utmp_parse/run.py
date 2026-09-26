#!/usr/bin/env python3
"""Read wtmp, btmp, utmp and lastlog: Linux's binary login records.

Text logs are edited; these are not, as often. An operator who cleans
/var/log/auth.log frequently leaves wtmp alone, and the two disagreeing is
itself evidence. wtmp holds successful sessions with the source address, btmp
holds the failures, and both keep going back as far as rotation allowed.

struct utmp on 64-bit Linux, 384 bytes, little-endian:

  0x000 int16  ut_type          0x004 int32  ut_pid
  0x008 char   ut_line[32]      0x028 char   ut_id[4]
  0x02c char   ut_user[32]      0x04c char   ut_host[256]
  0x14c int32  ut_exit          0x150 int32  ut_session
  0x154 int32  tv_sec           0x158 int32  tv_usec
  0x15c int32  ut_addr_v6[4]    0x16c char   unused[20]

tv_sec is a 32-bit signed value even on 64-bit systems, which is a real
year-2038 problem sitting inside the format and worth knowing before a date
comes back negative.
"""
import datetime
import json
import os
import re
import socket
import struct
import sys

RECORD = 384
LASTLOG_32 = 292
LASTLOG_64 = 296
TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
         5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS",
         9: "ACCOUNTING"}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def text(raw):
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def address(raw):
    """ut_addr_v6 holds an IPv4 address in its first word, or a whole IPv6 one."""
    words = struct.unpack("<4I", raw)
    if not any(words):
        return None
    if not any(words[1:]):
        return socket.inet_ntop(socket.AF_INET, raw[:4])
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except (OSError, ValueError):
        return raw.hex()


def timestamp(sec, usec=0):
    if not sec:
        return None
    try:
        value = datetime.datetime.fromtimestamp(
            sec, datetime.timezone.utc).replace(microsecond=usec % 1000000)
        return value.isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def passwd_users(path):
    users = {}
    if not path:
        return users
    if os.path.islink(path):
        fail("refusing a symlink passwd file", path=path, target=os.readlink(path))
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                fields = line.rstrip("\n").split(":")
                if len(fields) >= 3:
                    try:
                        users[int(fields[2])] = fields[0]
                    except ValueError:
                        continue
    except OSError as exc:
        fail("could not read passwd file", path=path, reason=str(exc))
    return users


def lastlog_layout(path, size):
    requested = []
    if size % LASTLOG_32 == 0:
        requested.append((LASTLOG_32, "<i", 4, "lastlog-32"))
    if size % LASTLOG_64 == 0:
        requested.append((LASTLOG_64, "<q", 8, "lastlog-64"))
    if len(requested) == 1:
        return requested[0]
    if not requested:
        fail("lastlog size is not a whole number of 292-byte or 296-byte records",
             path=path, bytes=size)
    # Ambiguous sparse files are rare. Prefer the layout whose non-zero epochs
    # decode to plausible dates and whose line/host fields contain no NUL-free
    # binary noise in the first 128 slots.
    scored = []
    with open(path, "rb") as fh:
        sample = fh.read(max(x[0] for x in requested) * 128)
    for layout in requested:
        width, fmt, text_at, _name = layout
        score = 0
        for at in range(0, len(sample) - width + 1, width):
            raw = sample[at:at + width]
            sec = struct.unpack_from(fmt, raw, 0)[0]
            if sec == 0:
                score += 1
            elif timestamp(sec):
                score += 4
            line = raw[text_at:text_at + 32]
            host = raw[text_at + 32:text_at + 288]
            if b"\x00" in line and b"\x00" in host:
                score += 1
        scored.append((score, layout))
    return max(scored, key=lambda row: row[0])[1]


def parse_lastlog(path, args, pattern):
    size = os.path.getsize(path)
    width, fmt, text_at, format_name = lastlog_layout(path, size)
    users = passwd_users(args.get("passwd"))
    records = []
    slots = size // width
    with open(path, "rb") as fh:
        for uid in range(slots):
            raw = fh.read(width)
            sec = struct.unpack_from(fmt, raw, 0)[0]
            line = text(raw[text_at:text_at + 32])
            host = text(raw[text_at + 32:text_at + 288])
            user = users.get(uid)
            if not sec and not line and not host:
                continue
            if pattern and not pattern.search(user or str(uid)):
                continue
            records.append({"type": "LASTLOG", "uid": uid, "user": user,
                            "line": line, "host": host, "time": timestamp(sec),
                            "epoch": sec})
    return records, slots, format_name


def parse_utmp(path, wanted, pattern):
    records, seen = [], 0
    with open(path, "rb") as fh:
        while True:
            raw = fh.read(RECORD)
            if len(raw) < RECORD:
                break
            seen += 1
            ut_type, pid = struct.unpack_from("<hxxi", raw, 0)
            sec, usec = struct.unpack_from("<ii", raw, 0x154)
            entry = {
                "type": TYPES.get(ut_type, str(ut_type)),
                "user": text(raw[0x02C:0x04C]),
                "line": text(raw[0x008:0x028]),
                "id": text(raw[0x028:0x02C]),
                "host": text(raw[0x04C:0x14C]),
                "address": address(raw[0x15C:0x16C]),
                "pid": pid,
                "session": struct.unpack_from("<i", raw, 0x150)[0],
                "time": timestamp(sec, usec),
                "epoch": sec,
            }
            if entry["type"] == "EMPTY" and not entry["user"] and not sec:
                continue
            if wanted and entry["type"] not in wanted:
                continue
            if pattern and not pattern.search(entry["user"]):
                continue
            records.append(entry)
    return records, seen


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a wtmp, btmp, utmp or lastlog file")
    if os.path.islink(path):
        fail("refusing a symlink: pass the binary log inside the evidence", path=path,
             target=os.readlink(path))
    if not os.path.isfile(path):
        fail("no such file", path=path)
    size = os.path.getsize(path)
    wanted = {str(t).upper() for t in (args.get("types") or [])}
    pattern = None
    if args.get("user"):
        try:
            pattern = re.compile(args["user"], re.I)
        except re.error as exc:
            fail("user is not a valid regex", reason=str(exc))

    requested_format = args.get("format")
    if requested_format not in (None, "utmp", "lastlog"):
        fail("format must be utmp or lastlog")
    is_lastlog = requested_format == "lastlog" or (
        requested_format is None and os.path.basename(path).lower() == "lastlog")
    if is_lastlog:
        records, seen, format_name = parse_lastlog(path, args, pattern)
        if wanted and "LASTLOG" not in wanted:
            records = []
        note = "lastlog is indexed by UID; pass passwd to map every slot to an account name"
    else:
        records, seen = parse_utmp(path, wanted, pattern)
        format_name = "utmp"
        note = None if size % RECORD == 0 else (
            "the file is not a whole number of %d-byte records; the short tail was named" % RECORD)

    boots = [r for r in records if r["type"] == "BOOT_TIME"]
    print(json.dumps({
        "path": path,
        "records_in_file": seen,
        "records": records,
        "record_count": len(records),
        "boots": len(boots),
        "format": format_name,
        "complete": is_lastlog or size % RECORD == 0,
        "file_note": note,
        "note": ("Each LASTLOG record is the most recent login stored for one UID; an empty slot is "
                 "not evidence the account never logged in. " if is_lastlog else
                 "A USER_PROCESS record is a session that started; the matching DEAD_PROCESS on the "
                 "same line is when it ended. btmp holds failures and its user field is what was "
                 "typed, which may be a user name that does not exist. ") +
                "Compare these records against /var/log/auth.log: disagreement can show that one "
                "source was cleared, rotated or damaged.",
    }, indent=2))


if __name__ == "__main__":
    main()
