#!/usr/bin/env python3
"""Read auth.log and secure as records rather than as text.

Three things this exists to get right, because doing them by hand with grep is
where the mistakes are.

Rotation. The current file usually covers days, and an intrusion usually is not
in it. auth.log.1, auth.log.2.gz and the rest hold the rest, and they have to be
read oldest first or the timeline comes out backwards.

The missing year. Traditional syslog lines carry a month, a day and a time and
no year at all, so every date is a guess until something supplies one. This uses
the file's own modification time, walks backwards when the month decreases, and
says in the output which year it applied — because around new year that guess
is wrong and a reviewer needs to see it was made.

The shape of each line. "Accepted publickey for deploy from 10.0.0.5" names a
key, not a person; the fingerprint that follows is what maps to an entry in some
authorized_keys file. That distinction is in the output as its own field.
"""
import datetime
import gzip
import json
import os
import re
import sys

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

TRADITIONAL = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
ISO = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")

RULES = [
    ("ssh_accepted", re.compile(
        r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<source>\S+) port (?P<port>\d+)"
        r"(?:\s+\S+)?(?::\s*(?P<keytype>\S+)\s+(?P<fingerprint>\S+))?")),
    ("ssh_failed", re.compile(
        r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<source>\S+) port (?P<port>\d+)")),
    ("ssh_invalid_user", re.compile(r"^Invalid user (?P<user>\S+) from (?P<source>\S+)")),
    ("ssh_disconnect", re.compile(r"^(?:Received disconnect|Disconnected) from (?P<source>\S+)")),
    ("sudo", re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.*)$")),
    ("sudo_failed", re.compile(r"^\s*(?P<user>\S+)\s*:\s*(?:\d+ incorrect password attempts|user NOT in sudoers)")),
    ("su", re.compile(r"^(?:\(to (?P<target>\S+)\)|Successful su for) (?P<user>\S+)")),
    ("session_opened", re.compile(r"^pam_unix\([^)]*\): session opened for user (?P<user>\S+)")),
    ("session_closed", re.compile(r"^pam_unix\([^)]*\): session closed for user (?P<user>\S+)")),
    ("auth_failure", re.compile(r"^pam_unix\([^)]*\): authentication failure;.*?(?:ruser=(?P<ruser>\S*)).*?(?:rhost=(?P<source>\S*))?.*?(?:user=(?P<user>\S+))?")),
    ("account_added", re.compile(r"^new (?:user|group): name=(?P<name>[^,]+)")),
    ("account_changed", re.compile(r"^(?:changed password|password changed) for (?P<user>\S+)")),
    ("key_added", re.compile(r"^(?:Authorized|Accepted) key (?P<fingerprint>\S+)")),
]


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def open_maybe_gzip(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def rotation_key(path):
    """auth.log, auth.log.1, auth.log.2.gz — oldest first means highest number first."""
    name = os.path.basename(path)
    found = re.search(r"\.(\d+)(?:\.gz)?$", name)
    return (-int(found.group(1)) if found else 0, name)


def classify(message):
    for kind, pattern in RULES:
        found = pattern.match(message)
        if found:
            fields = {k: v for k, v in found.groupdict().items() if v}
            return kind, fields
    return "other", {}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an auth.log or secure file, or a directory holding them")
    if os.path.islink(path):
        fail("refusing a symlink: pass the log file or directory inside the evidence", path=path,
             target=os.readlink(path))

    targets = []
    if os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for name in names:
                if re.match(r"^(auth\.log|secure)", name):
                    candidate = os.path.join(root, name)
                    if not os.path.islink(candidate):
                        targets.append(candidate)
    elif os.path.isfile(path):
        targets = [path]
    else:
        fail("no such file or directory", path=path)
    if not targets:
        fail("no auth.log or secure file found there", path=path)
    targets.sort(key=rotation_key)

    wanted = {str(k) for k in (args.get("kinds") or [])}
    needle = (args.get("contains") or "").lower()

    records, lines_read, unparsed, errors = [], 0, 0, []
    years_used = {}
    for target in targets:
        try:
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(target), datetime.timezone.utc)
        except OSError:
            mtime = datetime.datetime.now(datetime.timezone.utc)
        year = args.get("year") or mtime.year
        last_month = None
        years_used[target] = year
        try:
            handle = open_maybe_gzip(target)
        except OSError as exc:
            unparsed += 1
            errors.append({"file": target, "error": str(exc)})
            continue
        with handle:
            for line in handle:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                lines_read += 1
                found = TRADITIONAL.match(line) or ISO.match(line)
                if not found:
                    unparsed += 1
                    continue
                parts = found.groupdict()
                if "mon" in parts and parts.get("mon"):
                    month = MONTHS.get(parts["mon"], 1)
                    if last_month is None and args.get("year") is None:
                        # The file's last line is the one nearest its mtime. If it opens in a
                        # later month than the mtime, it started in the previous year.
                        if month > mtime.month:
                            year -= 1
                            years_used[target] = year
                    elif last_month is not None and month < last_month:
                        year += 1          # the file crossed new year while we read forward
                        years_used[target] = "%s then %s" % (years_used[target], year)
                    last_month = month
                    stamp = "%04d-%02d-%02dT%s" % (year, month, int(parts["day"]), parts["time"])
                    guessed = args.get("year") is None
                else:
                    stamp = parts["stamp"]
                    guessed = False
                kind, fields = classify(parts["msg"])
                if wanted and kind not in wanted:
                    continue
                if needle and needle not in line.lower():
                    continue
                records.append({
                    "time": stamp,
                    "year_guessed": guessed,
                    "host": parts.get("host"),
                    "process": parts.get("proc"),
                    "pid": int(parts["pid"]) if parts.get("pid") else None,
                    "kind": kind,
                    "file": target,
                    **fields,
                    "raw": parts["msg"],
                })

    counts = {}
    for r in records:
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1
    print(json.dumps({
        "files": targets,
        "lines_read": lines_read,
        "records": records,
        "record_count": len(records),
        "by_kind": counts,
        "unparsed_lines": unparsed,
        "complete": not errors,
        "errors": errors,
        "years_applied": years_used,
        "note": "Traditional syslog carries no year; the year applied per file is above and each "
                "record says whether it was guessed. An ssh_accepted with method 'publickey' names "
                "a key, not a person: map its fingerprint to an authorized_keys entry before you "
                "attribute the session. These lines are text a root user can edit — cross-check "
                "anything that matters against wtmp with utmp_parse.",
    }, indent=2))


if __name__ == "__main__":
    main()
