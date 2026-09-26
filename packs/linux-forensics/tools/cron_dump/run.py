#!/usr/bin/env python3
"""Put every scheduled job on the machine in one list.

Scheduling on Linux is scattered across six places and two subsystems, and an
agent that checks the obvious one has checked a sixth of it. The @reboot entry
in a user's spool file is persistence with no schedule at all and is the one
most often missed.

    /etc/crontab                     system table, with a user field
    /etc/cron.d/*                    drop-ins, also with a user field
    /etc/cron.{hourly,daily,weekly,monthly}/   scripts, run by run-parts
    /var/spool/cron/crontabs/<user>  per-user tables, no user field
    /var/spool/cron/<user>           the same, on Red Hat family
    *.timer + *.service              systemd, the modern route

Each entry comes back with the file it was in and that file's modification
time, because the question is almost never "what is scheduled" but "what was
added, and when".
"""
import datetime
import json
import os
import re
import sys

SPECIALS = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily",
            "@midnight", "@hourly"}
SYSTEM_TABLES = ["etc/crontab"]
SYSTEM_DIRS = ["etc/cron.d"]
RUN_PARTS = ["etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly"]
SPOOLS = ["var/spool/cron/crontabs", "var/spool/cron"]
UNIT_DIRS = ["etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system",
             "run/systemd/system"]


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def mtime_of(path):
    try:
        return datetime.datetime.fromtimestamp(
            os.path.getmtime(path), datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except OSError:
        return None


def inside(root, path):
    """False when an absolute evidence symlink would resolve into this VM."""
    try:
        return os.path.commonpath((os.path.realpath(root), os.path.realpath(path))) == os.path.realpath(root)
    except (OSError, ValueError):
        return False


def parse_table(path, has_user):
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        return [{"file": path, "error": str(exc)}]
    stamp = mtime_of(path)
    environment = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        assignment = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if assignment:          # MAILTO=, PATH=, SHELL= and implementation-specific variables
            environment[assignment.group(1)] = assignment.group(2)
            continue
        parts = line.split()
        if parts[0] in SPECIALS:
            schedule, rest = parts[0], parts[1:]
        elif len(parts) >= 6:
            schedule, rest = " ".join(parts[:5]), parts[5:]
        else:
            continue
        user = None
        if has_user and rest:
            user, rest = rest[0], rest[1:]
        out.append({"source": "cron", "file": path, "file_modified": stamp,
                    "schedule": schedule, "user": user, "command": " ".join(rest),
                    "environment": dict(environment), "at_reboot": schedule == "@reboot"})
    return out


def parse_unit(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return {"file": path, "error": str(exc)}
    # One line at a time, without a regex: a pattern that let whitespace run
    # on rescanned the rest of the file from every line start on a unit
    # padded with blank lines, or the rest of a line from every space after
    # an empty `Key=`, and a key given empty took the next line as its value.
    # The first line that gives the key a value is the one read, as before.
    lines = text.split("\n")
    def fields(name):
        out = []
        for line in lines:
            key, sep, value = line.partition("=")
            if sep and key.strip() == name and value.strip():
                out.append(value.strip())
        return out
    schedules = fields("OnCalendar") + fields("OnBootSec") + fields("OnUnitActiveSec")
    unit = fields("Unit")
    persistent = fields("Persistent")
    return {"source": "systemd", "file": path, "file_modified": mtime_of(path),
            "schedule": schedules[0] if schedules else None, "schedules": schedules,
            "unit": unit[0] if unit else os.path.basename(path).replace(".timer", ".service"),
            "persistent": persistent[0] if persistent else None, "command": None,
            "at_reboot": bool(fields("OnBootSec"))}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    root = args.get("root")
    if not isinstance(root, str) or not root:
        fail("root is required: an extracted file system root")
    if os.path.islink(root):
        fail("refusing a symlink root: pass the extracted evidence directory", root=root,
             target=os.readlink(root))
    if not os.path.isdir(root):
        fail("no such directory", root=root)
    pattern = None
    if args.get("contains"):
        try:
            pattern = re.compile(args["contains"], re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))

    entries, looked, skipped_symlinks = [], [], []
    def note(rel):
        looked.append(rel)

    for rel in SYSTEM_TABLES:
        full = os.path.join(root, rel); note(rel)
        if os.path.islink(full) or not inside(root, full):
            if os.path.lexists(full):
                skipped_symlinks.append({"file": full, "target": os.readlink(full) if os.path.islink(full) else "outside root"})
        elif os.path.isfile(full):
            entries += parse_table(full, has_user=True)
    for rel in SYSTEM_DIRS:
        full = os.path.join(root, rel); note(rel)
        if inside(root, full) and os.path.isdir(full):
            for name in sorted(os.listdir(full)):
                target = os.path.join(full, name)
                if os.path.islink(target):
                    skipped_symlinks.append({"file": target, "target": os.readlink(target)})
                elif os.path.isfile(target):
                    entries += parse_table(target, has_user=True)
    for rel in RUN_PARTS:
        full = os.path.join(root, rel); note(rel)
        if inside(root, full) and os.path.isdir(full):
            for name in sorted(os.listdir(full)):
                target = os.path.join(full, name)
                if os.path.islink(target):
                    skipped_symlinks.append({"file": target, "target": os.readlink(target)})
                elif os.path.isfile(target):
                    entries.append({"source": "run-parts", "file": target,
                                    "file_modified": mtime_of(target),
                                    "schedule": os.path.basename(rel).replace("cron.", "@"),
                                    "user": "root", "command": target, "at_reboot": False})
    for rel in SPOOLS:
        full = os.path.join(root, rel); note(rel)
        if inside(root, full) and os.path.isdir(full):
            for name in sorted(os.listdir(full)):
                target = os.path.join(full, name)
                if os.path.islink(target):
                    skipped_symlinks.append({"file": target, "target": os.readlink(target)})
                elif os.path.isfile(target):
                    for entry in parse_table(target, has_user=False):
                        entry["user"] = entry.get("user") or name
                        entries.append(entry)
    for rel in UNIT_DIRS:
        full = os.path.join(root, rel); note(rel)
        if inside(root, full) and os.path.isdir(full):
            for dirpath, _dirs, names in os.walk(full):
                for name in sorted(names):
                    if name.endswith(".timer"):
                        target = os.path.join(dirpath, name)
                        if os.path.islink(target):
                            skipped_symlinks.append({"file": target, "target": os.readlink(target)})
                        else:
                            entries.append(parse_unit(target))

    if pattern:
        entries = [e for e in entries
                   if pattern.search((e.get("command") or "") + " " + (e.get("unit") or ""))]
    print(json.dumps({
        "root": root,
        "locations_checked": looked,
        "entries": entries,
        "entry_count": len(entries),
        "at_reboot": sum(1 for e in entries if e.get("at_reboot")),
        "complete": not skipped_symlinks and not any("error" in entry for entry in entries),
        "skipped_symlinks": skipped_symlinks,
        "note": "file_modified is the thing to read first: a cron directory where every file "
                "dates from the build and one dates from last month answers the question on its "
                "own. An @reboot entry is persistence with no schedule. A systemd timer only says "
                "when; read the unit it names for what runs.",
    }, indent=2))


if __name__ == "__main__":
    main()
