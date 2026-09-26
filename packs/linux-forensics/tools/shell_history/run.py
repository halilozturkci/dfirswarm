#!/usr/bin/env python3
"""Collect the shell histories, and keep the order the shell wrote them in.

A history file is not a log. It is written by the shell into the user's own home
directory, so clearing /var/log does nothing to it, and an operator who cleaned
the logs has usually left this untouched. On more than one published case it was
the only surviving record of what was typed.

Two formats carry time and most do not:

    zsh, EXTENDED_HISTORY   : <epoch>:<elapsed>;<command>
    bash, HISTTIMEFORMAT    a #<epoch> line before each command
    everything else         order only, and order is still evidence

Order without time is worth saying out loud rather than leaving implicit: the
commands are in the sequence the shell appended them, and the file's own mtime
brackets the last one. Where the shell was killed rather than exited, the last
session may never have been written at all.
"""
import datetime
import json
import os
import re
import sys

NAMES = {
    ".bash_history": "bash", ".zsh_history": "zsh", ".sh_history": "sh",
    ".ash_history": "ash", ".history": "shell", ".python_history": "python",
    ".mysql_history": "mysql", ".psql_history": "psql", ".rediscli_history": "redis",
    ".node_repl_history": "node", ".lesshst": "less",
}
ZSH = re.compile(r"^:\s*(\d+):(\d+);(.*)$")
BASH_STAMP = re.compile(r"^#(\d{9,})$")


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def when(epoch):
    try:
        return datetime.datetime.fromtimestamp(
            int(epoch), datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


def read_history(path, shell):
    out, pending = [], None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for index, line in enumerate(fh):
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                found = ZSH.match(line)
                if found:
                    out.append({"index": len(out), "time": when(found.group(1)),
                                "elapsed_seconds": int(found.group(2)),
                                "command": found.group(3)})
                    continue
                found = BASH_STAMP.match(line)
                if found:
                    pending = when(found.group(1))
                    continue
                out.append({"index": len(out), "time": pending, "command": line})
                pending = None
    except OSError as exc:
        return None, str(exc)
    return out, None


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    root = args.get("root")
    if not isinstance(root, str) or not root:
        fail("root is required: a home directory or an extracted file system root")
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
    only_user = args.get("user")

    files, commands, skipped_symlinks = [], [], []
    for dirpath, dirs, names in os.walk(root):
        for name in dirs:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                skipped_symlinks.append({"file": full, "target": os.readlink(full)})
        dirs[:] = [d for d in dirs
                   if d not in ("proc", "sys", "dev") and not os.path.islink(os.path.join(dirpath, d))]
        for name in sorted(names):
            shell = NAMES.get(name)
            if not shell:
                continue
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                skipped_symlinks.append({"file": full, "target": os.readlink(full)})
                continue
            owner = os.path.basename(dirpath)
            if only_user and owner != only_user:
                continue
            entries, problem = read_history(full, shell)
            try:
                mtime = datetime.datetime.fromtimestamp(
                    os.path.getmtime(full), datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            except OSError:
                mtime = None
            record = {"file": full, "shell": shell, "home": dirpath, "user": owner,
                      "last_written": mtime,
                      "commands": 0 if entries is None else len(entries)}
            if problem:
                record["error"] = problem
            files.append(record)
            for entry in entries or []:
                if pattern and not pattern.search(entry["command"]):
                    continue
                commands.append({**entry, "user": owner, "shell": shell, "file": full})

    timed = sum(1 for c in commands if c.get("time"))
    print(json.dumps({
        "root": root,
        "files": files,
        "file_count": len(files),
        "commands": commands,
        "command_count": len(commands),
        "with_timestamps": timed,
        "complete": not skipped_symlinks and not any("error" in entry for entry in files),
        "skipped_symlinks": skipped_symlinks,
        "note": "Commands are in the order the shell appended them. Where a command has no time, "
                "the shell was not configured to record one, and order is all you have — say so "
                "rather than implying a sequence in time. The file's last_written brackets the "
                "final command; a session killed rather than exited may never have been written.",
    }, indent=2))


if __name__ == "__main__":
    main()
