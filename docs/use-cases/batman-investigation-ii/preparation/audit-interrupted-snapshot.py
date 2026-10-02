#!/usr/bin/env python3
"""Read-only comparison of an interrupted run and its private APFS clone.

No agent, registry, VM, custody verdict, or original run file is changed.
The full inventory is private: filenames/digests can themselves identify
sensitive evidence objects. Only its commitment and totals are published.
"""
import argparse
import hashlib
import json
import os
import stat
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def utc():
    return datetime.now(timezone.utc).isoformat()


def walk(root):
    result = {}
    def visit(base):
        with os.scandir(base) as children:
            for child in sorted(children, key=lambda c: c.name):
                s = child.stat(follow_symlinks=False)
                p = Path(child.path)
                rel = p.relative_to(root).as_posix()
                if stat.S_ISDIR(s.st_mode):
                    visit(p)
                elif stat.S_ISREG(s.st_mode):
                    result[rel] = ("file", s)
                elif stat.S_ISLNK(s.st_mode):
                    result[rel] = ("symlink", os.readlink(p))
                else:
                    result[rel] = ("special", stat.S_IFMT(s.st_mode))
    visit(root)
    return result


def digest(p):
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    h = hashlib.sha256()
    with os.fdopen(fd, "rb") as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("nonregular file")
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(chunk)
        after = os.fstat(f.fileno())
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("source changed while hashing")
    return h.hexdigest(), before


def main():
    a = argparse.ArgumentParser()
    a.add_argument("source", type=Path)
    a.add_argument("snapshot", type=Path)
    a.add_argument("private_manifest", type=Path)
    a.add_argument("summary", type=Path)
    args = a.parse_args()
    began = utc()
    src = walk(args.source)
    snap = walk(args.snapshot)
    regular = {p for p, x in src.items() if x[0] == "file"}
    copied = {p for p, x in snap.items() if x[0] == "file"}
    if regular != copied:
        raise ValueError(f"file inventory mismatch: missing={len(regular-copied)} extra={len(copied-regular)}")
    counts, sizes = Counter(), Counter()
    manifest_hash = hashlib.sha256()
    total = 0
    args.private_manifest.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.private_manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        for n, p in enumerate(sorted(regular), 1):
            sha, s = digest(args.source / p)
            copied_sha, cs = digest(args.snapshot / p)
            if sha != copied_sha or s.st_size != cs.st_size:
                raise ValueError("snapshot differs at " + p)
            row = {"path": p, "bytes": s.st_size, "sha256": sha,
                   "source_mtime_ns": s.st_mtime_ns, "source_mode": stat.S_IMODE(s.st_mode)}
            b = (json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n").encode()
            out.write(b)
            manifest_hash.update(b)
            key = p.split("/")[0]
            counts[key] += 1
            sizes[key] += s.st_size
            total += s.st_size
            if n % 20000 == 0:
                print(json.dumps({"verified_files": n, "total_files": len(regular)}), flush=True)
        out.flush()
        os.fsync(out.fileno())
    final = walk(args.source)
    # Detect changes after individual reads, including added/deleted paths.
    unchanged = set(final) == set(src)
    for p in regular:
        x, y = src[p][1], final[p][1]
        unchanged &= (x.st_size, x.st_mtime_ns, x.st_ino) == (y.st_size, y.st_mtime_ns, y.st_ino)
    links = []
    for p, v in src.items():
        if v[0] == "symlink":
            if snap.get(p) != v:
                raise ValueError("symlink metadata mismatch")
            links.append({"path": p, "target": v[1], "followed": False})
    if not unchanged:
        raise ValueError("original run changed during observer acquisition")
    summary = {"v": 1, "run": "s421201", "kind": "observer snapshot of interrupted run; not successful final custody",
               "started_at": began, "completed_at": utc(), "source": str(args.source),
               "private_snapshot": str(args.snapshot), "private_manifest": str(args.private_manifest),
               "private_manifest_sha256": manifest_hash.hexdigest(), "regular_files": len(regular),
               "source_bytes": total, "all_regular_files_byte_exact": True,
               "source_inventory_and_stats_unchanged": True, "symlinks": links,
               "nonregular_not_copied": [{"path": p, "type": "socket" if v[1] == stat.S_IFSOCK else "special"}
                                         for p, v in src.items() if v[0] == "special"],
               "categories": {k: {"files": counts[k], "bytes": sizes[k]} for k in sorted(counts)},
               "original_inputs_followed_or_copied": False, "vm_disks_copied": False,
               "auth_secrets_in_git": False, "solution_read": False,
               "formal_stop_custody_present": (args.source / "custody.json").is_file(),
               "all14_complete": False, "flag_verified": False}
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"complete": True, "files": len(regular), "bytes": total,
                      "manifest_sha256": manifest_hash.hexdigest()}), flush=True)


if __name__ == "__main__":
    main()
