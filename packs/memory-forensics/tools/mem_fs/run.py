#!/usr/bin/env python3
"""Drive MemProcFS, which turns a memory image into a file tree.

MemProcFS is AGPL-3.0, the same licence as this harness, and this pack drives it
as a separate executable. Volatility remains at its own executable boundary
under its Volatility Software License 1.0; the skills invoke `vol` directly.

What the mount gives you: sys/proc for the process tree, py/ and misc/ for the
parsed artefacts, and a directory per process holding its modules, handles,
memory map and dumped regions. All of it is files, so every other tool in the
packs works on it unchanged.

Mounting needs FUSE, which a sandbox may not allow. When the mount fails the
reason is returned rather than swallowed, because "no framework was available"
is a legitimate line in a report and "the memory was examined and nothing was
found" is not.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def writable_mount(path):
    """Resolve a mount below this agent's work/<id>/ directory."""
    root = Path.cwd().resolve()
    dest = (root / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    if dest == root:
        fail("mount must be a child directory, not the run directory itself", mount=str(path))
    if root not in dest.parents:
        fail("mount must stay inside the run directory", mount=str(path))
    work = (root / "work").resolve()
    if dest == work or work not in dest.parents:
        fail("mount must be under your own work/<your id>/ directory", mount=str(path))
    relative = dest.relative_to(work)
    if len(relative.parts) < 2 or relative.parts[0] in ("", ".", ".."):
        fail("mount must name a directory inside work/<your id>/, not work/ itself",
             mount=str(path))
    return dest


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the memory image")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    mount_arg = args.get("mount")
    if not isinstance(mount_arg, str) or not mount_arg:
        fail("mount is required: a directory under your own work/<your id>/ to mount the image at "
             "(the rest of work/ is read-only in a VM)")
    mount = writable_mount(mount_arg)
    timeout = args.get("timeout_seconds", 300)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")

    binary = shutil.which("memprocfs")
    if not binary:
        fail("memprocfs is not on PATH",
             install="https://github.com/ufrisk/MemProcFS/releases",
             note="MemProcFS is AGPL-3.0, the same licence as this harness. Without it, "
                  "triage/no-framework says what a memory image still gives you, and the report "
                  "should say no framework was available rather than that nothing was found.")
    if mount.exists() and not mount.is_dir():
        fail("mount exists and is not a directory", mount=str(mount))
    mount.mkdir(parents=True, exist_ok=True)
    if any(mount.iterdir()):
        fail("mount directory must be empty; refusing stale files or an existing mount",
             mount=str(mount))

    requested = args.get("list") or "sys/proc/proc.txt"
    if not isinstance(requested, str) or not requested:
        fail("list must be a non-empty path inside the mount")
    target = (mount / requested).resolve()
    if target != mount and mount not in target.parents:
        fail("list must stay inside the mount", list=requested)

    argv = [binary, "-device", path, "-mount", str(mount)]
    stdout_file = tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace")
    stderr_file = tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace")
    try:
        # Files instead of pipes: MemProcFS can be verbose, and a full pipe
        # would otherwise deadlock before the mount becomes readable.
        proc = subprocess.Popen(argv, stdout=stdout_file, stderr=stderr_file, text=True)
    except OSError as exc:
        stdout_file.close()
        stderr_file.close()
        fail("memprocfs would not start", reason=str(exc), command=" ".join(argv))

    listing, content, problem = [], None, None
    try:
        waited = 0.0
        ready_marker = mount / "sys"
        while waited < timeout:
            # The requested directory may legitimately be empty. It does not
            # prove readiness by being empty (and `list: .` names the mount
            # root created above), so also require MemProcFS's `sys/` tree.
            if (os.path.ismount(mount) and ready_marker.is_dir() and
                    (target.is_file() or target.is_dir())):
                break
            if proc.poll() is not None:
                problem = "memprocfs exited before the mount appeared"
                break
            time.sleep(0.5)
            waited += 0.5
        else:
            problem = "the mount did not appear within %ds" % timeout
        if not problem:
            if target.is_dir():
                for child in sorted(target.iterdir(), key=lambda p: p.name):
                    listing.append({"name": child.name, "directory": child.is_dir()})
            else:
                content = target.read_bytes().decode("utf-8", "replace")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=20)

        # A successful return must not leave a FUSE mount holding evidence.
        if os.path.ismount(mount):
            unmount = shutil.which("fusermount3") or shutil.which("fusermount")
            if unmount:
                subprocess.run([unmount, "-u", str(mount)], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=20, check=False)
        if os.path.ismount(mount) and not problem:
            problem = "memprocfs stopped but the FUSE mount remained"

    stdout_file.seek(0)
    stderr_file.seek(0)
    stdout, stderr = stdout_file.read(), stderr_file.read()
    stdout_file.close()
    stderr_file.close()

    if problem:
        fail(problem, command=" ".join(argv), mount=str(mount),
             stderr=(stderr or "").strip(),
             note="Mounting needs FUSE, which a sandbox may refuse. That is a limit on the host, "
                  "not a finding about the evidence, and the report should say so.")

    print(json.dumps({
        "path": path,
        "mount": str(mount),
        "listed": requested,
        "entries": listing,
        "entry_count": len(listing),
        "content": content,
        "command": " ".join(argv),
        "note": "The mount is gone now: this tool starts MemProcFS, reads the listing and stops "
                "it, so nothing is left holding the evidence open. To work inside the tree, run "
                "memprocfs yourself with the command above and keep it running.",
    }, indent=2))


if __name__ == "__main__":
    main()
