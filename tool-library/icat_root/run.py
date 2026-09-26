#!/usr/bin/env python3
"""Extract an inode from the root EXT4 at offset 503808. Args from JSON stdin."""
import json
import os
import subprocess
import sys
from pathlib import Path

# The case this was written for, kept as the default so the calls that exist
# still work. A tool that can only ever read one image is a tool the next run
# has to write again, which is the whole argument against the library.
DEFAULT_IMAGE = "inputs/Webserver.E01"
DEFAULT_OFFSET = "503808"


def fail(msg, **extra):
    print(json.dumps({"error": msg, **extra}))
    sys.exit(1)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    return dest


d = json.load(sys.stdin)
inode = d.get("inode")
if inode is None:
    fail("need inode")
output = d.get("output") or ""
IMAGE = d.get("image") or DEFAULT_IMAGE
OFFSET = str(d.get("offset", DEFAULT_OFFSET))
dest = resolve_output(str(output)) if output else None
if not os.path.isfile(IMAGE):
    fail("image not found", image=IMAGE)
r = subprocess.run(["icat", "-o", OFFSET, IMAGE, str(inode)], capture_output=True)
if r.returncode != 0:
    # Exiting on icat's code alone left the agent a failure with no reason:
    # nothing on stdout, nothing on stderr, and no way to tell a bad inode
    # from a missing image.
    fail(
        "icat failed",
        inode=inode,
        image=IMAGE,
        offset=OFFSET,
        exit_code=r.returncode,
        stderr=r.stderr.decode("utf-8", "replace").strip(),
    )
if dest is not None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(r.stdout)
    print(json.dumps({"inode": inode, "output": str(output), "size": len(r.stdout)}))
else:
    sys.stdout.buffer.write(r.stdout)
