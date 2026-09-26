#!/usr/bin/env python3
"""List the volume shadow copies on an image.

A shadow copy is a second, older state of the same volume, kept by Windows
itself. It holds the registry hives, the event logs and the files as they were
at the moment the snapshot was taken, which is how a file deleted last week is
still readable today and how a Run key that has since been cleaned is still
there to be found.

The unit trap is worth naming once: mmls and the Sleuth Kit's -o work in
**sectors**, and vshadowinfo's -o works in **bytes**. Passing one where the
other belongs is why this returns "unable to open volume" on an image that is
perfectly sound, so this tool takes bytes and says so in its own output.
"""
import json
import os
import re
import shutil
import subprocess
import sys

TIMEOUT = 240
STORE = re.compile(r"^Store:\s*(\d+)\s*$")
FIELD = re.compile(r"^\s+(.+?)\s*:\s*(.*\S)\s*$")


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def key_of(label):
    return re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))

    image = args.get("image")
    if not isinstance(image, str) or not image:
        fail("image is required")
    if not os.path.isfile(image):
        fail("no such image", image=image)

    offset = args.get("offset")
    if offset is not None and (not isinstance(offset, int) or isinstance(offset, bool) or offset < 0):
        fail("offset must be a byte offset, not a sector offset", offset=args.get("offset"))

    # Where a store would be mounted: the seat's own directory. The rest of
    # work/ is read-only in a VM, and a mount is that VM's alone either way.
    mount_dir = args.get("mount_dir")
    if mount_dir is None:
        mount_dir = "work/%s/vss" % (os.environ.get("AGENT_ID") or "<your id>")
    elif not isinstance(mount_dir, str) or not mount_dir:
        fail("mount_dir must be a directory path", mount_dir=mount_dir)
    mount_dir = mount_dir.rstrip("/")

    if not shutil.which("vshadowinfo"):
        fail("vshadowinfo is not on PATH",
             install="brew install libvshadow, or apt-get install -y libvshadow-utils")

    argv = ["vshadowinfo"]
    if offset is not None:
        argv += ["-o", str(offset)]
    argv.append(image)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        fail("vshadowinfo timed out", after_seconds=TIMEOUT, command=" ".join(argv))

    text = proc.stdout
    stderr = proc.stderr.strip()
    stores, current = [], None
    for line in text.splitlines():
        m = STORE.match(line)
        if m:
            current = {"store": int(m.group(1))}
            stores.append(current)
            continue
        if current is None:
            continue
        m = FIELD.match(line)
        if m:
            current[key_of(m.group(1))] = m.group(2)

    claimed = None
    m = re.search(r"Number of stores:\s*(\d+)", text)
    if m:
        claimed = int(m.group(1))

    mountable = shutil.which("vshadowmount") is not None
    for store in stores:
        store["mount_with"] = "mkdir -p %s && vshadowmount %s%s %s/  # then %s/vss%d" % (
            mount_dir, ("-o %d " % offset) if offset is not None else "", image, mount_dir, mount_dir, store["store"])

    out = {
        "image": image,
        "offset_bytes": offset,
        "mount_dir": mount_dir,
        "stores": stores,
        "store_count": len(stores),
        "stores_claimed": claimed,
        "vshadowmount_present": mountable,
        "exit_code": proc.returncode,
    }
    if stderr:
        out["vshadowinfo_said"] = stderr.splitlines()[-1]
    if not stores:
        out["note"] = ("No shadow-copy stores were observed on this volume. Absence alone does "
                       "not establish deletion or anti-forensics: correlate the host's age and "
                       "configuration with event logs, command history and free-space evidence "
                       "before attributing why no stores are present.")
    elif not mountable:
        out["note"] = ("vshadowmount is not installed, so the stores cannot be opened here. "
                       "The list above, with the creation times, still belongs in the timeline.")
    else:
        out["note"] = ("Mount a store, then run the ordinary toolkit against %s/vssN as if "
                       "it were a volume. The mount is yours alone: copy what you derive from it into "
                       "your own directory and record it. A hive or a log read there is the state at "
                       "the store's creation time, not at acquisition: cite both times." % mount_dir)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
