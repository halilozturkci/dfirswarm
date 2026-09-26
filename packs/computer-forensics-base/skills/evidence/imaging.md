---
id: evidence/imaging
title: What you were handed, and the offset every other command needs
when: Before your first listing, and any time a command says the image has no file system.
needs: [evidence/verify]
tools: [image_layout, file_type]
requires_host: [mmls, fsstat, ewfinfo]
---

Almost every wasted hour in the measured runs started here: a command run
against the whole image instead of against a volume inside it, and a tool that
answered "cannot determine file system type" while the file system was sitting
2048 sectors in.

Run `image_layout` once per image. It reads the container, the partition table
and each volume's file system in one pass and hands back the offsets the rest of
your commands need. Put its output on the board so six agents do not each
rediscover it.

**Know what the container is.** `file_type` reads the first bytes and says what it is, and whether that agrees with the extension. An extension is a claim by whoever named the file.

    raw, dd, .img, .001      the bytes of the disk, nothing around them
    E01, Ex01, L01           EnCase: compressed, with an acquisition record
    AFF4, AFM                open forensic format, sometimes logical
    VHD, VHDX, VMDK, QCOW2   a virtual disk, with its own header and possibly snapshots
    a directory or a zip     a triage collection, not an image at all

The Sleuth Kit reads raw and E01 directly and may also open VHD/VHDX or other
virtual-disk containers through the libraries in the installed build. Try
`mmls` and `fsstat` first: when they succeed, their offsets are sectors in the
virtual disk and can be passed back to Sleuth Kit commands against that same
container. Use `qemu-img info` to inspect the container, and convert it
(`qemu-img convert -O raw`) or attach it only when the next tool cannot open it.
A **split E01** is one image: hand the tools the first segment and libewf finds
the rest. A **split raw** is not: list
every segment on the command line in order, or join them through `affuse` or
`ewfmount` first, because passing only the first piece silently gives you an
image that ends early. `ewfinfo` prints the E01's acquisition record: the
examiner, the machine, the time, and the digests the imager computed. Quote
those separately from your own.

**Then find the volume.** `mmls` prints the partition table in **sectors**, and
the Sleuth Kit's `-o` also takes **sectors**, so pass the number `mmls` printed
and do not multiply it yourself. Read the sector size rather than assuming it:
`mmls` says it in its own header (`Units are in N-byte sectors`) and `fsstat`
prints it per volume. A 4096-byte-sector disk breaks every offset computed for
512, and `-b` is how you tell the toolkit when it cannot work it out.

    mmls image.E01                      # the table, with the sector offset per slot
    fsstat -o 2048 image.E01            # confirm: type, cluster size, volume serial

Three shapes that are not a mistake and need a different move:

- **No partition table.** A single volume imaged on its own. Drop `-o`
  entirely, or pass `-o 0`. `mmls` failing here is the correct answer, not a
  broken image.
- **A Linux LVM member, or a Windows dynamic disk or Storage Space.** `mmls`
  names the slot but `fsstat` cannot read it, because the file system starts
  inside a logical volume whose metadata sits at the front of the partition. The
  offset you want is not in the partition table. Look for the file system
  magic yourself and derive the offset from where it is.
- **An unallocated gap large enough to hold a volume.** A deleted partition. Its
  file system may still be intact at the old offset; search for the boot
  signature in the gap.

**A triage collection is not an image.** KAPE, CyLR, Velociraptor and friends
hand you a directory tree of copied files. There is no partition table, no
inode, and `icat` has nothing to work on. Work on the files directly, cite them
by path and hash instead of by inode, and say in the report that the acquisition
was logical: a reviewer needs to know that unallocated space, slack and deleted
records were never in your hands.

Two host tools widen what you can open, where the host has them. `fsapfsinfo`
reads an APFS container, which the Sleuth Kit does not. `target-query` from
dissect reads E01, VMDK, QCOW and a triage collection behind one interface, with
a plugin per artefact family; it is AGPL-3.0, the same licence as this harness,
so there is nothing to weigh before using it.

If the volume is there and the toolkit still refuses it, it is probably
encrypted. See `filesystem/encrypted` before you conclude the image is damaged.
If it is not a disk at all, see `evidence/collections`.
