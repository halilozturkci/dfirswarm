---
id: evidence/imaging
title: Identify the container, storage layers and address space
when: Before listing a disk or volume, converting a container, or diagnosing an unreadable source.
needs: [evidence/verify]
tools: [image_layout, file_type]
requires_host: [mmls, fsstat, ewfinfo, img_stat, img_cat, qemu-img, fsapfsinfo, target-query]
---

Most wasted hours start here: a command run against the whole image instead of a
volume inside it, or an offset passed in the wrong unit. Offsets mean something
only inside a defined address space, so know which one you are in.

Run `image_layout` once per image and put its output on the board so peers do
not rediscover it. It names the container from its signature, reads an E01's
acquisition record (`ewfinfo`), runs `mmls` and `fsstat`, and returns each volume's offset in
sectors and bytes. Treat it as a probe. `partition_table` is true (mmls read
one), false (mmls ran and recognised none: that does not show there is none) or
`unknown` (mmls was missing, timed out or was refused, mmls failed without saying
why and `img_stat` does not open the image, or `img_stat` says the Sleuth Kit opened
a VHD, QCOW2 or other container as raw, so its offsets belong to the container's
bytes: convert or attach it first). The programs' whole
output is kept in files (`raw_outputs`). Preserve it for any layout you rely on.

**Know the container.** `file_type` reads the first bytes and says whether they
agree with the extension, which is only a claim by whoever named the file. An
identification from a signature is a candidate, not a validation.

    raw, dd, .img, .001      the bytes of a disk or volume, with nothing around them
    E01, Ex01, L01           EnCase: compressed, with an acquisition record; a physical or volume acquisition, or a logical one (L01)
    AFF, AFF4                two different formats: AFF4 is a zip-based container
    VHD, VHDX, VMDK, QCOW2   a virtual disk, with its own header, possibly a backing chain and snapshots
    AD1 (.ad1, .ad2, ...)    FTK Imager's logical image: chosen files and folders, no volume
    a directory or a zip     a collection, not an image

Inventory every segment, descriptor, extent and backing file before parsing, and
record which state you read. The Sleuth Kit opens raw and E01 directly and may
open other virtual-disk containers through the libraries of the installed build.
Try `mmls` and `fsstat` first: when they succeed, their offsets are sectors in
the virtual disk, valid against that container. Inspect a virtual disk with
`qemu-img info` (backing chain, snapshots). Convert it (`qemu-img convert -O
raw`) only when the next tool cannot open it, into a separate output, and record
the source layers, the state chosen, the tool, version and options, and the
output's size and digest. A split E01 is one image: give the first segment and
libewf finds the rest. A split raw set is not: the Sleuth Kit takes every segment
on the command line in order (passing the first piece alone gives an image that
ends early), and `image_layout` reads one path, so say which you used.

`img_stat` prints an image's size and format as the Sleuth Kit reads it, the bound
for any scan over all of it. `img_cat -s <first sector> -e <last sector>` writes a
range of the decoded image, so a raw scanner can read the disk's sectors instead
of the container's bytes (`filesystem/carving`).

**Then find the volume.** `mmls` prints the partition table in sectors, and the
Sleuth Kit's `-o` also takes sectors: pass the number `mmls` printed and do not
multiply it. Read the sector size rather than assuming it: `mmls` says it in its
header (`Units are in N-byte sectors`), `fsstat` prints it per volume, and `-b`
tells the toolkit when it cannot work it out. Pass the same `-b` to every command
on the image; `image_layout` does when you give it `sector_size`, and returns the
commands with it.

    mmls image.E01                      # the table, with the sector offset per slot
    fsstat -o 2048 image.E01            # confirm: type, cluster size, volume serial

Three shapes that are not a mistake and need another move:

- **No partition table.** A single volume imaged alone. Drop `-o`. `mmls` finding
  none is an answer about those bytes at that sector size, not a broken image.
- **A mapping layer: LVM, a Windows dynamic disk or Storage Space, RAID.** `mmls`
  names the slot but `fsstat` cannot read it, because the file system starts
  inside a logical volume whose metadata sits at the front of the member.
  Reconstruct the logical address space from that metadata and the members
  with a reader that supports the layer (if the Linux pack is loaded, its
  `filesystem/storage` is the method). A file system signature found inside a
  member is a candidate structure, not the extent mapping. Validate the geometry,
  the metadata's consistency and that files read before accepting a volume.
- **An unallocated gap.** It may never have held a partition. Describe a deleted
  partition only when other metadata supports it. Its content, not its size, is
  the evidence for or against.

**A logical collection is not an image.** A directory of copied files or an AD1
has no partition table to read: see `evidence/collections`.

`fsapfsinfo` reads an APFS container's structure; the build's own declaration says
snapshots, Fusion drives and T2-based encryption are not supported. Whether the
installed Sleuth Kit reads an APFS volume is a fact about its version and build:
try `fsstat` and record `mmls -V`. For APFS structure see the macOS pack's
`filesystem/apfs`, when it is loaded. `target-query` (dissect) opens E01, VMDK,
QCOW and a collection behind one interface with a plugin per artefact family;
check the version the image carries.

**An unreadable volume is an observation, not a diagnosis.** Record the exact
failure, and treat incomplete segments, wrong geometry, an unsupported format or
feature, a missing mapping layer or backing data, encryption and corruption as
separate hypotheses. Unreadability alone establishes none of them.
`filesystem/encrypted` says what a positive encryption indicator looks like.

**Does not show.** A partition table shows the layout as it was last written, not
what the disk held. A file system that `fsstat` parses is not shown intact,
complete or unencrypted at the file level.
