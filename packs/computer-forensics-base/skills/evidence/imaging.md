---
id: evidence/imaging
title: Find the volume and its offset
when: Before listing a disk or volume, or diagnosing an unreadable source.
card: image_layout {"image": "<image>"} once per image: offsets are in sectors, so pass the number mmls printed to -o without multiplying, and the same sector size to every command. partition_table false is mmls finding none at that sector size, unknown is no answer. Does not show: what the disk held, or that a file system fsstat parses is intact.
needs: []
tools: [image_layout]
requires_host: [mmls, fsstat, ewfinfo, img_stat]
---

Use when you must list a disk or volume, or an image will not read. Not for the container formats, virtual disks, split sets, mapping layers and APFS (`filesystem/layers`).

Offsets mean something only inside a defined address space: know which one you are in (the whole image, or a volume inside it).

Run `image_layout` once per image and put its output on the board. It names the container, reads an E01's acquisition record (`ewfinfo`), runs `mmls` and `fsstat`, and returns each volume's offset in sectors and bytes. Treat it as a probe: `partition_table` is true (mmls read one), false (mmls ran and recognised none: that does not show there is none) or `unknown` (mmls gave no answer, or `img_stat` says the Sleuth Kit opened a VHD, QCOW2 or other container as raw, whose offsets are the container's: convert or attach it first, `filesystem/layers`). Keep `raw_outputs` for any layout you rely on.

**Then find the volume.** `mmls` prints the partition table in sectors, and the Sleuth Kit's `-o` also takes sectors: pass the number `mmls` printed and do not multiply it. Read the sector size, never assume it: `mmls` says it in its header, `fsstat` per volume; `-b` tells the toolkit when it cannot work it out. Pass the same `-b` to every command on the image; `image_layout` does when you give it `sector_size`, and returns the commands with it.

    mmls image.E01                      # the table, with the sector offset per slot
    fsstat -o 2048 image.E01            # confirm: type, cluster size, volume serial

Shapes that are not a mistake and need another move:

- **No partition table.** A single volume imaged alone. Drop `-o`. `mmls` finding none is an answer about those bytes at that sector size, not a broken image.
- **A mapping layer** (LVM, a dynamic disk, a Storage Space, RAID): `mmls` names the slot but `fsstat` cannot read it. Do not rebuild it from a signature: `filesystem/layers-mapping`.
- **An unallocated gap.** It may never have held a partition. Describe a deleted partition only when other metadata supports it.

**A logical collection is not an image.** A directory of copied files or an AD1 has no partition table to read: see `evidence/collections`.

**An unreadable volume is an observation, not a diagnosis.** Record the exact failure, and treat incomplete segments, wrong geometry, an unsupported format or feature, a missing mapping layer or backing data, encryption and corruption as separate hypotheses. Unreadability alone establishes none of them. `filesystem/encrypted` says what a positive encryption indicator looks like.

**Does not show.** A partition table shows the layout as it was last written, not what the disk held. A file system that `fsstat` parses is not shown intact, complete or unencrypted at the file level.
