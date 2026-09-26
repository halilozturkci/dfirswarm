---
id: filesystem/storage
title: LVM, LUKS, XFS, Btrfs and virtual disks without mounting evidence
when: A Linux partition is a volume manager or encrypted container, or the file system is not ext.
needs: [triage/system-profile, evidence/imaging]
tools: [image_layout, linux_triage]
requires_host: [target-query, lvs, cryptsetup, luksdeinfo, xfs_db, btrfs, qemu-img]
---

Do not call an unreadable partition damaged until you have identified the layer
at its offset. Linux disks commonly stack E01 -> partition table -> LVM PV -> LV
-> ext4/XFS, or partition -> LUKS -> LVM -> file system. Record every layer and
its byte or sector offset.

Start with `image_layout`. If it names `Linux Logical Volume Manager`, run
`linux_triage` on the **whole image** first. `dissect.target` reads E01, LVM and
the file system without activating a volume group or mounting evidence, and
keeps each complete artefact family in a named JSONL file. This is safer than
letting the analysis kernel discover an evidence PV.

When a copied partition or logical-volume image needs native metadata tools:

- `lvs --readonly -a -o+devices,segtype,lv_time` maps LVs to PV extents. Never
  activate an evidence VG by its original name on a host that might already
  have that VG; work in the throwaway VM and record `pvs`, `vgs` and `lvs`
  output before any activation.
- `cryptsetup luksDump --disable-locks <copy>` and `luksdeinfo <copy>` inventory
  the LUKS version, cipher and key slots without a key. Opening it is a separate
  step and needs a known key; never try guesses against the only copy.
- `xfs_db -r -c sb -c p <volume-copy>` reads XFS metadata in read-only mode.
  Do not run `xfs_repair` on evidence; even `-n` is a diagnostic, not a parser.
- `btrfs inspect-internal dump-super -f <volume-copy>` records devices and the
  generation. Enumerate subvolumes and snapshots: the default subvolume alone
  is not the whole file system. Do not mount Btrfs read-write for convenience.

For VDI/VMDK/QCOW2/VHD, first run `qemu-img info --force-share`; it identifies
the container and backing chain without conversion. A backing file is evidence
too. Convert only to a new file under work, never in place, record the command
and hashes, then analyse the converted bytes as a derived artefact. A successful
conversion proves readability, not that every snapshot or backing layer was
present.
