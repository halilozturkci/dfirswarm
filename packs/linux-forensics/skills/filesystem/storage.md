---
id: filesystem/storage
title: Linux storage layers, XFS, Btrfs and virtual disks
when: Identifying volume dependencies and parser coverage before examining a filesystem.
needs: [triage/system-profile, evidence/imaging]
tools: [image_layout, linux_triage]
requires_host: [target-query, lvs, pvs, vgs, cryptsetup, luksdeinfo, xfs_db, btrfs, qemu-img]
---

Do not call an unreadable partition damaged until you have identified the layer at its offset. Disks stack
E01, partition table, LVM physical volume, logical volume, filesystem, or partition, LUKS, LVM, filesystem.
Build a storage graph from container to filesystem and record every layer with its byte or sector offset, the
sector size, identifiers and member devices. RAID, striped or thin logical volumes and snapshots may not have
one linear offset: inventory every PV, the metadata areas, thin-pool dependencies, RAID members and any
external journal device, and name what is missing.

Start with `image_layout`. Where it names LVM, run `linux_triage` on the **complete acquired image set**.
It runs `target-query` (dissect.target), which reads E01, LVM and the filesystem without activating a volume
group or mounting evidence, and keeps each family's complete output. That is safer than letting the analysis
kernel discover an evidence PV. Its support is specific to the installed dissect.target version and the
target's features, so read each function's status; its output holds the bytes the selected functions
returned, not every artefact on the system.

For a copied volume that needs native metadata tools, work in an isolated worker with the acquired devices or
copies explicitly scoped and held read-only, with automatic activation prevented. Record the device filters,
UUIDs, missing members and the reporting command; `--readonly` is not a substitute for those controls.

- `lvs --readonly -a -o+devices,segtype,lv_time`, `pvs` and `vgs` map LVs to PV extents. Never activate an
  evidence volume group by its original name on a host that might already have that name; record the output
  of all three before any activation.
- `cryptsetup luksDump --disable-locks <copy>` and `luksdeinfo <copy>` inventory the LUKS version, cipher
  and key slots without a key. First confirm the chosen reader supports that LUKS version and whether a
  detached header exists. Header inspection does not show who owns a key slot. Any authorised offline unlock
  takes supplied key material from a protected file in a sealed job run with `secret_output: true`, never from
  a command line or the ledger; if the encrypted-containers pack is loaded, its LUKS skill holds the detail.
- XFS: `xfs_db -r -c sb -c p <volume-copy>` reads read-only. Record the filesystem and inode versions,
  enabled features, allocation groups and any external log or realtime device. An XFS log is recovery
  metadata, not a record of user actions. Do not run `xfs_repair` on evidence; even `-n` is a diagnostic.
- Btrfs: `btrfs inspect-internal dump-super -f <volume-copy>` records devices and the generation. Inventory every
  supplied device, subvolume, snapshot and root id: the default subvolume is not the whole filesystem. Reflinks
  and snapshots share extents, and a generation orders changes without being a wall-clock time. Never mount
  Btrfs read-write for convenience.
- If the installed tool cannot enumerate or extract what the question needs, record that as a coverage gap.

For VDI, VMDK, QCOW2 and VHD, inspect a stable acquired copy with `qemu-img info --output=json --backing-chain
<copy>` where the installed version supports it. Inventory and hash every backing file and relevant snapshot,
and treat backing paths as untrusted metadata: resolve them only to supplied objects inside the examination
scope. Use `--force-share` only when the need is stated, because it can read metadata that is changing under
you. Convert only to a new file under work, never in place; a conversion is one derived view and does not show
that every snapshot or backing layer was present. Keep the originals, the command, the errors and the mapping
from source to output.

**Does not show.** That a filesystem is intact because a superblock reads, or that a snapshot holds what a
live tree held. Absence of a layer from the listing is not absence from the disk.
