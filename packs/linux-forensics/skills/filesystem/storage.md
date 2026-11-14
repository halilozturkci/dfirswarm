---
id: filesystem/storage
title: Linux storage layers and parser coverage
when: Identifying volume dependencies and parser coverage before examining a filesystem.
needs: []
card: image_layout {"image": "<image>"} first: identify the layer at an offset before calling a partition damaged; table: false is no proof there is none. Where it names LVM, run linux_triage {"source": "<complete image set>", "out_dir": "work/<your id>/<name>"} as a secret_output job: it reads E01, LVM and the file system without activating or mounting; read each function's status. RAID, striped, thin and snapshot volumes have no single offset: name missing members. Does not show: an intact file system because a superblock reads; a layer absent from the listing is not absent from the disk.
tools: [image_layout, linux_triage]
requires_host: [target-query]
---

Use when a partition or volume will not read, or before examining a filesystem. Not for LVM and LUKS commands (`filesystem/storage-lvm-luks`), XFS, Btrfs or virtual disks (`filesystem/storage-xfs-btrfs-virtual`); open those only if the layer is one of them.

Do not call an unreadable partition damaged until you have identified the layer at its offset. Disks stack E01, partition table, LVM physical volume, logical volume, filesystem, or partition, LUKS, LVM, filesystem. Build a storage graph from container to filesystem and record every layer with its byte or sector offset, the sector size, identifiers and member devices. RAID, striped or thin logical volumes and snapshots may not have one linear offset: inventory every PV, the metadata areas, thin-pool dependencies, RAID members and any external journal device, and name what is missing.

Start with `image_layout`. Where it names LVM, run `linux_triage` on the **complete acquired image set**. It runs `target-query` (dissect.target), which reads E01, LVM and the filesystem without activating a volume group or mounting evidence, and keeps each family's complete output. That is safer than letting the analysis kernel discover an evidence PV. Its support is specific to the installed dissect.target version and the target's features, so read each function's status; its output holds the bytes the selected functions returned, not every artefact on the system.

For a copied volume that needs native metadata tools, work in an isolated worker with the acquired devices or copies explicitly scoped and held read-only, with automatic activation prevented. Record the device filters, UUIDs, missing members and the reporting command; `--readonly` is not a substitute for those controls. If the installed tool cannot enumerate or extract what the question needs, record that as a coverage gap.

Shows: the layers and the parser coverage you established. Does not show: that a filesystem is intact because a superblock reads, or that a snapshot holds what a live tree held. Absence of a layer from the listing is not absence from the disk. Record: each layer's offset, sector size, identifiers, members, the tool versions and function statuses.

Sensitive output: `linux_triage` keeps each family's complete output, which can hold command lines, authentication lines and container logs: run it as a job with `secret_output: true`, read the files by path and cite the file and line. Key material for an unlock stays in a protected file, never in an argument, the ledger or a hash.
