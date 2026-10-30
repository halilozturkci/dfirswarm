---
id: filesystem/storage-lvm-luks
title: LVM and LUKS on evidence copies
when: Mapping logical volumes and their files, and LUKS headers, without activating or unlocking.
needs: []
tools: [linux_triage]
requires_host: [lvs, pvs, vgs, cryptsetup, luksdeinfo, target-fs, fls, icat]
---

Use only if the stack holds LVM or LUKS. Not for the storage graph itself (`filesystem/storage`) or for XFS, Btrfs and virtual disks.

- `lvs --readonly -a -o+devices,segtype,lv_time`, `pvs` and `vgs` map LVs to PV extents. Never activate an evidence volume group by its original name on a host that might already have that name; record the output of all three before any activation.
- Files of a logical volume, without activating anything: first read what the catalogue's linux-target files or `linux_triage` already parsed. A volume of one linear segment holding a file system The Sleuth Kit reads (ext) is read at the PV's data start plus the segment's start, in sectors: `fls -o <sectors>`, then `icat` by inode, which keeps the record's identity. Anything else (striped, thin, several segments, XFS, Btrfs) comes out by path in a job: `target-fs -q <image> cp <path> -o "$OUT/root<dir>"`, a copy named by path whose times are the extraction's.
- `cryptsetup luksDump --disable-locks <copy>` and `luksdeinfo <copy>` inventory the LUKS version, cipher and key slots without a key. First confirm the chosen reader supports that LUKS version and whether a detached header exists. Header inspection does not show who owns a key slot. Any authorised offline unlock takes supplied key material from a protected file in a sealed job run with `secret_output: true`, never from a command line or the ledger; if the encrypted-containers pack is loaded, its LUKS skill holds the detail.

Shows: how logical volumes map to physical extents, and a LUKS header's version, cipher and slots. Does not show: who owns a key slot, or that the volume is unlockable. Record: all three listings before activation, device filters, UUIDs, missing members, the reader and its LUKS support; for a file, the offset and inode, or the path copied.

Sensitive output: key material stays in a protected file, never in an argument, the ledger or a hash of it.
