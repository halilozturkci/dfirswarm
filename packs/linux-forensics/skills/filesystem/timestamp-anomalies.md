---
id: filesystem/timestamp-anomalies
title: ext4, XFS and Btrfs time fields
when: A file time looks wrong, or you must say what produced it.
needs: [timeline/clocks]
tools: [timestamp_decode]
requires_host: [debugfs, istat, xfs_db, btrfs, target-fs, icat]
---

Use when a time on an ext4, XFS or Btrfs volume is in question. Not for ext inode relationships and deletion (`filesystem/ext`, `filesystem/ext-deleted`) or for ordering events across clocks (`timeline/clocks`).

Name the filesystem, its feature flags and the tool that printed each time before you read one. As of the kernel's own documents: ext4 keeps access, change and modification times as 32-bit seconds with an extra field of 30 bits of nanoseconds and two epoch bits, and a creation time only in inodes of 256 bytes or more; XFS keeps nanoseconds and a creation time in the version 5 inode, and a `bigtime` feature widens the range; Btrfs keeps access, change, modification and creation times with nanoseconds. Read the fields with `debugfs` (`stat`), `istat`, `xfs_db` or `btrfs inspect-internal`, and decode a raw value with `timestamp_decode` rather than by hand. A nanosecond field is precision, not accuracy: the clock that wrote it may have been wrong, and mount options (`noatime`, `relatime`, `lazytime`) decide whether an access time was written at all.

A time that looks forged has competing explanations, and each needs its own evidence before you prefer one:
- copying or extraction: a copy made with `target-fs` or `icat` carries the time of the extraction on the copy, not the evidence's;
- a package install, an archive unpacked with its times, a restore from backup, a snapshot or reflink, an overlay copy-up;
- a clock correction or a wrong clock at the time (compare `triage/clocks-boots`);
- a tool that sets times (`touch -d`, `utimes`) or edits an inode directly; the change time follows the clock and is not set by `utimes`, so a modification time later than the change time, or a change time before the creation time, is a lead.

Compare the same file's times across the inode, the directory, the journal and other logs before you call a time wrong, and say which fields you compared.

Shows: the times the filesystem stored and how they relate to each other. Does not show: which program wrote them, that they were changed on purpose, or that they are true. Record: filesystem and feature flags, the tool and command, raw values beside decoded ones, the explanations you ruled out and the evidence for each.

Sensitive output: none beyond file names; cite the inode and the path.
