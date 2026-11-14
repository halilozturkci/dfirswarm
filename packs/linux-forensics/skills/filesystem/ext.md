---
id: filesystem/ext
title: ext metadata and timestamps
when: Interpreting ext inode times and their relationships, with explicit limits.
needs: []
card: timestamp_decode {"value": "<raw field>"} lists candidates under every epoch: the inode's format decides the clock, not the plausible reading. Read the inode size first: crtime and nanoseconds exist only in inodes large enough. Read the inode directly (debugfs read-only, never -w; istat) and keep raw field, precision and mount options (relatime, noatime, lazytime). crtime later than mtime fits a copy, extraction, restore, clock error or edit alike; ctime later than mtime is a lead, not timestomping. ext keeps no second kernel copy of the times. Does not show: who set a time, why, or that it was changed.
tools: [timestamp_decode]
requires_host: [debugfs, istat]
---

Use when you read ext inode times. Not for deleted-file recovery (`filesystem/ext-deleted`, only if a file's contents are the question) or for carving (base pack `filesystem/carving`).

Record atime, mtime, ctime and the creation time (`crtime`) where the format stores them, with the inode number and the filesystem features:

    atime  last access       mtime  contents changed
    ctime  inode changed     crtime creation: ext4 inodes large enough to hold the extra fields

On ext4, creation time and the nanosecond fields exist only where the inode is large enough to carry them, so read the inode size first. Other filesystems keep a birth time as well, and a file-listing utility can print it when the kernel and the filesystem expose it; do not make that display your authority. Read the inode directly: `debugfs -R "stat <inode>" <volume-copy>` (debugfs opens read-only unless given `-w`: never give it `-w` on evidence) and a recent `istat`, and decode a raw value with `timestamp_decode`. Keep the raw field, the precision and the mount options that bear on it (`relatime`, `noatime`, `lazytime`): a delayed or skipped atime update is not an event time.

**Reading the relationships.** A `crtime` later than `mtime` is consistent with a copy or an extraction that kept the mtime, and equally with a restore, a clock error or edited metadata. It does not show which. A `ctime` later than `mtime` is a lead and not a timestomping diagnosis: a permission, owner or link-count change moves `ctime` legitimately, and `ctime` is set from the system clock, so it is not an immutable reference. ext has no second kernel-written copy of the times to compare against (nothing like NTFS's `$FILE_NAME` set), so corroborate with journal remnants, snapshots or backups, package records, audit events and independent logs.

Shows: the times the inode stores. Does not show: who set a time, why, or that a value was changed: the filesystem stores a result, not the operation. A time agrees with the other times of the same file, which are one actor's or one clock's. Record: inode number, inode size, raw fields, precision, mount options.

Sensitive output: none beyond file names and paths.
