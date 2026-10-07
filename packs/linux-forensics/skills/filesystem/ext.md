---
id: filesystem/ext
title: ext metadata, timestamps and recovery limits
when: Interpreting ext inode times or assessing deleted-file recovery with explicit limits.
needs: [evidence/imaging, filesystem/carving]
tools: [timestamp_decode]
requires_host: [istat, fls, icat, debugfs, dumpe2fs]
---

Record atime, mtime, ctime and the creation time (`crtime`) where the format stores them, with the inode number
and the filesystem features:

    atime  last access       mtime  contents changed
    ctime  inode changed     crtime creation: ext4 inodes large enough to hold the extra fields

On ext4, creation time and the nanosecond fields exist only where the inode is large enough to carry them, so
read the inode size first. Other filesystems keep a birth time as well, and GNU `stat` prints `Birth` when the
kernel and the filesystem expose it; do not make that display your authority. Read the inode directly:
`debugfs -R "stat <inode>" <volume-copy>` (debugfs opens read-only unless given `-w`: never give it `-w` on
evidence) and a recent `istat`, and decode a raw value with `timestamp_decode`. Keep the raw field, the
precision and the mount options that bear on it (`relatime`, `noatime`, `lazytime`): a delayed or skipped atime
update is not an event time.

**Reading the relationships.** A `crtime` later than `mtime` is consistent with a copy or an extraction that
kept the mtime, and equally with a restore, a clock error or edited metadata. It does not show which. A `ctime`
later than `mtime` is a lead and not a timestomping diagnosis: a permission, owner or link-count change moves
`ctime` legitimately, and `ctime` is set from the system clock, so it is not an immutable reference. ext has no
second kernel-written copy of the times to compare against (nothing like NTFS's `$FILE_NAME` set), so
corroborate with journal remnants, snapshots or backups, package records, audit events and independent logs.

**Deleted files.** Determine whether the filesystem has an internal journal, an external one or none, rather
than assuming the journal is inode 8: read the superblock (`dumpe2fs -h`) and its features. A journal
transaction can retain old copies of inode blocks, and `debugfs -R "logdump -i <inode>" <volume-copy>` is a way
into one; keep its complete output and errors. Wrapping, checkpointing, inode reuse and which journal features the
installed tool supports limit what that shows. Whether contents come back depends on fragmentation, overwrite,
discard and TRIM, thin provisioning and encryption; a surviving directory entry shows a name, not that its data
blocks are intact. `fls` lists names including deleted ones and `istat` shows an inode's extents. Unlinking may
leave the extent list cleared, so confirm the inode's state before assuming `icat` returns anything.

**Bounded negative.** State the routes and their scope separately, for example: "The inode named no usable
extents and no earlier mapping was found in the supplied journal with the stated tool and version. The contents
were not recovered by these routes. Carving, snapshots, backups and other copies were examined as listed, or
remain unexamined." Do not write that contents are unrecoverable on the strength of an inode and a journal
search; the next route is `filesystem/carving`.

**Does not show.** Who set a time, why, or that a value was changed: the filesystem stores a result, not the
operation. A time agrees with the other times of the same file, which are one actor's or one clock's.
