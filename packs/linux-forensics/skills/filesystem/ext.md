---
id: filesystem/ext
title: ext4 timestamps, deleted inodes, and what Linux does not keep
when: You need a file's true times on ext, or whether something deleted is recoverable.
needs: [evidence/imaging]
tools: [timestamp_decode]
requires_host: [istat, fls, debugfs]
---

ext4 keeps four times in the inode and the fourth is the one people miss:

    atime  accessed        mtime  contents changed
    ctime  inode changed   crtime CREATED — ext4 only, and no POSIX tool shows it

POSIX does not define a creation time. Modern GNU `stat` may print `Birth` when
the kernel and file system expose it, while older tools print `-`; do not make
that display your authority. `debugfs -R "stat <inode>" <volume-copy>` and a
recent `istat` read ext's inode field directly. A file whose `crtime` is later than its
`mtime` was copied, not created in place, and that distinction has decided
cases.

**ext has no `$FILE_NAME` equivalent.** There is no second, kernel-written copy
of the times to compare against, so the NTFS trick of catching a timestomp by
disagreement does not exist here. `touch -d` changes atime and mtime and leaves
`ctime` at the moment of the change — so a file whose `ctime` is much later than
its `mtime` was touched by something, and that is the closest Linux gets to the
tell. It is an indicator, not proof.

**Deletion on ext4 is often more destructive than on NTFS.** Unlinking may zero
extent pointers when the inode is released, so confirm the inode state rather
than assuming `icat` can recover it. What may survive:

- The **journal** (`$journal`, inode 8). It holds old copies of inode blocks,
  which is where a deleted file's extent list is often still intact. `debugfs
  -R "logdump -i <inode>"` is the way in, and `jls`/`jcat` from the Sleuth Kit
  read the same structure.
- **Carving**, because the data blocks are usually untouched until reused. See
  `filesystem/carving` in the base pack.
- The **directory entry** in the parent block, which keeps the name in the gap
  left behind by the deleted record.

Say plainly which of these you tried. "The inode's extents were cleared on
delete and the journal did not hold an older copy, so the contents are not
recoverable" is a complete answer.
