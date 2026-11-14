---
id: filesystem/apfs-recovery
title: APFS deletion, recovery limits and timestamps
when: Say what a deleted APFS file leaves behind, or read APFS file times.
needs: []
card: APFS file times are nanoseconds since the Unix epoch, not the Apple epoch: keep the raw integer beside the UTC value, and check that timestamp_decode keeps the fractions you need. Nanosecond storage is not clock accuracy, and the inode-change time is not a creation time. No $MFT does not mean no recoverable history. Does not show: that deleted content is gone or recoverable from one route, or an event's time from a changed time.
tools: [timestamp_decode]
requires_host: []
---

Use only if the question asks what survives a deletion on APFS or what its file times mean. Not for which volumes and snapshots were acquired (`filesystem/apfs`).

**Deletion.** APFS writes metadata copy-on-write, and it has filesystem records: that there is no NTFS-style `$MFT` does not mean there is no recoverable history. What can be recovered depends on retained snapshots and backups, surviving metadata and extents, block reuse, TRIM, encryption and what was acquired. A clone shares content without showing a user copied the file. Carved bytes need separate attribution and may carry no reliable name or time. Other places a deletion may show are the FSEvents record (`artifacts/fsevents`) and a Spotlight index entry; neither is ranked above the rest.

**Timestamps.** The creation, modification, inode-change and access times are stored in nanoseconds since the Unix epoch, not the Apple epoch: keep the raw integer beside the UTC value, and check that a conversion (`timestamp_decode`) keeps the fractions you need. Nanosecond storage is not clock accuracy. Copying, restoring and deliberate changes move them, and the inode-change time is not a creation time. Keep extended attributes, resource forks, compression and links, or record that they were lost.

Shows: the stored times and the metadata the acquisition kept. Does not show: that deleted content is gone or recoverable from one route, who copied a cloned file, or the time of an event from a changed time.
Record: the raw integer and UTC value of each time, the snapshots and backups checked, and what was lost (extended attributes, forks, compression, links).
