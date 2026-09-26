---
id: filesystem/apfs
title: APFS, snapshots, and what deletion means now
when: You need a file's true times, a previous state of the volume, or whether something is recoverable.
needs: [evidence/imaging]
tools: [timestamp_decode]
requires_host: [fsapfsinfo]
---

APFS is a container holding several volumes that share one pool of space. That
single fact changes three answers.

**There is more than one volume and you must say which you read.** A modern
machine has at least a sealed, read-only *system* volume and a writable *data*
volume, joined by firmlinks so a user sees one tree. `fsapfsinfo` lists the
container's volumes; the Sleuth Kit will not. Examining only the system volume
finds no user data at all and looks like an empty machine.

**Snapshots can preserve an earlier volume state**, but this image's
`libfsapfs` explicitly lists snapshots as unsupported. Do not use
`fsapfsinfo` to claim that snapshots are absent or to examine their contents.
Use an APFS-aware tool with documented snapshot support (or a macOS examination
host), record its version, and check snapshots before concluding that a deleted
file is gone.

**Deletion is more final than on NTFS.** APFS is copy-on-write with no file
table to leave a record behind: there is no `$MFT` entry to recover, and the
blocks are returned to the shared pool. What survives is the snapshot, the
FSEvents record of the delete (`artifacts/fsevents`), the path in a Spotlight
index, and carving — in that order of usefulness.

The four timestamps are stored in nanoseconds since the Unix epoch, not the
Apple epoch, which catches people who have just come from a plist. Creation
time is a first-class field here, unlike on ext.

The container may also be **encrypted per volume**, so one volume opens and
another does not (`filesystem/encrypted` in the base pack). This experimental
`libfsapfs` build does not support Fusion drives or T2 encryption; failure to
open those is a tool limitation, not evidence of corruption or absence.
