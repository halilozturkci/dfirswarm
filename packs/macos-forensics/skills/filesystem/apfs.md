---
id: filesystem/apfs
title: APFS, snapshots, and what deletion means now
when: Establish acquired volumes, snapshots, timestamps and recovery limits.
needs: [evidence/imaging]
tools: [timestamp_decode]
requires_host: [fsapfsinfo]
mentions: [fvdeinfo]
---

APFS is a container holding volumes that share one pool of space. Start from the layers
the acquisition really has: physical stores, partitions, containers, volumes, volume
groups and snapshots, with their identifiers, roles and offsets, and what could not be
accessed.

**Which volume.** A System and Data pair, joined by firmlinks so a user sees one tree,
is the usual arrangement and not the whole inventory. Say which acquired System and
Data volumes belong together, how the acquisition or parser represented the firmlinks,
and name the source volume and snapshot of every artefact you extract. The System
volume does not hold the user's home; reading only it looks like an empty machine.

**Tools.** `fsapfsinfo` inspects the container and lists its volumes. The libfsapfs
build declared here lists snapshots, Fusion drives and T2 encryption as unsupported:
those are limits of that build, not findings about the evidence. What another APFS
reader or a given Sleuth Kit build does depends on its version, so record the version
and test it on the evidence rather than carry one build's limit to every reader.

**Snapshots.** Enumerate them per acquired volume with a tool whose support you have
verified for this source, and record the parent volume UUID, the snapshot UUID and
name, the transaction identifier and any creation metadata. The booted System snapshot
is not a Data-volume or a Time Machine snapshot, and a System snapshot does not keep
user data because the paths share one namespace. Read snapshots read-only, and never
revert, delete or create one on the evidence. If the acquisition left snapshots out or
the parser cannot list them, write "snapshot coverage unavailable", not "no snapshots".

**Deletion.** APFS writes metadata copy-on-write, and it has filesystem records: that
there is no NTFS-style `$MFT` does not mean there is no recoverable history. What can be
recovered depends on retained snapshots and backups, surviving metadata and extents,
block reuse, TRIM, encryption and what was acquired. A clone shares content without
showing a user copied the file. Carved bytes need separate attribution and may carry no
reliable name or time. Other places a deletion may show are the FSEvents record
(`artifacts/fsevents`) and a Spotlight index entry; neither is ranked above the rest.

**Timestamps.** The creation, modification, inode-change and access times are stored in
nanoseconds since the Unix epoch, not the Apple epoch: keep the raw integer beside the
UTC value, and check that a conversion (`timestamp_decode`) keeps the fractions you
need. Nanosecond storage is not clock accuracy. Copying, restoring and deliberate
changes move them, and the inode-change time is not a creation time. Keep extended
attributes, resource forks, compression and links, or record that they were lost.

**Encryption.** Separate legacy Core Storage FileVault from an encrypted APFS volume,
and Intel without a T2 chip from Intel with one and from Apple silicon. An unreadable
volume or a FileVault preference does not show the key state, and hardware-bound
encryption can leave a raw acquisition unreadable even with some credentials in hand.
`fvdeinfo` is for Core Storage; it is not assumed to read APFS. Use an acquisition and
parser documented for the hardware, filesystem and encryption state; if the
encrypted-containers pack is loaded, its skill index says which skill carries the
FileVault route. Any step that handles credentials is a `secret_output` job inside the
case's authority and offline.

**Does not show.** A logical extraction cannot show what survives in unacquired
allocation space, inaccessible volumes or omitted snapshots: keep those outside any
negative you write.
