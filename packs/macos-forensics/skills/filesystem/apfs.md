---
id: filesystem/apfs
title: APFS, snapshots, and what deletion means now
when: Establish acquired volumes, snapshots, timestamps and recovery limits.
needs: []
tools: [apfs_inventory]
requires_host: [fsapfsinfo]
---

Use when you establish which APFS container, volumes and snapshots were acquired. Not for deletion, recovery and timestamps (`filesystem/apfs-recovery`, only if the question asks what survives or when) or for encryption (`filesystem/apfs-encryption`, only if a volume is unreadable or FileVault is in question); base pack `evidence/imaging` covers the acquisition.

APFS is a container holding volumes that share one pool of space. Start from the layers the acquisition really has: physical stores, partitions, containers, volumes, volume groups and snapshots, with their identifiers, roles and offsets, and what could not be accessed.

**Which volume.** A System and Data pair, joined by firmlinks so a user sees one tree, is the usual arrangement and not the whole inventory. Say which acquired System and Data volumes belong together, how the acquisition or parser represented the firmlinks, and name the source volume and snapshot of every artefact you extract. The System volume does not hold the user's home; reading only it looks like an empty machine.

**Tools.** `fsapfsinfo` inspects the container and lists its volumes; `apfs_inventory` runs it and keeps its output, and gives no snapshot, extraction or unlock. The libfsapfs build declared here lists snapshots, Fusion drives and T2 encryption as unsupported: those are limits of that build, not findings about the evidence. What another APFS reader or a given Sleuth Kit build does depends on its version, so record the version and test it on the evidence rather than carry one build's limit to every reader.

**Snapshots.** Enumerate them per acquired volume with a tool whose support you have verified for this source, and record the parent volume UUID, the snapshot UUID and name, the transaction identifier and any creation metadata. The booted System snapshot is not a Data-volume or a Time Machine snapshot, and a System snapshot does not keep user data because the paths share one namespace. Read snapshots read-only, and never revert, delete or create one on the evidence. If the acquisition left snapshots out or the parser cannot list them, write "snapshot coverage unavailable", not "no snapshots".

**Does not show.** A logical extraction cannot show what survives in unacquired allocation space, inaccessible volumes or omitted snapshots: keep those outside any negative you write.

Record: container and volume identifiers, roles, volume groups, snapshot UUIDs and names, the reader and its version, and what could not be listed.
