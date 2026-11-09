---
id: filesystem/layers-mapping
title: Mapping layers and APFS
when: mmls names the slot but fsstat cannot read it.
needs: []
tools: [layer_describe]
requires_host: [mmls, fsstat, fsapfsinfo, target-query]
---

Use only if `filesystem/layers` sends you here: the file system starts inside a logical volume (LVM, dynamic disk, Storage Space, RAID member) or the container is APFS. Not for the container, backing-chain and snapshot rules (`filesystem/layers`).

**Mapping layers.** `mmls` names the slot but `fsstat` cannot read it: the file system starts inside a logical volume whose metadata is at the front of the member. Rebuild it from that metadata and all the members with a reader that supports the layer: `target-query` (dissect; it also opens E01, VMDK, QCOW and a collection behind one interface, with a plugin per artefact family) or the Linux pack's `filesystem/storage` when loaded; check the version the image carries. A signature inside a member is a candidate, not the extent mapping. Validate the geometry, the metadata's consistency and that files read before accepting the volume. A missing member is a limitation. A `layer_describe` descriptor lists the volumes `fsstat` read; a slot it shows as unreadable is where this note starts.

**APFS.** `fsapfsinfo` reads a container's structure; snapshots, Fusion drives and T2-based encryption are not supported, so a failure there is the reader's limit. Whether the Sleuth Kit reads APFS is a fact of its build: try `fsstat`, record `mmls -V` (`filesystem/apfs`, macOS pack, when loaded).

**Record.** The mapping layer, its members and any that were missing, the reader and the version the image carries, and the geometry and file reads that were checked.

**Does not show.** That a signature inside a member is the extent mapping, or that a volume a reader opened is the one the system used.
