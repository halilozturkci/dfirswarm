---
id: router/start
title: Where to start with virtualization and backup evidence
when: A case involves virtual machine images, a hypervisor, a backup system or its repository.
needs: []
tools: []
requires_host: []
router: true
---

Use when the evidence is the control plane of virtualization or backup: hypervisor records, VM configuration, disk descriptors, backup catalogues and job records. Not for what is inside a guest (the platform packs) or a cloud provider's snapshot API (cloud pack).

| Question | Read |
|---|---|
| What may I do with this evidence, and what is on each plane? | `evidence/boundaries` |
| Whose clock is this, and which events can be ordered? | `control-plane/chronology` |
| What did someone do to the hypervisor, VMs or snapshots? | `hypervisor/activity` |
| Which VMs, disks, snapshots and datastores do the files name? | `hypervisor/inventory` |
| Is the disk or snapshot chain whole? | `snapshots/chain-integrity` |
| What do flags, leftover deltas and dirty bits suggest? | `snapshots/markers` |
| What does a header, descriptor or parent marker mean? | `snapshots/header-markers` |
| What do the catalogue, repository and retention setting each say? | `backup/catalogues-and-retention` |
| Was a backup deleted, or only a deletion requested or reported? | `backup/deletion-vs-loss` |
| Which recovery points still stand, and could one be restored? | `recovery/survivability` |

The incident sequence of a ransomware case (what ran, in what order, who is told) belongs to the ransomware pack when loaded; guest artefacts belong to the Windows, Linux and macOS packs.
