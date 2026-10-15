---
id: snapshots/chain-integrity
title: Is the disk or snapshot chain whole?
when: A VM's disk is a snapshot, delta or differencing disk, or a backing chain must be established.
needs: []
tools: [snapshot_chain_check]
requires_host: [qemu-img, target-query]
---

Use when a disk may depend on a parent or earlier snapshot and you must say whether the set you hold is whole. Not for a disk's content (`filesystem/layers` of the base pack) or for guessing what a missing parent held.

1. **Collect the set** first: every descriptor, extent, parent, `.vmx`, `.vmsd`, lock and state file. Hash them. A chain is judged over the files you hold.
2. **Run `snapshot_chain_check` on the directory.** It reads VMware descriptors, VHD, VHDX and QCOW2 headers (not content) and prints each disk, parent edge, extent and chain from leaf to base. A name a file holds is looked up among the files given, never opened.
3. **Read each edge.** `resolved_to` is the parent found; `id_check` is `match` (VHDX also `match_via_parent_linkage2`), `mismatch` or `not_available`. VMDK compares the child's recorded parent CID with the parent's CID (as numbers); VHD, its parent unique id; VHDX, its `parent_linkage` with the parent's DataWriteGuid (MS-VHDX; the virtual disk id is not what a child records). QCOW2 records no identity of its backing file, only its name: never call a QCOW2 chain verified by identity.
4. **Chain status** is the first problem from the leaf; `issues` lists each kind. `complete`: parents present and read, identities agree where recorded, extents and data files present (a raw base: `base_note`). `broken`: a parent not in the set. `parent_unreadable`, `identity_not_compared`, `identity_mismatch` (another parent file, or the parent changed since), `extent_missing`, `data_file_missing`, `cycle`, `too_deep`. A mismatch is no single history until its cause is shown.
5. **Extents.** `missing` or `short`: the disk cannot be read whole from this set; that does not show deletion (it may not have been collected).
6. **Optional second reading.** `qemu_img: auto` runs `qemu-img info` once per image on the evidence path given (no copy is made); its answer sits beside the tool's, and disagreement is a question. It skips a VMDK text descriptor and a QCOW2 image with an external data file (it would open the files they name: `qemu_img.skipped`); a failed or timed-out run makes the answer `partial`. `qemu-img` is optional (base pack): if absent, the answer says so and the native reading stands. `qemu-img info --backing-chain` is an examiner's command on a copy in a job with no network; it follows names the image holds. Read guest content only after the chain is established, with `target-query` (Dissect) or the base pack's layer skill.
7. **Never repair.** `qemu-img commit`, `rebase`, `convert` or a hypervisor's consolidate on evidence changes the chain. Work on copies.

**Shows.** The files' own statements about their parents, and whether the set satisfies them. **Does not show.** That the disk boots, what the parent held when the child was made, or why a parent is absent.
**Record.** Each leaf's chain and status, each edge's resolution and id check, missing extents, hashes, tool version, qemu-img's answer or absence.
**Sensitive output.** Names and hints are shape-checked, not secret-proof: run as a job with `secret_output: true`.
