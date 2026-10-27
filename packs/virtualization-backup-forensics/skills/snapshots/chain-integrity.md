---
id: snapshots/chain-integrity
title: Is the disk or snapshot chain whole?
when: A VM's disk is a snapshot, delta or differencing disk, or a backing chain must be established.
needs: []
tools: [snapshot_chain_check]
requires_host: [qemu-img, target-query]
---

Use when a disk may depend on a parent or earlier snapshot and you must say whether the set you hold is whole. Not for a disk's content (`filesystem/layers` of the base pack) or for guessing what a missing parent held.

1. **Collect the set** first: every descriptor, extent, parent, `.vmx`, `.vmsd`, lock and state file, hashed. A chain is judged over the files you hold.
2. **Run `snapshot_chain_check` on the directory.** It reads VMDK descriptors and VHD, VHDX and QCOW2 headers (not content) and prints each disk, edge, extent and chain. A name a file holds is looked up in the set, never opened.
3. **Read each edge.** `resolved_to` is the parent; `id_check` is `match` (VHDX also `match_via_parent_linkage2`), `mismatch` or `not_available`. VMDK compares the child's recorded parent CID with the parent's CID (as numbers); VHD, its parent unique id; VHDX, its `parent_linkage` with the parent's DataWriteGuid. QCOW2 records only its backing file's name: never call a QCOW2 chain verified by identity.
4. **Chain status** is the first problem from the leaf; `issues` lists each kind. `complete`: parents present and read, identities agree where recorded, extents and data files present (raw base: `base_note`). `broken`: a parent not in the set. `record_incomplete`: a descriptor or header not read whole or not followable (a cap, an extent line it cannot read, a CID that is not a number): what it names is not all known. `parent_unreadable`, `identity_not_compared`, `identity_mismatch` (another parent file, or the parent changed since; no single history until its cause is shown), `extent_missing`, `data_file_missing`, `cycle`, `too_deep`.
5. **Extents.** `missing` or `short`: the disk cannot be read whole from this set; that does not show deletion.
6. **Optional second reading.** `qemu_img: auto` runs `qemu-img info` once per image on the evidence path given; its answer sits beside the tool's. It skips a VMDK text descriptor or sparse VMDK that names another file, and a QCOW2 image with an external data file (it would open them: `qemu_img.skipped`); a failed or timed-out run makes the answer `partial`. If `qemu-img` is absent the answer says so and the native reading stands. `qemu-img info --backing-chain` follows names the image holds: use it on a copy, in a job with no network. Read guest content only once the chain is established (`target-query`).
7. **Never repair.** `qemu-img commit`, `rebase`, `convert` or a hypervisor's consolidate on evidence changes the chain. Work on copies. For flags, leftover deltas and lock files read `snapshots/markers`.

**Shows.** The files' own statements about their parents, and whether the set satisfies them. **Does not show.** That the disk boots, what the parent held when the child was made, or why a parent is absent.
**Record.** Each leaf's chain and status, each edge's resolution and id check, missing extents, hashes, tool version, qemu-img's answer or absence.
**Sensitive output.** Run as a job with `secret_output: true`. Names, paths and ids are shown only if plain, else `<withheld: N bytes, field F>`; a short password used as a name passes unseen.
