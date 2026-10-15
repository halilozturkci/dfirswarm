---
id: snapshots/markers
title: Consolidation and unclean-close markers
when: snapshot_chain_check lists a marker, or snapshots may have been removed, merged or interrupted.
needs: [snapshots/chain-integrity]
tools: [snapshot_chain_check]
requires_host: []
---

Use when `snapshot_chain_check` lists a marker, or the question is whether a snapshot was removed, a consolidation did not finish, or an image was copied while in use. Not for a chain's completeness (`snapshots/chain-integrity`).

Each marker is a candidate with its observation beside it. Read the observation first, the reading second, then corroborate.

| Marker | Observation | Reading to test |
|---|---|---|
| `unclean_shutdown_flag` (VMDK) | the sparse extent's flag is set | open for writing when last written, or a copy of a live file |
| `qcow2_dirty_bit`, `qcow2_corrupt_bit` | feature bits set | not closed cleanly, or marked corrupt by the program that last wrote it |
| `vhdx_log_guid_set` | header log GUID not zero | a log is present; replay state is not read here |
| `running_disk_is_a_delta_without_snapshots` | configuration's disk records a parent, snapshot database lists none | a consolidation not finished, a snapshot removed without merging its delta, or the database not collected |
| `delta_not_in_snapshot_database` | a delta no configuration or snapshot names, not a parent of one that is named | a delta left by a removed snapshot, or another VM's file |
| `snapshot_disk_missing` | database names a disk not in the set | removed, renamed, or not collected |
| `extent_without_descriptor` | a sparse extent no descriptor in the set names | its descriptor was not collected or was removed, or it belongs to a disk outside the set |
| `lock_artefact` | a lock file or directory is present | held when copied, or left after a crash |
| a header, descriptor, parent, extent or second-reading marker (`vhd_*`, `parent_*`, `*_mismatch`, `extent_*` and the rest) | | `snapshots/header-markers` |

1. **Corroborate with the platform's own records** of the operation: the task or event for a snapshot remove, consolidate or power operation (`hypervisor/activity`). A marker without such a record stays a candidate.
2. **Compare file times** on the delta, the parent and the configuration, remembering that a copy sets times as well as an edit. Hash the files before touching them.
3. **Internal QCOW2 snapshots** list name, id and a host-side creation time with their entries; the names are what their creator wrote. They show the image contained snapshots, not who removed one.
4. **What would weaken a reading:** the same flag on a clean copy made the same way, a second copy without it, a task record of a normal shutdown.
5. **Do not name a cause** ("tampering", "failed backup") from a marker. Say what the files show, what else would show it, and what you asked for.

**Shows.** A flag, bit or leftover file as written. **Does not show.** Who or what caused it, when, or whether data was lost.
**Record.** Marker, source id, the observation verbatim, corroborating or contradicting records, and the alternatives.
**Sensitive output.** Run `snapshot_chain_check` as a job with `secret_output: true`. A name, path or id is shown only if plain (no `=` or `@`, no token-like run; GUIDs, VMFS and `naa.` ids stay), else `<withheld: N bytes, field F>`; a short password used as a name passes unseen.
