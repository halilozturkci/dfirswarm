---
id: snapshots/header-markers
title: Header, descriptor and parent markers
when: snapshot_chain_check lists a header, descriptor, parent or second-reading marker.
needs: [snapshots/chain-integrity]
tools: [snapshot_chain_check]
requires_host: []
---

Use when `snapshot_chain_check` lists a marker about a disk's own header or descriptor, a parent link or the second reading. Not for consolidation, leftover deltas or locks (`snapshots/markers`; its method applies here too).

| Marker | Observation | Reading to test |
|---|---|---|
| `vhd_saved_state_flag` | VHD footer's Saved State byte set | a VM saved state: keep it with the disk |
| `vhd_footer_copy_differs` | the footer copy at the start is not the one at the end | not written together: an interrupted write or an edit |
| `newline_detection_mismatch` (VMDK) | the sparse header's newline-detection bytes are not the fixed ones | copied in a mode that rewrites line ends |
| `vhd_footer_checksum_fail`, `vhd_dynamic_header_checksum_fail`, `vhdx_headers_checksum_fail`, `vhdx_region_table_checksum_fail` | a VHD footer or dynamic header checksum, or both VHDX headers' or region tables' CRC-32C, fail | damaged or edited; read as written (the VHDX header by sequence alone); `partial` |
| `vhdx_region_table_copy_damaged`, `vhdx_header_copy_damaged`, `vhd_footer_copy_missing` | a region-table copy or a VHDX header fails, or a VHD's end footer is missing; the other copy was read (last two: `partial`) | a damaged, edited or cut copy |
| `descriptor_problem` | a bad CID or parentCID, or a parentCID with no hint | inconsistent as written; the chain stops there |
| `duplicate_cid` | descriptors that carry one CID | a copy or a clone with no new CID: a CID match proves less |
| `parent_missing`, `parent_ambiguous` | the parent is not in the set, or several files match its name | not collected, deleted or renamed; the set does not decide which |
| `parent_names_disagree` (VHD, VHDX) | the header name and the locators name different files | written at different times, or edited; the first name that resolved was used |
| `parent_cid_mismatch`, `parent_unique_id_mismatch`, `parent_linkage_mismatch` | the child records a parent identity the parent does not carry | made against another file, or the parent was written since (a VHDX's DataWriteGuid changes then) |
| `extent_missing`, `extent_short` | an extent is not in the set or is smaller than the descriptor says | not collected, truncated or partly copied |
| `external_data_file_missing` (QCOW2) | the header names a data file not in the set | the guest data is in that file: not whole here |
| `chain_cycle` | parent names lead back to a file on the path | at least one name or file is wrong |
| `qemu_img_disagrees` | the second reading's (`qemu_img`) virtual size is not the header's | one reading is wrong or the file damaged; neither is preferred |

**Shows.** What a header or descriptor records about itself and its parent, held against the set. **Does not show.** Who wrote it, when, why, or whether data was lost.
**Record.** Marker, source ids, the observation verbatim, the edge's `resolution` and `id_check`, records for and against.
**Sensitive output.** Run `snapshot_chain_check` as a job with `secret_output: true`. Names, paths and ids are shown only if plain, else `<withheld: N bytes, field F>`; a short password used as a name passes unseen.
