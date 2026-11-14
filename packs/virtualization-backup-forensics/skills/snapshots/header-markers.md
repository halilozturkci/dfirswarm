---
id: snapshots/header-markers
title: Header, descriptor and parent markers
when: snapshot_chain_check lists a header, descriptor, parent or second-reading marker.
needs: [snapshots/chain-integrity]
card: A snapshot_chain_check marker is an observation, not a cause. A failed checksum is read as written; the answer is partial. Does not show: who wrote a header, when, why, or whether data was lost.
tools: [snapshot_chain_check]
requires_host: []
---

Use when `snapshot_chain_check` lists a marker about a header, descriptor, parent link or the second reading. Not for consolidation, leftover deltas or locks (`snapshots/markers`; its method applies here too).

| Marker | Observation | Reading to test |
|---|---|---|
| `vhd_saved_state_flag` | VHD footer's Saved State byte set | a VM saved state: keep it with the disk |
| `vhd_footer_copy_differs` | the footer's start copy differs from its end one | an interrupted write or an edit |
| `newline_detection_mismatch` (VMDK) | sparse header's newline-detection bytes not the fixed ones | copied in a mode that rewrites line ends |
| `vhd_footer_checksum_fail`, `vhd_dynamic_header_checksum_fail`, `vhdx_headers_checksum_fail`, `vhdx_region_table_checksum_fail` | a VHD footer or dynamic header checksum, or both VHDX headers' or region tables' CRC-32C, fail | damaged or edited; read as written; `partial` |
| `vhdx_region_table_copy_damaged`, `vhdx_header_copy_damaged`, `vhd_footer_copy_missing` | a region-table copy or a VHDX header fails, or a VHD's end footer is missing; the other copy was read (last two: `partial`) | damaged, edited or cut |
| `descriptor_problem` | a descriptor or QCOW2 header not read whole (a cap, an unreadable line or name), a bad CID or parentCID, or a parentCID with no hint | `record_incomplete`, `partial` |
| `duplicate_cid` | descriptors that carry one CID | a clone with no new CID: a match proves less |
| `parent_missing`, `parent_ambiguous` | the parent not in the set, or several files match its name | not collected, deleted or renamed; the set does not decide which |
| `parent_names_disagree` (VHD, VHDX) | header name and locators name different files | written at different times, or edited; the first name resolved is used |
| `parent_cid_mismatch`, `parent_unique_id_mismatch`, `parent_linkage_mismatch` | the child records a parent identity the parent does not carry | made against another file, or the parent written since |
| `extent_missing`, `extent_short` | an extent not in the set, or smaller than the descriptor says | not collected or truncated |
| `external_data_file_missing` (QCOW2) | the header names a data file not in the set | the guest data is in that file |
| `chain_cycle` | parent names lead back to a file on the path | at least one name or file is wrong |
| `qemu_img_disagrees` | `qemu_img`'s virtual size is not the header's | one reading wrong or the file damaged; neither preferred |

**Shows.** What a header or descriptor records of itself and its parent, against the set. **Does not show.** Who wrote it, when, why, or whether data was lost.
**Record.** Marker, source ids, the observation verbatim, the edge's `resolution` and `id_check`, records for and against.
**Sensitive output.** Run `snapshot_chain_check` as a job with `secret_output: true`. Names show only if plain, else `<withheld N characters: reason>`; a short password used as a name passes.
