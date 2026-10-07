---
id: filesystem/mft
title: Reading MFT records and their state
when: You need names, streams, allocation or deletion state of NTFS files from the $MFT.
needs: []
tools: [mft_records, icat_extract, extract_stream]
requires_host: [fls, istat, fsntfsinfo, MFTECmd]
---

Use when you read `$MFT` records. Not for time comparison, index slack or alternate streams.

- Cite a record by number and sequence: another sequence is another file in the same slot. Extract entry 0 with `icat_extract`, hash it, give the copy to `mft_records`, which reads every record once. `limit` is an inline page; `all_results` names the whole list; `record_size_from` says where the record size came from.
- State before content. A record whose update-sequence fixup fails is still parsed, flagged `fixup_failed` and `unreliable`, counted in `records_fixup_failed`, and does not make `status` partial: read the count. A range outside its attribute, or a used size past the record or short of the first attribute, gives `structural_errors`, keeps what was sound and makes the run partial. Confirm an unreliable record with `istat` or a second parser.
- BAAD is `record_marked_bad`. Slots with neither FILE nor BAAD are not records: `slots_zeroed` (unused, ordinary at the end) and `slots_unrecognised` (holds data; a problem, partial); `slots_without_signature` is their sum. A file not starting on a record boundary is read at its own alignment (`alignment_offset` nonzero, partial); under 48 bytes left is `trailing_bytes`.
- Names (long, DOS, one per hard link) carry `parent_entry` and `parent_sequence`, streams their `instance`. `$ATTRIBUTE_LIST` is not resolved: `has_attribute_list` with `attribute_list_resolved: false` means the rest sits in extension records, which come as records of their own (`base_record`, `base_sequence`, `is_extension_record`). Join them by hand and say so. No path is built: take it from `fls`, or join parents whose sequences match.
- Inode address `<entry>-<type>-<id>`: type 128 is $DATA, the id is per record, so no id range means "alternate stream".
- Resident data is a property of the attribute, not of size; `with_resident` returns it for that record only (check `sequence`, `in_use`, `unreliable`). A non-resident stream has `allocated_size`, `real_size`, `initialised_size` and no runs: `istat` gives the runs, `extract_stream` the bytes, under your own `work/<your id>/...`.
- A deleted record (`deleted_only`; `in_use` false) keeps names and times until reuse: the times the file had, not of its deletion. For records that matter, `fsntfsinfo` (volume; `-h` gives the offset unit) and `MFTECmd` (extracted $MFT) are second parsers; the record's bytes decide a disagreement.

Shows: the volume held this record, with these names and streams, in this state. Does not show: who changed or deleted a file, why or when; a complete stream while an attribute list is unresolved; absence (records are reused). Record: entry and sequence, `status`, `alignment_offset`, slot counts, `structural_errors`, stream `instance`, parser versions.
Sensitive output: `with_resident` returns small files whole; run `mft_records` as a job with `secret_output: true` when they may hold secrets.

Open `filesystem/timestamps` only if the time sets disagree, `filesystem/indx` only for names a directory no longer lists, `filesystem/ads` only for a named stream.
