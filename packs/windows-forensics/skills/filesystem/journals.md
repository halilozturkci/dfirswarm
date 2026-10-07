---
id: filesystem/journals
title: The NTFS change journal and the transaction log
when: You need what changed on an NTFS volume, under which name, and the order the journal gives.
needs: []
tools: [usn_journal, extract_stream]
requires_host: [fls, istat]
---

Use when you read `$UsnJrnl:$J` or are asked about `$LogFile`. Not for what an $MFT record holds (`filesystem/mft`) or who deleted a file (`filesystem/recycle-bin`).

- Find `$Extend\$UsnJrnl` in `fls`, take the `$J` address (`<entry>-128-<id>`), confirm it with `istat`, extract it with `extract_stream` under `work/<your id>/...` and keep the hash. Run `usn_journal` once without a filter and keep the whole result (`all_results`; `limit` is an inline page). A `name` filter narrows what is returned, never what is read: `records_read` is the total.
- A record: the file's name at that moment, `file_reference`/`file_sequence`, `parent_reference`/`parent_sequence`, `reason` with `reason_raw`, `source_info`, `security_id`, `usn`, `minor_version`, the timestamp with its raw FILETIME. Reason bits accumulate and `CLOSE` ends an accumulation: not one entry per operation. `security_id` is a descriptor id, not an actor; a record has no process or account.
- A rename is `RENAME_OLD_NAME` and `RENAME_NEW_NAME`: pair them by reference and sequence, not adjacency. A shell delete to the bin is a rename into it; `FILE_DELETE` appears when the item leaves it, and a restore is a rename too.
- Version 4 records have no name: a `name` filter drops them (`nameless_excluded_by_filter`) unless `include_nameless: true`; `records_by_version` says what the journal holds. A record of another major version that has the shape of one is listed (`unsupported_version_records`, `unsupported_versions`, `unsupported_version_bytes`, `unsupported_version_list`, whole in `all_unsupported_version_list`); its bytes are also `unrecognised_bytes`.
- Paths: join `parent_reference`/`parent_sequence` to an $MFT record with the same entry and sequence; a changed sequence means the parent was reused and the path is unresolved. A non-regular file is refused (`not_attempted`).
- `usn` orders records in this journal on this volume; the timestamp is the clock when written. If they disagree report both (clock change, journal recreated); nothing orders volumes or hosts.
- The journal is a window: state first and last timestamp, `first_record_offset`, `zero_bytes_skipped`, `unrecognised_bytes`, `prefix_unrecognised_bytes`, `unrecognised_ranges` (there is no `status`). No `$J`, an empty one or a late start is coverage, not clearing. `$UsnJrnl:$Max` is not read.
- A rename, overwrite and delete sequence fits a temporary-file save, an installer, a sync client, a cleanup job and a secure-delete utility alike: a hypothesis until another record picks one.
- `$LogFile`: log sequence numbers order records within one log generation and are not clock times. This pack has no decoder, so an extract is not an examination: say the route was not available, or use a parser you validated, with its version.

Shows: the volume recorded a change with these reasons, under this name and reference, at this clock time. Does not show: who or which program, that content was overwritten, malice, or the file's current state. Record: stream address and hash, the window and counts above, how each path was resolved.
