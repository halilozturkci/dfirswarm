---
id: artifacts/knowledgec-fields-time
title: KnowledgeC row fields and time columns
when: Read the values, metadata and dates of a KnowledgeC row from knowledgec_query.
needs: []
tools: [knowledgec_query, timestamp_decode]
requires_host: []
---

Use only if you read a `knowledgec_query` row's values or convert its dates. Not for which streams exist, whose activity it is or what it supports (`artifacts/knowledgec`).

**What an entry carries.** The row's `z_pk`; typed values (`value_string`, `value_integer`, `value_double`, `value_type_code`: a state stream keeps its state in the integer, so confirm the encoding for the build before reading 0 or 1); the raw and converted start, end and creation times; the `metadata` (ZSTRUCTUREDMETADATA columns that are set) and the `source` (ZSOURCE: bundle id, device id, and so on) joined from the file's own schema. `schema.joins` false means the file lacks that table (or its schema could not be read, which `problems` says) and the rows have no such data. Streams to look for, not a guaranteed set: `/app/inFocus`, `/app/usage`, `/display/isBacklit`, `/device/isLocked`, `/safari/history`, `/app/webUsage`. A TEXT or BLOB cell longer than 4096 characters or bytes is returned cut, with its whole length and where the whole is (`_truncated`, `_where`); a BLOB's head is hexadecimal (`_hex`). `export_oversize` (a `secret_output` job) writes the whole values to files.

**A read that stops.** The tool has a clock (`max_seconds`, 80 by default, at most 90). When it passes, or a stop signal arrives, `status` is `partial` and `resume` says where: the entries are a prefix in start order, whole in the file the answer names. Run again with `after_start_raw` and `after_z_pk` set to the two values in `resume` (and the same `stream`, `since`, `until`): the read goes on at the next row, none twice and none skipped, also when thousands of rows share one start (`since` set to `resume_since` reads the rows at the last start again). A stopped read is not the stream's extent.

**Time.** The date columns are commonly seconds since 2001-01-01 UTC; confirm each column's type and meaning, keep the raw start, end and creation values, and do not read creation (ingestion) time as the time of the activity. `utc_offset_seconds` is the offset the row recorded; it is not an instruction to shift the UTC value again. `timestamp_decode` lists candidate readings of a raw number; it does not choose the field's epoch. `since` and `until` select by start time, so an interval that began before the window and overlapped it is missed.

Shows: the recorded state or event for a stream, with its raw and converted times. Does not show: that creation time is the activity time, the epoch of a column you did not confirm, or an overlapping interval that began before `since`.
Record: `z_pk`, the raw start, end and creation values, the type code, the offset recorded and the filters that were applied.
Sensitive output: URL cells (`/safari/history`, `/app/webUsage`) follow the rule in `artifacts/knowledgec`.
