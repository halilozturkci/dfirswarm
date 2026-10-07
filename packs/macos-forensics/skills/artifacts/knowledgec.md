---
id: artifacts/knowledgec
title: KnowledgeC activity records and their limits
when: Interpret retained application and device-state activity.
needs: [artifacts/plists]
tools: [knowledgec_query, sqlite_query, timestamp_decode]
requires_host: []
---

macOS keeps application and device-state records for its own features in SQLite. They
are records of what the machine's features saw, not a log of what a person did.

    ~/Library/Application Support/Knowledge/knowledgeC.db     per user
    /private/var/db/CoreDuet/Knowledge/knowledgeC.db          system-wide

Inventory the user and system stores separately, and take each database with its
`-wal`, `-shm` and `-journal` as one set. A write-ahead log holds committed rows the main
file lacks: `knowledgec_query` applies one it finds in a private copy and counts the
frames applied (`source_used`); a log left behind at collection is rows you do not have.
A rollback journal holds the old pages of a transaction that did not commit and no rows
the main file lacks: the tool rolls a hot one back in the copy and says so in `problems`,
because the copy is then not the main file as acquired.

**Enumerate before you query.** The answer lists every stream in the file with its
count and its first and last start. Candidates to look for, not a guaranteed set:
`/app/inFocus`, `/app/usage`, `/display/isBacklit`, `/device/isLocked`,
`/safari/history`, `/app/webUsage`. Streams, field types and retention vary by build.

**What an entry carries.** The row's `z_pk`; typed values (`value_string`,
`value_integer`, `value_double`, `value_type_code`: a state stream keeps its state in
the integer, so confirm the encoding for the build before reading 0 or 1); the raw and
converted start, end and creation times; the `metadata` (ZSTRUCTUREDMETADATA columns
that are set) and the `source` (ZSOURCE: bundle id, device id, and so on) joined from the
file's own schema. `schema.joins` false means the file lacks that table (or its schema could not
be read, which `problems` says) and the rows have no such data. A TEXT or BLOB cell
longer than 4096 characters or bytes is returned cut, with its whole length and where the
whole is (`_truncated`, `_where`); `export_oversize` writes the whole values to files.
Check `status`, `problems` and `filters_unapplied`. For another table or a
query the tool does not make, use `sqlite_query` on a copy, and read what it says about
the write-ahead log before you rely on a negative.

**Time.** The date columns are commonly seconds since 2001-01-01 UTC; confirm each
column's type and meaning, keep the raw start, end and creation values, and do not
read creation (ingestion) time as the time of the activity. `utc_offset_seconds` is the
offset the row recorded; it is not an instruction to shift the UTC value again.
`timestamp_decode` lists candidate readings of a raw number; it does not choose the
field's epoch. `since` and `until` select by start time, so an interval that began
before the window and overlapped it is missed.

**Whose activity.** The `source` columns can name a device other than this Mac. Decide
whether the source identifies this device before you attribute a row to this machine.

**What foreground and display records support.** Statements about recorded application
or device state: this application was in front, the screen was lit, the device was
locked, for these seconds. They do not show keyboard input, physical presence,
attention, intent or who the human was, alone or in a row. Correlate authentication and
session evidence (`logs/unified`, `accounts/users`) and weigh remote access and
background activity before you say more.

**Biome.** Newer activity stores under `~/Library/Biome/` are another format:
SEGB-framed records whose payloads belong to each stream. `knowledgec_query` does not
read them and this pack has no decoder; if the mobile-forensics pack is loaded, its
`ios/biome-segb` skill separates the framing from the payload, and iOS semantics do not
carry over to macOS unchanged. A gap in KnowledgeC does not show that the activity did
not happen elsewhere.

**Coverage.** Measure it per stream and source: first and last rows, gaps, decoding
failures, sidecars present. Cite the database, table, `z_pk`, query and sealed output,
and keep apart "not retained", "not acquired", "unsupported" and "searched, no match".

**Sensitive output.** `/safari/history` and web-usage values are URLs and can carry
tokens and session identifiers in their query strings. Cite the row, and write a URL
without its query string unless the question needs it.
