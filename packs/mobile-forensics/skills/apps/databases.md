---
id: apps/databases
title: App databases, transaction state and deleted fragments
when: Use when an answer rests on an application's SQLite records or on possibly deleted content. Not for the meaning of one app's tables.
needs: [extractions/what-you-have]
tools: [sqlite_query, sqlite_freespace, file_type]
requires_host: []
---

Use when an answer rests on an application's SQLite records or on possibly deleted content. Not for the meaning of one app's tables (`ios/artifacts`, `android/artifacts`).

**Identify the format first** (`file_type`): SQLite, SQLCipher, protobuf, plist, JSON, LevelDB. A missing SQLite header is not proof of encryption; an unsupported format, a damaged file and protected content are three different things.

**Keep the set.** The database and every `-wal`, `-shm` and `-journal` are separate evidence objects: keep their names and source paths. A missing companion may be acquisition policy or database state; never borrow one from another acquisition. Work on a copy under `$OUT` (originals untouched), and never checkpoint, vacuum or repair the original.

**WAL and journal.** A WAL may hold committed changes absent from the main file, older page versions or an unfinished transaction; a rollback journal holds the pre-change pages of a write. Neither is "the newest messages". As of October 2026 `sqlite_query` opens the main file immutable and does not apply a `-wal` beside it: check the installed tool's answer. For the WAL-applied state open a copy of the whole set in a SQLite client under `$OUT`, and say that the result is from that copy.

**Read the schema before the rows** (`SELECT sql FROM sqlite_master`). Record the exact query, table, row id, units of each time field and the raw value beside any conversion.

**Deleted fragments** (`sqlite_freespace`; fetch `apps/fragments` for how to read its answer): it reads free pages, the gap of a page and its freeblock chain in the main file only. It does not read a `-wal` or `-journal`, does not rebuild rows, and cannot tell secure deletion, reuse or vacuum from nothing having been there. A free-space hit may be obsolete, duplicated or unrelated to a user's deletion.

**Does not show**: which column, table, time, sender or thread a fragment came from, or that the user deleted it. A negative covers the regions and encodings counted in `scanned` and nothing else.

**Record**: format, schema version, each companion's presence, the query, and for a negative the source, the regions scanned and the encodings.

**Sensitive output**: `sqlite_freespace` and message tables hold private text and sometimes credentials: run them as a job with `secret_output: true`; cite a location, never a password, token or key value.
