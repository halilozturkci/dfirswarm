---
id: apps/databases
title: App databases, WAL, and what deleted means in SQLite
when: The answer is inside an application's own storage.
needs: [extractions/what-you-have]
tools: [sqlite_freespace, sqlite_query]
requires_host: []
---

Almost every app on either platform stores its data in SQLite, so this one skill
covers messengers, browsers, mail, notes and most of the rest.

**Copy the whole set, always.** A SQLite database is up to three files: the
database, a `-wal` write-ahead log, and a `-shm` shared-memory index. Query the
database alone and you see the state at the last checkpoint — which can be weeks
old on a phone that is never closed cleanly. **The newest messages are in the
WAL.** Copying only the `.db` is the single most common mistake in mobile work
and it silently loses exactly the period a case is about.

**Deletion inside SQLite is not necessarily erasure.** A deleted row's bytes
can stay in page free space until reuse. `secure_delete`, `VACUUM`, page reuse
and application-level encryption can instead leave nothing useful.
`sqlite_freespace` walks freelist pages, the unallocated gap and the freeblock
chain of each b-tree page and returns readable fragments.

Three rules for a recovered row:

1. **It has no guaranteed column mapping.** You are reading a record's payload
   out of free space; which value was in which column is inference unless the
   record header survived intact. Say which.
2. **It has no reliable time** unless the timestamp is inside the recovered
   bytes, and then it is only as good as the record.
3. **It may be from a different table.** Free space is per page and pages are
   reused across the file.

Read the schema before the data — `sqlite_query` with
`SELECT sql FROM sqlite_master` — because column names carry meaning that no
amount of staring at values will give you. And check for a `-journal` file as
well as a WAL: a rollback journal holds the *previous* contents of changed
pages, which is another route to a value that was overwritten.

Call `sqlite_freespace` on a working copy that keeps the database, `-wal` and
`-shm` under the same basename. Filter with `contains` only after an unfiltered
run has been retained: a negative filtered result proves only that expression
was absent from the regions this parser understands.
