---
id: accounts/session-accounting
title: utmp, wtmp, btmp, lastlog and the SQLite successors
when: Choosing a session-accounting source and judging what its records cover.
needs: []
card: utmp_parse {"path": "<wtmp, btmp or lastlog>"}: read layout, its basis and byte_order first; name layout where lastlog is ambiguous. wtmpdb and lastlog2 are read only in a job, from a copy in $OUT; an unknown schema is refused; then sqlite_query {"db_path": "<that copy>"} reads it. A start and end paired by line and pid is a lead, not one session. lastlog keeps only the latest per uid. btmp's typed user is a length. A missing record excludes no login. Does not show: who was at the keyboard, or that a session ended.
tools: [utmp_parse, sqlite_query]
requires_host: []
---

Use when you read login accounting and need to say which format it is and how far it reaches. Not for authentication log lines (`logs/auth`) or the short rules for sessions and histories (`accounts/sessions-histories`).

Name the producer first: the classic files `utmp`, `wtmp`, `btmp` and `lastlog` (glibc's `struct utmp` of 384-byte records and `struct lastlog`, indexed by uid) and the SQLite databases of wtmpdb (a `wtmp` table) and lastlog2 (a `lastlog2` table). A distribution may keep either, both or neither, and a login program writes only the ones it was configured to. `utmp_parse` tells the classic layouts from the file (read `layout`, its basis and `byte_order` in the answer, and pass the one it says is ambiguous) and the SQLite pair from their tables and columns, in a job, from a copy of the database and its `-wal` that it keeps in `$OUT`; an unknown schema is listed and refused, and then `sqlite_query` can read the copy.

Read a classic record by its type: `USER_PROCESS` is a session that started, `DEAD_PROCESS` on the same line is one that ended, `BOOT_TIME` and `RUN_LVL` are system records. Pair them by line and pid only as a lead: a pid and a terminal name are reused, so a start and a later end on the same line are not shown to be one session. A SQLite row has its login and logout in one record; its unit (seconds or microseconds) is told by the size of the number and its raw value is kept beside the time.

A lastlog file is a sparse array by uid and holds one record per uid, the most recent: an empty slot is not proof the account never logged in, and the file says nothing of earlier logins. A btmp file holds failures, and the user field is what was typed, which can be a password in the wrong field (the answer carries its length, and the text is only in the job's text file). Coverage is the writers': sshd, login, a display manager and `su` write records only when their PAM stack or configuration says so, so a missing record excludes no login. Compare with `logs/auth` and the journal before you say a session did or did not happen.

Shows: the sessions and last logins the accounting stored, with the raw time beside the converted one. Does not show: that a session ended or stayed open, who was at the keyboard, or a login that no writer recorded. Record: the file or database, the format and `layout`, `byte_order`, the snapshot directory for SQLite, decoding errors, the rotated files read.

Sensitive output: a typed name can be a secret. Run `utmp_parse` as a job with `secret_output: true` to read typed text. Cite the record locator, never a typed value or a hash of it.
