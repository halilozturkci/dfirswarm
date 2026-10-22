---
id: accounts/sessions-histories
title: Sessions and shell histories
when: Reading wtmp, btmp, lastlog and shell histories as leads.
needs: []
tools: [utmp_parse, shell_history, sqlite_query]
requires_host: []
---

Use only if you read session accounting or shell histories. Not for accounts and authorization (`accounts/users`) or for authentication log lines (`logs/auth`).

**Sessions.** `utmp_parse` reads classic wtmp, btmp, utmp and lastlog in the layouts it names (read `layout`, its basis and `byte_order` in the answer; it refuses an ambiguous lastlog layout and tells you to pass one). It does not decode `lastlog2` or `wtmpdb`, which are SQLite databases: copy them with their -wal and -shm files and open the copy read-only with `sqlite_query`. A `user` filter on btmp is refused outside a job (its names are withheld, so it would read as no such user). Inventory the rotated files and record decoding errors and ambiguity. Session accounting is written by the applications and PAM modules configured to write it, so a missing record does not exclude an authentication, and a session with no end record is not shown to be open.

**Histories.** `shell_history` is a lead source. A history file holds what the program saved and when it wrote it; its `user` is `unknown` unless the evidence's `etc/passwd` gives that home to one account, and the directory's name is not an account. A recorded command shows neither that it ran to success nor who typed it. Keep source order, multi-line context and any recorded times, and allow for suppression (`HISTCONTROL`, `HISTFILE` unset), concurrent shells, custom history paths and sessions that were never flushed.

Shows: sessions and commands the accounting and history files saved. Does not show: who was at the keyboard, that a command ran, or that a session ended or stayed open. Record: file, record, `layout`, `byte_order`, decoding errors.

Sensitive output: history commands can hold secrets. Run `shell_history` as a job with `secret_output: true`, with `write_commands: true` to read the text; the answer without it carries locators and lengths only. Cite file and record, never the command or a hash of it.
