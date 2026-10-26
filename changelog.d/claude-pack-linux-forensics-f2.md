### Fixed: linux-forensics tools end at their deadline under a slow expression, show only plausible user names, bound their paging files and the link walk, and answer a signal

Time:

- **utmp_parse, shell_history, cron_dump**: a `user` / `contains` expression of the caller's was matched under a 2-second clock per match, but the loop read its own clock only every 4,096 records / 1,024 records / 2,048 lines and every match after the deadline still got 50 ms, so a few thousand records that each cost 16 ms ran a minute past `max_seconds` (68 seconds for the 60-second manifest) and no JSON came back. The clock is now read before every match, no match is begun after the deadline, and a match gets no more than the time that is left. When the cause is the deadline the reason says `max_seconds`, not "did not finish within 2.0 s".
- **journal_export**: the walk for links in a journal directory had no deadline and no cap, and a root directory walked the whole file system. The root directory is refused by name; the walk reads the clock for every entry, shares `max_seconds` with `journalctl`, ends at 100,000 entries, and a directory it could not check in that is refused as not a journal directory, naming where the walk stopped.

Output and disk:

- **cron_dump** shows the word in the user position of a table line only when it is `root`, an account of the evidence's passwd or a lower-case name of at most 32 characters; a pasted line whose first command word stood there (a key, a password) is `unparsed`, its text in the text file. Its paging files hold at most 128 MiB together (a timer of millions of assignments wrote about 55 times its size): past that the rows are counted (`not_written`, `assignments_not_paged`), located in the evidence by file and line, and the answer is partial. The place the inventory stopped in is in the census as `stopped`, and the status basis no longer calls it missing.
- **auth_log**: a `Disconnected from invalid user` line that is not sshd's form (`<name> <address> port <n>` with at most a bracketed stage) is read as a typed name whole, so a name that holds ` x port 1` no longer sets `source`, `port` or `stage`.
- **utmp_parse** lastlog: a selected slot whose user match was ended is no longer counted among the non-empty slots read.

Signals:

- **utmp_parse, shell_history, cron_dump** end on SIGTERM, SIGINT and SIGHUP with a last word (status `failed`, exit 128 plus the signal) that names the paging files and the text file written so far; the paging file is kept under its name and no unfinished temporary file is left.

New tests in `tests/pack-linux-bounds.test.ts` and `tests/pack-linux-auth-log.test.ts`. linux-forensics is re-sealed at 1.5.3.
