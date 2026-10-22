### Fixed: linux-forensics tools read the clock inside long files, bound a timer's row, withhold a typed name by its position and say what they did not read

Resource bounds on hostile evidence:

- **shell_history** read the clock once per 1,024 records, so a history file of blank lines, or of millions of data lines under one `#<epoch>` stamp, or of one line of gigabytes, ran past `max_seconds` (and past the manifest's 120 seconds) and said `complete`. The clock is now read between physical lines and after every 8 MiB piece; the file is named partial and the record in hand is kept. `byte_offset` lost one byte per line end (two with CRLF): it is the position of the record's first byte.
- **cron_dump** put a whole `.timer` file into the answer (an 8 MiB timer made a 320 MB answer and 2.7 GB of memory). A timer's row now shows its first 50 assignments (`assignment_count`, `assignments_not_shown`) and the first 50 schedules; the rest are paged under `pages.assignments`, and `write_text` writes every assignment of every timer as a row of its own. The unit file is read as a stream (41 MB of memory for the same file). The clock is read for every file and inside a timer file; sixty thousand small tables ended at `max_seconds` only after the whole directory before.
- **auth_log** reads the clock inside the loop that skips a line of many megabytes (a sparse file with no newline ran two passes past its deadline).
- **shell_history, cron_dump, utmp_parse**: a `contains` or `user` expression runs under a 2-second clock per match (a nested repeat on a 28-character command took 17 seconds, and 32 characters minutes). A match that does not finish ends the read as partial and says where.
- **journal_export** bounds every field of a row: a byte array is named by its length (and no longer printed as numbers that read back as the text), a long string or list is cut with its whole length, a field holding several values shows the first five, and the cursor, clocks and boot id are cut like the identity fields; a field name over 128 characters is cut in the census and a boot id over 128 characters is counted and not grouped.

Typed names and the columns of a cron line:

- **auth_log** withholds a typed name by its position in a line it recognises: `Invalid user` and `Illegal user` to the last `from <address>`, `Failed <method> for invalid user` and `illegal user`, `Disconnected from invalid user`, a PAM `ruser=`, and all of a PAM `user=` to the end of the line (a name can hold spaces, `from x port 1`, or `tty=x`). The source is the address after the name. The skill and the manifest say "by position, not by shape".
- **cron_dump** takes the first word after a table's schedule as the user only when it has the shape of a user name, and a month or weekday field only when it is a number, `*`, a three-letter name, a range, a step or a list; a pasted line without a user field, or with a word in a schedule position, is `unparsed` and its text is in the text file.

Statuses that say what was done:

- **cron_dump** is `partial`, not `complete`, when no place was read or when a cron line matched no table shape; **shell_history** when no history file was found; **utmp_parse** refuses a `user` filter on a typed file (btmp) outside a job instead of answering with an empty list, and no longer says a byte order is supported by records when every record is empty; **auth_log** does not call the order of files consistent when one of them is ordered by its name only.
- **linux-target recipe**: a second run into the same `--out` is refused before anything is written, so the first run's receipt is not replaced by a smaller one.
- **journal_export**: the guard against this machine's own journal resolves links (a path through a symlink, or through `/proc/self/root`, to `/var/log/journal` was read).

Shared process block: the linux, reverse-engineering and base (`timeline_super`) copies are the network pack's current text, and the windows pack and its tool-library copies carry the same walk fixes. `kill_tree` leaves a program that was already waited for alone (its pid may be another process's), the walk below a pid has a seen set, and macOS lists children through libproc before it runs `ps` (a slow `ps` returned nothing and left the tree running). A test holds every carrier of the block to these.

New tests: `tests/pack-linux-bounds.test.ts` and additions to the auth_log, journal_export, utmp_parse, process and shared-block suites. linux-forensics, reverse-engineering, computer-forensics-base and windows-forensics are re-sealed and raised by a patch version.
