---
id: logs/auth-time
title: Auth log years, rollovers and parse status
when: Dating, ordering or counting auth log lines whose stamps have no year or zone.
needs: []
tools: [auth_log, utmp_parse]
requires_host: [fls, istat]
---

Use only if you convert, order or count `auth_log` lines. Not for file order and sources (`logs/auth`) or for what a line shows (`logs/auth-lines`).

**Time.** A traditional stamp has no year and no zone. `auth_log` takes the year from the file's modification time (on a copied tree that is the time of the copy) or from your `year` or `years`, and says which per file (`year_basis`, `year_anchor`); `time_raw` is the stamp as written, `time` the clock reading as written, `time_utc` is set only where the stamp carries its zone, and `time_zone` is `unknown` until the profile establishes one (`triage/system-profile`). A month that goes down is read as a year end (`rollovers`, `rollover_lines`) only where the way forward round the calendar to it is six months or fewer (December to January); any other step back, and a line the next line contradicts, is flagged `reordered` and does not date the file, and the last line in order, with a day's margin for the unknown zone, does. A month that goes up is later, whatever the gap: a log that skips from January to September is not given a year end. So the year of a traditional line is inferred: fix it from a source with full dates before a conclusion rests on it (wtmp, btmp and lastlog through `utmp_parse`, the journal, `dpkg.log` and apt `history.log`, web server logs, the log's inode times through `istat`/`fls` or the catalogue's listing, a gzip file's `gzip_header_time`), then pass `year`, or `years` for a file that spans years. It matters most for a line before a long forward step (`forward_steps`; every record before the last one has `year_assumed`, and years may lie in it) and for any line of a copied tree (`mtime_may_be_copy_time`). An RFC 3339 stamp keeps its own offset. Read `unparsed` and `read_errors` before trusting a count: `status` is `complete` only where `all_lines_parsed` is true, which says every line matched a syslog shape and every file was read through, nothing more (a read that ran past `max_seconds` names the files it did not reach).

Shows: the year and zone `auth_log` applied and on what basis, and how complete the parse was. Does not show: the true year of a line the file's modification time dated, or that a complete parse means complete coverage. Record: `year_basis`, `year_assumed`, `forward_steps`, `time_zone`, `rollovers`, `rollover_lines`, `reordered` lines, `unparsed`, `read_errors`, `status`.

Sensitive output: none beyond the lines themselves; cite the locator.
